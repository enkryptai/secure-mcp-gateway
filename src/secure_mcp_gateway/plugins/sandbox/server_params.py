"""
build_server_params — async context manager that transparently wraps
MCP server launches in a sandbox when configured.

Drop-in replacement for the raw ``stdio_client(StdioServerParameters(...))``
pattern used at every call site in client.py and tool_execution_service.py.

Supports three transport modes:
- **stdio** (default for command-based servers)
- **streamable_http** (default for URL-based servers)
- **sse** (legacy HTTP+SSE for older remote servers)

Server configs can declare a remote transport in two ways:

1. **Explicit URL** (gateway-native format)::

       {"url": "https://…", "transport": "streamable_http"}

2. **Standard ``type`` field** (VS Code / Claude / Cursor format)::

       {"type": "http", "url": "https://…"}
       {"type": "sse",  "url": "https://…"}

Both are accepted everywhere a ``server_config`` / ``server_entry["config"]``
dict is expected.
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx
from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client

from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    TransportError,
    create_transport_error,
)
from secure_mcp_gateway.plugins.sandbox.config_manager import get_sandbox_config_manager
from secure_mcp_gateway.utils import logger

# Maps the standard MCP client ``type`` values to our internal transport names.
_TYPE_TO_TRANSPORT = {
    "http": "streamable_http",
    "sse": "sse",
}


def is_url_config(config: Dict[str, Any]) -> bool:
    """Return True when *config* describes a remote HTTP server.

    Recognised indicators (either is sufficient):
    - ``config["url"]`` is present, **or**
    - ``config["type"]`` is ``"http"`` or ``"sse"``
    """
    if config.get("url"):
        return True
    return config.get("type", "").lower() in _TYPE_TO_TRANSPORT


def _resolve_transport(config: Dict[str, Any]) -> str:
    """Derive the internal transport name from a remote-server config dict.

    Priority:
    1. Explicit ``transport`` key  (``"streamable_http"`` / ``"sse"``)
    2. Standard ``type`` key       (``"http"`` → ``"streamable_http"``,
                                     ``"sse"``  → ``"sse"``)
    3. Default                      ``"streamable_http"``
    """
    explicit = config.get("transport")
    if explicit:
        return explicit
    cfg_type = config.get("type", "").lower()
    return _TYPE_TO_TRANSPORT.get(cfg_type, "streamable_http")


def _is_url_server(server_entry: Dict[str, Any]) -> bool:
    """Return True when the server config specifies a URL instead of command+args."""
    config = server_entry.get("config", {})
    return is_url_config(config)


def _extract_http_error(exc: BaseException) -> Optional[httpx.HTTPStatusError]:
    """Unwrap an ExceptionGroup to find an httpx.HTTPStatusError, if any."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _extract_http_error(sub)
            if found is not None:
                return found
    return None


def _unwrap_exception_group(exc: BaseException) -> BaseException:
    """Recursively unwrap single-child ExceptionGroups to find the root cause."""
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def _raise_transport_error(
    exc: BaseException,
    url: str,
    server_name: str,
) -> None:
    """Convert raw transport exceptions into structured TransportError."""
    ctx = ErrorContext(server_name=server_name, operation="transport.connect")

    http_err = _extract_http_error(exc)
    if http_err is not None:
        status = http_err.response.status_code
        if status == 401:
            raise create_transport_error(
                code=ErrorCode.TRANSPORT_HTTP_UNAUTHORIZED,
                message=(
                    f"Server '{server_name}' returned 401 Unauthorized for {url}. "
                    "The server requires authentication. If it supports MCP OAuth, "
                    "enable mcp_oauth in the server config."
                ),
                context=ctx, cause=http_err, status_code=status, url=url,
            ) from exc
        if status == 403:
            raise create_transport_error(
                code=ErrorCode.TRANSPORT_HTTP_FORBIDDEN,
                message=(
                    f"Server '{server_name}' returned 403 Forbidden for {url}. "
                    "Access denied — check credentials or token scopes."
                ),
                context=ctx, cause=http_err, status_code=status, url=url,
            ) from exc
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_HTTP_ERROR,
            message=f"Server '{server_name}' returned HTTP {status} for {url}.",
            context=ctx, cause=http_err, status_code=status, url=url,
        ) from exc

    if isinstance(exc, (httpx.ConnectError, ConnectionError)):
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_CONNECTION_ERROR,
            message=f"Connection to '{server_name}' at {url} failed: {exc}",
            context=ctx, cause=exc if isinstance(exc, Exception) else None, url=url,
        ) from exc

    if isinstance(exc, (httpx.TimeoutException,)):
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_TIMEOUT,
            message=f"Connection to '{server_name}' at {url} timed out.",
            context=ctx, cause=exc, url=url,
        ) from exc

    import asyncio
    if isinstance(exc, (asyncio.CancelledError, TimeoutError)):
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_TIMEOUT,
            message=(
                f"Connection to '{server_name}' at {url} was cancelled or timed out. "
                "If the server requires OAuth, the authorization flow may not have "
                "completed in time."
            ),
            context=ctx, cause=None, url=url,
        ) from exc

    desc = str(exc) or type(exc).__name__
    raise create_transport_error(
        code=ErrorCode.TRANSPORT_HTTP_ERROR,
        message=f"Transport error for '{server_name}' at {url}: {desc}",
        context=ctx, cause=exc if isinstance(exc, Exception) else None, url=url,
    ) from exc


def _raise_stdio_error(
    exc: BaseException,
    server_name: str,
    command: Optional[str] = None,
) -> None:
    """Convert raw stdio transport exceptions into structured TransportError."""
    ctx = ErrorContext(server_name=server_name, operation="transport.stdio")
    root = _unwrap_exception_group(exc)
    root_msg = str(root)

    if "Connection closed" in root_msg or "BrokenPipeError" in root_msg:
        cmd_hint = f" (command: {command})" if command else ""
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_STDIO_CLOSED,
            message=(
                f"Server '{server_name}' connection closed unexpectedly{cmd_hint}. "
                "The server process may have crashed or the command may not be installed."
            ),
            context=ctx,
            cause=root if isinstance(root, Exception) else None,
        ) from exc

    if "No such file" in root_msg or "not found" in root_msg.lower() or "ModuleNotFoundError" in root_msg:
        raise create_transport_error(
            code=ErrorCode.TRANSPORT_STDIO_CONNECT,
            message=(
                f"Server '{server_name}' failed to start: {root_msg}. "
                "Check that the command and required packages are installed."
            ),
            context=ctx,
            cause=root if isinstance(root, Exception) else None,
        ) from exc

    raise create_transport_error(
        code=ErrorCode.TRANSPORT_STDIO_CONNECT,
        message=f"Server '{server_name}' stdio transport error: {root_msg}",
        context=ctx,
        cause=root if isinstance(root, Exception) else None,
    ) from exc


@asynccontextmanager
async def _open_url_transport(
    server_entry: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[httpx.Auth] = None,
) -> AsyncIterator[Tuple[Any, Any]]:
    """Yield ``(read, write)`` for a URL-based remote MCP server.

    Transport is resolved via :func:`_resolve_transport` — the ``transport``
    field, the standard ``type`` field, or the default (streamable HTTP).

    An optional *auth* (httpx.Auth) may be provided for MCP OAuth handling.
    HTTP errors are caught and re-raised as structured :class:`TransportError`.
    """
    config = server_entry.get("config", {})
    url = config.get("url") or config.get("serverUrl", "")
    transport = _resolve_transport(config)
    cfg_headers = config.get("headers") or {}
    merged_headers = {**cfg_headers, **(headers or {})}
    server_name = server_entry.get("server_name", "unknown")

    logger.info(
        f"[build_server_params] URL transport={transport} url={url} server={server_name}"
    )

    try:
        if transport == "sse":
            from mcp.client.sse import sse_client

            async with sse_client(url, headers=merged_headers) as (read, write):
                yield read, write
        else:
            from mcp.client.streamable_http import streamablehttp_client

            async with streamablehttp_client(
                url, headers=merged_headers, auth=auth,
            ) as (read, write, _get_session_id):
                yield read, write
    except TransportError:
        raise
    except BaseException as exc:
        _raise_transport_error(exc, url, server_name)


@asynccontextmanager
async def build_server_params(
    server_entry: Dict[str, Any],
    command: Optional[str] = None,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> AsyncIterator[Tuple[Any, Any]]:
    """
    Async context manager that yields ``(read_stream, write_stream)`` for
    an MCP ``ClientSession``.

    Transport selection:
    - If the server config contains a ``url`` key or ``type`` of ``"http"``
      / ``"sse"``, a native HTTP transport is used.  Sandboxing does not apply.
    - Otherwise the classic stdio path is taken: when sandboxing is enabled
      the provider either wraps the command or opens a custom transport;
      when disabled this is a thin passthrough to ``stdio_client``.
    """

    # --- URL-based remote servers (streamable HTTP / SSE) ---
    if _is_url_server(server_entry):
        auth = None
        try:
            from secure_mcp_gateway.services.oauth.mcp_oauth_provider import (
                build_mcp_oauth_auth,
            )
            auth = await build_mcp_oauth_auth(server_entry)
        except Exception as exc:
            logger.warning(f"[build_server_params] Could not build MCP OAuth auth: {exc}")

        async with _open_url_transport(server_entry, auth=auth) as (read, write):
            yield read, write
        return

    # --- stdio-based local servers ---
    manager = get_sandbox_config_manager()
    server_name = server_entry.get("server_name", "unknown")
    sandbox_enabled = manager.is_sandbox_enabled(server_entry)
    logger.info(
        f"[build_server_params] server={server_name} sandbox_enabled={sandbox_enabled} "
        f"server_sandbox_config={server_entry.get('sandbox', 'NONE')}"
    )

    if sandbox_enabled:
        provider = manager.get_provider()
        sandbox_config = manager.get_effective_sandbox_config(server_entry)
        logger.info(
            f"[build_server_params] provider={provider.get_name() if provider else 'NONE'} "
            f"effective_config={sandbox_config}"
        )

        if provider is not None:
            transport_ctx = await provider.create_sandboxed_transport(
                server_name, command, args, env, sandbox_config
            )
            if transport_ctx is not None:
                logger.info(f"[build_server_params] Using custom transport for {server_name}")
                async with transport_ctx as (read, write):
                    try:
                        yield read, write
                    finally:
                        await provider.cleanup(server_name)
                return

            params = await provider.wrap_server_params(
                server_name, command, args, env, sandbox_config
            )
            logger.info(
                f"[build_server_params] SANDBOXED via {provider.get_name()}: "
                f"{params.command} {' '.join(params.args[:6])}..."
            )
        else:
            logger.warning(
                "[build_server_params] Sandbox enabled but no provider registered — "
                "falling through to direct execution"
            )
            params = StdioServerParameters(command=command, args=args, env=env)
    else:
        params = StdioServerParameters(command=command, args=args, env=env)

    try:
        async with stdio_client(params) as (read, write):
            yield read, write
    except TransportError:
        raise
    except BaseException as exc:
        _raise_stdio_error(exc, server_name, command)
