"""
build_server_params — async context manager that transparently wraps
MCP server launches in a sandbox when configured.

Drop-in replacement for the raw ``stdio_client(StdioServerParameters(...))``
pattern used at every call site in client.py and tool_execution_service.py.

Supports three transport modes:
- **stdio** (default for command-based servers)
- **streamable_http** (default for URL-based servers)
- **sse** (legacy HTTP+SSE for older remote servers)
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client

from secure_mcp_gateway.plugins.sandbox.config_manager import get_sandbox_config_manager
from secure_mcp_gateway.utils import logger


def _is_url_server(server_entry: Dict[str, Any]) -> bool:
    """Return True when the server config specifies a URL instead of command+args."""
    config = server_entry.get("config", {})
    return bool(config.get("url"))


@asynccontextmanager
async def _open_url_transport(
    server_entry: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
) -> AsyncIterator[Tuple[Any, Any]]:
    """Yield ``(read, write)`` for a URL-based remote MCP server.

    The ``transport`` field in the server config selects the protocol:
    - ``streamable_http`` (default) — modern streamable HTTP transport
    - ``sse`` — legacy Server-Sent Events transport
    """
    config = server_entry.get("config", {})
    url = config["url"]
    transport = config.get("transport", "streamable_http")
    cfg_headers = config.get("headers") or {}
    merged_headers = {**cfg_headers, **(headers or {})}
    server_name = server_entry.get("server_name", "unknown")

    logger.info(
        f"[build_server_params] URL transport={transport} url={url} server={server_name}"
    )

    if transport == "sse":
        from mcp.client.sse import sse_client

        async with sse_client(url, headers=merged_headers) as (read, write):
            yield read, write
    else:
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(url, headers=merged_headers) as (
            read,
            write,
            _get_session_id,
        ):
            yield read, write


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
    - If the server config contains a ``url`` key, a native HTTP transport
      (streamable HTTP or SSE) is used.  Sandboxing does not apply.
    - Otherwise the classic stdio path is taken: when sandboxing is enabled
      the provider either wraps the command or opens a custom transport;
      when disabled this is a thin passthrough to ``stdio_client``.
    """

    # --- URL-based remote servers (streamable HTTP / SSE) ---
    if _is_url_server(server_entry):
        async with _open_url_transport(server_entry) as (read, write):
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

    async with stdio_client(params) as (read, write):
        yield read, write
