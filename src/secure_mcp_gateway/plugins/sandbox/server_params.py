"""
build_server_params — async context manager that transparently wraps
MCP server launches in a sandbox when configured.

Drop-in replacement for the raw ``stdio_client(StdioServerParameters(...))``
pattern used at every call site in client.py and tool_execution_service.py.
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client

from secure_mcp_gateway.plugins.sandbox.config_manager import get_sandbox_config_manager
from secure_mcp_gateway.utils import logger


@asynccontextmanager
async def build_server_params(
    server_entry: Dict[str, Any],
    command: str,
    args: List[str],
    env: Optional[Dict[str, str]],
) -> AsyncIterator[Tuple[Any, Any]]:
    """
    Async context manager that yields ``(read_stream, write_stream)`` for
    an MCP ``ClientSession``.

    When sandboxing is enabled for the server, the provider either:
    - wraps the command (Docker/Podman/NovaVM) and delegates to ``stdio_client``, or
    - opens a custom SDK-level transport (Microsandbox).

    When sandboxing is disabled (the default), this is a thin passthrough
    to ``stdio_client(StdioServerParameters(...))``.
    """
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
