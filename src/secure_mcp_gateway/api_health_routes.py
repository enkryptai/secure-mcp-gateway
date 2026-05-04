"""MCP server health check and info REST API endpoints.

These endpoints accept arbitrary user-supplied MCP server commands and
arguments. Because that is inherently high-risk (RCE-by-API otherwise),
they spawn the target server **inside a sandbox by default**.

Callers may override sandbox behaviour per-call via the optional ``sandbox``
field in the request body (e.g. ``{"enabled": false}`` to opt out, or to
override runtime / resource limits).

The route handlers here are thin wrappers; OpenTelemetry traces, metrics, and
structured logs are emitted by ``MCPHealthService`` so we don't double-count
or duplicate spans.  Each route still emits a single info-level log on entry
so the request boundary is visible even when telemetry is disabled.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends

from secure_mcp_gateway.api_models import (
    MCPServerRequest,
    MCPToolRequest,
    SuccessResponse,
    get_api_key,
)
from secure_mcp_gateway.services.health.mcp_health_service import MCPHealthService
from secure_mcp_gateway.utils import logger

health_router = APIRouter(tags=["MCP Health"])

_service = MCPHealthService()


def _extract_sandbox(request: MCPServerRequest) -> Optional[Dict[str, Any]]:
    """Return the request's sandbox override as a plain dict (or None)."""
    if request.sandbox is None:
        return None
    return request.sandbox.model_dump(exclude_none=True)


@health_router.post("/api/v1/health/mcp/server", response_model=SuccessResponse)
async def server_health_check(
    request: MCPServerRequest, api_key: str = Depends(get_api_key)
):
    """Check connectivity to an MCP server.

    Spawns the server process **inside a sandbox by default**, runs
    ``session.initialize()``, and returns the server's reported name,
    version, and description along with the connection latency.

    Pass ``sandbox: {"enabled": false}`` in the body to disable.
    """
    logger.info(
        "[api] /api/v1/health/mcp/server received",
        extra={
            "endpoint": "server_check",
            "server_name": request.server_name,
        },
    )
    config = request.config.model_dump()
    result = await _service.check_server_health(
        server_name=request.server_name,
        config=config,
        description=request.description or "",
        sandbox=_extract_sandbox(request),
    )
    return SuccessResponse(message="Server health check completed", data=result)


@health_router.post("/api/v1/mcp/server/info", response_model=SuccessResponse)
async def server_info(
    request: MCPServerRequest, api_key: str = Depends(get_api_key)
):
    """Discover all tools exposed by an MCP server.

    Spawns the server **inside a sandbox by default**, initialises a
    session, calls ``list_tools()``, and returns the server metadata
    together with every tool's name, description, and input schema.

    Pass ``sandbox: {"enabled": false}`` in the body to disable.
    """
    logger.info(
        "[api] /api/v1/mcp/server/info received",
        extra={
            "endpoint": "server_info",
            "server_name": request.server_name,
        },
    )
    config = request.config.model_dump()
    result = await _service.get_server_info(
        server_name=request.server_name,
        config=config,
        description=request.description or "",
        sandbox=_extract_sandbox(request),
    )
    return SuccessResponse(message="Server info retrieved", data=result)


@health_router.post("/api/v1/health/mcp/tool", response_model=SuccessResponse)
async def tool_health_check(
    request: MCPToolRequest, api_key: str = Depends(get_api_key)
):
    """Execute a specific tool on an MCP server and return the result.

    Spawns the server **inside a sandbox by default**, initialises a
    session, calls the named tool with the supplied arguments, and
    returns the tool's response content.

    Pass ``sandbox: {"enabled": false}`` in the body to disable.
    """
    logger.info(
        "[api] /api/v1/health/mcp/tool received",
        extra={
            "endpoint": "tool_call",
            "server_name": request.server_name,
            "tool_name": request.tool_name,
        },
    )
    config = request.config.model_dump()
    result = await _service.execute_tool_health_check(
        server_name=request.server_name,
        config=config,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        description=request.description or "",
        sandbox=_extract_sandbox(request),
    )
    return SuccessResponse(message="Tool health check completed", data=result)
