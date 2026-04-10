"""MCP server health check and info REST API endpoints."""

from fastapi import APIRouter, Depends

from secure_mcp_gateway.api_models import (
    MCPServerRequest,
    MCPToolRequest,
    SuccessResponse,
    get_api_key,
)
from secure_mcp_gateway.services.health.mcp_health_service import MCPHealthService

health_router = APIRouter(tags=["MCP Health"])

_service = MCPHealthService()


@health_router.post("/api/v1/health/mcp/server", response_model=SuccessResponse)
async def server_health_check(
    request: MCPServerRequest, api_key: str = Depends(get_api_key)
):
    """Check connectivity to an MCP server.

    Spawns the server process, runs session.initialize(), and returns
    the server's reported name, version, and description along with
    the connection latency.
    """
    config = request.config.model_dump()
    result = await _service.check_server_health(
        server_name=request.server_name,
        config=config,
        description=request.description or "",
    )
    return SuccessResponse(message="Server health check completed", data=result)


@health_router.post("/api/v1/mcp/server/info", response_model=SuccessResponse)
async def server_info(
    request: MCPServerRequest, api_key: str = Depends(get_api_key)
):
    """Discover all tools exposed by an MCP server.

    Spawns the server, initialises a session, calls list_tools(), and
    returns the server metadata together with every tool's name,
    description, and input schema.
    """
    config = request.config.model_dump()
    result = await _service.get_server_info(
        server_name=request.server_name,
        config=config,
        description=request.description or "",
    )
    return SuccessResponse(message="Server info retrieved", data=result)


@health_router.post("/api/v1/health/mcp/tool", response_model=SuccessResponse)
async def tool_health_check(
    request: MCPToolRequest, api_key: str = Depends(get_api_key)
):
    """Execute a specific tool on an MCP server and return the result.

    Spawns the server, initialises a session, calls the named tool with
    the supplied arguments, and returns the tool's response content.
    """
    config = request.config.model_dump()
    result = await _service.execute_tool_health_check(
        server_name=request.server_name,
        config=config,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        description=request.description or "",
    )
    return SuccessResponse(message="Tool health check completed", data=result)
