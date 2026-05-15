"""REST endpoints for cache + config hot-reload management."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from secure_mcp_gateway.reload import get_last_reload_info, trigger_full_reload
from secure_mcp_gateway.utils import logger

cache_router = APIRouter(prefix="/api/v1/cache", tags=["cache"])


def _verify_api_key(request: Request) -> str:
    """Late-bound auth dependency to avoid circular import with api_server."""
    from secure_mcp_gateway.api_server import get_api_key

    apikey = request.headers.get("apikey")
    return get_api_key(apikey=apikey)


class FlushRequest(BaseModel):
    gateway_id: Optional[str] = Field(
        None,
        description=(
            "Optional gateway/user id to scope the flush. Currently the "
            "implementation always performs a full flush; this field is "
            "accepted for forward compatibility."
        ),
    )
    gateway_key: Optional[str] = Field(
        None,
        description=(
            "Optional gateway API key to scope the flush. Currently the "
            "implementation always performs a full flush; this field is "
            "accepted for forward compatibility."
        ),
    )
    include_tool_cache: bool = Field(
        False,
        description=(
            "When true, also clears per-server tool caches. Tools will be "
            "re-discovered on the next request. Defaults to false because "
            "re-discovery is comparatively expensive."
        ),
    )


@cache_router.post(
    "/flush-gateway-config",
    summary="Flush gateway config cache and reload providers",
    description=(
        "Drops every in-memory binding to enkrypt_mcp_config.json and "
        "rebuilds the auth/guardrail/telemetry providers from the current "
        "file contents. Use this after editing the config when you do not "
        "want to wait for the config watcher to pick up the change."
    ),
)
async def flush_gateway_config(
    request: FlushRequest = Body(default_factory=FlushRequest),
    api_key: str = Depends(_verify_api_key),
):
    try:
        summary = trigger_full_reload(
            include_tool_cache=request.include_tool_cache,
        )
        if summary.get("status") == "skipped_busy":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A reload is already in progress; try again shortly.",
            )
        return {"status": "ok", "summary": summary}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[api_cache_routes] flush failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"flush failed: {e}",
        )


@cache_router.get(
    "/last-reload",
    summary="Last hot-reload metadata",
    description="Returns timestamp + summary of the most recent reload.",
)
async def last_reload(api_key: str = Depends(_verify_api_key)):
    return get_last_reload_info()


__all__ = ["cache_router"]
