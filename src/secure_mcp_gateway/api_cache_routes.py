"""REST endpoints for cache + config hot-reload management."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from secure_mcp_gateway.auth_policy import (
    AUTHZ_OK_ORG_MATCH,
    AUTHZ_OK_STATIC,
    authorize_apikey_for_cache_flush,
)
from secure_mcp_gateway.reload import get_last_reload_info, trigger_full_reload
from secure_mcp_gateway.utils import get_common_config, logger, mask_key

cache_router = APIRouter(prefix="/api/v1/cache", tags=["cache"])


async def _verify_admin(request: Request, apikey: str | None) -> dict:
    """Run the provider-aware cache-flush authz check.

    Supports two paths:

    1. Static admin keys (root-level ``admin_apikey``, deprecated
       ``enkrypt_config.admin_apikey``, or under ``provider=enkrypt`` the
       operator's own ``enkrypt_config.api_key``).
    2. When ``provider=enkrypt`` AND ``enkrypt_config.org_id`` is set:
       any apikey whose cloud ``/consumer-info.org_id`` matches the
       configured value.

    Raises :class:`HTTPException` with the appropriate status code on
    failure; returns the authz-result dict (with ``principal`` /
    ``via`` / ``reason``) on success so the handler can log who flushed.
    """
    cfg = get_common_config() or {}
    result = await authorize_apikey_for_cache_flush(cfg, apikey)

    if result["authorized"]:
        return result

    detail = {
        "status": "error",
        "error": result.get("detail")
        or f"cache-flush authorization failed: {result['reason']}",
        "reason": result["reason"],
    }
    raise HTTPException(status_code=result["status_code"], detail=detail)


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
        "want to wait for the config watcher to pick up the change.\n\n"
        "Auth: send your ``apikey`` header. Static admin keys (root "
        "``admin_apikey`` / ``enkrypt_config.admin_apikey`` / "
        "``enkrypt_config.api_key`` under provider=enkrypt) are always "
        "accepted. Additionally, when provider=enkrypt and "
        "``enkrypt_config.org_id`` is configured, any cloud apikey whose "
        "``/consumer-info.org_id`` matches that value is accepted."
    ),
)
async def flush_gateway_config(
    request: Request,
    body: FlushRequest = Body(default_factory=FlushRequest),
    apikey: str | None = Header(None),
):
    authz = await _verify_admin(request, apikey)
    try:
        summary = trigger_full_reload(
            include_tool_cache=body.include_tool_cache,
        )
        if summary.get("status") == "skipped_busy":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A reload is already in progress; try again shortly.",
            )
        logger.info(
            "[api_cache_routes] cache flushed",
            via=authz["via"],
            principal=authz.get("principal") or mask_key(apikey or ""),
            include_tool_cache=body.include_tool_cache,
        )
        return {
            "status": "ok",
            "summary": summary,
            "authorized_via": authz["via"],
            "principal": authz.get("principal"),
        }
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
async def last_reload(
    request: Request,
    apikey: str | None = Header(None),
):
    await _verify_admin(request, apikey)
    return get_last_reload_info()


__all__ = ["cache_router"]
