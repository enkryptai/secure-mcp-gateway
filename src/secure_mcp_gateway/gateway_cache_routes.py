"""Custom HTTP routes mounted onto the FastMCP gateway process.

The REST admin API (``api_cache_routes.cache_router``) already exposes a
manual cache-flush endpoint, but it only flushes the in-memory state of the
REST API process (port 8001). The MCP gateway (port 8000) is a separate
Python process with its own ``EnkryptAuthProvider._cache``, session pool,
tool cache, etc.

This module mirrors the same endpoints onto the gateway so a single REST
call refreshes both processes when they're running side-by-side.

Endpoints:
    POST /api/v1/cache/flush-gateway-config
    GET  /api/v1/cache/last-reload

Both endpoints require the ``apikey`` header. Authorization is delegated
to ``auth_policy.authorize_apikey_for_cache_flush`` so the surface stays
identical to the REST admin API on port 8001 -- both static admin keys
and (when provider=enkrypt + ``enkrypt_config.org_id`` is set) any
cloud apikey whose ``/consumer-info.org_id`` matches the configured
``org_id`` are accepted.

NOTE: ``FastMCP.custom_route`` deliberately bypasses the MCP protocol's auth
chain (it's intended for OAuth callbacks / health checks). We re-implement
admin-key validation here rather than relying on that decorator.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from secure_mcp_gateway.auth_policy import authorize_apikey_for_cache_flush
from secure_mcp_gateway.consts import CONFIG_PATH, DOCKER_CONFIG_PATH
from secure_mcp_gateway.utils import is_docker, logger, mask_key

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _picked_config_path() -> str:
    return DOCKER_CONFIG_PATH if is_docker() else CONFIG_PATH


def _load_config_from_disk() -> dict[str, Any]:
    """Read the gateway config file fresh so rotations / org_id additions
    take effect on the next flush attempt without restarting the gateway.

    Returns an empty dict on any IO/JSON error -- the authz helper then
    decides fail-closed (no admin keys configured -> 500 / 401).
    """
    try:
        with open(_picked_config_path(), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(
            "[gateway_cache_routes] config file not found",
            path=_picked_config_path(),
        )
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"[gateway_cache_routes] config JSON invalid: {e}")
        return {}
    except Exception as e:
        logger.error(f"[gateway_cache_routes] config read failed: {e}")
        return {}


async def _auth_admin(request: Request) -> tuple[JSONResponse | None, dict | None]:
    """Run the provider-aware cache-flush authz check.

    Returns ``(error_response, None)`` on rejection (caller forwards the
    ``JSONResponse`` to the client) or ``(None, authz_result)`` on
    success so the handler can log ``via`` / ``principal``.
    """
    apikey = request.headers.get("apikey")
    cfg = _load_config_from_disk()
    result = await authorize_apikey_for_cache_flush(cfg, apikey)
    if result["authorized"]:
        return None, result

    detail = result.get("detail") or f"cache-flush authorization failed: {result['reason']}"
    return (
        JSONResponse(
            {
                "status": "error",
                "error": detail,
                "reason": result["reason"],
            },
            status_code=result["status_code"],
        ),
        None,
    )


async def _parse_body(request: Request) -> dict[str, Any]:
    """Tolerantly parse the request body. Empty / malformed bodies -> {}."""
    try:
        if int(request.headers.get("content-length") or 0) <= 0:
            return {}
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


async def _flush_handler(request: Request) -> JSONResponse:
    auth_err, authz = await _auth_admin(request)
    if auth_err is not None:
        return auth_err

    body = await _parse_body(request)
    include_tool_cache = bool(body.get("include_tool_cache", False))

    try:
        from secure_mcp_gateway.reload import trigger_full_reload

        summary = trigger_full_reload(include_tool_cache=include_tool_cache)
    except Exception as e:
        logger.error(f"[gateway_cache_routes] trigger_full_reload failed: {e}")
        return JSONResponse(
            {"status": "error", "error": f"flush failed: {e}"},
            status_code=500,
        )

    if summary.get("status") == "skipped_busy":
        return JSONResponse(
            {
                "status": "error",
                "error": "A reload is already in progress; try again shortly.",
            },
            status_code=409,
        )

    apikey = request.headers.get("apikey") or ""
    logger.info(
        "[gateway_cache_routes] cache flushed",
        via=authz["via"],
        principal=authz.get("principal") or mask_key(apikey),
        include_tool_cache=include_tool_cache,
    )

    return JSONResponse(
        {
            "status": "ok",
            "summary": summary,
            "authorized_via": authz["via"],
            "principal": authz.get("principal"),
        }
    )


async def _last_reload_handler(request: Request) -> JSONResponse:
    auth_err, _ = await _auth_admin(request)
    if auth_err is not None:
        return auth_err

    from secure_mcp_gateway.reload import get_last_reload_info

    return JSONResponse(get_last_reload_info())


def register_gateway_cache_routes(mcp: FastMCP) -> None:
    """Attach the cache-flush + last-reload routes to the FastMCP server.

    Call this *after* the FastMCP instance has been constructed and *before*
    ``mcp.run(...)``. Idempotent only at the call-site level: invoking it
    twice will register the routes twice -- guard against that yourself if
    needed.
    """
    mcp.custom_route(
        "/api/v1/cache/flush-gateway-config",
        methods=["POST"],
        name="gateway_flush_cache",
        include_in_schema=False,
    )(_flush_handler)
    mcp.custom_route(
        "/api/v1/cache/last-reload",
        methods=["GET"],
        name="gateway_last_reload",
        include_in_schema=False,
    )(_last_reload_handler)
    logger.info(
        "[gateway_cache_routes] registered cache flush endpoints "
        "(POST /api/v1/cache/flush-gateway-config, GET /api/v1/cache/last-reload)"
    )


__all__ = [
    "register_gateway_cache_routes",
]
