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

Both endpoints require the ``apikey`` header. The acceptable keys come from
``auth_policy.resolve_admin_keys`` -- identical to the REST admin API -- so
the same credential works for both surfaces.

NOTE: ``FastMCP.custom_route`` deliberately bypasses the MCP protocol's auth
chain (it's intended for OAuth callbacks / health checks). We re-implement
admin-key validation here rather than relying on that decorator.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from secure_mcp_gateway.auth_policy import resolve_admin_keys
from secure_mcp_gateway.consts import CONFIG_PATH, DOCKER_CONFIG_PATH
from secure_mcp_gateway.utils import is_docker, logger

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def _picked_config_path() -> str:
    return DOCKER_CONFIG_PATH if is_docker() else CONFIG_PATH


def _load_acceptable_admin_keys() -> list[str]:
    """Read fresh admin keys from disk so rotations take effect immediately.

    Returns an empty list on any IO/JSON error -- callers treat that as a
    fail-closed condition (no key matches -> 401).
    """
    try:
        with open(_picked_config_path(), encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        logger.warning(
            "[gateway_cache_routes] config file not found",
            path=_picked_config_path(),
        )
        return []
    except json.JSONDecodeError as e:
        logger.error(f"[gateway_cache_routes] config JSON invalid: {e}")
        return []
    except Exception as e:
        logger.error(f"[gateway_cache_routes] config read failed: {e}")
        return []

    return resolve_admin_keys(cfg)


def _auth_admin(request: Request) -> JSONResponse | None:
    """Return a 401 response if the request lacks a valid admin apikey, else None."""
    apikey = request.headers.get("apikey")
    if not apikey:
        return JSONResponse(
            {"status": "error", "error": "apikey header required"},
            status_code=401,
        )
    accepted = _load_acceptable_admin_keys()
    if not accepted:
        return JSONResponse(
            {
                "status": "error",
                "error": (
                    "Admin API key not configured on the gateway. "
                    "Set 'admin_apikey' (or, for the enkrypt provider, "
                    "'enkrypt_config.api_key') in enkrypt_mcp_config.json."
                ),
            },
            status_code=500,
        )
    if apikey not in accepted:
        return JSONResponse(
            {"status": "error", "error": "invalid apikey"},
            status_code=401,
        )
    return None


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
    auth_err = _auth_admin(request)
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

    return JSONResponse({"status": "ok", "summary": summary})


async def _last_reload_handler(request: Request) -> JSONResponse:
    auth_err = _auth_admin(request)
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
