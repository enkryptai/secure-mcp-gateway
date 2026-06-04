"""MCP-playground HTTP routes mounted onto the FastMCP gateway process.

Why this module exists
======================
The 3 playground endpoints (``test-server`` / ``get-tools`` / ``call-tool``)
live in :mod:`secure_mcp_gateway.api_health_routes` and are wired onto the
FastAPI REST API server (port 8001).  Most deployments only run the
:mod:`secure_mcp_gateway.gateway` process (port 8000, the MCP gateway),
not :mod:`secure_mcp_gateway.api_server`, so the playground UI hitting
those URLs gets a 404 from the ingress -- there is literally no process
listening on the REST surface.

This module mirrors the same 3 endpoints onto the FastMCP gateway via
``FastMCP.custom_route`` (same pattern as
``gateway_cache_routes.register_gateway_cache_routes``).  Single process,
single port already exposed, ingress already configured -- no k8s
changes required to make the playground reachable.

Endpoints
---------
* ``POST /mcp-playground/test-server``  -- health-check the supplied MCP
                                            server (sandbox by default).
* ``GET  /mcp-playground/get-tools``    -- list_tools() against the
                                            supplied MCP server.
* ``POST /mcp-playground/call-tool``    -- execute a specific tool on
                                            the supplied MCP server.

Authentication
--------------
Each request must carry an ``apikey`` header.  The header is accepted
if it matches either of:

* ``config["admin_apikey"]``           (root-level; local_apikey provider)
* ``config["enkrypt_config"]["api_key"]``  (cloud-backed provider)
* ``config["enkrypt_config"]["admin_apikey"]``  (legacy nested location)

Self-contained intentionally
----------------------------
``api_health_routes.get_api_key`` only checks ``admin_apikey`` and crashes
500 if it's missing -- which kills cloud-config deployments that never set
that field.  We re-implement the validation here so cloud users can
authenticate with their cloud apikey, the same way the cache-flush
endpoint does (without dragging in the
``auth_policy.authorize_apikey_for_cache_flush`` cloud-roundtrip helper
which doesn't exist on every branch this module needs to ship to).

Sandbox default
---------------
The endpoints inherit :class:`MCPHealthService`'s "sandbox by default"
policy -- requests without a ``sandbox`` block run inside the configured
sandbox provider.  Pass ``"sandbox": {"enabled": false}`` to opt out.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from secure_mcp_gateway.services.health.mcp_health_service import MCPHealthService
from secure_mcp_gateway.utils import logger, mask_key

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


# ----------------------------------------------------------------------
# Config lookup -- duplicated tiny helper rather than importing CONFIG_PATH
# constants because this module needs to work on both the v2.2.0 base
# image (which has consts.CONFIG_PATH + DOCKER_CONFIG_PATH) and the
# feature branch (which structures them slightly differently).
# ----------------------------------------------------------------------

def _picked_config_path() -> str:
    docker = "/app/.enkrypt/docker/enkrypt_mcp_config.json"
    if os.path.exists("/.dockerenv") or os.path.exists(docker):
        return docker
    home = os.path.expanduser("~")
    return os.path.join(home, ".enkrypt", "enkrypt_mcp_config.json")


def _load_config_from_disk() -> dict[str, Any]:
    """Read the gateway config fresh so admin-key rotations / cloud-key
    updates take effect on the NEXT playground call -- no restart."""
    try:
        with open(_picked_config_path(), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"[gateway_playground_routes] config JSON invalid: {e}")
        return {}
    except Exception as e:
        logger.error(f"[gateway_playground_routes] config read failed: {e}")
        return {}


# ----------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------

# Placeholder values the config generator emits.  Never authorise on these.
_PLACEHOLDER_KEYS = {
    "",
    "YOUR_ENKRYPT_API_KEY",
    "YOUR_ADMIN_API_KEY",
    "REPLACE_ME",
}


def _collect_accepted_keys(cfg: dict[str, Any]) -> list[str]:
    """Return every apikey value that should authorise a playground call.

    Order matters only for the failure-message path (we report which slot
    rejected the key).  The verification itself is a set membership test.
    """
    keys: list[str] = []
    root_admin = cfg.get("admin_apikey")
    if isinstance(root_admin, str) and root_admin not in _PLACEHOLDER_KEYS:
        keys.append(root_admin)
    enk = cfg.get("enkrypt_config") or {}
    if isinstance(enk, dict):
        nested_admin = enk.get("admin_apikey")
        if isinstance(nested_admin, str) and nested_admin not in _PLACEHOLDER_KEYS:
            keys.append(nested_admin)
        cloud_key = enk.get("api_key")
        if isinstance(cloud_key, str) and cloud_key not in _PLACEHOLDER_KEYS:
            keys.append(cloud_key)
    return keys


def _authorize(request: Request) -> tuple[JSONResponse | None, str | None]:
    """Validate the ``apikey`` header.  Returns ``(error_response, via)``.

    On success: ``(None, "<accepted-slot-label>")`` -- the slot label is
    one of ``admin_apikey``, ``enkrypt_config.admin_apikey``,
    ``enkrypt_config.api_key`` so audit logs can record HOW the request
    was authorised.

    On failure: ``(JSONResponse, None)`` with a 401 / 500 detail.
    """
    apikey = request.headers.get("apikey")
    if not apikey:
        return (
            JSONResponse(
                {"detail": "apikey header required"},
                status_code=401,
            ),
            None,
        )

    cfg = _load_config_from_disk()
    if not cfg:
        return (
            JSONResponse(
                {"detail": "Gateway config not loadable; cannot validate apikey."},
                status_code=500,
            ),
            None,
        )

    root_admin = cfg.get("admin_apikey")
    if isinstance(root_admin, str) and root_admin not in _PLACEHOLDER_KEYS \
            and apikey == root_admin:
        return None, "admin_apikey"

    enk = cfg.get("enkrypt_config") or {}
    if isinstance(enk, dict):
        nested_admin = enk.get("admin_apikey")
        if isinstance(nested_admin, str) and nested_admin not in _PLACEHOLDER_KEYS \
                and apikey == nested_admin:
            return None, "enkrypt_config.admin_apikey"
        cloud_key = enk.get("api_key")
        if isinstance(cloud_key, str) and cloud_key not in _PLACEHOLDER_KEYS \
                and apikey == cloud_key:
            return None, "enkrypt_config.api_key"

    # If no admin keys are configured at all, fail with a clearer message.
    if not _collect_accepted_keys(cfg):
        return (
            JSONResponse(
                {
                    "detail": (
                        "No admin API key is configured.  Add a root-level "
                        "'admin_apikey' to the gateway config (or set "
                        "enkrypt_config.api_key for cloud-backed deployments)."
                    ),
                },
                status_code=500,
            ),
            None,
        )

    return (
        JSONResponse({"detail": "Invalid API key."}, status_code=401),
        None,
    )


# ----------------------------------------------------------------------
# Body parsing
# ----------------------------------------------------------------------

async def _parse_body(request: Request) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Parse + minimally validate the JSON body.  Returns ``(body, None)``
    on success, or ``(None, error_response)`` on failure."""
    try:
        body = await request.json()
    except Exception as e:
        return None, JSONResponse(
            {"detail": f"invalid JSON body: {e}"},
            status_code=400,
        )
    if not isinstance(body, dict):
        return None, JSONResponse(
            {"detail": "body must be a JSON object"},
            status_code=400,
        )
    return body, None


def _validate_server_request(body: dict[str, Any]) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Coerce ``body`` into the (server_name, config, description, sandbox)
    shape that :class:`MCPHealthService` expects.

    Returns ``(coerced_dict, None)`` on success or
    ``(None, error_response)`` on validation failure.

    Mirrors :class:`MCPServerRequest` from api_models.py without
    importing pydantic -- so the handler still validates input even if
    Pydantic v1/v2 import is unavailable on the runtime image.
    """
    server_name = body.get("server_name")
    cfg = body.get("config")
    if not isinstance(server_name, str) or not server_name:
        return None, JSONResponse(
            {"detail": "server_name (string) is required"},
            status_code=400,
        )
    if not isinstance(cfg, dict):
        return None, JSONResponse(
            {"detail": "config (object) is required"},
            status_code=400,
        )
    if not isinstance(cfg.get("command"), str):
        return None, JSONResponse(
            {"detail": "config.command (string) is required"},
            status_code=400,
        )
    if not isinstance(cfg.get("args"), list):
        return None, JSONResponse(
            {"detail": "config.args (array of strings) is required"},
            status_code=400,
        )
    description = body.get("description") or ""
    if not isinstance(description, str):
        description = str(description)
    sandbox = body.get("sandbox")
    if sandbox is not None and not isinstance(sandbox, dict):
        return None, JSONResponse(
            {"detail": "sandbox must be an object (or omitted)"},
            status_code=400,
        )
    return (
        {
            "server_name": server_name,
            "config": cfg,
            "description": description,
            "sandbox": sandbox,
        },
        None,
    )


# ----------------------------------------------------------------------
# Handlers
# ----------------------------------------------------------------------

_service = MCPHealthService()


def _ok(message: str, data: dict[str, Any]) -> JSONResponse:
    """Mirror :class:`SuccessResponse` from api_models.py without
    requiring its Pydantic class at runtime."""
    from datetime import datetime, timezone
    return JSONResponse(
        {
            "message": message,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


async def _test_server_handler(request: Request) -> JSONResponse:
    auth_err, via = _authorize(request)
    if auth_err is not None:
        return auth_err

    body, err = await _parse_body(request)
    if err is not None:
        return err
    coerced, err = _validate_server_request(body)
    if err is not None:
        return err

    apikey = request.headers.get("apikey") or ""
    logger.info(
        "[gateway_playground_routes] /mcp-playground/test-server",
        endpoint="test_server",
        server_name=coerced["server_name"],
        authorized_via=via,
        principal=mask_key(apikey),
    )

    try:
        result = await _service.check_server_health(
            server_name=coerced["server_name"],
            config=coerced["config"],
            description=coerced["description"],
            sandbox=coerced["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] test-server failed: {e}")
        return JSONResponse(
            {"detail": f"test-server failed: {e}"},
            status_code=500,
        )
    return _ok("Server health check completed", result)


async def _get_tools_handler(request: Request) -> JSONResponse:
    auth_err, via = _authorize(request)
    if auth_err is not None:
        return auth_err

    body, err = await _parse_body(request)
    if err is not None:
        return err
    coerced, err = _validate_server_request(body)
    if err is not None:
        return err

    apikey = request.headers.get("apikey") or ""
    logger.info(
        "[gateway_playground_routes] /mcp-playground/get-tools",
        endpoint="get_tools",
        server_name=coerced["server_name"],
        authorized_via=via,
        principal=mask_key(apikey),
    )

    try:
        result = await _service.get_server_info(
            server_name=coerced["server_name"],
            config=coerced["config"],
            description=coerced["description"],
            sandbox=coerced["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] get-tools failed: {e}")
        return JSONResponse(
            {"detail": f"get-tools failed: {e}"},
            status_code=500,
        )
    return _ok("Server info retrieved", result)


async def _call_tool_handler(request: Request) -> JSONResponse:
    auth_err, via = _authorize(request)
    if auth_err is not None:
        return auth_err

    body, err = await _parse_body(request)
    if err is not None:
        return err
    coerced, err = _validate_server_request(body)
    if err is not None:
        return err

    tool_name = body.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        return JSONResponse(
            {"detail": "tool_name (string) is required"},
            status_code=400,
        )
    tool_args = body.get("tool_args")
    if tool_args is not None and not isinstance(tool_args, dict):
        return JSONResponse(
            {"detail": "tool_args must be an object (or omitted)"},
            status_code=400,
        )

    apikey = request.headers.get("apikey") or ""
    logger.info(
        "[gateway_playground_routes] /mcp-playground/call-tool",
        endpoint="call_tool",
        server_name=coerced["server_name"],
        tool_name=tool_name,
        authorized_via=via,
        principal=mask_key(apikey),
    )

    try:
        result = await _service.execute_tool_health_check(
            server_name=coerced["server_name"],
            config=coerced["config"],
            tool_name=tool_name,
            tool_args=tool_args,
            description=coerced["description"],
            sandbox=coerced["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] call-tool failed: {e}")
        return JSONResponse(
            {"detail": f"call-tool failed: {e}"},
            status_code=500,
        )
    return _ok("Tool health check completed", result)


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------

def register_gateway_playground_routes(mcp: "FastMCP") -> None:
    """Attach the 3 playground routes to the FastMCP gateway instance.

    Call this *after* the FastMCP instance has been constructed and
    *before* ``mcp.run(...)``.  Idempotent only at the call-site level:
    invoking it twice will register the routes twice -- guard against
    that yourself if needed.

    NOTE: ``FastMCP.custom_route`` bypasses the MCP protocol's auth
    chain (intended for OAuth callbacks / health checks).  Each handler
    re-implements admin-key validation via :func:`_authorize` so a
    missing or invalid apikey returns 401 immediately.
    """
    mcp.custom_route(
        "/mcp-playground/test-server",
        methods=["POST"],
        name="gateway_playground_test_server",
        include_in_schema=False,
    )(_test_server_handler)
    mcp.custom_route(
        "/mcp-playground/get-tools",
        methods=["GET"],
        name="gateway_playground_get_tools",
        include_in_schema=False,
    )(_get_tools_handler)
    mcp.custom_route(
        "/mcp-playground/call-tool",
        methods=["POST"],
        name="gateway_playground_call_tool",
        include_in_schema=False,
    )(_call_tool_handler)
    logger.info(
        "[gateway_playground_routes] registered 3 playground endpoints "
        "(POST /mcp-playground/test-server, "
        "GET  /mcp-playground/get-tools, "
        "POST /mcp-playground/call-tool)"
    )


__all__ = [
    "register_gateway_playground_routes",
]
