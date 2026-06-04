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

Request modes (parity with api_health_routes)
----------------------------------------------
Two request modes are supported, picked by what the caller sends -- the
SAME contract the REST surface implements in
:func:`secure_mcp_gateway.api_health_routes._resolve_target`:

* **Inline** -- request body carries ``server_name`` + ``config``.  Auth is
  provider-aware: ``local_apikey`` validates against the local admin-key
  allow-list; ``enkrypt`` validates by calling the cloud ``GET
  /consumer-info`` (any valid cloud apikey passes).  Callers may override
  sandbox per-call via the optional ``sandbox`` body field.
* **Registry** -- request body has NO inline ``config`` and the caller
  sends the ``X-Enkrypt-MCP-Registry-Server`` header.  The gateway fetches
  the server config from ``GET {base_url}/mcp-registry/get-server`` (using
  the same ``apikey``) and uses the cloud's 200 as the auth gate.  Sandbox
  stays at its global default -- no per-call override in registry mode.
  Registry mode requires ``plugins.auth.provider == "enkrypt"``.

The two modes are mutually exclusive: a body ``config`` *and* the registry
header together is a 400 (ambiguous); neither is a 400 (missing config).

Endpoints
---------
* ``POST /mcp-playground/test-server``  -- health-check the supplied MCP
                                            server (sandbox by default).
* ``GET  /mcp-playground/get-tools``    -- list_tools() against the
                                            supplied MCP server.
* ``POST /mcp-playground/call-tool``    -- execute a specific tool on
                                            the supplied MCP server.

Sandbox default
---------------
The endpoints inherit :class:`MCPHealthService`'s "sandbox by default"
policy -- inline requests without a ``sandbox`` block run inside the
configured sandbox provider.  Pass ``"sandbox": {"enabled": false}`` to
opt out (inline mode only).
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from starlette.responses import JSONResponse

from secure_mcp_gateway.services.health.consumer_info_client import (
    ConsumerAuthError,
    ConsumerInfo,
    ConsumerParseError,
    ConsumerTimeoutError,
    ConsumerUpstreamError,
    fetch_consumer_info,
)
from secure_mcp_gateway.services.health.mcp_health_service import MCPHealthService
from secure_mcp_gateway.services.health.registry_client import (
    RegistryAuthError,
    RegistryBadRequestError,
    RegistryForbiddenError,
    RegistryNotFoundError,
    RegistryParseError,
    RegistryServerLookup,
    RegistryTimeoutError,
    RegistryUpstreamError,
    fetch_registry_server,
    get_enkrypt_base_url,
)
from secure_mcp_gateway.utils import logger, mask_key

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from starlette.requests import Request


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


def _auth_provider_name(cfg: dict[str, Any]) -> str:
    """Read ``plugins.auth.provider`` from the config, defaulting to
    ``local_apikey`` (mirrors the rest of the codebase)."""
    return (cfg.get("plugins") or {}).get("auth", {}).get("provider") or "local_apikey"


# ----------------------------------------------------------------------
# Auth (inline mode, local_apikey provider)
# ----------------------------------------------------------------------

# Placeholder values the config generator emits.  Never authorise on these.
_PLACEHOLDER_KEYS = {
    "",
    "YOUR_ENKRYPT_API_KEY",
    "YOUR_ADMIN_API_KEY",
    "REPLACE_ME",
}


def _collect_accepted_keys(cfg: dict[str, Any]) -> list[str]:
    """Return every apikey value that should authorise a local-admin
    (inline + local_apikey) playground call."""
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


# ----------------------------------------------------------------------
# Internal error signalling -- mirrors the FastAPI HTTPException pattern in
# api_health_routes so the resolve helper can stay readable.  Each raise
# carries a ready-to-return Starlette JSONResponse.
# ----------------------------------------------------------------------


class _PlaygroundError(Exception):
    def __init__(self, response: JSONResponse) -> None:
        self.response = response


def _err(detail: str, status_code: int) -> _PlaygroundError:
    return _PlaygroundError(JSONResponse({"detail": detail}, status_code=status_code))


def _registry_error(exc: Exception) -> _PlaygroundError:
    """Map a ``RegistryLookupError`` subclass to a 4xx/5xx response.

    Mirrors :func:`api_health_routes._registry_error_to_http`.
    """
    if isinstance(exc, RegistryAuthError):
        return _err(
            "Invalid Enkrypt apikey (cloud /mcp-registry/get-server rejected the request)",
            401,
        )
    if isinstance(exc, RegistryForbiddenError):
        return _err("Apikey is not authorised to access this registry server", 403)
    if isinstance(exc, RegistryNotFoundError):
        return _err(str(exc), 404)
    if isinstance(exc, RegistryBadRequestError):
        return _err(str(exc), 400)
    if isinstance(exc, RegistryTimeoutError):
        return _err(str(exc), 504)
    if isinstance(exc, RegistryParseError):
        return _err(str(exc), 502)
    if isinstance(exc, RegistryUpstreamError):
        return _err(str(exc), getattr(exc, "status_code", 502))
    # Unknown -- surface as 502 with the message so we never leak a stack trace.
    return _err(f"Upstream registry error: {exc}", 502)


async def _inline_consumer_auth(cfg: dict[str, Any], apikey: str) -> ConsumerInfo:
    """Validate an inline-mode apikey via the cloud ``GET /consumer-info``
    (provider=enkrypt).  Raises :class:`_PlaygroundError` on rejection.

    Mirrors :func:`api_health_routes._validate_inline_apikey_via_consumer_info`.
    """
    base_url = get_enkrypt_base_url(cfg)
    try:
        return await fetch_consumer_info(base_url=base_url, apikey=apikey)
    except ConsumerAuthError:
        raise _err(
            "Invalid Enkrypt apikey (cloud /consumer-info rejected the request)",
            401,
        )
    except ConsumerTimeoutError as exc:
        raise _err(str(exc), 504)
    except ConsumerParseError as exc:
        raise _err(str(exc), 502)
    except ConsumerUpstreamError as exc:
        raise _err(str(exc), getattr(exc, "status_code", 502))


def _inline_local_auth(cfg: dict[str, Any], apikey: str) -> None:
    """Validate an inline-mode apikey against the local admin-key allow-list
    (provider=local_apikey).  Raises :class:`_PlaygroundError` on rejection."""
    accepted = _collect_accepted_keys(cfg)
    if not accepted:
        raise _err(
            "No admin API key is configured.  Add a root-level 'admin_apikey' "
            "to the gateway config (or set enkrypt_config.api_key for "
            "cloud-backed deployments).",
            500,
        )
    if apikey not in accepted:
        raise _err("Invalid API key.", 401)


# ----------------------------------------------------------------------
# Body parsing -- tolerant of an empty body (registry mode sends none).
# ----------------------------------------------------------------------


async def _parse_body(
    request: Request,
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Parse the JSON body.  An empty body resolves to ``({}, None)`` so
    registry-mode requests (which carry no body) are NOT rejected.  A
    present-but-malformed body still 400s.

    Returns ``(body, None)`` on success, or ``(None, error_response)``.
    """
    raw = await request.body()
    if not raw or not raw.strip():
        return {}, None
    try:
        body = json.loads(raw)
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


def _validate_inline_config(config_block: dict[str, Any]) -> None:
    """Validate an inline-mode ``config`` block: stdio (command+args) OR
    URL transport (url + optional type).  Raises :class:`_PlaygroundError`."""
    url = config_block.get("url")
    cfg_type = config_block.get("type")
    is_url = (isinstance(url, str) and url) or (
        isinstance(cfg_type, str) and cfg_type.lower() in {"http", "sse"}
    )
    if is_url:
        if not (isinstance(url, str) and url):
            raise _err("config.url (string) is required for http/sse transport", 400)
        return
    # stdio shape
    if not isinstance(config_block.get("command"), str) or not config_block.get(
        "command"
    ):
        raise _err("config.command (string) is required", 400)
    if not isinstance(config_block.get("args"), list):
        raise _err("config.args (array of strings) is required", 400)


# ----------------------------------------------------------------------
# Mode dispatcher -- single source of truth for inline vs registry.
# ----------------------------------------------------------------------


async def _resolve_target(
    *,
    endpoint: str,
    apikey: str,
    cfg: dict[str, Any],
    body: dict[str, Any],
    registry_server: str | None,
    registry_version: str,
    registry_name: str,
    project_name: str,
) -> dict[str, Any]:
    """Resolve the request into a dict with keys ``mode``, ``server_name``,
    ``config``, ``description``, ``sandbox``, ``lookup``, ``consumer``.

    Enforces the mode invariants and runs the per-mode auth check.  Raises
    :class:`_PlaygroundError` on every error path so the handlers stay thin.
    Mirrors :func:`api_health_routes._resolve_target`.
    """
    # Only count the body as inline config when it carries an executable
    # shape (``command`` for stdio, ``url``/``type`` for URL transport).  A
    # bare ``{"config": {}}`` from a frontend default is "no inline config",
    # so we fall through to registry mode (if the header is set) or the
    # "missing config" 400 below.
    config_block = body.get("config")
    has_body_config = False
    if isinstance(config_block, dict):
        cmd = config_block.get("command")
        url = config_block.get("url")
        cfg_type = config_block.get("type")
        has_body_config = bool(
            (isinstance(cmd, str) and cmd)
            or (isinstance(url, str) and url)
            or (isinstance(cfg_type, str) and cfg_type.lower() in {"http", "sse"})
        )
    has_registry_header = bool(registry_server)

    # --- Both modes signalled: ambiguous (400) ---------------------------
    if has_body_config and has_registry_header:
        raise _err(
            "Ambiguous request: provide either an inline body 'config' OR the "
            "X-Enkrypt-MCP-Registry-Server header, not both. Pick one mode.",
            400,
        )

    # --- Neither mode signalled (400) ------------------------------------
    if not has_body_config and not has_registry_header:
        raise _err(
            "Missing config: send either 'config' in the request body (inline "
            "mode) or the X-Enkrypt-MCP-Registry-Server header (registry mode).",
            400,
        )

    provider = _auth_provider_name(cfg)

    # --- Inline mode ------------------------------------------------------
    if has_body_config:
        server_name = body.get("server_name")
        if not isinstance(server_name, str) or not server_name:
            raise _err(
                "Inline mode requires both 'server_name' and 'config' in the "
                "request body.",
                400,
            )
        _validate_inline_config(config_block)  # type: ignore[arg-type]

        sandbox = body.get("sandbox")
        if sandbox is not None and not isinstance(sandbox, dict):
            raise _err("sandbox must be an object (or omitted)", 400)

        # Auth dispatch is provider-aware:
        #   local_apikey -> local admin-key allow-list check
        #   enkrypt      -> cloud GET /consumer-info (any valid cloud key)
        consumer: ConsumerInfo | None = None
        if provider == "enkrypt":
            consumer = await _inline_consumer_auth(cfg, apikey)
        else:
            _inline_local_auth(cfg, apikey)

        description = body.get("description") or ""
        if not isinstance(description, str):
            description = str(description)

        return {
            "mode": "inline",
            "server_name": server_name,
            "config": config_block,
            "description": description,
            "sandbox": sandbox,
            "lookup": None,
            "consumer": consumer,
        }

    # --- Registry mode ----------------------------------------------------
    if provider != "enkrypt":
        raise _err(
            "Registry-header mode requires plugins.auth.provider='enkrypt'. "
            f"Current provider is '{provider}'. Use inline-body mode (send "
            "'server_name' + 'config' in the request body) or reconfigure the "
            "gateway to use the enkrypt auth provider.",
            400,
        )

    # Body must NOT contain server_name / sandbox in registry mode.  We allow
    # tool_name / tool_args because those are meaningful for call-tool.
    if body.get("server_name"):
        raise _err(
            "Registry-header mode does not accept 'server_name' in the body -- "
            "the saved_name from X-Enkrypt-MCP-Registry-Server is authoritative.",
            400,
        )
    if body.get("sandbox") is not None:
        raise _err(
            "Registry-header mode does not support per-call sandbox overrides -- "
            "sandbox runs with the global default. Use inline-body mode to "
            "override sandbox settings.",
            400,
        )

    base_url = get_enkrypt_base_url(cfg)
    try:
        lookup = await fetch_registry_server(
            base_url=base_url,
            apikey=apikey,
            saved_name=registry_server,  # type: ignore[arg-type]  # bool-checked above
            server_version=registry_version,
            registry_name=registry_name,
            project_name=project_name,
        )
    except Exception as exc:
        raise _registry_error(exc) from exc

    display_name = lookup.saved_name or registry_server  # type: ignore[arg-type]
    return {
        "mode": "registry",
        "server_name": display_name,
        "config": lookup.config_dict,
        "description": lookup.description or "",
        "sandbox": None,  # no per-call sandbox override in registry mode
        "lookup": lookup,
        "consumer": None,
    }


# ----------------------------------------------------------------------
# Response decoration
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


def _attach_metadata(
    result: dict[str, Any], resolved: dict[str, Any]
) -> dict[str, Any]:
    """Annotate the response with ``playground_mode`` plus (when present)
    the cloud's authoritative identifiers from /mcp-registry/get-server
    (``registry`` block) and /consumer-info (``consumer`` block).

    Returns a new dict -- never mutates the service payload in place.  Email
    is deliberately excluded from the response payload.  Mirrors
    :func:`api_health_routes._attach_playground_metadata`.
    """
    out: dict[str, Any] = (
        dict(result) if isinstance(result, dict) else {"result": result}
    )
    out["playground_mode"] = resolved["mode"]
    lookup: RegistryServerLookup | None = resolved.get("lookup")
    if lookup is not None:
        out["registry"] = {
            "saved_name": lookup.saved_name,
            "server_version": lookup.server_version,
            "registry_id": lookup.registry_id,
            "registry_name": lookup.registry_name,
            "project_name": lookup.project_name,
            "server_name": lookup.server_name,
            "description": lookup.description,
            "is_active": lookup.is_active,
            "is_sample": lookup.is_sample,
            "source_url": lookup.source_url,
            "source_version": lookup.source_version,
        }
    consumer: ConsumerInfo | None = resolved.get("consumer")
    if consumer is not None:
        out["consumer"] = {
            "user_id": consumer.user_id,
            "org_id": consumer.org_id,
            "project_name": consumer.project_name,
            "is_internal_req": consumer.is_internal_req,
        }
    return out


# ----------------------------------------------------------------------
# Shared request preamble
# ----------------------------------------------------------------------


async def _prepare(
    request: Request, endpoint: str
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """apikey -> config -> body -> mode dispatch.  Returns ``(resolved, None)``
    on success or ``(None, error_response)`` on any failure."""
    apikey = request.headers.get("apikey")
    if not apikey:
        return None, JSONResponse({"detail": "apikey header required"}, status_code=401)

    cfg = _load_config_from_disk()
    if not cfg:
        return None, JSONResponse(
            {"detail": "Gateway config not loadable; cannot validate apikey."},
            status_code=500,
        )

    body, err = await _parse_body(request)
    if err is not None:
        return None, err
    assert body is not None  # _parse_body returns ({}, None) for empty bodies

    registry_server = request.headers.get("X-Enkrypt-MCP-Registry-Server")
    registry_version = (
        request.headers.get("X-Enkrypt-MCP-Registry-Server-Version") or "v1"
    )
    registry_name = request.headers.get("X-Enkrypt-MCP-Registry") or "default"
    project_name = request.headers.get("X-Enkrypt-Project") or "default"

    try:
        resolved = await _resolve_target(
            endpoint=endpoint,
            apikey=apikey,
            cfg=cfg,
            body=body,
            registry_server=registry_server,
            registry_version=registry_version,
            registry_name=registry_name,
            project_name=project_name,
        )
    except _PlaygroundError as e:
        return None, e.response

    resolved["apikey"] = apikey
    resolved["body"] = body
    return resolved, None


def _log(endpoint: str, resolved: dict[str, Any], **extra: Any) -> None:
    lookup: RegistryServerLookup | None = resolved.get("lookup")
    logger.info(
        f"[gateway_playground_routes] /mcp-playground/{endpoint}",
        endpoint=endpoint,
        playground_mode=resolved["mode"],
        server_name=resolved["server_name"],
        registry_id=(lookup.registry_id if lookup else None),
        principal=mask_key(resolved.get("apikey") or ""),
        **extra,
    )


# ----------------------------------------------------------------------
# Handlers
# ----------------------------------------------------------------------


async def _test_server_handler(request: Request) -> JSONResponse:
    resolved, err = await _prepare(request, "test-server")
    if err is not None:
        return err
    assert resolved is not None
    _log("test-server", resolved)

    try:
        result = await _service.check_server_health(
            server_name=resolved["server_name"],
            config=resolved["config"],
            description=resolved["description"],
            sandbox=resolved["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] test-server failed: {e}")
        return JSONResponse(
            {"detail": f"test-server failed: {e}"},
            status_code=500,
        )
    return _ok("Server health check completed", _attach_metadata(result, resolved))


async def _get_tools_handler(request: Request) -> JSONResponse:
    resolved, err = await _prepare(request, "get-tools")
    if err is not None:
        return err
    assert resolved is not None
    _log("get-tools", resolved)

    try:
        result = await _service.get_server_info(
            server_name=resolved["server_name"],
            config=resolved["config"],
            description=resolved["description"],
            sandbox=resolved["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] get-tools failed: {e}")
        return JSONResponse(
            {"detail": f"get-tools failed: {e}"},
            status_code=500,
        )
    return _ok("Server info retrieved", _attach_metadata(result, resolved))


async def _call_tool_handler(request: Request) -> JSONResponse:
    resolved, err = await _prepare(request, "call-tool")
    if err is not None:
        return err
    assert resolved is not None

    body = resolved["body"]
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

    _log("call-tool", resolved, tool_name=tool_name)

    try:
        result = await _service.execute_tool_health_check(
            server_name=resolved["server_name"],
            config=resolved["config"],
            tool_name=tool_name,
            tool_args=tool_args,
            description=resolved["description"],
            sandbox=resolved["sandbox"],
        )
    except Exception as e:
        logger.error(f"[gateway_playground_routes] call-tool failed: {e}")
        return JSONResponse(
            {"detail": f"call-tool failed: {e}"},
            status_code=500,
        )
    return _ok("Tool health check completed", _attach_metadata(result, resolved))


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_gateway_playground_routes(mcp: FastMCP) -> None:
    """Attach the 3 playground routes to the FastMCP gateway instance.

    Call this *after* the FastMCP instance has been constructed and
    *before* ``mcp.run(...)``.  Idempotent only at the call-site level:
    invoking it twice will register the routes twice -- guard against
    that yourself if needed.

    NOTE: ``FastMCP.custom_route`` bypasses the MCP protocol's auth
    chain (intended for OAuth callbacks / health checks).  Each handler
    re-implements auth via :func:`_resolve_target` (local admin-key check
    for inline+local_apikey, cloud /consumer-info for inline+enkrypt, cloud
    /mcp-registry/get-server for registry mode) so a missing or invalid
    apikey returns 401 immediately.
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
