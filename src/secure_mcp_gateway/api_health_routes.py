"""MCP server health check and info REST API endpoints.

These endpoints (``/mcp-playground/*``) accept arbitrary user-supplied MCP
server commands and arguments. Because that is inherently high-risk
(RCE-by-API otherwise), they spawn the target server **inside a sandbox by
default**.

Two request modes are supported, picked by what the caller sends:

- **Inline** — request body contains ``server_name`` + ``config``. Auth is
  the local admin apikey check (see ``resolve_admin_keys``). Callers may
  override sandbox per-call via the optional ``sandbox`` body field.
- **Registry** — request body has no ``config``, and the caller sends the
  ``X-Enkrypt-MCP-Registry-Server`` header. The gateway fetches the server
  config from ``GET {base_url}/mcp-registry/get-server`` (using the same
  ``apikey``) and uses the cloud's 200 as the auth gate. Sandbox stays at
  its global default — there is no per-call override in registry mode.

The two modes are mutually exclusive: if the caller sends both a body
``config`` *and* the registry header, we return 400. Registry mode also
requires ``plugins.auth.provider == "enkrypt"``; with the local-apikey
provider registry headers are rejected with 400.

The route handlers here are thin wrappers; OpenTelemetry traces, metrics,
and structured logs for the MCP-server interactions are emitted by
``MCPHealthService``. Registry-lookup spans / metrics are emitted by
``services/health/registry_client.py``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status

from secure_mcp_gateway.api_models import (
    PICKED_CONFIG_PATH,
    MCPServerRequest,
    MCPToolRequest,
    SuccessResponse,
    get_api_key_raw,
)
from secure_mcp_gateway.cli import load_config
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
from secure_mcp_gateway.utils import logger

health_router = APIRouter(tags=["MCP Health"])

_service = MCPHealthService()


# ---------------------------------------------------------------------------
# Mode dispatcher
# ---------------------------------------------------------------------------


def _extract_sandbox(request: MCPServerRequest | None) -> dict[str, Any] | None:
    """Return the request's sandbox override as a plain dict (or None).

    Caller is responsible for only invoking this in inline mode — registry
    mode disallows the override and we never reach here in that path.
    """
    if request is None or request.sandbox is None:
        return None
    return request.sandbox.model_dump(exclude_none=True)


def _load_auth_provider_name() -> str:
    """Read ``plugins.auth.provider`` from the current config.

    Defaults to ``"local_apikey"`` to mirror the rest of the codebase.
    Tolerates a missing / unreadable config file by returning the default —
    the caller will then enforce inline-mode invariants and surface a
    clearer 4xx.
    """
    try:
        config = load_config(PICKED_CONFIG_PATH)
    except Exception:  # pragma: no cover - hot path tested via mocks
        return "local_apikey"
    return (config.get("plugins") or {}).get("auth", {}).get(
        "provider"
    ) or "local_apikey"


def _validate_inline_apikey(apikey: str) -> None:
    """Validate ``apikey`` against ``resolve_admin_keys`` for inline mode.

    Inline-mode behaviour matches the previous ``get_api_key`` dependency:
    the apikey must appear in the configured admin-key list. Registry mode
    bypasses this — the cloud GET is the gate.
    """
    from secure_mcp_gateway.auth_policy import (
        describe_missing_admin_key_hint,
        resolve_admin_keys,
    )

    try:
        config = load_config(PICKED_CONFIG_PATH)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration file not found",
        )

    acceptable = resolve_admin_keys(config)
    if not acceptable:
        provider = (config.get("plugins") or {}).get("auth", {}).get(
            "provider"
        ) or "local_apikey"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Admin API key not configured. "
                + describe_missing_admin_key_hint(provider)
            ),
        )

    if apikey not in acceptable:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )


def _registry_error_to_http(exc: Exception) -> HTTPException:
    """Map a ``RegistryLookupError`` subclass to an HTTPException."""
    if isinstance(exc, RegistryAuthError):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Enkrypt apikey (cloud /mcp-registry/get-server rejected the request)",
        )
    if isinstance(exc, RegistryForbiddenError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apikey is not authorised to access this registry server",
        )
    if isinstance(exc, RegistryNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    if isinstance(exc, RegistryBadRequestError):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    if isinstance(exc, RegistryTimeoutError):
        return HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(exc),
        )
    if isinstance(exc, RegistryParseError):
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )
    if isinstance(exc, RegistryUpstreamError):
        return HTTPException(
            status_code=getattr(exc, "status_code", status.HTTP_502_BAD_GATEWAY),
            detail=str(exc),
        )
    # Unknown — surface as 502 with the message so we never leak a stack trace
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Upstream registry error: {exc}",
    )


async def _resolve_target(
    *,
    endpoint: str,
    request: MCPServerRequest | None,
    apikey: str,
    registry_server: str | None,
    registry_server_version: str,
    registry_name: str,
    project_name: str,
) -> tuple[
    str,
    str,
    dict[str, Any],
    str,
    dict[str, Any] | None,
    RegistryServerLookup | None,
]:
    """Resolve the request into ``(mode, server_name, config, description, sandbox, registry_lookup)``.

    Enforces mode invariants and runs the per-mode auth check. Raises
    ``HTTPException`` on every error path so the route handlers stay thin.
    """
    has_body_config = request is not None and request.config is not None
    has_registry_header = bool(registry_server)

    # --- Both modes signalled: ambiguous (400) ---------------------------
    if has_body_config and has_registry_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Ambiguous request: provide either an inline body 'config' OR the "
                "X-Enkrypt-MCP-Registry-Server header, not both. Inline body wins "
                "no precedence here — pick one mode."
            ),
        )

    # --- Neither mode signalled (400) ------------------------------------
    if not has_body_config and not has_registry_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Missing config: send either 'config' in the request body (inline "
                "mode) or the X-Enkrypt-MCP-Registry-Server header (registry mode)."
            ),
        )

    # --- Inline mode ------------------------------------------------------
    if has_body_config:
        if request is None or request.config is None or not request.server_name:
            # request.server_name None is theoretically possible since we made
            # it Optional; require it explicitly in inline mode so the
            # response payload keeps a stable display name.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Inline mode requires both 'server_name' and 'config' in the "
                    "request body."
                ),
            )
        _validate_inline_apikey(apikey)
        sandbox = _extract_sandbox(request)
        logger.info(
            "[api] /mcp-playground/%s mode=inline server_name=%s",
            endpoint,
            request.server_name,
            extra={
                "endpoint": endpoint,
                "playground_mode": "inline",
                "server_name": request.server_name,
            },
        )
        return (
            "inline",
            request.server_name,
            request.config.model_dump(),
            request.description or "",
            sandbox,
            None,
        )

    # --- Registry mode ----------------------------------------------------
    provider = _load_auth_provider_name()
    if provider != "enkrypt":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Registry-header mode requires plugins.auth.provider='enkrypt'. "
                f"Current provider is '{provider}'. Use inline-body mode "
                "(send 'server_name' + 'config' in the request body) or "
                "reconfigure the gateway to use the enkrypt auth provider."
            ),
        )

    # Body must NOT contain server_name / sandbox in registry mode either.
    # We allow `tool_name`/`tool_args` because those are MCPToolRequest-only
    # and meaningful for /mcp-playground/call-tool in registry mode.
    if request is not None:
        if request.server_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Registry-header mode does not accept 'server_name' in the "
                    "body — the saved_name from X-Enkrypt-MCP-Registry-Server is "
                    "authoritative."
                ),
            )
        if request.sandbox is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Registry-header mode does not support per-call sandbox "
                    "overrides — sandbox runs with the global default. Use "
                    "inline-body mode to override sandbox settings."
                ),
            )

    config = load_config(PICKED_CONFIG_PATH)
    base_url = get_enkrypt_base_url(config)

    try:
        lookup = await fetch_registry_server(
            base_url=base_url,
            apikey=apikey,
            saved_name=registry_server,  # type: ignore[arg-type]  # bool-checked above
            server_version=registry_server_version,
            registry_name=registry_name,
            project_name=project_name,
        )
    except Exception as exc:
        raise _registry_error_to_http(exc) from exc

    # Authoritative server identity comes from the response body, not the
    # request headers — see the prompt for /mcp-playground/get-tools where
    # the client only sees `saved_name`. We log both so request/response
    # divergences are easy to spot.
    display_name = lookup.saved_name or registry_server  # type: ignore[arg-type]
    logger.info(
        "[api] /mcp-playground/%s mode=registry "
        "requested_saved_name=%s requested_version=%s "
        "resolved_saved_name=%s resolved_version=%s "
        "registry_id=%s registry_name=%s project_name=%s "
        "server_name=%s description=%s is_active=%s is_sample=%s",
        endpoint,
        registry_server,
        registry_server_version,
        lookup.saved_name,
        lookup.server_version,
        lookup.registry_id,
        lookup.registry_name,
        lookup.project_name,
        lookup.server_name,
        lookup.description,
        lookup.is_active,
        lookup.is_sample,
        extra={
            "endpoint": endpoint,
            "playground_mode": "registry",
            "server_name": display_name,
            "registry_saved_name": lookup.saved_name,
            "registry_server_version": lookup.server_version,
            "registry_id": lookup.registry_id,
            "registry_name": lookup.registry_name,
            "project_name": lookup.project_name,
            "registry_server_package_name": lookup.server_name,
            "registry_is_active": lookup.is_active,
            "registry_is_sample": lookup.is_sample,
        },
    )

    return (
        "registry",
        display_name,
        lookup.config_dict,
        lookup.description or "",
        None,  # no per-call sandbox override in registry mode
        lookup,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@health_router.post("/mcp-playground/test-server", response_model=SuccessResponse)
async def server_health_check(
    request: MCPServerRequest | None = Body(None),
    apikey: str = Depends(get_api_key_raw),
    x_enkrypt_mcp_registry_server: str | None = Header(
        None, alias="X-Enkrypt-MCP-Registry-Server"
    ),
    x_enkrypt_mcp_registry_server_version: str = Header(
        "v1", alias="X-Enkrypt-MCP-Registry-Server-Version"
    ),
    x_enkrypt_mcp_registry: str = Header("default", alias="X-Enkrypt-MCP-Registry"),
    x_enkrypt_project: str = Header("default", alias="X-Enkrypt-Project"),
):
    """Check connectivity to an MCP server.

    Inline mode: provide ``server_name`` + ``config`` in the body and (optionally)
    ``sandbox``. Registry mode: send ``X-Enkrypt-MCP-Registry-Server`` and the
    gateway fetches the config from Enkrypt cloud. See module docstring.
    """
    (
        mode,
        server_name,
        config_dict,
        description,
        sandbox,
        lookup,
    ) = await _resolve_target(
        endpoint="test-server",
        request=request,
        apikey=apikey,
        registry_server=x_enkrypt_mcp_registry_server,
        registry_server_version=x_enkrypt_mcp_registry_server_version,
        registry_name=x_enkrypt_mcp_registry,
        project_name=x_enkrypt_project,
    )

    result = await _service.check_server_health(
        server_name=server_name,
        config=config_dict,
        description=description,
        sandbox=sandbox,
    )
    return SuccessResponse(
        message="Server health check completed",
        data=_attach_registry_metadata(result, mode, lookup),
    )


@health_router.get("/mcp-playground/get-tools", response_model=SuccessResponse)
async def server_info(
    request: MCPServerRequest | None = Body(None),
    apikey: str = Depends(get_api_key_raw),
    x_enkrypt_mcp_registry_server: str | None = Header(
        None, alias="X-Enkrypt-MCP-Registry-Server"
    ),
    x_enkrypt_mcp_registry_server_version: str = Header(
        "v1", alias="X-Enkrypt-MCP-Registry-Server-Version"
    ),
    x_enkrypt_mcp_registry: str = Header("default", alias="X-Enkrypt-MCP-Registry"),
    x_enkrypt_project: str = Header("default", alias="X-Enkrypt-Project"),
):
    """Discover all tools exposed by an MCP server.

    Inline mode: provide ``server_name`` + ``config`` in the body and (optionally)
    ``sandbox``. Registry mode: send ``X-Enkrypt-MCP-Registry-Server`` and the
    gateway fetches the config from Enkrypt cloud. See module docstring.
    """
    (
        mode,
        server_name,
        config_dict,
        description,
        sandbox,
        lookup,
    ) = await _resolve_target(
        endpoint="get-tools",
        request=request,
        apikey=apikey,
        registry_server=x_enkrypt_mcp_registry_server,
        registry_server_version=x_enkrypt_mcp_registry_server_version,
        registry_name=x_enkrypt_mcp_registry,
        project_name=x_enkrypt_project,
    )

    result = await _service.get_server_info(
        server_name=server_name,
        config=config_dict,
        description=description,
        sandbox=sandbox,
    )
    return SuccessResponse(
        message="Server info retrieved",
        data=_attach_registry_metadata(result, mode, lookup),
    )


@health_router.post("/mcp-playground/call-tool", response_model=SuccessResponse)
async def tool_health_check(
    request: MCPToolRequest,
    apikey: str = Depends(get_api_key_raw),
    x_enkrypt_mcp_registry_server: str | None = Header(
        None, alias="X-Enkrypt-MCP-Registry-Server"
    ),
    x_enkrypt_mcp_registry_server_version: str = Header(
        "v1", alias="X-Enkrypt-MCP-Registry-Server-Version"
    ),
    x_enkrypt_mcp_registry: str = Header("default", alias="X-Enkrypt-MCP-Registry"),
    x_enkrypt_project: str = Header("default", alias="X-Enkrypt-Project"),
):
    """Execute a specific tool on an MCP server and return the result.

    Both modes always require ``tool_name`` in the body (and optionally
    ``tool_args``). In registry mode, the rest of the body must be empty;
    in inline mode it must also contain ``server_name`` + ``config``.
    """
    (
        mode,
        server_name,
        config_dict,
        description,
        sandbox,
        lookup,
    ) = await _resolve_target(
        endpoint="call-tool",
        request=request,
        apikey=apikey,
        registry_server=x_enkrypt_mcp_registry_server,
        registry_server_version=x_enkrypt_mcp_registry_server_version,
        registry_name=x_enkrypt_mcp_registry,
        project_name=x_enkrypt_project,
    )

    result = await _service.execute_tool_health_check(
        server_name=server_name,
        config=config_dict,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        description=description,
        sandbox=sandbox,
    )
    return SuccessResponse(
        message="Tool health check completed",
        data=_attach_registry_metadata(result, mode, lookup),
    )


# ---------------------------------------------------------------------------
# Response decoration
# ---------------------------------------------------------------------------


def _attach_registry_metadata(
    result: dict[str, Any],
    mode: str,
    lookup: RegistryServerLookup | None,
) -> dict[str, Any]:
    """Annotate the response with ``mode`` and (in registry mode) the cloud's
    authoritative identifiers so callers can correlate without re-fetching.

    Returns a new dict — never mutates the service's payload in place.
    """
    out: dict[str, Any] = (
        dict(result) if isinstance(result, dict) else {"result": result}
    )
    out["playground_mode"] = mode
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
    return out
