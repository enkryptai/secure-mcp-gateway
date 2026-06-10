"""Gateway-owned OAuth Authorization-Code routes mounted on the FastMCP gateway.

These endpoints let the gateway *itself* drive the OAuth 2.1 authorization-code
+ PKCE flow for downstream MCP servers that need a user browser sign-in, then
deliver the resulting token to the server -- specifically for stdio servers that
consume a credentials FILE (``token_delivery: google_credentials_file``, e.g.
``mkummer225/google-sheets-mcp``) and cannot run their own browser flow inside a
container.

Why this lives on the FastMCP gateway (port 8000) rather than a separate
callback server: the gateway's Starlette/uvicorn app already binds ``0.0.0.0``
and that port is published from the container, so the OAuth redirect can be
``http://localhost:8000/oauth2callback`` -- the host browser reaches it with no
extra published ports and no in-container browser. The callback handler can't
require the apikey (the IdP redirect won't send it); it is protected instead by
a one-time, short-lived ``state`` that must match a flow this gateway started
(CSRF) plus PKCE.

Endpoints:
    POST /api/v1/oauth/authorize   (apikey-authed) -> { auth_url, state, ... }
    GET  /oauth2callback           (state-protected) -> exchanges code, writes creds file
    GET  /api/v1/oauth/status      (apikey-authed) -> { credentials_present, last_result }

The POST/status endpoints authenticate by reusing the gateway's own auth
provider via a lightweight header shim, so they work in both local_apikey and
cloud (enkrypt) auth modes -- identical to how a normal MCP request authorizes.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from starlette.responses import HTMLResponse, JSONResponse

from secure_mcp_gateway.services.oauth.local_credentials import (
    load_oauth_client_from_keys_file,
    materialize_google_credentials_file,
    resolve_credentials_file_path,
)
from secure_mcp_gateway.services.oauth.models import OAuthConfig
from secure_mcp_gateway.services.oauth.oauth_service import get_oauth_service
from secure_mcp_gateway.utils import (
    GATEWAY_OAUTH_CALLBACK_PATH,
    get_gateway_base_url,
    get_gateway_oauth_redirect_uri,
    logger,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from starlette.requests import Request

# State TTL for a pending authorization flow (seconds).
_STATE_TTL_SECONDS = 600

# Well-known OAuth redirect/callback paths the gateway serves (all -> the same
# _callback_handler). OAuth 2.0/2.1 do NOT standardize a callback path -- the
# redirect_uri is opaque to the spec and the only rule is exact-match
# registration at the IdP -- so we serve the common conventions as aliases so
# whichever path an operator registers "just works". The default the gateway
# *advertises* stays GATEWAY_OAUTH_CALLBACK_PATH ("/oauth2callback", matching
# Google's @google-cloud/local-auth convention); the others are accept-only
# aliases. Serving the handler on multiple paths is safe: it is idempotent and
# protected by one-time state + PKCE, not by the path. The gateway ROOT ("/") is
# registered separately (it doubles as the loopback redirect + a landing page).
_CALLBACK_PATHS = (
    GATEWAY_OAUTH_CALLBACK_PATH,  # "/oauth2callback" -- canonical / advertised default
    "/oauth/callback",
    "/oauth2/callback",
    "/callback",
    "/auth/callback",
)


def _resolve_callback_paths(configured_redirect: str | None) -> list[str]:
    """GET paths to serve the callback handler on.

    The well-known aliases (``_CALLBACK_PATHS``) PLUS the path of the configured
    redirect, so that whatever the gateway *advertises*
    (``ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI`` / a custom path) is guaranteed to be
    *served* -- closing the gap where a custom redirect path would otherwise 404.
    Order-preserving and de-duplicated. ``/`` is handled by the caller.
    """
    paths = list(_CALLBACK_PATHS)
    if configured_redirect:
        try:
            configured_path = urlparse(configured_redirect).path or "/"
        except Exception:
            configured_path = ""
        if configured_path and configured_path != "/" and configured_path not in paths:
            paths.append(configured_path)
    return paths


# In-memory store of pending flows, keyed by OAuth `state`.
#   state -> { server_name, oauth_dict, redirect_uri, code_verifier, scope,
#              output_path, config_id, project_id, created_at }
_pending_flows: dict[str, dict[str, Any]] = {}
# Last completion result per server_name (for the status endpoint).
_last_results: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Auth shim: reuse the gateway's auth provider from a plain Starlette request
# ---------------------------------------------------------------------------
class _ShimRequest:
    def __init__(self, headers):
        self.headers = headers


class _ShimReqCtx:
    def __init__(self, headers):
        self.request = _ShimRequest(headers)


class _ShimCtx:
    """Minimal stand-in for an MCP Context exposing request headers.

    ``AuthConfigManager.extract_credentials`` only touches
    ``ctx.request_context.request.headers``.
    """

    def __init__(self, headers):
        self.request_context = _ShimReqCtx(headers)


async def _authenticate(request: Request):
    """Authenticate the caller using the gateway's auth provider.

    Returns the AuthResult (``.is_success``, ``.gateway_config``, ``.mcp_config``)
    or None if the auth manager is unavailable.
    """
    from secure_mcp_gateway.plugins.auth.config_manager import get_auth_config_manager

    manager = get_auth_config_manager()
    return await manager.authenticate(_ShimCtx(request.headers))


def _purge_expired() -> None:
    now = time.time()
    with _lock:
        stale = [
            s
            for s, f in _pending_flows.items()
            if now - f.get("created_at", 0) > _STATE_TTL_SECONDS
        ]
        for s in stale:
            _pending_flows.pop(s, None)


async def _parse_body(request: Request) -> dict[str, Any]:
    try:
        if int(request.headers.get("content-length") or 0) <= 0:
            return {}
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


def _find_server_entry(auth_result, server_name: str) -> dict | None:
    gateway_config = getattr(auth_result, "gateway_config", None) or {}
    mcp_config = (
        getattr(auth_result, "mcp_config", None)
        or gateway_config.get("mcp_config", [])
        or []
    )
    return next((s for s in mcp_config if s.get("server_name") == server_name), None)


# ---------------------------------------------------------------------------
# Shared authorization starter (used by the HTTP route and the MCP tool)
# ---------------------------------------------------------------------------
async def begin_authorization(
    server_name: str,
    server_entry: dict | None,
    gateway_config: dict | None = None,
    *,
    body_overrides: dict | None = None,
    default_redirect: str | None = None,
    open_browser: bool | None = None,
) -> dict:
    """Start a gateway-managed OAuth authorization-code flow for a server.

    Resolves the OAuth client config from (in priority order) the server's
    ``oauth_config``, caller-supplied ``body_overrides``, and the mounted
    ``gcp-oauth.keys.json`` (so client_id/secret/endpoints can come straight
    from the keyfile the downstream server already uses -- no secrets need to be
    passed in). The redirect_uri is resolved separately so a remotely deployed
    gateway can advertise its own public callback: explicit override >
    configured public URL (ENKRYPT_GATEWAY_BASE_URL) > keyfile loopback >
    request-derived (see the resolution block below). Generates the PKCE auth
    URL, stashes the pending flow, and (optionally) opens the browser when the
    gateway runs on a host with a display. Returns a JSON-able dict; on error it
    carries ``status_code``.
    """
    _purge_expired()
    gateway_config = gateway_config or {}

    oauth_dict: dict[str, Any] = dict((server_entry or {}).get("oauth_config") or {})
    oauth_dict.update(body_overrides or {})

    # An explicit redirect from oauth_config / body override outranks everything
    # else. Capture it before the keyfile fill so it stays distinguishable from
    # the keyfile's registered (loopback) redirect.
    explicit_redirect = oauth_dict.get("OAUTH_REDIRECT_URI")

    # Fill client_id / client_secret / endpoints from the mounted keyfile when
    # absent (the cloud registry never stores secrets). The keyfile also carries
    # the redirect registered with the IdP -- kept separately as the local
    # loopback default (see redirect resolution below), NOT force-applied here,
    # so a configured public gateway URL can take precedence on remote deploys.
    keyfile_redirect: str | None = None
    if server_entry:
        keys = load_oauth_client_from_keys_file(server_entry)
        if keys:
            if not oauth_dict.get("OAUTH_CLIENT_ID") and keys.get("client_id"):
                oauth_dict["OAUTH_CLIENT_ID"] = keys["client_id"]
            if not oauth_dict.get("OAUTH_CLIENT_SECRET") and keys.get("client_secret"):
                oauth_dict["OAUTH_CLIENT_SECRET"] = keys["client_secret"]
            if not oauth_dict.get("OAUTH_AUTHORIZATION_URL") and keys.get("auth_uri"):
                oauth_dict["OAUTH_AUTHORIZATION_URL"] = keys["auth_uri"]
            if not oauth_dict.get("OAUTH_TOKEN_URL") and keys.get("token_uri"):
                oauth_dict["OAUTH_TOKEN_URL"] = keys["token_uri"]
            keyfile_redirect = keys.get("redirect_uri")

    if not oauth_dict.get("OAUTH_CLIENT_ID"):
        return {
            "status": "error",
            "status_code": 400,
            "error": f"No OAuth client_id for server '{server_name}'. Provide it via "
            "oauth_config, an 'oauth_config' override, or a mounted gcp-oauth.keys.json.",
        }

    # Force authorization-code + PKCE + offline access (Google needs the latter
    # to return a refresh_token). setdefault preserves any explicit overrides.
    oauth_dict["enabled"] = True
    oauth_dict["OAUTH_GRANT_TYPE"] = "authorization_code"
    oauth_dict.setdefault("OAUTH_VERSION", "2.1")
    oauth_dict.setdefault("OAUTH_USE_PKCE", True)
    oauth_dict.setdefault(
        "OAUTH_AUTHORIZATION_URL", "https://accounts.google.com/o/oauth2/v2/auth"
    )
    oauth_dict.setdefault("OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token")

    # Redirect-URI resolution (highest priority first). Whatever is chosen MUST
    # be registered with the IdP (e.g. as an Authorized redirect URI in Google
    # Cloud Console):
    #   1. explicit OAUTH_REDIRECT_URI from oauth_config / body override
    #   2. the gateway's configured PUBLIC callback -- set ENKRYPT_GATEWAY_BASE_URL
    #      (or enkrypt_gateway_base_url) on remotely deployed gateways so the IdP
    #      redirects back to the public host
    #      (e.g. https://mcp.dev.enkryptai.com/oauth2callback) rather than localhost
    #   3. the loopback redirect registered in the mounted gcp-oauth.keys.json
    #      (the local-install default -- unchanged behavior when no public URL is set)
    #   4. default_redirect -- request-derived; last resort
    redirect_uri = (
        explicit_redirect
        or get_gateway_oauth_redirect_uri()
        or keyfile_redirect
        or default_redirect
    )
    if not redirect_uri:
        return {
            "status": "error",
            "status_code": 400,
            "error": "Could not determine OAUTH_REDIRECT_URI. Set ENKRYPT_GATEWAY_BASE_URL "
            "(remote deploy), register a redirect in gcp-oauth.keys.json (local), or pass "
            "oauth_config.OAUTH_REDIRECT_URI.",
        }
    oauth_dict["OAUTH_REDIRECT_URI"] = redirect_uri

    extra = dict(oauth_dict.get("OAUTH_ADDITIONAL_PARAMS") or {})
    extra.setdefault("access_type", "offline")
    extra.setdefault("prompt", "consent")
    oauth_dict["OAUTH_ADDITIONAL_PARAMS"] = extra

    output_path = oauth_dict.get("OAUTH_CREDENTIALS_FILE") or (
        resolve_credentials_file_path(server_entry) if server_entry else None
    )
    if not output_path:
        return {
            "status": "error",
            "status_code": 400,
            "error": "Could not determine the credentials file path. Set "
            "oauth_config.OAUTH_CREDENTIALS_FILE (or config.env.GSHEETS_CREDENTIALS_PATH).",
        }

    try:
        oauth_config = OAuthConfig.from_dict(oauth_dict)
        auth_url, state, code_verifier, _challenge = (
            get_oauth_service().generate_authorization_url(oauth_config=oauth_config)
        )
    except ValueError as e:
        return {
            "status": "error",
            "status_code": 400,
            "error": f"Invalid oauth_config: {e}",
        }
    except Exception as e:
        logger.error(f"[gateway_oauth_routes] authorize failed: {e}")
        return {
            "status": "error",
            "status_code": 500,
            "error": f"Failed to start OAuth flow: {e}",
        }

    with _lock:
        _pending_flows[state] = {
            "server_name": server_name,
            "oauth_dict": oauth_dict,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "scope": oauth_dict.get("OAUTH_SCOPE"),
            "output_path": output_path,
            "config_id": gateway_config.get("mcp_config_id"),
            "project_id": gateway_config.get("project_id"),
            "created_at": time.time(),
        }

    # Auto-open the browser only when the gateway runs on a host with a display
    # (never inside Docker, where webbrowser.open is a no-op). Callers may force
    # it on/off via open_browser.
    do_open = open_browser
    if do_open is None:
        try:
            from secure_mcp_gateway.utils import is_docker

            # Never auto-open on a server deployment: inside Docker/K8s there is
            # no display, and when a public gateway URL is configured the user
            # opens auth_url on THEIR machine (the IdP redirect comes back to the
            # gateway's public host, not to a browser on the server).
            do_open = not is_docker() and not get_gateway_base_url()
        except Exception:
            do_open = False
    browser_opened = False
    if do_open:
        try:
            import webbrowser

            browser_opened = bool(webbrowser.open(auth_url))
        except Exception as e:
            logger.warning(f"[gateway_oauth_routes] webbrowser.open failed: {e}")

    logger.info(
        "[gateway_oauth_routes] authorization flow started",
        server_name=server_name,
        redirect_uri=redirect_uri,
        credentials_file=output_path,
        state=state[:8] + "...",
        browser_opened=browser_opened,
    )

    instructions = (
        "Open auth_url in a browser and approve access. You'll be redirected to the "
        "gateway, which exchanges the code and writes the credentials file; then call "
        "the server's tools normally."
    )
    if browser_opened:
        instructions = "Browser opened for authorization. " + instructions

    return {
        "status": "ok",
        "server_name": server_name,
        "auth_url": auth_url,
        "state": state,
        "redirect_uri": redirect_uri,
        "credentials_file": output_path,
        "expires_in": _STATE_TTL_SECONDS,
        "browser_opened": browser_opened,
        "instructions": instructions,
    }


def _request_derived_redirect(request: Request) -> str:
    """Best-effort public callback URL derived from the inbound request.

    Honors ``X-Forwarded-Proto`` / ``X-Forwarded-Host`` (set by most ingresses
    and load balancers that terminate TLS) so a proxied request still yields an
    ``https://`` callback on the public host rather than the internal
    ``http://<pod-ip>:8000`` uvicorn sees. This is only a LAST-RESORT fallback
    behind the explicit OAUTH_REDIRECT_URI and ENKRYPT_GATEWAY_BASE_URL paths --
    prefer those, since they don't depend on proxy header hygiene.
    """
    headers = request.headers
    proto = (
        (headers.get("x-forwarded-proto") or request.url.scheme or "http")
        .split(",")[0]
        .strip()
    )
    host = (
        (headers.get("x-forwarded-host") or headers.get("host") or request.url.netloc)
        .split(",")[0]
        .strip()
    )
    if not host:
        return str(request.base_url).rstrip("/") + GATEWAY_OAUTH_CALLBACK_PATH
    return f"{proto}://{host}{GATEWAY_OAUTH_CALLBACK_PATH}"


# ---------------------------------------------------------------------------
# POST /api/v1/oauth/authorize
# ---------------------------------------------------------------------------
async def _authorize_handler(request: Request) -> JSONResponse:
    auth_result = await _authenticate(request)
    if auth_result is None or not getattr(auth_result, "is_success", False):
        msg = (
            getattr(auth_result, "message", "authentication failed")
            if auth_result
            else "auth unavailable"
        )
        return JSONResponse(
            {"status": "error", "error": f"Unauthorized: {msg}"}, status_code=401
        )

    body = await _parse_body(request)
    server_name = body.get("server_name")
    if not server_name:
        return JSONResponse(
            {"status": "error", "error": "Missing 'server_name' in request body"},
            status_code=400,
        )

    server_entry = _find_server_entry(auth_result, server_name)
    # Merge convenience top-level body.redirect_uri into oauth_config overrides.
    overrides = dict(body.get("oauth_config") or {})
    if body.get("redirect_uri") and "OAUTH_REDIRECT_URI" not in overrides:
        overrides["OAUTH_REDIRECT_URI"] = body["redirect_uri"]

    result = await begin_authorization(
        server_name,
        server_entry,
        getattr(auth_result, "gateway_config", None) or {},
        body_overrides=overrides,
        default_redirect=_request_derived_redirect(request),
        open_browser=body.get("open_browser"),
    )
    status_code = result.pop(
        "status_code", 200 if result.get("status") == "ok" else 400
    )
    return JSONResponse(result, status_code=status_code)


# ---------------------------------------------------------------------------
# GET /oauth2callback   (the IdP redirects the browser here)
# ---------------------------------------------------------------------------
def _html(
    title: str, heading_emoji: str, heading: str, body_html: str, status_code: int
) -> HTMLResponse:
    return HTMLResponse(
        f"""<!DOCTYPE html><html><head><title>{title}</title>
<style>body{{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;
height:100vh;margin:0;background:#f0f0f0}}.card{{background:#fff;padding:40px;border-radius:10px;
box-shadow:0 2px 10px rgba(0,0,0,.1);text-align:center;max-width:560px}}h1{{color:#333}}
p{{color:#666}}code{{background:#eee;padding:2px 6px;border-radius:4px}}.big{{font-size:48px}}</style>
</head><body><div class="card"><div class="big">{heading_emoji}</div><h1>{heading}</h1>{body_html}
</div></body></html>""",
        status_code=status_code,
    )


async def _callback_handler(request: Request) -> HTMLResponse:
    _purge_expired()
    params = request.query_params
    code = params.get("code")
    state = params.get("state")
    err = params.get("error")
    err_desc = params.get("error_description")

    if err:
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Authorization Failed",
            f"<p>The identity provider returned an error.</p><p><code>{err}: {err_desc or ''}</code></p>",
            400,
        )

    if not code and not state:
        # Bare hit (e.g. someone opened the gateway root in a browser). Return a
        # neutral page so the root path doesn't look broken; this route doubles
        # as the default loopback OAuth callback.
        return _html(
            "Enkrypt Secure MCP Gateway",
            "&#128272;",
            "Enkrypt Secure MCP Gateway",
            "<p>OAuth callback endpoint. Start a flow with "
            "<code>POST /api/v1/oauth/authorize</code>.</p>",
            200,
        )

    if not code or not state:
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Invalid Callback",
            "<p>Missing authorization <code>code</code> or <code>state</code>.</p>",
            400,
        )

    with _lock:
        flow = _pending_flows.pop(state, None)

    if not flow:
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Invalid or Expired State",
            "<p>No matching authorization request (it may have expired). "
            "Please restart the flow via <code>POST /api/v1/oauth/authorize</code>.</p>",
            400,
        )

    server_name = flow["server_name"]
    try:
        oauth_config = OAuthConfig.from_dict(flow["oauth_dict"])
        token, exchange_err = await get_oauth_service().exchange_authorization_code(
            server_name=server_name,
            oauth_config=oauth_config,
            authorization_code=code,
            code_verifier=flow.get("code_verifier"),
            state=state,
            expected_state=state,
            config_id=flow.get("config_id"),
            project_id=flow.get("project_id"),
        )
    except Exception as e:
        logger.error(f"[gateway_oauth_routes] token exchange crashed: {e}")
        with _lock:
            _last_results[server_name] = {
                "success": False,
                "error": str(e),
                "at": time.time(),
            }
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Token Exchange Error",
            f"<p>{e}</p>",
            500,
        )

    if exchange_err or not token:
        with _lock:
            _last_results[server_name] = {
                "success": False,
                "error": exchange_err,
                "at": time.time(),
            }
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Token Exchange Failed",
            f"<p><code>{exchange_err}</code></p>",
            400,
        )

    try:
        materialize_google_credentials_file(
            token=token, output_path=flow["output_path"], scope=flow.get("scope")
        )
    except Exception as e:
        logger.error(f"[gateway_oauth_routes] failed to write credentials file: {e}")
        with _lock:
            _last_results[server_name] = {
                "success": False,
                "error": f"write failed: {e}",
                "at": time.time(),
            }
        return _html(
            "Authorization Failed",
            "&#10007;",
            "Could Not Save Credentials",
            f"<p>{e}</p>",
            500,
        )

    with _lock:
        _last_results[server_name] = {
            "success": True,
            "credentials_file": flow["output_path"],
            "has_refresh_token": bool(token.refresh_token),
            "expires_in": token.expires_in,
            "scope": token.scope or flow.get("scope"),
            "at": time.time(),
        }

    logger.info(
        "[gateway_oauth_routes] authorization complete",
        server_name=server_name,
        has_refresh_token=bool(token.refresh_token),
        expires_in=token.expires_in,
    )

    refresh_note = (
        "A refresh token was obtained."
        if token.refresh_token
        else "WARNING: no refresh token was returned; the access token is short-lived."
    )
    return _html(
        "Authorization Successful",
        "&#10003;",
        "Authorization Successful!",
        f"<p>Credentials for <code>{server_name}</code> have been saved.</p>"
        f"<p>{refresh_note}</p>"
        "<p>You can close this window and use your MCP tools.</p>",
        200,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/oauth/status?server_name=...
# ---------------------------------------------------------------------------
async def _status_handler(request: Request) -> JSONResponse:
    auth_result = await _authenticate(request)
    if auth_result is None or not getattr(auth_result, "is_success", False):
        return JSONResponse(
            {"status": "error", "error": "Unauthorized"}, status_code=401
        )

    server_name = request.query_params.get("server_name")
    if not server_name:
        return JSONResponse(
            {"status": "error", "error": "Missing 'server_name' query parameter"},
            status_code=400,
        )

    server_entry = _find_server_entry(auth_result, server_name)
    creds_path = resolve_credentials_file_path(server_entry) if server_entry else None
    import os

    with _lock:
        last = _last_results.get(server_name)
        pending = any(f["server_name"] == server_name for f in _pending_flows.values())

    return JSONResponse(
        {
            "status": "ok",
            "server_name": server_name,
            "credentials_file": creds_path,
            "credentials_present": bool(creds_path) and os.path.exists(creds_path),
            "flow_pending": pending,
            "last_result": last,
        }
    )


def register_gateway_oauth_routes(mcp: FastMCP) -> None:
    """Attach the gateway-owned OAuth authorize/callback/status routes.

    Call after the FastMCP instance is constructed and before ``mcp.run(...)``.
    Not idempotent at the route level -- call exactly once.
    """
    mcp.custom_route(
        "/api/v1/oauth/authorize",
        methods=["POST"],
        name="gateway_oauth_authorize",
        include_in_schema=False,
    )(_authorize_handler)
    mcp.custom_route(
        "/api/v1/oauth/status",
        methods=["GET"],
        name="gateway_oauth_status",
        include_in_schema=False,
    )(_status_handler)

    # Serve the callback handler on every well-known alias path plus the path of
    # the configured redirect (so what we advertise is always what we serve).
    # Each route is registered defensively so one failure can't stop the rest.
    registered: list[str] = []
    for i, path in enumerate(_resolve_callback_paths(get_gateway_oauth_redirect_uri())):
        try:
            mcp.custom_route(
                path,
                methods=["GET"],
                name=f"gateway_oauth_callback_{i}",
                include_in_schema=False,
            )(_callback_handler)
            registered.append(path)
        except Exception as e:
            logger.warning(
                f"[gateway_oauth_routes] could not register callback route {path}: {e}"
            )
    # The gateway ROOT ("/") doubles as the loopback redirect (Google Desktop
    # clients match on "/") and a neutral landing page. Register it separately so
    # a "/" route conflict can't stop the primary endpoints above.
    try:
        mcp.custom_route(
            "/",
            methods=["GET"],
            name="gateway_oauth_callback_root",
            include_in_schema=False,
        )(_callback_handler)
        registered.append("/")
    except Exception as e:
        logger.warning(
            f"[gateway_oauth_routes] could not register root callback route: {e}"
        )
    logger.info(
        "[gateway_oauth_routes] registered OAuth endpoints "
        "(POST /api/v1/oauth/authorize, GET /api/v1/oauth/status, "
        f"GET callbacks on {registered})"
    )


__all__ = ["register_gateway_oauth_routes"]
