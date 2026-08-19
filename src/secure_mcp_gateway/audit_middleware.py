"""FastAPI middleware that auto-emits audit events for every admin
mutation, without per-endpoint instrumentation.

Why a middleware
----------------
The admin REST surface (``api_routes.py``) has 30+ mutation endpoints.
Wrapping each one with explicit ``log_audit()`` calls works but:

  1. Couples the audit logic to every individual endpoint's
     try/except shape, so a tweak (e.g. a new failure_reason category)
     requires touching all sites.
  2. Makes the patch image fragile: shipping per-endpoint changes as
     an overlay on top of an upstream ``api_routes.py`` (e.g.
     v2.2.0) means matching every endpoint's exact text -- if the
     upstream version drifted, the overlay breaks.
  3. Every new endpoint added later silently skips audit until
     someone remembers to wrap it.

This middleware centralises all three concerns in one file.  Path +
method are mapped to ``(action, resource_type, target_id_source)`` by
a single table; success/failure is inferred from the response status
code.  ANY admin endpoint -- existing or future -- gets audit
emission automatically.

What's lost vs per-endpoint
---------------------------
Body inspection.  The per-endpoint instrumentation could read e.g.
``request.email`` to set ``target_id`` for ``user_created``.  The
middleware can only see the URL path and ID-bearing path params.  For
the dashboard's pivots this is sufficient -- ``user_created`` records
get the URL target (the email isn't in the URL but the user_id
returned in the response isn't easy to read here either, so we set
target_id to "<from_body>" and rely on the structured log for the
detail).

The HTTPException handler in ``api_server.py`` already emits
``enkrypt.auth.unauthorized_http`` for 401/403, so we explicitly skip
those status codes in the middleware to avoid double-counting.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional, Pattern

from fastapi import Request, Response

from .audit import log_audit


def _actor_id_from_apikey(apikey: Optional[str]) -> str:
    """Audit display for the admin apikey suffix (last 4 chars).

    Mirrors the helper that lived in api_routes.py before the
    middleware refactor; centralised here so the same display logic is
    used everywhere the middleware emits.
    """
    if not apikey:
        return "unknown"
    return f"****{apikey[-4:]}" if len(apikey) >= 4 else "****"


# ---------------------------------------------------------------------------
# Path -> (action, resource_type, target_id-source) table
# ---------------------------------------------------------------------------
#
# Each entry is (method, compiled_pattern, action, resource_type,
# target_id_group_name).  Patterns use named groups so the middleware
# can lift the target_id out of the path (e.g. project_identifier from
# /api/v1/projects/{project_identifier}).  ``target_id_group_name = None``
# means the endpoint creates a new resource -- target id is in the
# response body, not the path, so we emit with an empty target_id
# placeholder; the structured log_audit() record still captures every
# path param via the ``path_params`` extra.
#
# Read-only endpoints (search, list, get, health-check) are intentionally
# omitted -- the dashboard's "Admin Actions" panel only counts mutations.

_Route = tuple[str, Pattern[str], str, str, Optional[str]]


def _compile(pat: str) -> Pattern[str]:
    """Convert a FastAPI-style path with ``{name}`` params into a regex
    with named groups.  Tail must match exactly so ``/users`` doesn't
    swallow ``/users/{id}/api-keys``."""
    regex = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pat)
    return re.compile(rf"^{regex}$")


_ROUTES: list[_Route] = [
    # ------ Project lifecycle ------
    ("POST",   _compile("/api/v1/projects"),
        "project_created", "project", None),
    ("DELETE", _compile("/api/v1/projects/{project_identifier}"),
        "project_deleted", "project", "project_identifier"),

    # ------ Project membership / assignment ------
    ("POST",   _compile("/api/v1/projects/{project_identifier}/assign-config"),
        "project_assign_config", "project", "project_identifier"),
    ("POST",   _compile("/api/v1/projects/{project_identifier}/unassign-config"),
        "project_unassign_config", "project", "project_identifier"),
    ("POST",   _compile("/api/v1/projects/{project_identifier}/users"),
        "project_add_user", "project", "project_identifier"),
    ("DELETE", _compile("/api/v1/projects/{project_identifier}/users"),
        "project_remove_all_users", "project", "project_identifier"),
    ("DELETE", _compile("/api/v1/projects/{project_identifier}/users/{user_identifier}"),
        "project_remove_user", "project", "project_identifier"),
    ("POST",   _compile("/api/v1/projects/{project_identifier}/export"),
        "project_exported", "project", "project_identifier"),

    # ------ User lifecycle ------
    ("POST",   _compile("/api/v1/users"),
        "user_created", "user", None),
    ("PUT",    _compile("/api/v1/users/{user_identifier}"),
        "user_updated", "user", "user_identifier"),
    ("DELETE", _compile("/api/v1/users/{user_identifier}"),
        "user_deleted", "user", "user_identifier"),

    # ------ API key lifecycle ------
    ("POST",   _compile("/api/v1/users/{user_identifier}/api-keys"),
        "apikey_created", "apikey", "user_identifier"),
    ("DELETE", _compile("/api/v1/users/{user_identifier}/api-keys"),
        "apikey_deleted", "apikey", "user_identifier"),
    ("POST",   _compile("/api/v1/api-keys/rotate"),
        "apikey_rotated", "apikey", None),
    ("POST",   _compile("/api/v1/api-keys/{api_key}/disable"),
        "apikey_disabled", "apikey", "api_key"),
    ("POST",   _compile("/api/v1/api-keys/{api_key}/enable"),
        "apikey_enabled", "apikey", "api_key"),
    ("DELETE", _compile("/api/v1/api-keys/{api_key}"),
        "apikey_deleted", "apikey", "api_key"),

    # ------ System operations ------
    ("POST",   _compile("/api/v1/system/backup"),
        "system_backup", "system", None),
    ("POST",   _compile("/api/v1/system/restore"),
        "system_restore", "system", None),
    ("POST",   _compile("/api/v1/system/reset"),
        "system_reset", "system", None),

    # ------ Cache flush (only present on v2.2.0; harmless if endpoint
    #        doesn't exist -- the regex just never matches a request)
    ("POST",   _compile("/api/v1/cache/flush-gateway-config"),
        "cache_flush", "cache", None),
    ("POST",   _compile("/api/v1/cache/clear"),
        "cache_flush", "cache", None),
]


# Routes that look like mutations (POST/PUT/DELETE) but are actually
# read-only operations -- they exist in the API but don't mutate state.
# Skipped to keep the audit log noise-free.
_SKIP_PATHS = {
    "/api/v1/projects/search",
    "/api/v1/users/search",
}


def _suffix(value: str, n: int = 4) -> str:
    """Mask all but the last n chars of an apikey-like value for
    audit display.  Used when the target_id is itself a secret (apikey
    disable/enable/delete path captures the raw apikey in the URL)."""
    if not value:
        return "****"
    if len(value) <= n:
        return "****"
    return f"****{value[-n:]}"


def _resolve_route(method: str, path: str) -> Optional[tuple[str, str, dict[str, str]]]:
    """Find the matching (action, resource_type, path_params) for an
    incoming request, or ``None`` if the request isn't an audit-worthy
    mutation.

    Returns the path_params dict so the caller can lift out a target_id
    *and* attach all params to the log record for drill-down.
    """
    if path in _SKIP_PATHS:
        return None
    for route_method, pat, action, resource_type, _tid_group in _ROUTES:
        if route_method != method:
            continue
        m = pat.match(path)
        if m is None:
            continue
        return action, resource_type, m.groupdict()
    return None


async def audit_http_middleware(request: Request, call_next: Callable) -> Response:
    """FastAPI HTTP middleware.

    On every request:
      1. Forward to the endpoint (always; never short-circuit the
         actual response).
      2. If the request matches an audit route, emit log_audit with
         success inferred from the response status code.

    Skips 401/403 -- the HTTPException handler in api_server.py
    already emits ``enkrypt.auth.unauthorized_http`` for those.
    """
    response: Response = await call_next(request)

    # Cheap upfront filters -- 99% of requests bail here.
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return response
    # 401/403 are handled by the HTTPException handler in api_server.py;
    # emitting here too would double-count.
    if response.status_code in (401, 403):
        return response

    route = _resolve_route(request.method, request.url.path)
    if route is None:
        return response

    action, resource_type, path_params = route

    # Lookup the target_id column for this route in the table again.
    # (Not great O(n) but the table is tiny and this is one request.)
    target_id: Optional[str] = None
    for route_method, pat, route_action, _rt, tid_group in _ROUTES:
        if (
            route_method == request.method
            and route_action == action
            and pat.match(request.url.path)
        ):
            if tid_group and tid_group in path_params:
                raw = path_params[tid_group]
                # API keys appearing in URL paths should be masked --
                # never log full apikey values, even at INFO.
                target_id = (
                    _suffix(raw) if tid_group == "api_key" else raw
                )
            break

    actor_id = _actor_id_from_apikey(request.headers.get("apikey"))
    success = 200 <= response.status_code < 300
    failure_reason = None if success else f"http_{response.status_code}"

    try:
        log_audit(
            action=action,
            resource_type=resource_type,
            surface="rest_api",
            actor="admin_apikey",
            actor_id=actor_id,
            target_id=target_id or "<from_body>",
            success=success,
            failure_reason=failure_reason,
            http_method=request.method,
            http_path=request.url.path,
            http_status=str(response.status_code),
            path_params=",".join(f"{k}={v}" for k, v in path_params.items())
                          if path_params else None,
        )
    except Exception:  # pragma: no cover - middleware must never break responses
        pass

    return response


__all__ = ["audit_http_middleware", "_resolve_route"]
