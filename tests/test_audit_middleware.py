"""Tests for the FastAPI audit middleware route table.

We don't spin up a full FastAPI app for these tests -- the middleware's
state is pure data (the ``_ROUTES`` table) plus the route-resolution
function ``_resolve_route``.  Exercising that table directly catches
the bulk of "did I cover this endpoint?" regressions without an HTTP
fixture stack.

A separate integration smoke (firing real requests at the gateway in
dev OS verification) covers the end-to-end pipe.
"""

from __future__ import annotations

import pytest

from secure_mcp_gateway.audit_middleware import _resolve_route, _suffix


# ---------------------------------------------------------------------------
# Mutations the dashboard pivots on -- every one of these must resolve.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "method,path,expected_action,expected_resource_type",
    [
        # Project lifecycle
        ("POST",   "/api/v1/projects",
            "project_created", "project"),
        ("DELETE", "/api/v1/projects/proj_123",
            "project_deleted", "project"),

        # Project membership / config
        ("POST",   "/api/v1/projects/proj_123/assign-config",
            "project_assign_config", "project"),
        ("POST",   "/api/v1/projects/proj_123/unassign-config",
            "project_unassign_config", "project"),
        ("POST",   "/api/v1/projects/proj_123/users",
            "project_add_user", "project"),
        ("DELETE", "/api/v1/projects/proj_123/users/user_456",
            "project_remove_user", "project"),
        ("DELETE", "/api/v1/projects/proj_123/users",
            "project_remove_all_users", "project"),
        ("POST",   "/api/v1/projects/proj_123/export",
            "project_exported", "project"),

        # User lifecycle
        ("POST",   "/api/v1/users",                 "user_created", "user"),
        ("PUT",    "/api/v1/users/user_456",        "user_updated", "user"),
        ("DELETE", "/api/v1/users/user_456",        "user_deleted", "user"),

        # Apikey lifecycle
        ("POST",   "/api/v1/users/user_456/api-keys",
            "apikey_created", "apikey"),
        ("DELETE", "/api/v1/users/user_456/api-keys",
            "apikey_deleted", "apikey"),
        ("POST",   "/api/v1/api-keys/rotate",
            "apikey_rotated", "apikey"),
        ("POST",   "/api/v1/api-keys/abc123/disable",
            "apikey_disabled", "apikey"),
        ("POST",   "/api/v1/api-keys/abc123/enable",
            "apikey_enabled", "apikey"),
        ("DELETE", "/api/v1/api-keys/abc123",
            "apikey_deleted", "apikey"),

        # System operations
        ("POST",   "/api/v1/system/backup",
            "system_backup", "system"),
        ("POST",   "/api/v1/system/restore",
            "system_restore", "system"),
        ("POST",   "/api/v1/system/reset",
            "system_reset", "system"),

        # Cache flush (v2.2.0-only routes; middleware still resolves them
        # cleanly because the route table is data, not import-bound)
        ("POST",   "/api/v1/cache/flush-gateway-config",
            "cache_flush", "cache"),
        ("POST",   "/api/v1/cache/clear",
            "cache_flush", "cache"),
    ],
)
def test_route_resolves_to_correct_action(
    method, path, expected_action, expected_resource_type
):
    result = _resolve_route(method, path)
    assert result is not None, f"{method} {path} must be audit-tracked"
    action, resource_type, _params = result
    assert action == expected_action
    assert resource_type == expected_resource_type


def test_route_returns_path_params_for_drill_down():
    """The dashboard's per-resource drill-down panels need the path
    params surfaced in the log record."""
    result = _resolve_route("DELETE", "/api/v1/projects/proj_xyz/users/user_abc")
    assert result is not None
    _action, _rt, params = result
    assert params == {"project_identifier": "proj_xyz", "user_identifier": "user_abc"}


# ---------------------------------------------------------------------------
# Things that should NOT be audit-tracked
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        # GETs are read-only
        ("GET", "/api/v1/projects"),
        ("GET", "/api/v1/users/user_456/api-keys"),
        ("GET", "/api/v1/system/health"),
        # Search endpoints are read-only despite POST (search criteria in body)
        ("POST", "/api/v1/projects/search"),
        ("POST", "/api/v1/users/search"),
        # Unknown paths
        ("POST", "/api/v1/something/that/does/not/exist"),
        # Non-admin paths
        ("POST", "/mcp"),
        ("GET", "/health"),
        ("GET", "/docs"),
    ],
)
def test_routes_that_should_be_skipped(method, path):
    assert _resolve_route(method, path) is None, (
        f"{method} {path} must NOT trigger audit (read-only or out-of-scope)"
    )


# ---------------------------------------------------------------------------
# Wrong-method should not resolve to right-method route
# ---------------------------------------------------------------------------

def test_method_must_match():
    # POST /projects creates; GET /projects lists.  The route table
    # only has the POST entry; GET must NOT resolve to project_created.
    assert _resolve_route("GET", "/api/v1/projects") is None
    assert _resolve_route("POST", "/api/v1/projects")[0] == "project_created"

    # DELETE /api-keys/{key} deletes; PUT would be undefined -- must not
    # accidentally resolve to apikey_deleted.
    assert _resolve_route("PUT", "/api/v1/api-keys/abc") is None


# ---------------------------------------------------------------------------
# Apikey suffix masking
# ---------------------------------------------------------------------------

def test_suffix_masks_long_secrets_keeps_last_4():
    assert _suffix("abcdef123456") == "****3456"


def test_suffix_returns_stars_for_short_or_empty():
    assert _suffix("") == "****"
    assert _suffix("abc") == "****"
    assert _suffix(None) == "****"
