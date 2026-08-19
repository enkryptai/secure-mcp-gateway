from __future__ import annotations

from secure_mcp_gateway.utils import (
    build_log_extra,
    clear_request_identity_context,
    set_request_identity_context,
)


def setup_function():
    clear_request_identity_context()


def teardown_function():
    clear_request_identity_context()


def test_build_log_extra_uses_request_identity_context():
    set_request_identity_context(
        {
            "user_id": "user-123",
            "user_email": "alice@example.com",
            "project_id": "proj-001",
            "project_name": "demo-project",
            "org_id": "org-007",
            "gateway_name": "demo_mcp_gateway",
            "gateway_version": "v1",
        }
    )

    extra = build_log_extra(None, custom_id="cid", server_name="srv")

    # 2026-05-26 toggle: gateway emits only the snake_case identity form;
    # canonical ``enkrypt.user.id`` etc. were commented out in
    # ``log.CANONICAL_ATTR_KEYS``. Tests track the toggle.
    assert extra["user_id"] == "user-123"
    assert extra["project_id"] == "proj-001"
    assert extra["project_name"] == "demo-project"
    assert extra["org_id"] == "org-007"
    assert extra["gateway_name"] == "demo_mcp_gateway"
    # Canonical dotted form is suppressed while the toggle is OFF.
    assert "enkrypt.user.id" not in extra
    assert "enkrypt.project.id" not in extra
    assert "enkrypt.gateway.name" not in extra


def test_kwargs_override_request_identity_context():
    set_request_identity_context({"user_id": "user-from-context"})

    extra = build_log_extra(None, custom_id="cid", server_name="srv", user_id="explicit")

    assert extra["user_id"] == "explicit"
    assert "enkrypt.user.id" not in extra


def test_clearing_request_identity_context_reverts_to_default():
    set_request_identity_context({"user_id": "user-from-context"})
    clear_request_identity_context()

    extra = build_log_extra(None, custom_id="cid", server_name="srv")

    assert extra["user_id"] == "not_provided"
