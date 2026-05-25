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

    assert extra["enkrypt.user.id"] == "user-123"
    assert extra["enkrypt.project.id"] == "proj-001"
    assert extra["enkrypt.project.name"] == "demo-project"
    assert extra["enkrypt.org.id"] == "org-007"
    assert extra["enkrypt.gateway.name"] == "demo_mcp_gateway"

    # Legacy aliases should be mirrored too.
    assert extra["user_id"] == "user-123"
    assert extra["project_id"] == "proj-001"
    assert extra["project_name"] == "demo-project"
    assert extra["org_id"] == "org-007"
    assert extra["gateway_name"] == "demo_mcp_gateway"


def test_kwargs_override_request_identity_context():
    set_request_identity_context({"user_id": "user-from-context"})

    extra = build_log_extra(None, custom_id="cid", server_name="srv", user_id="explicit")

    assert extra["enkrypt.user.id"] == "explicit"
    assert extra["user_id"] == "explicit"


def test_clearing_request_identity_context_reverts_to_default():
    set_request_identity_context({"user_id": "user-from-context"})
    clear_request_identity_context()

    extra = build_log_extra(None, custom_id="cid", server_name="srv")

    assert extra["enkrypt.user.id"] == "not_provided"
