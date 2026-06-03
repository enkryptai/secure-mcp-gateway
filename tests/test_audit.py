"""Tests for ``secure_mcp_gateway.audit.log_audit``.

The audit module is a thin pair of (1) a structlog INFO emit with a
stable ``log.attributes.*`` shape and (2) automatic dispatch into the
right metrics_helpers function based on ``action``.  These tests pin
both halves of that contract.
"""

from __future__ import annotations

import pytest

from secure_mcp_gateway import audit
from secure_mcp_gateway.plugins.telemetry import metrics_helpers as mh


class RecordingCounter:
    def __init__(self):
        self.calls = []

    def add(self, value, attributes=None):
        self.calls.append((value, dict(attributes or {})))


class FakeManager:
    """Same shape FakeManager as test_metrics_helpers' -- duplicated to
    keep this test file self-contained (the other file's FakeManager is
    a fixture, not importable)."""

    metric_names = (
        "admin_actions_counter",
        "privileged_operations_counter",
        "admin_cache_flush_counter",
        "apikey_rotations_counter",
        "audit_apikey_created_counter",
        "audit_apikey_deleted_counter",
        "audit_apikey_disabled_counter",
        "audit_apikey_rotated_counter",
        "audit_config_modified_counter",
        "audit_settings_enkrypt_api_key_set_counter",
        "audit_settings_telemetry_changed_counter",
        "audit_user_created_counter",
        "audit_user_deleted_counter",
        "projects_created_counter",
        "system_backup_completed_counter",
        "system_reset_counter",
        "system_restore_counter",
        "auth_unauthorized_http_counter",
    )

    def __init__(self):
        for n in self.metric_names:
            setattr(self, n, RecordingCounter())


@pytest.fixture
def fake_manager(monkeypatch):
    mgr = FakeManager()
    monkeypatch.setattr(mh, "_get_manager", lambda: mgr)
    return mgr


@pytest.fixture
def captured_logs(monkeypatch):
    """Capture every call to audit._audit_logger.info so we can assert
    on the structured payload without touching real logging."""
    captured = []

    class FakeLogger:
        def info(self, event, **kwargs):
            captured.append({"event": event, **kwargs})

    monkeypatch.setattr(audit, "_audit_logger", FakeLogger())
    return captured


def test_log_audit_emits_log_and_routes_to_apikey_counter(fake_manager, captured_logs):
    audit.log_audit(
        action="apikey_rotated",
        resource_type="apikey",
        surface="cli",
        actor="alice@enkryptai.com",
        actor_id="****abcd",
        target_id="****1234",
        success=True,
        changed_fields=("apikey_value",),
    )

    # Log record present with the canonical field set
    assert len(captured_logs) == 1
    log = captured_logs[0]
    assert log["event"] == "audit.apikey_rotated"
    extra = log["extra"]
    assert extra["audit_action"] == "apikey_rotated"
    assert extra["admin_action"] == "apikey_rotated"  # dashboard pivots on either
    assert extra["resource_type"] == "apikey"
    assert extra["surface"] == "cli"
    assert extra["actor"] == "alice@enkryptai.com"
    assert extra["target_id"] == "****1234"
    assert extra["changed_fields"] == "apikey_value"
    assert extra["success"] == "true"

    # Metrics: umbrella + privileged + specific rotated + umbrella rotations
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert len(fake_manager.privileged_operations_counter.calls) == 1
    assert len(fake_manager.audit_apikey_rotated_counter.calls) == 1
    assert len(fake_manager.apikey_rotations_counter.calls) == 1


def test_log_audit_failure_path_emits_failure_reason(fake_manager, captured_logs):
    audit.log_audit(
        action="apikey_deleted",
        resource_type="apikey",
        surface="rest_api",
        actor="bob",
        success=False,
        failure_reason="unauthorized",
    )
    log = captured_logs[0]
    assert log["extra"]["success"] == "false"
    assert log["extra"]["failure_reason"] == "unauthorized"
    # Specific metric still fires even on failure -- dashboard uses success
    # attribute to compute success rate.
    _, attrs = fake_manager.audit_apikey_deleted_counter.calls[0]
    assert attrs["success"] == "false"
    assert attrs["failure_reason"] == "unauthorized"


def test_log_audit_cache_flush_dispatch(fake_manager, captured_logs):
    audit.log_audit(
        action="cache_flush",
        resource_type="cache",
        surface="mcp_gateway",
        actor="alice",
        scope="gateway_config",
        authorization_path="admin_apikey",
    )
    assert len(fake_manager.admin_cache_flush_counter.calls) == 1
    _, attrs = fake_manager.admin_cache_flush_counter.calls[0]
    assert attrs["scope"] == "gateway_config"
    assert attrs["authorization_path"] == "admin_apikey"


def test_log_audit_system_op_dispatch(fake_manager, captured_logs):
    audit.log_audit(
        action="system_backup",
        resource_type="system",
        surface="cli",
        actor="root",
    )
    assert len(fake_manager.system_backup_completed_counter.calls) == 1
    # Privileged
    assert len(fake_manager.privileged_operations_counter.calls) == 1


def test_log_audit_settings_dispatch(fake_manager, captured_logs):
    audit.log_audit(
        action="settings_telemetry_changed",
        resource_type="settings",
        surface="rest_api",
        actor="alice",
        old_provider="opentelemetry",
        new_provider="stdout",
    )
    assert len(fake_manager.audit_settings_telemetry_changed_counter.calls) == 1


def test_log_audit_config_modified_passes_changed_fields_to_metric(
    fake_manager, captured_logs
):
    audit.log_audit(
        action="config_modified",
        resource_type="config",
        surface="cli",
        actor="alice",
        target_id="config_default",
        change_kind="update_server",
        changed_fields=["input_guardrails", "config.command", "input_guardrails"],
    )
    _, attrs = fake_manager.audit_config_modified_counter.calls[0]
    assert attrs["changed_fields"] == "config.command,input_guardrails"
    assert attrs["change_kind"] == "update_server"


def test_log_audit_unknown_action_still_emits_umbrella(fake_manager, captured_logs):
    """Unknown action shouldn't be a silent no-op -- the totals KPI
    still needs to count it."""
    audit.log_audit(
        action="some_new_event_no_one_added_a_specific_for",
        resource_type="settings",
        surface="cli",
        actor="alice",
    )
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert len(captured_logs) == 1


def test_log_audit_never_raises_when_metric_helper_throws(monkeypatch, captured_logs):
    """Internal safety net: even if a metrics_helpers function blows up
    for any reason, log_audit must not propagate it (admin mutations
    must never be aborted by telemetry)."""

    class BoomManager:
        def __getattr__(self, name):
            raise RuntimeError(f"boom: {name}")

    monkeypatch.setattr(mh, "_get_manager", lambda: BoomManager())
    # Must not raise
    audit.log_audit(
        action="apikey_created",
        resource_type="apikey",
        surface="cli",
        actor="alice",
    )
    # Log still made it through
    assert len(captured_logs) == 1


def test_log_audit_constructed_log_keys_cannot_be_overwritten_by_extras(
    fake_manager, captured_logs
):
    """The log record contains constructed keys (``audit_action``,
    ``admin_action``) that aren't in the signature, so a caller could
    smuggle them via ``**extras`` (Python would NOT reject because they
    don't collide with explicit kwargs).  The filter inside log_audit
    must drop those so the dashboard sees the canonical value, not
    user-controlled override.

    Non-reserved extras should still attach to the log record."""
    sneaky_extras = {
        # These are LOG-LEVEL constructed keys, not signature keys, so
        # Python allows them through **extras.  log_audit must drop them.
        "audit_action": "spoofed_action",
        "admin_action": "spoofed_action",
        # These are signature reserved-keys; the filter strips them so
        # they don't leak into the log record's extras either.
        # (Python would reject if they collided with explicit kwargs, but
        # passing them as a dict-splat alongside the explicit kwargs
        # is exactly what the filter is for.)
        # Non-reserved -- should propagate:
        "scope": "should_propagate",
        "old_provider": "opentelemetry",
    }
    audit.log_audit(
        action="apikey_created",
        resource_type="apikey",
        surface="cli",
        actor="alice",
        **sneaky_extras,
    )
    log = captured_logs[0]
    # Canonical values win
    assert log["extra"]["audit_action"] == "apikey_created"
    assert log["extra"]["admin_action"] == "apikey_created"
    assert log["extra"]["actor"] == "alice"
    assert log["extra"]["resource_type"] == "apikey"
    # Non-reserved extras still attach
    assert log["extra"]["scope"] == "should_propagate"
    assert log["extra"]["old_provider"] == "opentelemetry"
