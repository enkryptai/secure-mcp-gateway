"""Tests for ``plugins.telemetry.metrics_helpers``.

These tests inject a fake telemetry manager that records every counter / histogram
call so we can assert that:

  * each helper picks the right instrument by name
  * the standard label set is attached
  * helpers degrade to a silent no-op when telemetry is not initialised
  * helpers never raise
"""

from __future__ import annotations

import pytest

from secure_mcp_gateway.plugins.telemetry import metrics_helpers as mh


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class RecordingCounter:
    def __init__(self):
        self.calls: list[tuple[int, dict]] = []

    def add(self, value, attributes=None):
        self.calls.append((value, dict(attributes or {})))


class RecordingHistogram:
    def __init__(self):
        self.calls: list[tuple[float, dict]] = []

    def record(self, value, attributes=None):
        self.calls.append((value, dict(attributes or {})))


class FakeManager:
    """Stand-in telemetry manager exposing every metric we wire."""

    metric_names = (
        "tool_call_success_counter",
        "tool_call_failure_counter",
        "tool_call_error_counter",
        "tool_call_blocked_counter",
        "tool_call_duration",
        "guardrail_violation_counter",
        "input_guardrail_violation_counter",
        "output_guardrail_violation_counter",
        "relevancy_violation_counter",
        "adherence_violation_counter",
        "hallucination_violation_counter",
        "guardrail_api_request_counter",
        "guardrail_api_request_duration",
        "pii_redactions_counter",
        "auth_success_counter",
        "auth_failure_counter",
        # Tier-1 (PR #41) additions:
        "guardrail_compliance_hit_counter",
        "tool_permission_denied_counter",
        "errors_by_code_counter",
        "degradation_fail_open_counter",
        "degradation_fail_closed_counter",
        "transport_error_counter",
        "discovery_server_failure_counter",
        # Audit (Phase A) additions:
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
        # Guardrail-detail (Phase: PII entities + Toxicity subtypes):
        "guardrail_pii_entity_counter",
        "guardrail_toxicity_subtype_counter",
        # Cache & Performance (session-pool active gauge wiring):
        "active_sessions_gauge",
    )

    def __init__(self):
        for name in self.metric_names:
            if name.endswith("_duration"):
                setattr(self, name, RecordingHistogram())
            else:
                setattr(self, name, RecordingCounter())


@pytest.fixture
def fake_manager(monkeypatch):
    mgr = FakeManager()
    monkeypatch.setattr(mh, "_get_manager", lambda: mgr)
    return mgr


# ---------------------------------------------------------------------------
# Tool-call lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "outcome, expected_counter",
    [
        ("success", "tool_call_success_counter"),
        ("failure", "tool_call_failure_counter"),
        ("error", "tool_call_error_counter"),
        ("blocked", "tool_call_blocked_counter"),
    ],
)
def test_tool_call_outcome_routes_to_right_counter(
    fake_manager, outcome, expected_counter
):
    mh.record_tool_call_outcome(
        server_name="echo_server", tool_name="echo", outcome=outcome
    )

    counter = getattr(fake_manager, expected_counter)
    assert len(counter.calls) == 1, f"{expected_counter} should be incremented once"
    value, attrs = counter.calls[0]
    assert value == 1
    assert attrs["server_name"] == "echo_server"
    assert attrs["tool_name"] == "echo"
    assert attrs["outcome"] == outcome


def test_tool_call_blocked_carries_block_reason(fake_manager):
    mh.record_tool_call_outcome(
        server_name="echo_server",
        tool_name="echo",
        outcome="blocked",
        block_reason="input_violation",
    )
    _, attrs = fake_manager.tool_call_blocked_counter.calls[0]
    assert attrs["block_reason"] == "input_violation"


def test_tool_call_records_duration_when_provided(fake_manager):
    mh.record_tool_call_outcome(
        "s", "t", "success", duration_ms=42.5
    )
    assert fake_manager.tool_call_duration.calls == [(42.5, {
        "server_name": "s",
        "tool_name": "t",
        "outcome": "success",
    })]


# ---------------------------------------------------------------------------
# Guardrail violations
# ---------------------------------------------------------------------------


def test_input_violation_increments_overall_and_directional(fake_manager):
    mh.record_guardrail_violations(
        "input",
        ["policy_violation", "injection_attack"],
        server_name="srv",
        tool_name="tool",
    )
    assert len(fake_manager.guardrail_violation_counter.calls) == 2
    assert len(fake_manager.input_guardrail_violation_counter.calls) == 2
    # output counter must NOT be touched
    assert fake_manager.output_guardrail_violation_counter.calls == []


def test_output_violation_records_per_check_counter(fake_manager):
    mh.record_guardrail_violations(
        "output",
        ["relevancy", "adherence", "hallucination", "policy_violation"],
        server_name="srv",
        tool_name="tool",
    )
    # overall + directional fire 4 times each
    assert len(fake_manager.guardrail_violation_counter.calls) == 4
    assert len(fake_manager.output_guardrail_violation_counter.calls) == 4
    # each per-check counter fires exactly once
    assert len(fake_manager.relevancy_violation_counter.calls) == 1
    assert len(fake_manager.adherence_violation_counter.calls) == 1
    assert len(fake_manager.hallucination_violation_counter.calls) == 1


def test_violation_with_empty_list_is_a_noop(fake_manager):
    mh.record_guardrail_violations("input", [], server_name="s", tool_name="t")
    assert fake_manager.guardrail_violation_counter.calls == []


# ---------------------------------------------------------------------------
# PII / auth / guardrail-API
# ---------------------------------------------------------------------------


def test_pii_redaction_increments_with_count(fake_manager):
    mh.record_pii_redaction("input", count=3, server_name="s")
    assert fake_manager.pii_redactions_counter.calls == [(3, {
        "direction": "input",
        "server_name": "s",
    })]


def test_pii_redaction_zero_is_noop(fake_manager):
    mh.record_pii_redaction("input", count=0)
    assert fake_manager.pii_redactions_counter.calls == []


def test_auth_success_and_failure(fake_manager):
    mh.record_auth_outcome("local_apikey", "success")
    mh.record_auth_outcome("local_apikey", "failure", failure_reason="bad_key")
    assert len(fake_manager.auth_success_counter.calls) == 1
    assert len(fake_manager.auth_failure_counter.calls) == 1
    _, attrs = fake_manager.auth_failure_counter.calls[0]
    assert attrs["failure_reason"] == "bad_key"


def test_guardrail_api_records_count_and_duration(fake_manager):
    mh.record_guardrail_api(
        direction="output",
        status_code=200,
        duration_ms=12.7,
        check_kind="relevancy",
    )
    assert len(fake_manager.guardrail_api_request_counter.calls) == 1
    assert fake_manager.guardrail_api_request_duration.calls == [(12.7, {
        "direction": "output",
        "status_code": "200",
        "provider": "enkrypt",
        "check_kind": "relevancy",
    })]


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_helpers_are_silent_when_telemetry_unavailable(monkeypatch):
    """If get_telemetry_config_manager is not initialised, helpers must not raise."""
    monkeypatch.setattr(mh, "_get_manager", lambda: None)

    # All helpers - none of these should raise
    mh.record_tool_call_outcome("s", "t", "success")
    mh.record_guardrail_violations("input", ["policy_violation"], "s", "t")
    mh.record_pii_redaction("input", 1)
    mh.record_auth_outcome("p", "success")
    mh.record_guardrail_api("output", 200, 5.0)
    mh.record_compliance_hits([], "input")
    mh.record_error_by_code("E001", "high", "fail_closed")
    mh.record_tool_permission_denied("s", "t")
    mh.record_degradation("fail_open", "x", "y")
    mh.record_transport_error("http", "timeout")
    mh.record_discovery_failure("s", "boom")


def test_helpers_swallow_counter_errors(monkeypatch):
    """A buggy SDK that raises on .add must not crash the request."""

    class Boom:
        def add(self, *a, **kw):  # noqa: D401, ARG002
            raise RuntimeError("boom")

        def record(self, *a, **kw):  # noqa: D401, ARG002
            raise RuntimeError("boom")

    class BoomManager:
        def __getattr__(self, name):
            return Boom()

    monkeypatch.setattr(mh, "_get_manager", lambda: BoomManager())

    mh.record_tool_call_outcome("s", "t", "success", duration_ms=1.0)
    mh.record_guardrail_violations("input", ["x"], "s", "t")
    mh.record_pii_redaction("input", 1)
    mh.record_auth_outcome("p", "success")
    mh.record_guardrail_api("output", 200, 5.0)

    # Tier-1 helpers must also swallow SDK errors.
    fake_violation = type(
        "V",
        (),
        {
            "violation_type": "x",
            "metadata": {"details": {"compliance_mapping": {"owasp_llm_2025": ["LLM01"]}}},
        },
    )()
    mh.record_compliance_hits([fake_violation], "input")
    mh.record_error_by_code("E001", "high", "fail_closed")
    mh.record_tool_permission_denied("s", "t")
    mh.record_degradation("fail_open", "x", "y")
    mh.record_transport_error("http", "timeout")
    mh.record_discovery_failure("s", "boom")


def test_drops_none_attributes(fake_manager):
    """OTel SDK rejects None attribute values; helpers should strip them."""
    mh.record_tool_call_outcome("s", "t", "blocked", block_reason=None)
    _, attrs = fake_manager.tool_call_blocked_counter.calls[0]
    assert "block_reason" not in attrs


# ---------------------------------------------------------------------------
# user_id / project_id propagation (per-principal alerting)
# ---------------------------------------------------------------------------


def test_tool_call_outcome_carries_principal_attrs(fake_manager):
    """Threading user_id/project_id from the auth context must surface as
    metric attributes — that's what powers the per-user Grafana alert."""
    mh.record_tool_call_outcome(
        server_name="echo_server",
        tool_name="echo",
        outcome="blocked",
        block_reason="input_violation",
        user_id="user-abc",
        project_id="proj-xyz",
    )
    _, attrs = fake_manager.tool_call_blocked_counter.calls[0]
    assert attrs["user_id"] == "user-abc"
    assert attrs["project_id"] == "proj-xyz"


def test_guardrail_violation_carries_principal_attrs(fake_manager):
    mh.record_guardrail_violations(
        "input",
        ["injection_attack"],
        server_name="srv",
        tool_name="tool",
        user_id="user-abc",
        project_id="proj-xyz",
    )
    # overall + directional must both carry the labels
    _, overall_attrs = fake_manager.guardrail_violation_counter.calls[0]
    _, input_attrs = fake_manager.input_guardrail_violation_counter.calls[0]
    assert overall_attrs["user_id"] == "user-abc"
    assert overall_attrs["project_id"] == "proj-xyz"
    assert input_attrs["user_id"] == "user-abc"
    assert input_attrs["project_id"] == "proj-xyz"


def test_pii_redaction_carries_principal_attrs(fake_manager):
    mh.record_pii_redaction(
        "input",
        count=2,
        server_name="srv",
        tool_name="tool",
        user_id="user-abc",
        project_id="proj-xyz",
    )
    _, attrs = fake_manager.pii_redactions_counter.calls[0]
    assert attrs["user_id"] == "user-abc"
    assert attrs["project_id"] == "proj-xyz"


def test_principal_attrs_omitted_when_none(fake_manager):
    """Passing no auth context (or explicit Nones) must NOT explode label
    cardinality with empty strings — the labels should simply be absent."""
    mh.record_tool_call_outcome(
        "srv", "tool", "success", user_id=None, project_id=None
    )
    _, attrs = fake_manager.tool_call_success_counter.calls[0]
    assert "user_id" not in attrs
    assert "project_id" not in attrs


def test_principal_attrs_omitted_when_empty_string(fake_manager):
    """Same as the None case — empty strings are also treated as absent so
    that an unauthenticated path doesn't pollute the metric series."""
    mh.record_guardrail_violations(
        "input", ["injection_attack"], "srv", "tool",
        user_id="", project_id="",
    )
    _, attrs = fake_manager.guardrail_violation_counter.calls[0]
    assert "user_id" not in attrs
    assert "project_id" not in attrs


# ---------------------------------------------------------------------------
# Tier-1 additions (PR #41): compliance_hit / errors_by_code /
# permission_denied / degradation / transport_errors / discovery_failures
# ---------------------------------------------------------------------------


class _StubViolation:
    """Mimics ``GuardrailViolation`` enough for ``record_compliance_hits``."""

    def __init__(self, violation_type, compliance_mapping):
        self.violation_type = violation_type
        self.metadata = {
            "policy_type": violation_type,
            "details": {"compliance_mapping": compliance_mapping},
        }


def test_compliance_hits_emits_one_per_framework_id(fake_manager):
    """Each (framework, framework_id) pair in compliance_mapping should
    increment the counter once, with framework + framework_id labels."""
    v = _StubViolation(
        "injection_attack",
        {
            "owasp_llm_2025": ["LLM01:2025 Prompt Injection"],
            "mitre_atlas": ["AML.T0051", "AML.T0054"],
        },
    )
    mh.record_compliance_hits(
        [v], "input", server_name="srv", tool_name="tool",
        user_id="u1", project_id="p1",
    )
    calls = fake_manager.guardrail_compliance_hit_counter.calls
    assert len(calls) == 3  # 1 owasp + 2 mitre
    frameworks = {attrs["framework"] for _, attrs in calls}
    framework_ids = {attrs["framework_id"] for _, attrs in calls}
    assert frameworks == {"owasp_llm_2025", "mitre_atlas"}
    assert "LLM01:2025 Prompt Injection" in framework_ids
    assert "AML.T0051" in framework_ids
    # Standard attrs propagate
    _, first_attrs = calls[0]
    assert first_attrs["direction"] == "input"
    assert first_attrs["violation_type"] == "injection_attack"
    assert first_attrs["server_name"] == "srv"
    assert first_attrs["user_id"] == "u1"


def test_compliance_hits_handles_string_value_not_list(fake_manager):
    """Some providers return a bare string instead of a list; we wrap."""
    v = _StubViolation("policy_violation", {"eu_ai_act": "Article 15(4)"})
    mh.record_compliance_hits([v], "output")
    assert len(fake_manager.guardrail_compliance_hit_counter.calls) == 1


def test_compliance_hits_is_noop_without_mapping(fake_manager):
    v = _StubViolation("policy_violation", None)
    v.metadata["details"].pop("compliance_mapping", None)
    mh.record_compliance_hits([v], "input")
    assert fake_manager.guardrail_compliance_hit_counter.calls == []


def test_compliance_hits_is_noop_on_empty_input(fake_manager):
    mh.record_compliance_hits([], "input")
    mh.record_compliance_hits(None, "input")
    assert fake_manager.guardrail_compliance_hit_counter.calls == []


def test_compliance_hits_works_with_dict_violations(fake_manager):
    """The helper must also handle violations that come as plain dicts
    (e.g. when replayed from a cached upstream response)."""
    v = {
        "violation_type": "injection_attack",
        "metadata": {
            "details": {"compliance_mapping": {"owasp_llm_2025": ["LLM01"]}}
        },
    }
    mh.record_compliance_hits([v], "input")
    assert len(fake_manager.guardrail_compliance_hit_counter.calls) == 1


def test_error_by_code_stringifies_enum_like_values(fake_manager):
    """ErrorCode / ErrorSeverity / RecoveryStrategy may be passed as enums
    or strings; helper must produce string label values either way."""

    class _EnumLike:
        def __init__(self, v):
            self.value = v

    mh.record_error_by_code(
        error_code=_EnumLike("DISC_003"),
        severity=_EnumLike("high"),
        recovery_strategy=_EnumLike("fail_closed"),
        component="discovery",
        server_name="deepwiki",
    )
    assert len(fake_manager.errors_by_code_counter.calls) == 1
    _, attrs = fake_manager.errors_by_code_counter.calls[0]
    assert attrs["error_code"] == "DISC_003"
    assert attrs["severity"] == "high"
    assert attrs["recovery_strategy"] == "fail_closed"
    assert attrs["component"] == "discovery"
    assert attrs["server_name"] == "deepwiki"


def test_tool_permission_denied_carries_reason(fake_manager):
    mh.record_tool_permission_denied(
        server_name="github",
        tool_name="create_or_update_file",
        reason="deny_list",
        user_id="u1",
    )
    assert len(fake_manager.tool_permission_denied_counter.calls) == 1
    _, attrs = fake_manager.tool_permission_denied_counter.calls[0]
    assert attrs["reason"] == "deny_list"
    assert attrs["server_name"] == "github"
    assert attrs["user_id"] == "u1"


def test_degradation_routes_to_fail_open_vs_fail_closed(fake_manager):
    mh.record_degradation("fail_open", "guardrail_timeout", "input_guardrail")
    mh.record_degradation("fail_closed", "guardrail_api_error", "input_guardrail")
    assert len(fake_manager.degradation_fail_open_counter.calls) == 1
    assert len(fake_manager.degradation_fail_closed_counter.calls) == 1
    _, open_attrs = fake_manager.degradation_fail_open_counter.calls[0]
    assert open_attrs["mode"] == "fail_open"
    assert open_attrs["reason"] == "guardrail_timeout"
    assert open_attrs["component"] == "input_guardrail"


def test_transport_error_carries_transport_and_kind(fake_manager):
    mh.record_transport_error(
        transport="stdio",
        error_kind="BrokenPipeError",
        server_name="echo",
        tool_name="echo",
    )
    assert len(fake_manager.transport_error_counter.calls) == 1
    _, attrs = fake_manager.transport_error_counter.calls[0]
    assert attrs["transport"] == "stdio"
    assert attrs["error_kind"] == "BrokenPipeError"
    assert attrs["server_name"] == "echo"


def test_transport_error_serialises_status_code(fake_manager):
    mh.record_transport_error("http", "http_5xx", "srv", status_code=503)
    _, attrs = fake_manager.transport_error_counter.calls[0]
    assert attrs["status_code"] == "503"  # always stringified for label compat


def test_discovery_failure_carries_reason(fake_manager):
    mh.record_discovery_failure("deepwiki", "TimeoutError", transport="http")
    assert len(fake_manager.discovery_server_failure_counter.calls) == 1
    _, attrs = fake_manager.discovery_server_failure_counter.calls[0]
    assert attrs["server_name"] == "deepwiki"
    assert attrs["reason"] == "TimeoutError"
    assert attrs["transport"] == "http"


# ---------------------------------------------------------------------------
# Audit / compliance helpers (Phase A) -- 9 helpers, ~17 tests below.
#
# All audit helpers fire TWO counters: the umbrella (admin_actions_counter,
# and privileged_operations_counter when applicable) + the specific
# category counter.  Every test asserts both sides of that contract so a
# future refactor that drops one path breaks loudly.
# ---------------------------------------------------------------------------


def test_admin_action_fires_only_umbrella_for_unknown_action(fake_manager):
    mh.record_admin_action(
        action="config_search",
        resource_type="config",
        surface="cli",
        actor="alice",
    )
    # Umbrella fires; no specific counter for this action exists.
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert fake_manager.privileged_operations_counter.calls == []
    _, attrs = fake_manager.admin_actions_counter.calls[0]
    assert attrs["action"] == "config_search"
    assert attrs["resource_type"] == "config"
    assert attrs["surface"] == "cli"
    assert attrs["actor"] == "alice"
    assert attrs["success"] == "true"


def test_admin_action_marks_failure(fake_manager):
    mh.record_admin_action(
        action="apikey_export",
        resource_type="apikey",
        surface="rest_api",
        actor="bob",
        success=False,
        failure_reason="unauthorized",
    )
    _, attrs = fake_manager.admin_actions_counter.calls[0]
    assert attrs["success"] == "false"
    assert attrs["failure_reason"] == "unauthorized"


def test_cache_flush_fires_both_umbrella_and_specific(fake_manager):
    mh.record_cache_flush(
        scope="gateway_config",
        surface="mcp_gateway",
        authorization_path="admin_apikey",
        actor="alice",
        target_id="all",
    )
    # Cache flush is a privileged action: umbrella + privileged + specific.
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert len(fake_manager.privileged_operations_counter.calls) == 1
    assert len(fake_manager.admin_cache_flush_counter.calls) == 1
    _, attrs = fake_manager.admin_cache_flush_counter.calls[0]
    assert attrs["action"] == "cache_flush"
    assert attrs["scope"] == "gateway_config"
    assert attrs["surface"] == "mcp_gateway"
    assert attrs["authorization_path"] == "admin_apikey"


@pytest.mark.parametrize(
    "event,expected_counter",
    [
        ("created", "audit_apikey_created_counter"),
        ("deleted", "audit_apikey_deleted_counter"),
        ("disabled", "audit_apikey_disabled_counter"),
        ("rotated", "audit_apikey_rotated_counter"),
    ],
)
def test_apikey_lifecycle_routes_to_correct_specific_counter(
    fake_manager, event, expected_counter
):
    mh.record_apikey_lifecycle(
        event=event, surface="cli", actor="alice", target_id="****abcd"
    )
    # Always: umbrella + privileged + specific
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert len(fake_manager.privileged_operations_counter.calls) == 1
    counter = getattr(fake_manager, expected_counter)
    assert len(counter.calls) == 1
    # Rotation also fires the umbrella apikey_rotations_counter.
    if event == "rotated":
        assert len(fake_manager.apikey_rotations_counter.calls) == 1
    else:
        assert fake_manager.apikey_rotations_counter.calls == []


def test_apikey_lifecycle_unknown_event_falls_through_to_umbrella(fake_manager):
    mh.record_apikey_lifecycle(event="exported", surface="cli")
    assert len(fake_manager.admin_actions_counter.calls) == 1
    # No specific counter matched -- shouldn't have fired any:
    for name in (
        "audit_apikey_created_counter",
        "audit_apikey_deleted_counter",
        "audit_apikey_disabled_counter",
        "audit_apikey_rotated_counter",
    ):
        assert getattr(fake_manager, name).calls == []


@pytest.mark.parametrize(
    "event,expected_counter",
    [
        ("created", "audit_user_created_counter"),
        ("deleted", "audit_user_deleted_counter"),
    ],
)
def test_user_lifecycle_routes_to_correct_specific_counter(
    fake_manager, event, expected_counter
):
    mh.record_user_lifecycle(event=event, surface="rest_api", actor="alice")
    assert len(fake_manager.admin_actions_counter.calls) == 1
    counter = getattr(fake_manager, expected_counter)
    assert len(counter.calls) == 1


def test_project_created_fires_specific_counter(fake_manager):
    mh.record_project_created(surface="cli", actor="alice", target_id="proj_xyz")
    assert len(fake_manager.admin_actions_counter.calls) == 1
    assert len(fake_manager.projects_created_counter.calls) == 1
    _, attrs = fake_manager.projects_created_counter.calls[0]
    assert attrs["resource_type"] == "project"
    assert attrs["target_id"] == "proj_xyz"


@pytest.mark.parametrize(
    "op,expected_counter",
    [
        ("backup", "system_backup_completed_counter"),
        ("reset", "system_reset_counter"),
        ("restore", "system_restore_counter"),
    ],
)
def test_system_op_routes_to_correct_specific_counter_and_is_privileged(
    fake_manager, op, expected_counter
):
    mh.record_system_op(op=op, surface="cli", actor="root")
    assert len(fake_manager.admin_actions_counter.calls) == 1
    # All system ops are privileged
    assert len(fake_manager.privileged_operations_counter.calls) == 1
    assert len(getattr(fake_manager, expected_counter).calls) == 1


@pytest.mark.parametrize(
    "setting,expected_counter",
    [
        ("enkrypt_api_key_set", "audit_settings_enkrypt_api_key_set_counter"),
        ("telemetry_changed", "audit_settings_telemetry_changed_counter"),
    ],
)
def test_settings_change_routes_correctly(fake_manager, setting, expected_counter):
    mh.record_settings_change(setting=setting, surface="cli", actor="alice")
    assert len(fake_manager.admin_actions_counter.calls) == 1
    # Settings changes are privileged
    assert len(fake_manager.privileged_operations_counter.calls) == 1
    assert len(getattr(fake_manager, expected_counter).calls) == 1


def test_config_modified_serialises_changed_fields(fake_manager):
    """changed_fields must be sorted-unique-joined to keep label
    cardinality bounded (one per panel value, not one per field name)."""
    mh.record_config_modified(
        surface="cli",
        actor="alice",
        target_id="config_default",
        change_kind="update_server",
        changed_fields=["input_guardrails", "config.command", "input_guardrails"],
    )
    assert len(fake_manager.audit_config_modified_counter.calls) == 1
    _, attrs = fake_manager.audit_config_modified_counter.calls[0]
    # Sorted + de-duped
    assert attrs["changed_fields"] == "config.command,input_guardrails"
    assert attrs["change_kind"] == "update_server"


def test_unauthorized_http_attaches_endpoint_and_status(fake_manager):
    mh.record_unauthorized_http(
        endpoint="/api/v1/configs",
        surface="rest_api",
        method="POST",
        status_code=401,
        reason="missing_apikey",
    )
    assert len(fake_manager.auth_unauthorized_http_counter.calls) == 1
    _, attrs = fake_manager.auth_unauthorized_http_counter.calls[0]
    assert attrs["endpoint"] == "/api/v1/configs"
    assert attrs["status_code"] == "401"  # stringified
    assert attrs["reason"] == "missing_apikey"
    # Unauthorized HTTP is *not* a general admin action, so umbrella stays at 0.
    assert fake_manager.admin_actions_counter.calls == []


def test_audit_helpers_silent_when_manager_unavailable(monkeypatch):
    """Same no-op contract as the Tier-1 helpers: never raise when
    telemetry isn't initialised."""
    monkeypatch.setattr(mh, "_get_manager", lambda: None)
    mh.record_admin_action("x", "y", "cli")
    mh.record_cache_flush("all", "cli")
    mh.record_apikey_lifecycle("created", "cli")
    mh.record_user_lifecycle("created", "cli")
    mh.record_project_created("cli")
    mh.record_system_op("backup", "cli")
    mh.record_settings_change("telemetry_changed", "cli")
    mh.record_config_modified("cli")


# ---------------------------------------------------------------------------
# Guardrail-detail: PII entities
# ---------------------------------------------------------------------------


class _FakeViolation:
    """Mimics GuardrailViolation just enough for the helpers."""

    def __init__(self, violation_type: str, details=None):
        # The real class uses an enum (.value gives the string); a bare
        # string is fine for the helpers because they str()-cast and
        # lower-case before matching.
        self.violation_type = violation_type
        self.metadata = {"details": details} if details is not None else {}


def test_record_pii_entities_extracts_list_of_dicts(fake_manager):
    """Most common Enkrypt shape:
    details = {"entities": [{"type": "EMAIL", ...}, {"type": "PHONE", ...}]}"""
    v = _FakeViolation("pii", details={
        "entities": [
            {"type": "EMAIL", "value": "a@b.com"},
            {"type": "PHONE", "value": "+1..."},
            {"type": "EMAIL", "value": "c@d.com"},
        ],
    })
    result = mh.record_pii_entities(
        [v], "input", server_name="srv", tool_name="ask",
    )
    assert result["pii_entities_count"] == 3
    assert result["pii_entity_types"] == ["EMAIL", "PHONE"]  # dedup+sort
    assert "entities" in result["pii_details_keys"]
    # 3 increments: EMAIL, PHONE, EMAIL
    assert len(fake_manager.guardrail_pii_entity_counter.calls) == 3
    types_emitted = [
        attrs["entity_type"]
        for _, attrs in fake_manager.guardrail_pii_entity_counter.calls
    ]
    assert types_emitted == ["EMAIL", "PHONE", "EMAIL"]
    _, attrs = fake_manager.guardrail_pii_entity_counter.calls[0]
    assert attrs["direction"] == "input"
    assert attrs["server_name"] == "srv"
    assert attrs["tool_name"] == "ask"


def test_record_pii_entities_extracts_bare_string_list(fake_manager):
    """Older shape: details = {"entities": ["EMAIL", "PHONE"]}"""
    v = _FakeViolation("pii", details={"entities": ["email", "phone"]})
    result = mh.record_pii_entities([v], "input")
    assert result["pii_entities_count"] == 2
    # Upper-cased for stable dashboard rendering
    assert result["pii_entity_types"] == ["EMAIL", "PHONE"]
    assert len(fake_manager.guardrail_pii_entity_counter.calls) == 2


def test_record_pii_entities_ignores_non_pii_violations(fake_manager):
    """A toxicity violation in the same batch is skipped."""
    pii_v = _FakeViolation("pii", details={"entities": [{"type": "SSN"}]})
    tox_v = _FakeViolation("toxicity", details={"toxicity": 0.9})
    result = mh.record_pii_entities([pii_v, tox_v], "input")
    assert result["pii_entities_count"] == 1
    assert result["pii_entity_types"] == ["SSN"]
    assert len(fake_manager.guardrail_pii_entity_counter.calls) == 1


def test_record_pii_entities_empty_details_returns_zero(fake_manager):
    v = _FakeViolation("pii", details={})
    result = mh.record_pii_entities([v], "input")
    assert result["pii_entities_count"] == 0
    assert result["pii_entity_types"] == []
    # Zero entries: no metric emission (avoid noise counters at 0)
    assert fake_manager.guardrail_pii_entity_counter.calls == []


def test_record_pii_entities_silent_when_manager_unavailable(monkeypatch):
    monkeypatch.setattr(mh, "_get_manager", lambda: None)
    v = _FakeViolation("pii", details={"entities": [{"type": "EMAIL"}]})
    result = mh.record_pii_entities([v], "input")
    # Even without telemetry, the return value must be safe to splat
    # into a log call -- the dashboard's log-based panels depend on it.
    assert result["pii_entities_count"] == 1
    assert result["pii_entity_types"] == ["EMAIL"]


# ---------------------------------------------------------------------------
# Guardrail-detail: Toxicity subtypes
# ---------------------------------------------------------------------------


def test_record_toxicity_subtypes_flat_dict(fake_manager):
    """Most common Enkrypt shape: flat per-subtype scores."""
    v = _FakeViolation("toxicity", details={
        "toxicity":        0.91,
        "severe_toxicity": 0.12,   # below threshold -> skipped
        "insult":          0.74,
        "threat":          0.0,    # below threshold
        "identity_hate":   0.55,
    })
    result = mh.record_toxicity_subtypes([v], "input", threshold=0.5)
    assert set(result["toxicity_subtypes"]) == {"toxicity", "insult", "identity_hate"}
    # Top is the highest scoring -> toxicity at 0.91
    assert result["toxicity_top_subtype"] == "toxicity"
    assert result["toxicity_top_score"] == pytest.approx(0.91, rel=1e-3)
    assert len(fake_manager.guardrail_toxicity_subtype_counter.calls) == 3
    # Score buckets: 0.91=high, 0.74=medium, 0.55=medium
    buckets = sorted(
        attrs["score_bucket"]
        for _, attrs in fake_manager.guardrail_toxicity_subtype_counter.calls
    )
    assert buckets == ["high", "medium", "medium"]


def test_record_toxicity_subtypes_nested_categories(fake_manager):
    """Variant shape: details = {"categories": {...}}."""
    v = _FakeViolation("toxic_content", details={
        "categories": {"insult": 0.88, "threat": 0.3},
    })
    result = mh.record_toxicity_subtypes([v], "output")
    assert result["toxicity_subtypes"] == ["insult"]
    assert result["toxicity_top_subtype"] == "insult"
    assert "categories" in result["toxicity_details_keys"]


def test_record_toxicity_subtypes_below_threshold_keeps_metric_at_zero(fake_manager):
    """No subtype above threshold -> nothing emitted, but details_keys
    still returned so operators can see what arrived."""
    v = _FakeViolation("toxicity", details={"toxicity": 0.2, "insult": 0.1})
    result = mh.record_toxicity_subtypes([v], "input", threshold=0.5)
    assert result["toxicity_subtypes"] == []
    assert result["toxicity_top_subtype"] == ""
    assert result["toxicity_top_score"] == 0.0
    assert sorted(result["toxicity_details_keys"]) == ["insult", "toxicity"]
    assert fake_manager.guardrail_toxicity_subtype_counter.calls == []


def test_record_toxicity_subtypes_ignores_non_toxicity_violations(fake_manager):
    pii_v = _FakeViolation("pii", details={"entities": [{"type": "EMAIL"}]})
    tox_v = _FakeViolation("toxicity", details={"insult": 0.9})
    result = mh.record_toxicity_subtypes([pii_v, tox_v], "input")
    assert result["toxicity_subtypes"] == ["insult"]
    assert len(fake_manager.guardrail_toxicity_subtype_counter.calls) == 1


def test_record_toxicity_subtypes_silent_when_manager_unavailable(monkeypatch):
    monkeypatch.setattr(mh, "_get_manager", lambda: None)
    v = _FakeViolation("toxicity", details={"insult": 0.9})
    result = mh.record_toxicity_subtypes([v], "input")
    # Same contract as PII helper: return dict is always safe to splat
    # into structured logs even when telemetry isn't initialised.
    assert result["toxicity_top_subtype"] == "insult"
    assert result["toxicity_top_score"] == pytest.approx(0.9, rel=1e-3)


# ---------------------------------------------------------------------------
# _score_bucket boundary check (covers the only piece of pure logic that
# can drift the dashboards' low|medium|high pivots).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0,  "low"),
        (0.49, "low"),
        (0.50, "medium"),
        (0.84, "medium"),
        (0.85, "high"),
        (1.0,  "high"),
        ("garbage", "unknown"),
        (None,      "unknown"),
    ],
)
def test_score_bucket_boundaries(score, expected):
    assert mh._score_bucket(score) == expected


# ---------------------------------------------------------------------------
# Cache & Performance: per-request phase timing
# ---------------------------------------------------------------------------


def test_phase_timer_records_into_request_timings():
    """A phase_timer block accumulates wall-clock ms into the active
    contextvar dict under the named field."""
    mh.reset_request_timings()
    mh.start_request_timings()
    with mh.phase_timer("preprocess_duration_ms"):
        # No-op sleep; just take a measurable amount of time
        for _ in range(100):
            _ = sum(range(100))
    timings = mh.get_request_timings()
    assert "preprocess_duration_ms" in timings
    assert timings["preprocess_duration_ms"] > 0
    mh.reset_request_timings()


def test_phase_timer_accumulates_on_repeat_entry():
    """Calling phase_timer twice with the same field name SUMS into
    the same accumulator (used for multi-leg phases like
    guardrail_duration_ms = input + output)."""
    mh.reset_request_timings()
    mh.start_request_timings()
    with mh.phase_timer("guardrail_duration_ms"):
        for _ in range(50):
            _ = sum(range(50))
    first = mh.get_request_timings()["guardrail_duration_ms"]
    with mh.phase_timer("guardrail_duration_ms"):
        for _ in range(50):
            _ = sum(range(50))
    total = mh.get_request_timings()["guardrail_duration_ms"]
    assert total > first  # accumulation is monotonic
    mh.reset_request_timings()


def test_phase_timer_also_into_propagates_to_aggregate():
    """``phase_timer("preprocess_duration_ms", "guardrail_duration_ms")``
    records the same elapsed under BOTH fields so the dashboard can
    show per-phase AND aggregate-phase numbers off the same code path."""
    mh.reset_request_timings()
    mh.start_request_timings()
    with mh.phase_timer("preprocess_duration_ms", "guardrail_duration_ms"):
        for _ in range(50):
            _ = sum(range(50))
    t = mh.get_request_timings()
    assert "preprocess_duration_ms" in t
    assert "guardrail_duration_ms" in t
    # The two should be within float-rounding of each other (same wall time).
    assert abs(t["preprocess_duration_ms"] - t["guardrail_duration_ms"]) < 0.001
    mh.reset_request_timings()


def test_finalize_request_timings_adds_total_and_strips_underscores():
    """finalize_request_timings() returns a clean dict suitable for
    splatting into build_log_extra(...): no leading-underscore keys,
    all values rounded to 2 dp, total_request_duration_ms computed
    from start mark."""
    mh.reset_request_timings()
    mh.start_request_timings()
    with mh.phase_timer("preprocess_duration_ms"):
        for _ in range(20):
            _ = sum(range(50))
    out = mh.finalize_request_timings()
    assert "total_request_duration_ms" in out
    assert out["total_request_duration_ms"] > 0
    assert "preprocess_duration_ms" in out
    # No underscore-prefixed bookkeeping survives finalize
    assert not any(k.startswith("_") for k in out)
    # All values are floats rounded to 2 dp
    for v in out.values():
        assert isinstance(v, float)
        assert round(v, 2) == v


def test_finalize_when_no_timings_returns_empty():
    """No request context active -> empty dict, never raises."""
    mh.reset_request_timings()
    assert mh.finalize_request_timings() == {}


def test_phase_timer_noop_without_request_timings():
    """phase_timer is safe to use when no request timings dict is
    active -- it just doesn't record anywhere."""
    mh.reset_request_timings()
    # No start_request_timings() called
    with mh.phase_timer("execution_duration_ms"):
        for _ in range(10):
            _ = sum(range(10))
    # Should not have created a timings dict
    assert mh.get_request_timings() is None


@pytest.mark.asyncio
async def test_phase_timer_async_context_works():
    """phase_timer is also an async context manager for ``async with``
    callsites (the more common use in STES)."""
    mh.reset_request_timings()
    mh.start_request_timings()

    async def work():
        for _ in range(50):
            _ = sum(range(50))

    async with mh.phase_timer("execution_duration_ms"):
        await work()
    t = mh.get_request_timings()
    assert t["execution_duration_ms"] > 0
    mh.reset_request_timings()


def test_record_session_active_attaches_server_name(fake_manager):
    """record_session_active(+/-) bumps active_sessions_gauge with
    server_name attribute so the Active Sessions panel can pivot
    per-server."""
    mh.record_session_active(+1, server_name="srv1")
    mh.record_session_active(-1, server_name="srv1")
    mh.record_session_active(+1, server_name="srv2")
    assert len(fake_manager.active_sessions_gauge.calls) == 3
    deltas = [v for v, _ in fake_manager.active_sessions_gauge.calls]
    assert deltas == [+1, -1, +1]
    server_names = [a["server_name"] for _, a in fake_manager.active_sessions_gauge.calls]
    assert server_names == ["srv1", "srv1", "srv2"]


def test_record_session_active_zero_delta_is_noop(fake_manager):
    """Zero deltas don't pollute the gauge -- avoid 0-add noise."""
    mh.record_session_active(0, server_name="srv1")
    assert fake_manager.active_sessions_gauge.calls == []


def test_record_session_active_silent_when_manager_unavailable(monkeypatch):
    monkeypatch.setattr(mh, "_get_manager", lambda: None)
    # Just must not raise
    mh.record_session_active(+1, server_name="x")
    mh.record_session_active(-5, server_name="y")


def test_record_phase_ms_manual_recording():
    """record_phase_ms(field, ms) is the manual-recording variant for
    cases where a context manager isn't convenient (e.g. timing was
    captured by a span end-time)."""
    mh.reset_request_timings()
    mh.start_request_timings()
    mh.record_phase_ms("mcp_handshake_duration_ms", 42.5)
    mh.record_phase_ms("mcp_handshake_duration_ms", 7.5)  # accumulates
    t = mh.get_request_timings()
    assert t["mcp_handshake_duration_ms"] == 50.0
    mh.reset_request_timings()
    mh.record_unauthorized_http("/x", "rest_api")
