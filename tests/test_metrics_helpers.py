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
