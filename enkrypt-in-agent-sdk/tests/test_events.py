"""Tests for the event protocol."""

import pytest

from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    GuardrailAction,
    GuardrailVerdict,
    new_run_id,
    new_step_id,
)


class TestAgentEvent:
    def test_required_fields(self):
        ev = AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a1", run_id="r1")
        assert ev.agent_id == "a1"
        assert ev.run_id == "r1"
        assert ev.name == EventName.LIFECYCLE_START

    def test_immutable(self):
        ev = AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a1", run_id="r1")
        with pytest.raises(AttributeError):
            ev.agent_id = "changed"  # type: ignore[misc]

    def test_agent_id_required(self):
        with pytest.raises(ValueError, match="agent_id"):
            AgentEvent(name=EventName.LIFECYCLE_START, agent_id="", run_id="r1")

    def test_run_id_required(self):
        with pytest.raises(ValueError, match="run_id"):
            AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a1", run_id="")

    def test_auto_populated_fields(self):
        ev = AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a1", run_id="r1")
        assert ev.ts_ns > 0
        assert len(ev.event_id) == 32

    def test_security_fields(self):
        verdict = GuardrailVerdict(
            action=GuardrailAction.BLOCK,
            violations=("injection_attack",),
            processing_time_ms=42.0,
            provider="enkrypt",
        )
        ev = AgentEvent(
            name=EventName.GUARDRAIL_BLOCK,
            agent_id="a1",
            run_id="r1",
            guardrail=verdict,
            blocked=True,
            pii_redacted=True,
        )
        assert ev.blocked is True
        assert ev.pii_redacted is True
        assert ev.guardrail is not None
        assert not ev.guardrail.is_safe


class TestGuardrailVerdict:
    def test_is_safe_allow(self):
        v = GuardrailVerdict(action=GuardrailAction.ALLOW)
        assert v.is_safe is True

    def test_is_safe_warn(self):
        v = GuardrailVerdict(action=GuardrailAction.WARN)
        assert v.is_safe is True

    def test_not_safe_block(self):
        v = GuardrailVerdict(action=GuardrailAction.BLOCK)
        assert v.is_safe is False


class TestIDFactories:
    def test_unique(self):
        ids = {new_run_id() for _ in range(100)}
        assert len(ids) == 100

    def test_step_ids_are_hex(self):
        sid = new_step_id()
        assert len(sid) == 32
        int(sid, 16)
