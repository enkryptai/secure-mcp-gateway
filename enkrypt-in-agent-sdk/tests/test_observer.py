"""Tests for the AgentObserver."""

from enkrypt_agent_sdk.events import AgentEvent, EventName, GuardrailAction, GuardrailVerdict
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpMeter, _NoOpTracer


def _make_observer() -> AgentObserver:
    return AgentObserver(_NoOpTracer(), _NoOpMeter())


class TestObserverSpanTracking:
    def test_lifecycle(self):
        obs = _make_observer()
        obs.emit(AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a", run_id="r1"))
        assert obs.open_span_count == 1

        obs.emit(AgentEvent(name=EventName.LIFECYCLE_END, agent_id="a", run_id="r1", ok=True))
        assert obs.open_span_count == 0

    def test_step(self):
        obs = _make_observer()
        obs.emit(AgentEvent(name=EventName.STEP_START, agent_id="a", run_id="r1", step_id="s1"))
        assert obs.open_span_count == 1

        obs.emit(AgentEvent(name=EventName.STEP_END, agent_id="a", run_id="r1", step_id="s1", ok=True))
        assert obs.open_span_count == 0

    def test_tool_call(self):
        obs = _make_observer()
        obs.emit(AgentEvent(
            name=EventName.TOOL_CALL_START, agent_id="a", run_id="r1",
            tool_call_id="tc1", tool_name="search",
        ))
        assert obs.open_span_count == 1

        obs.emit(AgentEvent(
            name=EventName.TOOL_CALL_END, agent_id="a", run_id="r1",
            tool_call_id="tc1", ok=True,
        ))
        assert obs.open_span_count == 0

    def test_llm_call(self):
        obs = _make_observer()
        obs.emit(AgentEvent(
            name=EventName.LLM_CALL_START, agent_id="a", run_id="r1",
            llm_call_id="lc1", model_name="gpt-4",
        ))
        assert obs.open_span_count == 1

        obs.emit(AgentEvent(
            name=EventName.LLM_CALL_END, agent_id="a", run_id="r1",
            llm_call_id="lc1", ok=True,
        ))
        assert obs.open_span_count == 0

    def test_nested_spans(self):
        obs = _make_observer()
        obs.emit(AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a", run_id="r1"))
        obs.emit(AgentEvent(name=EventName.STEP_START, agent_id="a", run_id="r1", step_id="s1"))
        obs.emit(AgentEvent(
            name=EventName.TOOL_CALL_START, agent_id="a", run_id="r1",
            step_id="s1", tool_call_id="tc1",
        ))
        assert obs.open_span_count == 3

        obs.emit(AgentEvent(
            name=EventName.TOOL_CALL_END, agent_id="a", run_id="r1",
            step_id="s1", tool_call_id="tc1", ok=True,
        ))
        assert obs.open_span_count == 2

    def test_guardrail_event(self):
        obs = _make_observer()
        obs.emit(AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a", run_id="r1"))
        verdict = GuardrailVerdict(
            action=GuardrailAction.BLOCK,
            violations=("injection_attack",),
            processing_time_ms=5.0,
            provider="enkrypt",
        )
        obs.emit(AgentEvent(
            name=EventName.GUARDRAIL_BLOCK, agent_id="a", run_id="r1",
            guardrail=verdict, blocked=True,
        ))
        # guardrail events don't create new spans, just annotate existing ones
        assert obs.open_span_count == 1

    def test_error_event(self):
        obs = _make_observer()
        obs.emit(AgentEvent(name=EventName.LIFECYCLE_START, agent_id="a", run_id="r1"))
        obs.emit(AgentEvent(
            name=EventName.ERROR, agent_id="a", run_id="r1",
            error_type="ValueError", error_message="bad input",
        ))
        assert obs.open_span_count == 1
