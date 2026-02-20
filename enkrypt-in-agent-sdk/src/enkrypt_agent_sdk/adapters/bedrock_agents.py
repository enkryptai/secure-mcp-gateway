"""Amazon Bedrock Agents adapter — processes runtime trace events from
``bedrock-agent-runtime`` into Enkrypt observability events.
"""

from __future__ import annotations

from typing import Any

from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    new_llm_call_id,
    new_run_id,
    new_step_id,
    new_tool_call_id,
)
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver


class BedrockAgentsAdapter:
    """Adapter for Amazon Bedrock Agents runtime trace events.

    Usage::

        adapter = BedrockAgentsAdapter(observer, guard_engine)
        response = bedrock_client.invoke_agent(...)
        adapter.process_trace(response["trace"])
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "bedrock-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

    def process_trace(self, trace: dict[str, Any], run_id: str | None = None) -> str:
        """Process a Bedrock Agent runtime trace and emit Enkrypt events.

        Returns the run_id used for correlation.
        """
        rid = run_id or new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
        ))

        orchestration_trace = trace.get("orchestrationTrace", {})

        if "modelInvocationInput" in orchestration_trace:
            inv = orchestration_trace["modelInvocationInput"]
            model = inv.get("foundationModel", "bedrock")
            lc_id = new_llm_call_id()
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_START,
                agent_id=self._agent_id, run_id=rid,
                llm_call_id=lc_id, model_name=model,
            ))
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=self._agent_id, run_id=rid,
                llm_call_id=lc_id, model_name=model, ok=True,
            ))

        if "invocationInput" in orchestration_trace:
            inv_input = orchestration_trace["invocationInput"]
            action_group = inv_input.get("actionGroupInvocationInput", {})
            if action_group:
                tool_name = action_group.get("apiPath", action_group.get("function", "unknown"))
                tc_id = new_tool_call_id()
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_START,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name=str(tool_name),
                    attributes={"parameters": str(action_group.get("parameters", []))[:4096]},
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_END,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name=str(tool_name), ok=True,
                ))

            kb_input = inv_input.get("knowledgeBaseLookupInput", {})
            if kb_input:
                tc_id = new_tool_call_id()
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_START,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name="knowledge_base_lookup",
                    attributes={"text": str(kb_input.get("text", ""))[:4096]},
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_END,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name="knowledge_base_lookup", ok=True,
                ))

        if "rationale" in orchestration_trace:
            sid = new_step_id()
            text = orchestration_trace["rationale"].get("text", "")
            self._observer.emit(AgentEvent(
                name=EventName.STEP_START,
                agent_id=self._agent_id, run_id=rid, step_id=sid,
                attributes={"rationale": str(text)[:4096]},
            ))
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=rid, step_id=sid, ok=True,
            ))

        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_END,
            agent_id=self._agent_id, run_id=rid, ok=True,
        ))
        return rid

    def process_traces(self, traces: list[dict[str, Any]], run_id: str | None = None) -> str:
        """Process multiple trace events from a streaming response."""
        rid = run_id or new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
        ))
        for trace in traces:
            orch = trace.get("orchestrationTrace", {})
            if "modelInvocationInput" in orch:
                model = orch["modelInvocationInput"].get("foundationModel", "bedrock")
                lc_id = new_llm_call_id()
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_START,
                    agent_id=self._agent_id, run_id=rid,
                    llm_call_id=lc_id, model_name=model,
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_END,
                    agent_id=self._agent_id, run_id=rid,
                    llm_call_id=lc_id, model_name=model, ok=True,
                ))
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_END,
            agent_id=self._agent_id, run_id=rid, ok=True,
        ))
        return rid
