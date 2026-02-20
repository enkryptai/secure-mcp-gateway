"""OpenAI Agents SDK adapter — implements ``RunHooks`` to emit Enkrypt events.

Works with the ``openai-agents`` package (``agents.run.RunHooks``).
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

try:
    from agents import RunHooks, RunContextWrapper, Agent, Tool
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

    class RunHooks:  # type: ignore[no-redef]
        pass


class EnkryptRunHooks(RunHooks):  # type: ignore[misc]
    """Implements ``RunHooks`` from the OpenAI Agents SDK to emit Enkrypt events."""

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "openai-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id
        self._run_id = new_run_id()
        self._step_map: dict[str, str] = {}
        self._tool_map: dict[str, str] = {}
        self._llm_map: dict[str, str] = {}

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        agent_name = getattr(agent, "name", self._agent_id)
        sid = new_step_id()
        self._step_map[agent_name] = sid
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self._run_id, step_id=sid,
            attributes={"agent_name": agent_name},
        ))

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        agent_name = getattr(agent, "name", self._agent_id)
        sid = self._step_map.pop(agent_name, None)
        self._observer.emit(AgentEvent(
            name=EventName.STEP_END,
            agent_id=self._agent_id, run_id=self._run_id, step_id=sid,
            ok=True,
            attributes={"output": str(output)[:4096]},
        ))

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        tc_id = new_tool_call_id()
        self._tool_map[tool_name] = tc_id
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            tool_call_id=tc_id, tool_name=tool_name,
        ))

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        tc_id = self._tool_map.pop(tool_name, None)
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=self._run_id,
            tool_call_id=tc_id, tool_name=tool_name, ok=True,
            attributes={"output": str(result)[:4096]},
        ))

    async def on_llm_start(
        self, context: Any, agent: Any,
        system_prompt: Any = None, input_items: Any = None,
    ) -> None:
        agent_name = getattr(agent, "name", self._agent_id)
        model = getattr(agent, "model", "unknown") or "unknown"
        lc_id = new_llm_call_id()
        self._llm_map[agent_name] = lc_id
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            llm_call_id=lc_id, model_name=model,
            attributes={"agent_name": agent_name},
        ))

    async def on_llm_end(self, context: Any, agent: Any, response: Any) -> None:
        agent_name = getattr(agent, "name", self._agent_id)
        model = getattr(agent, "model", "unknown") or "unknown"
        lc_id = self._llm_map.pop(agent_name, None)
        attrs: dict[str, Any] = {}
        if hasattr(response, "usage"):
            usage = response.usage
            attrs["tokens"] = {
                "input": getattr(usage, "input_tokens", 0),
                "output": getattr(usage, "output_tokens", 0),
            }
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_END,
            agent_id=self._agent_id, run_id=self._run_id,
            llm_call_id=lc_id, model_name=model, ok=True,
            attributes=attrs,
        ))

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        from_name = getattr(from_agent, "name", str(from_agent))
        to_name = getattr(to_agent, "name", str(to_agent))
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=new_step_id(),
            attributes={"handoff_from": from_name, "handoff_to": to_name},
        ))
