"""Strands Agents SDK adapter — implements ``HookProvider`` to emit Enkrypt events.

Works with the ``strands-agents`` package (``strands.hooks.HookProvider``).
"""

from __future__ import annotations

from typing import Any

from enkryptai_agent_security.sdk.events import (
    AgentEvent,
    EventName,
    new_llm_call_id,
    new_run_id,
    new_step_id,
    new_tool_call_id,
)
from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.observer import AgentObserver

try:
    from strands.hooks import HookProvider, HookRegistry
    from strands.hooks.events import (
        AfterInvocationEvent,
        AfterModelCallEvent,
        AfterToolCallEvent,
        BeforeInvocationEvent,
        BeforeModelCallEvent,
        BeforeToolCallEvent,
        MessageAddedEvent,
    )
    _STRANDS_AVAILABLE = True
except ImportError:
    _STRANDS_AVAILABLE = False

    class HookProvider:  # type: ignore[no-redef]
        pass

    class HookRegistry:  # type: ignore[no-redef]
        def add_callback(self, *args: Any, **kwargs: Any) -> None:
            pass


class EnkryptStrandsAdapter(HookProvider):  # type: ignore[misc]
    """Implements Strands ``HookProvider`` to emit Enkrypt observability events.

    Pass this as a hook when creating a Strands ``Agent``::

        from strands import Agent
        from enkryptai_agent_security.sdk.adapters.strands import EnkryptStrandsAdapter

        adapter = EnkryptStrandsAdapter(observer, guard_engine)
        agent = Agent(hooks=[adapter])

    Events emitted:

    - ``LIFECYCLE_START`` / ``LIFECYCLE_END`` — on agent invocation start/end
    - ``STEP_START`` / ``STEP_END`` — on model call start/end
    - ``TOOL_CALL_START`` / ``TOOL_CALL_END`` — on tool call start/end
    - ``LLM_CALL_START`` / ``LLM_CALL_END`` — on model call start/end (detailed)
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "strands-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id
        self._run_id = new_run_id()
        self._tool_map: dict[str, str] = {}
        self._llm_call_id: str | None = None
        self._step_id: str | None = None

    def register_hooks(self, registry: Any) -> None:
        """Register all event callbacks with the Strands hook registry."""
        if not _STRANDS_AVAILABLE:
            return
        registry.add_callback(MessageAddedEvent, self._on_message_added)
        registry.add_callback(BeforeInvocationEvent, self._on_before_invocation)
        registry.add_callback(AfterInvocationEvent, self._on_after_invocation)
        registry.add_callback(BeforeModelCallEvent, self._on_before_model_call)
        registry.add_callback(AfterModelCallEvent, self._on_after_model_call)
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_call)
        registry.add_callback(AfterToolCallEvent, self._on_after_tool_call)

    def _on_message_added(self, event: Any) -> None:
        role = getattr(event, "role", "unknown")
        content = getattr(event, "content", "")
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=new_step_id(),
            attributes={"role": str(role), "content": str(content)[:4096], "event": "message_added"},
        ))

    def _on_before_invocation(self, event: Any) -> None:
        self._run_id = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=self._run_id,
            attributes={"event": "before_invocation"},
        ))

    def _on_after_invocation(self, event: Any) -> None:
        ok = not getattr(event, "exception", None)
        error_type = type(getattr(event, "exception", None)).__name__ if not ok else None
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_END,
            agent_id=self._agent_id, run_id=self._run_id,
            ok=ok,
            error_type=error_type if not ok else None,
            attributes={"event": "after_invocation"},
        ))

    def _on_before_model_call(self, event: Any) -> None:
        self._llm_call_id = new_llm_call_id()
        self._step_id = new_step_id()
        model = getattr(event, "model", None) or "unknown"
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            llm_call_id=self._llm_call_id,
            model_name=str(model),
        ))

    def _on_after_model_call(self, event: Any) -> None:
        model = getattr(event, "model", None) or "unknown"
        attrs: dict[str, Any] = {}
        usage = getattr(event, "usage", None)
        if usage:
            attrs["tokens"] = {
                "input": getattr(usage, "input_tokens", 0),
                "output": getattr(usage, "output_tokens", 0),
            }
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_END,
            agent_id=self._agent_id, run_id=self._run_id,
            llm_call_id=self._llm_call_id,
            model_name=str(model), ok=True,
            attributes=attrs,
        ))

    def _on_before_tool_call(self, event: Any) -> None:
        tool = getattr(event, "tool", None)
        tool_name = getattr(tool, "name", str(tool)) if tool else "unknown"
        tool_input = getattr(event, "tool_input", None)
        tc_id = new_tool_call_id()
        self._tool_map[tool_name] = tc_id
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            tool_call_id=tc_id, tool_name=tool_name,
            attributes={"input": str(tool_input)[:4096] if tool_input else ""},
        ))

    def _on_after_tool_call(self, event: Any) -> None:
        tool = getattr(event, "tool", None)
        tool_name = getattr(tool, "name", str(tool)) if tool else "unknown"
        tc_id = self._tool_map.pop(tool_name, None)
        result = getattr(event, "tool_result", None)
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=self._run_id,
            tool_call_id=tc_id, tool_name=tool_name, ok=True,
            attributes={"output": str(result)[:4096] if result else ""},
        ))
