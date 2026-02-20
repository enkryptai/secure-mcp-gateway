"""Semantic Kernel adapter — implements the filter protocol to emit events
for function invocations and prompt rendering.

Works with Microsoft Semantic Kernel's ``FunctionInvocationFilter``.
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


class EnkryptSKFilter:
    """Semantic Kernel function invocation filter that emits Enkrypt events.

    Usage::

        from semantic_kernel import Kernel
        kernel = Kernel()
        sk_filter = EnkryptSKFilter(observer, guard_engine)
        kernel.add_filter("function_invocation", sk_filter)
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "semantic-kernel-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id
        self._run_id = new_run_id()
        self._invocation_map: dict[str, dict[str, str]] = {}

    async def on_function_invocation(self, context: Any, next_handler: Any) -> None:
        """Filter handler for SK function invocations.

        This is the async filter method that SK calls for each function invocation.
        """
        func_name = ""
        plugin_name = ""
        if hasattr(context, "function"):
            func = context.function
            func_name = getattr(func, "name", "")
            plugin_name = getattr(func, "plugin_name", "")

        full_name = f"{plugin_name}.{func_name}" if plugin_name else func_name
        is_llm = plugin_name in ("ChatCompletion", "TextCompletion", "TextGeneration")

        if is_llm:
            lc_id = new_llm_call_id()
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_START,
                agent_id=self._agent_id, run_id=self._run_id,
                llm_call_id=lc_id, model_name=full_name,
            ))
            try:
                await next_handler(context)
            except Exception as exc:
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_END,
                    agent_id=self._agent_id, run_id=self._run_id,
                    llm_call_id=lc_id, model_name=full_name, ok=False,
                    error_type=type(exc).__name__, error_message=str(exc)[:4096],
                ))
                raise
            else:
                attrs: dict[str, Any] = {}
                if hasattr(context, "result") and context.result:
                    result_val = context.result
                    if hasattr(result_val, "value"):
                        attrs["output"] = str(result_val.value)[:4096]
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_END,
                    agent_id=self._agent_id, run_id=self._run_id,
                    llm_call_id=lc_id, model_name=full_name, ok=True,
                    attributes=attrs,
                ))
        else:
            tc_id = new_tool_call_id()
            input_str = ""
            if hasattr(context, "arguments"):
                input_str = str(context.arguments)[:4096]
            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_START,
                agent_id=self._agent_id, run_id=self._run_id,
                tool_call_id=tc_id, tool_name=full_name,
                attributes={"input": input_str},
            ))
            try:
                await next_handler(context)
            except Exception as exc:
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_END,
                    agent_id=self._agent_id, run_id=self._run_id,
                    tool_call_id=tc_id, tool_name=full_name, ok=False,
                    error_type=type(exc).__name__, error_message=str(exc)[:4096],
                ))
                raise
            else:
                out = ""
                if hasattr(context, "result") and context.result:
                    out = str(context.result.value)[:4096] if hasattr(context.result, "value") else str(context.result)[:4096]
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_END,
                    agent_id=self._agent_id, run_id=self._run_id,
                    tool_call_id=tc_id, tool_name=full_name, ok=True,
                    attributes={"output": out},
                ))
