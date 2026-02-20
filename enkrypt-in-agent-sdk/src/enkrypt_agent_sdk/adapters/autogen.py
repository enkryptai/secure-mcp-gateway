"""AutoGen adapter — context managers for multi-agent conversations.

Works with Microsoft AutoGen's ``ConversableAgent`` and ``GroupChat``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

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


class AutoGenAdapter:
    """Adapter for Microsoft AutoGen framework.

    Usage::

        adapter = AutoGenAdapter(observer, guard_engine)
        with adapter.observe_chat(task="Code review") as ctx:
            result = user_proxy.initiate_chat(assistant, message="Review this code")
            ctx.set_result(result)
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "autogen-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

    @contextmanager
    def observe_chat(
        self, task: str = "", **attrs: Any,
    ) -> Generator[_ChatContext, None, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        ctx = _ChatContext(self._observer, self._guard, self._agent_id, rid)
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_END,
                agent_id=self._agent_id, run_id=rid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._result_attrs,
            ))

    @asynccontextmanager
    async def aobserve_chat(
        self, task: str = "", **attrs: Any,
    ) -> AsyncGenerator[_ChatContext, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        ctx = _ChatContext(self._observer, self._guard, self._agent_id, rid)
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_END,
                agent_id=self._agent_id, run_id=rid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._result_attrs,
            ))


class _ChatContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self.run_id = run_id
        self._result_attrs: dict[str, Any] = {}
        self._turn_count = 0

    def record_turn(
        self, sender: str, recipient: str, message: str, **attrs: Any,
    ) -> None:
        self._turn_count += 1
        sid = new_step_id()
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
            attributes={
                "sender": sender, "recipient": recipient,
                "turn": self._turn_count, **attrs,
            },
        ))
        self._observer.emit(AgentEvent(
            name=EventName.STEP_END,
            agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
            ok=True,
            attributes={"message": message[:4096]},
        ))

    def record_tool_call(
        self, tool_name: str, input_data: Any = None, output_data: Any = None,
    ) -> None:
        tc_id = new_tool_call_id()
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=self.run_id,
            tool_call_id=tc_id, tool_name=tool_name,
            attributes={"input": str(input_data)[:4096] if input_data else ""},
        ))
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=self.run_id,
            tool_call_id=tc_id, tool_name=tool_name, ok=True,
            attributes={"output": str(output_data)[:4096] if output_data else ""},
        ))

    def record_llm_call(
        self, model: str = "unknown", input_tokens: int = 0, output_tokens: int = 0,
    ) -> None:
        lc_id = new_llm_call_id()
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self.run_id,
            llm_call_id=lc_id, model_name=model,
        ))
        attrs: dict[str, Any] = {}
        if input_tokens or output_tokens:
            attrs["tokens"] = {"input": input_tokens, "output": output_tokens}
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_END,
            agent_id=self._agent_id, run_id=self.run_id,
            llm_call_id=lc_id, model_name=model, ok=True,
            attributes=attrs,
        ))

    def set_result(self, result: Any) -> None:
        self._result_attrs["output"] = str(result)[:4096]
        self._result_attrs["total_turns"] = self._turn_count
