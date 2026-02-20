"""PydanticAI adapter — context managers for ``Agent.run()`` and post-hoc
instrumentation from ``RunResult.all_messages()``.
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


class PydanticAIAdapter:
    """Adapter for the PydanticAI framework.

    Usage::

        adapter = PydanticAIAdapter(observer, guard_engine)
        with adapter.observe_run(task="Summarize") as ctx:
            result = await agent.run("Summarize this...")
            ctx.set_result(result)

        # Or post-hoc from result messages:
        adapter.replay_messages(result.all_messages())
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "pydantic-ai-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

    @contextmanager
    def observe_run(
        self, task: str = "", **attrs: Any,
    ) -> Generator[_PydanticRunContext, None, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        ctx = _PydanticRunContext(self._observer, self._guard, self._agent_id, rid)
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
    async def aobserve_run(
        self, task: str = "", **attrs: Any,
    ) -> AsyncGenerator[_PydanticRunContext, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        ctx = _PydanticRunContext(self._observer, self._guard, self._agent_id, rid)
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

    def replay_messages(self, messages: list[Any], run_id: str | None = None) -> None:
        """Post-hoc instrumentation from ``RunResult.all_messages()``."""
        rid = run_id or new_run_id()
        for msg in messages:
            kind = getattr(msg, "kind", "") or getattr(msg, "role", "")
            if kind in ("request", "system-prompt"):
                continue
            elif kind in ("model-text-response", "response"):
                lc_id = new_llm_call_id()
                text = ""
                model = getattr(msg, "model_name", "unknown")
                if hasattr(msg, "parts"):
                    for part in msg.parts:
                        if hasattr(part, "content"):
                            text = str(part.content)[:4096]
                            break
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_START,
                    agent_id=self._agent_id, run_id=rid, llm_call_id=lc_id,
                    model_name=model,
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_END,
                    agent_id=self._agent_id, run_id=rid, llm_call_id=lc_id,
                    model_name=model, ok=True,
                    attributes={"output": text},
                ))
            elif kind in ("model-structured-response",):
                lc_id = new_llm_call_id()
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_START,
                    agent_id=self._agent_id, run_id=rid, llm_call_id=lc_id,
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.LLM_CALL_END,
                    agent_id=self._agent_id, run_id=rid, llm_call_id=lc_id,
                    ok=True,
                ))
            elif kind in ("tool-return", "tool-call"):
                tc_id = new_tool_call_id()
                tool_name = getattr(msg, "tool_name", "") or ""
                content = getattr(msg, "content", "")
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_START,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name=tool_name,
                ))
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_END,
                    agent_id=self._agent_id, run_id=rid,
                    tool_call_id=tc_id, tool_name=tool_name, ok=True,
                    attributes={"output": str(content)[:4096]},
                ))


class _PydanticRunContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self.run_id = run_id
        self._result_attrs: dict[str, Any] = {}

    def set_result(self, result: Any) -> None:
        output = ""
        if hasattr(result, "data"):
            output = str(result.data)[:4096]
        elif hasattr(result, "output"):
            output = str(result.output)[:4096]
        else:
            output = str(result)[:4096]
        self._result_attrs["output"] = output

        if hasattr(result, "all_messages"):
            try:
                self._result_attrs["message_count"] = len(result.all_messages())
            except Exception:
                pass
