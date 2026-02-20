"""CrewAI adapter — wraps crew execution with observability and guardrails.

CrewAI doesn't have a formal callback interface, so this adapter provides
explicit methods and a context manager for wrapping ``Crew.kickoff()``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    new_run_id,
    new_step_id,
    new_tool_call_id,
)
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver


class CrewAIAdapter:
    """Adapter for CrewAI framework.

    Usage::

        adapter = CrewAIAdapter(observer, guard_engine)
        with adapter.observe_crew(crew_name="Research Crew") as ctx:
            result = crew.kickoff()
            ctx.set_result(result)
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "crewai-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

    @contextmanager
    def observe_crew(
        self, crew_name: str = "", **attrs: Any,
    ) -> Generator[_CrewContext, None, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"crew_name": crew_name, **attrs},
        ))
        ctx = _CrewContext(self._observer, self._guard, self._agent_id, rid)
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
    async def aobserve_crew(
        self, crew_name: str = "", **attrs: Any,
    ) -> AsyncGenerator[_CrewContext, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"crew_name": crew_name, **attrs},
        ))
        ctx = _CrewContext(self._observer, self._guard, self._agent_id, rid)
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

    def on_task_start(self, task_name: str, run_id: str, **attrs: Any) -> str:
        sid = new_step_id()
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=run_id, step_id=sid,
            attributes={"task_name": task_name, **attrs},
        ))
        return sid

    def on_task_end(self, run_id: str, step_id: str, output: Any = None, **attrs: Any) -> None:
        self._observer.emit(AgentEvent(
            name=EventName.STEP_END,
            agent_id=self._agent_id, run_id=run_id, step_id=step_id,
            ok=True,
            attributes={"output": str(output)[:4096] if output else "", **attrs},
        ))

    def on_tool_use(self, tool_name: str, run_id: str, input_data: Any = None, **attrs: Any) -> str:
        tc_id = new_tool_call_id()
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=run_id,
            tool_call_id=tc_id, tool_name=tool_name,
            attributes={"input": str(input_data)[:4096] if input_data else "", **attrs},
        ))
        return tc_id

    def on_tool_result(self, run_id: str, tool_call_id: str, tool_name: str, result: Any = None, **attrs: Any) -> None:
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=run_id,
            tool_call_id=tool_call_id, tool_name=tool_name, ok=True,
            attributes={"output": str(result)[:4096] if result else "", **attrs},
        ))


class _CrewContext:
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
        self._result_attrs["output"] = str(result)[:4096]
