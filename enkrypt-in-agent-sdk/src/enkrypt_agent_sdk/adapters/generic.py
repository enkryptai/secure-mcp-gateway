"""Generic adapter — nested context managers for manual instrumentation.

Supports both **async** and **sync** context managers::

    # Sync usage (as shown in the architecture document)
    with adapter.run(task="Book a flight") as run_ctx:
        with run_ctx.step(reason="Search") as step_ctx:
            with step_ctx.tool_call("flight_search", input={...}) as tc:
                results = search_flights(...)
                tc.set_output(results)
            with step_ctx.llm_call(model="gpt-4") as llm:
                response = call_llm(...)
                llm.set_output(response)

    # Async usage
    async with adapter.arun(task="...") as run_ctx:
        async with run_ctx.step(reason="Plan") as step_ctx: ...

Guards are checked automatically at tool_call and llm_call boundaries.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    GuardrailAction,
    GuardrailVerdict,
    new_llm_call_id,
    new_run_id,
    new_step_id,
    new_tool_call_id,
)
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver


def _run_coro(coro: Any) -> Any:
    """Run a coroutine from synchronous code, handling event-loop edge cases."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is None:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


# ---------------------------------------------------------------------------
# Leaf contexts
# ---------------------------------------------------------------------------

class _ToolCallContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str, step_id: str | None,
        tool_call_id: str, tool_name: str, input_content: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self._run_id = run_id
        self._step_id = step_id
        self._tool_call_id = tool_call_id
        self._tool_name = tool_name
        self._input = input_content
        self._output_attrs: dict[str, Any] = {}
        self._ok: bool | None = None

    def set_output(self, output: Any, **extra: Any) -> None:
        self._output_attrs = {"output": str(output)[:4096], **extra}
        self._ok = True

    async def _check_output(self, output_text: str) -> GuardrailVerdict | None:
        if self._guard is None or not self._guard.has_output_guard:
            return None
        return await self._guard.check_output(output_text, self._input, tool_name=self._tool_name)


class _LLMCallContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str, step_id: str | None,
        llm_call_id: str, model: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self._run_id = run_id
        self._step_id = step_id
        self._llm_call_id = llm_call_id
        self._model = model
        self._output_attrs: dict[str, Any] = {}
        self._ok: bool | None = None

    def set_output(
        self, output: Any, *, tokens: dict[str, int] | None = None, **extra: Any,
    ) -> None:
        attrs: dict[str, Any] = {"output": str(output)[:4096], **extra}
        if tokens:
            attrs["tokens"] = tokens
        self._output_attrs = attrs
        self._ok = True


# ---------------------------------------------------------------------------
# Step context
# ---------------------------------------------------------------------------

class _StepContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str, step_id: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self._run_id = run_id
        self._step_id = step_id

    # --- async tool_call --------------------------------------------------

    @asynccontextmanager
    async def atool_call(
        self, tool_name: str, *, input: Any = None, **attrs: Any,
    ) -> AsyncGenerator[_ToolCallContext, None]:
        tc_id = new_tool_call_id()
        input_str = str(input) if input is not None else ""

        if self._guard and self._guard.has_input_guard and input_str:
            verdict = await self._guard.check_input(input_str, tool_name=tool_name)
            self._observer.emit(AgentEvent(
                name=EventName.GUARDRAIL_BLOCK if verdict.action == GuardrailAction.BLOCK else EventName.GUARDRAIL_CHECK,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, tool_call_id=tc_id,
                tool_name=tool_name, guardrail=verdict, blocked=not verdict.is_safe,
            ))
            if not verdict.is_safe:
                raise GuardrailBlockedError(
                    f"Input blocked for tool '{tool_name}': {verdict.violations}",
                    violations=[{"type": v} for v in verdict.violations],
                )

        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=self._step_id, tool_call_id=tc_id,
            tool_name=tool_name, attributes={"input": input_str, **attrs},
        ))

        ctx = _ToolCallContext(
            self._observer, self._guard,
            self._agent_id, self._run_id, self._step_id,
            tc_id, tool_name, input_str,
        )
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            ctx._ok = False
            raise
        finally:
            output_verdict: GuardrailVerdict | None = None
            output_text = ctx._output_attrs.get("output", "")
            if ctx._ok and output_text and self._guard and self._guard.has_output_guard:
                try:
                    output_verdict = await ctx._check_output(output_text)
                    if output_verdict and not output_verdict.is_safe:
                        self._observer.emit(AgentEvent(
                            name=EventName.GUARDRAIL_BLOCK,
                            agent_id=self._agent_id, run_id=self._run_id,
                            step_id=self._step_id, tool_call_id=tc_id,
                            tool_name=tool_name, guardrail=output_verdict, blocked=True,
                        ))
                except Exception:
                    pass

            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, tool_call_id=tc_id,
                tool_name=tool_name,
                ok=ctx._ok if error_type is None else False,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._output_attrs,
                guardrail=output_verdict,
            ))

    # --- sync tool_call ---------------------------------------------------

    @contextmanager
    def tool_call(
        self, tool_name: str, *, input: Any = None, **attrs: Any,
    ) -> Generator[_ToolCallContext, None, None]:
        tc_id = new_tool_call_id()
        input_str = str(input) if input is not None else ""

        if self._guard and self._guard.has_input_guard and input_str:
            verdict = _run_coro(self._guard.check_input(input_str, tool_name=tool_name))
            self._observer.emit(AgentEvent(
                name=EventName.GUARDRAIL_BLOCK if verdict.action == GuardrailAction.BLOCK else EventName.GUARDRAIL_CHECK,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, tool_call_id=tc_id,
                tool_name=tool_name, guardrail=verdict, blocked=not verdict.is_safe,
            ))
            if not verdict.is_safe:
                raise GuardrailBlockedError(
                    f"Input blocked for tool '{tool_name}': {verdict.violations}",
                    violations=[{"type": v} for v in verdict.violations],
                )

        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=self._step_id, tool_call_id=tc_id,
            tool_name=tool_name, attributes={"input": input_str, **attrs},
        ))

        ctx = _ToolCallContext(
            self._observer, self._guard,
            self._agent_id, self._run_id, self._step_id,
            tc_id, tool_name, input_str,
        )
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            ctx._ok = False
            raise
        finally:
            output_verdict: GuardrailVerdict | None = None
            output_text = ctx._output_attrs.get("output", "")
            if ctx._ok and output_text and self._guard and self._guard.has_output_guard:
                try:
                    output_verdict = _run_coro(ctx._check_output(output_text))
                    if output_verdict and not output_verdict.is_safe:
                        self._observer.emit(AgentEvent(
                            name=EventName.GUARDRAIL_BLOCK,
                            agent_id=self._agent_id, run_id=self._run_id,
                            step_id=self._step_id, tool_call_id=tc_id,
                            tool_name=tool_name, guardrail=output_verdict, blocked=True,
                        ))
                except Exception:
                    pass

            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, tool_call_id=tc_id,
                tool_name=tool_name,
                ok=ctx._ok if error_type is None else False,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._output_attrs,
                guardrail=output_verdict,
            ))

    # --- async llm_call ---------------------------------------------------

    @asynccontextmanager
    async def allm_call(
        self, model: str = "unknown", **attrs: Any,
    ) -> AsyncGenerator[_LLMCallContext, None]:
        lc_id = new_llm_call_id()
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=self._step_id, llm_call_id=lc_id,
            model_name=model, attributes=attrs,
        ))

        ctx = _LLMCallContext(
            self._observer, self._guard,
            self._agent_id, self._run_id, self._step_id,
            lc_id, model,
        )
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            ctx._ok = False
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, llm_call_id=lc_id,
                model_name=model,
                ok=ctx._ok if error_type is None else False,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._output_attrs,
            ))

    # --- sync llm_call ----------------------------------------------------

    @contextmanager
    def llm_call(
        self, model: str = "unknown", **attrs: Any,
    ) -> Generator[_LLMCallContext, None, None]:
        lc_id = new_llm_call_id()
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=self._step_id, llm_call_id=lc_id,
            model_name=model, attributes=attrs,
        ))

        ctx = _LLMCallContext(
            self._observer, self._guard,
            self._agent_id, self._run_id, self._step_id,
            lc_id, model,
        )
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            ctx._ok = False
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=self._step_id, llm_call_id=lc_id,
                model_name=model,
                ok=ctx._ok if error_type is None else False,
                error_type=error_type, error_message=error_msg,
                attributes=ctx._output_attrs,
            ))


# ---------------------------------------------------------------------------
# Run context
# ---------------------------------------------------------------------------

class _RunContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self.run_id = run_id

    @asynccontextmanager
    async def astep(
        self, reason: str = "", **attrs: Any,
    ) -> AsyncGenerator[_StepContext, None]:
        sid = new_step_id()
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
            attributes={"reason": reason, **attrs},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield _StepContext(self._observer, self._guard, self._agent_id, self.run_id, sid)
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
            ))

    @contextmanager
    def step(
        self, reason: str = "", **attrs: Any,
    ) -> Generator[_StepContext, None, None]:
        sid = new_step_id()
        self._observer.emit(AgentEvent(
            name=EventName.STEP_START,
            agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
            attributes={"reason": reason, **attrs},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield _StepContext(self._observer, self._guard, self._agent_id, self.run_id, sid)
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=self.run_id, step_id=sid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
            ))


# ---------------------------------------------------------------------------
# Top-level adapter
# ---------------------------------------------------------------------------

class GenericAgentAdapter:
    """Framework-agnostic adapter for manual instrumentation.

    Provides both **sync** and **async** context managers that emit events
    and enforce guardrails at every boundary.

    Sync usage (``with``)::

        with adapter.run(task="...") as run:
            with run.step(reason="Plan") as step:
                with step.tool_call("search", input="q") as tc:
                    tc.set_output("result")

    Async usage (``async with``)::

        async with adapter.arun(task="...") as run:
            async with run.astep(reason="Plan") as step:
                async with step.atool_call("search", input="q") as tc:
                    tc.set_output("result")
    """

    def __init__(
        self,
        observer: AgentObserver | None = None,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "generic-agent",
    ) -> None:
        if observer is None:
            from enkrypt_agent_sdk._state import get_observer
            observer = get_observer()
        self._observer = observer  # type: ignore[assignment]
        self._guard = guard_engine
        self._agent_id = agent_id

    # --- async run --------------------------------------------------------

    @asynccontextmanager
    async def arun(
        self, task: str = "", **attrs: Any,
    ) -> AsyncGenerator[_RunContext, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield _RunContext(self._observer, self._guard, self._agent_id, rid)
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
            ))

    # --- sync run ---------------------------------------------------------

    @contextmanager
    def run(
        self, task: str = "", **attrs: Any,
    ) -> Generator[_RunContext, None, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield _RunContext(self._observer, self._guard, self._agent_id, rid)
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
            ))
