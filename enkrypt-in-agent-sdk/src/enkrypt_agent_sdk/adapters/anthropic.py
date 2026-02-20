"""Anthropic SDK adapter — wraps ``messages.create()`` responses into Enkrypt events.

Provides both a manual adapter (context manager) and utilities for auto-patching.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

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


class AnthropicAdapter:
    """Manual adapter for Anthropic SDK usage.

    Usage::

        adapter = AnthropicAdapter(observer, guard, agent_id="claude-agent")
        async with adapter.agentic_loop(task="Summarize") as loop_ctx:
            # each LLM turn
            async with loop_ctx.llm_turn(model="claude-sonnet-4-20250514") as turn:
                response = await client.messages.create(...)
                turn.set_response(response)
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "anthropic-agent",
    ) -> None:
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

    @asynccontextmanager
    async def agentic_loop(
        self, task: str = "", **attrs: Any,
    ) -> AsyncGenerator[_LoopContext, None]:
        rid = new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=self._agent_id, run_id=rid,
            attributes={"task": task, **attrs},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield _LoopContext(self._observer, self._guard, self._agent_id, rid)
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


class _LoopContext:
    def __init__(
        self, observer: AgentObserver, guard: GuardEngine | None,
        agent_id: str, run_id: str,
    ) -> None:
        self._observer = observer
        self._guard = guard
        self._agent_id = agent_id
        self._run_id = run_id

    @asynccontextmanager
    async def llm_turn(
        self, model: str = "unknown", **attrs: Any,
    ) -> AsyncGenerator[_TurnContext, None]:
        lc_id = new_llm_call_id()
        sid = new_step_id()
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._run_id,
            step_id=sid, llm_call_id=lc_id, model_name=model,
            attributes=attrs,
        ))
        ctx = _TurnContext(self._observer, self._agent_id, self._run_id, sid, lc_id, model)
        error_type: str | None = None
        error_msg: str | None = None
        try:
            yield ctx
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            out_attrs = ctx._output_attrs.copy()
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=sid, llm_call_id=lc_id, model_name=model,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
                attributes=out_attrs,
            ))

            # Emit tool_use blocks as tool events
            for tc in ctx._tool_uses:
                tc_id = new_tool_call_id()
                self._observer.emit(AgentEvent(
                    name=EventName.TOOL_CALL_START,
                    agent_id=self._agent_id, run_id=self._run_id,
                    step_id=sid, tool_call_id=tc_id,
                    tool_name=tc.get("name", ""),
                    attributes={"input": str(tc.get("input", ""))[:4096]},
                ))


class _TurnContext:
    def __init__(
        self, observer: AgentObserver,
        agent_id: str, run_id: str, step_id: str, llm_call_id: str, model: str,
    ) -> None:
        self._observer = observer
        self._agent_id = agent_id
        self._run_id = run_id
        self._step_id = step_id
        self._llm_call_id = llm_call_id
        self._model = model
        self._output_attrs: dict[str, Any] = {}
        self._tool_uses: list[dict[str, Any]] = []

    def set_response(self, response: Any) -> None:
        """Extract metadata from an Anthropic ``Message`` response object."""
        attrs: dict[str, Any] = {}

        if hasattr(response, "usage"):
            usage = response.usage
            attrs["tokens"] = {
                "input": getattr(usage, "input_tokens", 0),
                "output": getattr(usage, "output_tokens", 0),
            }

        if hasattr(response, "stop_reason"):
            attrs["stop_reason"] = response.stop_reason

        if hasattr(response, "content"):
            for block in response.content:
                btype = getattr(block, "type", "")
                if btype == "text":
                    attrs["output"] = getattr(block, "text", "")[:4096]
                elif btype == "tool_use":
                    self._tool_uses.append({
                        "name": getattr(block, "name", ""),
                        "input": getattr(block, "input", {}),
                        "id": getattr(block, "id", ""),
                    })

        self._output_attrs = attrs
