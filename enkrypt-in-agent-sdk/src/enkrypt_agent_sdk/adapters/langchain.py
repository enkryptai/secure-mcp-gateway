"""LangChain callback adapter — translates LangChain callbacks into AgentEvents.

Works with ``langchain_core.callbacks.BaseCallbackHandler``.  Chain depth is
tracked so we can distinguish top-level chains (lifecycle events) from nested
ones (step events).
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

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
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    BaseCallbackHandler = object  # type: ignore[misc, assignment]


class EnkryptLangChainHandler(BaseCallbackHandler):  # type: ignore[misc]
    """Drop-in LangChain callback handler that emits Enkrypt agent events."""

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "langchain-agent",
    ) -> None:
        super().__init__()
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id

        self._chain_depth = 0
        self._run_id: str | None = None
        self._run_uuid_map: dict[str, str] = {}
        self._step_map: dict[str, str] = {}
        self._tool_map: dict[str, str] = {}
        self._llm_map: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Chain callbacks → lifecycle / step
    # ------------------------------------------------------------------

    def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any],
        *, run_id: UUID, parent_run_id: UUID | None = None, **kwargs: Any,
    ) -> None:
        rid_str = run_id.hex
        if self._chain_depth == 0:
            self._run_id = new_run_id()
            self._run_uuid_map[rid_str] = self._run_id
            self._observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=self._agent_id, run_id=self._run_id,
                attributes={"inputs": str(inputs)[:4096]},
            ))
        else:
            sid = new_step_id()
            self._step_map[rid_str] = sid
            self._observer.emit(AgentEvent(
                name=EventName.STEP_START,
                agent_id=self._agent_id,
                run_id=self._run_id or "",
                step_id=sid,
                attributes={"chain": serialized.get("name", "")},
            ))
        self._chain_depth += 1

    def on_chain_end(
        self, outputs: dict[str, Any], *, run_id: UUID, **kwargs: Any,
    ) -> None:
        self._chain_depth = max(0, self._chain_depth - 1)
        rid_str = run_id.hex

        if rid_str in self._run_uuid_map:
            self._observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_END,
                agent_id=self._agent_id,
                run_id=self._run_uuid_map.pop(rid_str),
                ok=True,
            ))
        elif rid_str in self._step_map:
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id,
                run_id=self._run_id or "",
                step_id=self._step_map.pop(rid_str),
                ok=True,
            ))

    def on_chain_error(
        self, error: BaseException, *, run_id: UUID, **kwargs: Any,
    ) -> None:
        self._chain_depth = max(0, self._chain_depth - 1)
        rid_str = run_id.hex
        run = self._run_uuid_map.pop(rid_str, None) or self._run_id or ""
        step = self._step_map.pop(rid_str, None)

        ev_name = EventName.LIFECYCLE_END if step is None else EventName.STEP_END
        self._observer.emit(AgentEvent(
            name=ev_name,
            agent_id=self._agent_id, run_id=run, step_id=step,
            ok=False, error_type=type(error).__name__, error_message=str(error),
        ))

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str,
        *, run_id: UUID, **kwargs: Any,
    ) -> None:
        tc_id = new_tool_call_id()
        self._tool_map[run_id.hex] = tc_id
        tool_name = serialized.get("name", "unknown")

        # Auto-assign a run_id when the tool is invoked directly (no parent chain)
        current_run = self._run_id or new_run_id()
        if self._run_id is None:
            self._run_id = current_run

        if self._guard and self._guard.has_input_guard and input_str:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    pass
                else:
                    verdict = loop.run_until_complete(
                        self._guard.check_input(input_str, tool_name=tool_name)
                    )
                    if not verdict.is_safe:
                        self._observer.emit(AgentEvent(
                            name=EventName.GUARDRAIL_BLOCK,
                            agent_id=self._agent_id, run_id=current_run,
                            tool_call_id=tc_id, tool_name=tool_name,
                            guardrail=verdict, blocked=True,
                        ))
            except Exception:
                pass

        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_START,
            agent_id=self._agent_id, run_id=current_run,
            tool_call_id=tc_id, tool_name=tool_name,
            attributes={"input": input_str[:4096]},
        ))

    def on_tool_end(self, output: str, *, run_id: UUID, **kwargs: Any) -> None:
        tc_id = self._tool_map.pop(run_id.hex, None)
        if tc_id is None:
            return
        current_run = self._run_id or new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=current_run,
            tool_call_id=tc_id, ok=True,
            attributes={"output": str(output)[:4096]},
        ))

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        tc_id = self._tool_map.pop(run_id.hex, None)
        if tc_id is None:
            return
        current_run = self._run_id or new_run_id()
        self._observer.emit(AgentEvent(
            name=EventName.TOOL_CALL_END,
            agent_id=self._agent_id, run_id=current_run,
            tool_call_id=tc_id, ok=False,
            error_type=type(error).__name__, error_message=str(error),
        ))

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def _ensure_run_id(self) -> str:
        """Auto-assign a run_id when LLM is invoked without a parent chain."""
        if self._run_id is None:
            self._run_id = new_run_id()
        return self._run_id

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: list[str],
        *, run_id: UUID, **kwargs: Any,
    ) -> None:
        lc_id = new_llm_call_id()
        self._llm_map[run_id.hex] = lc_id
        model = serialized.get("kwargs", {}).get("model_name") or serialized.get("name", "unknown")
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=self._agent_id, run_id=self._ensure_run_id(),
            llm_call_id=lc_id, model_name=model,
            attributes={"prompt_count": len(prompts)},
        ))

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        lc_id = self._llm_map.pop(run_id.hex, None)
        if lc_id is None:
            return
        attrs: dict[str, Any] = {}
        if hasattr(response, "llm_output") and response.llm_output:
            usage = response.llm_output.get("token_usage", {})
            if usage:
                attrs["tokens"] = usage
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_END,
            agent_id=self._agent_id, run_id=self._ensure_run_id(),
            llm_call_id=lc_id, ok=True, attributes=attrs,
        ))

    def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        lc_id = self._llm_map.pop(run_id.hex, None)
        if lc_id is None:
            return
        self._observer.emit(AgentEvent(
            name=EventName.LLM_CALL_END,
            agent_id=self._agent_id, run_id=self._ensure_run_id(),
            llm_call_id=lc_id, ok=False,
            error_type=type(error).__name__, error_message=str(error),
        ))
