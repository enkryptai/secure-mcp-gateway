"""LlamaIndex adapter — implements the callback handler interface to emit
Enkrypt events for queries, retrievals, and LLM calls.
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
    from llama_index.core.callbacks import CBEventType, CallbackManager
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler
    _LLAMAINDEX_AVAILABLE = True
except ImportError:
    _LLAMAINDEX_AVAILABLE = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.event_starts_to_ignore: list = []
            self.event_ends_to_ignore: list = []


class EnkryptLlamaIndexHandler(BaseCallbackHandler):
    """LlamaIndex callback handler that emits Enkrypt observability events."""

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        *,
        agent_id: str = "llamaindex-agent",
    ) -> None:
        super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
        self._observer = observer
        self._guard = guard_engine
        self._agent_id = agent_id
        self._run_id = new_run_id()
        self._event_map: dict[str, dict[str, Any]] = {}

    def on_event_start(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        payload = payload or {}
        event_name = str(event_type)

        if "QUERY" in event_name:
            sid = new_step_id()
            self._event_map[event_id] = {"type": "query", "step_id": sid}
            self._observer.emit(AgentEvent(
                name=EventName.STEP_START,
                agent_id=self._agent_id, run_id=self._run_id, step_id=sid,
                attributes={"event_type": event_name, "query": str(payload.get("query_str", ""))[:4096]},
            ))

        elif "RETRIEVE" in event_name:
            tc_id = new_tool_call_id()
            self._event_map[event_id] = {"type": "retrieve", "tool_call_id": tc_id}
            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_START,
                agent_id=self._agent_id, run_id=self._run_id,
                tool_call_id=tc_id, tool_name="retriever",
                attributes={"event_type": event_name},
            ))

        elif "LLM" in event_name:
            lc_id = new_llm_call_id()
            model = str(payload.get("model_name", "unknown"))
            self._event_map[event_id] = {"type": "llm", "llm_call_id": lc_id, "model": model}
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_START,
                agent_id=self._agent_id, run_id=self._run_id,
                llm_call_id=lc_id, model_name=model,
                attributes={"event_type": event_name},
            ))

        elif "FUNCTION_CALL" in event_name or "TOOL" in event_name.upper():
            tc_id = new_tool_call_id()
            tool_name = str(payload.get("tool", {}).get("name", "unknown") if isinstance(payload.get("tool"), dict) else payload.get("tool_name", "unknown"))
            self._event_map[event_id] = {"type": "tool", "tool_call_id": tc_id, "tool_name": tool_name}
            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_START,
                agent_id=self._agent_id, run_id=self._run_id,
                tool_call_id=tc_id, tool_name=tool_name,
                attributes={"event_type": event_name},
            ))

        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        info = self._event_map.pop(event_id, None)
        if info is None:
            return

        payload = payload or {}

        if info["type"] == "query":
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=info["step_id"], ok=True,
                attributes={"response": str(payload.get("response", ""))[:4096]},
            ))

        elif info["type"] == "retrieve":
            nodes = payload.get("nodes", [])
            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                tool_call_id=info["tool_call_id"], tool_name="retriever", ok=True,
                attributes={"num_nodes": len(nodes)},
            ))

        elif info["type"] == "llm":
            attrs: dict[str, Any] = {}
            response = payload.get("response", payload.get("completion", ""))
            if response:
                attrs["output"] = str(response)[:4096]
            token_info = payload.get("token_usage", {})
            if token_info:
                attrs["tokens"] = {
                    "input": token_info.get("prompt_tokens", 0),
                    "output": token_info.get("completion_tokens", 0),
                }
            self._observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                llm_call_id=info["llm_call_id"], model_name=info.get("model", "unknown"),
                ok=True, attributes=attrs,
            ))

        elif info["type"] == "tool":
            self._observer.emit(AgentEvent(
                name=EventName.TOOL_CALL_END,
                agent_id=self._agent_id, run_id=self._run_id,
                tool_call_id=info["tool_call_id"],
                tool_name=info.get("tool_name", "unknown"), ok=True,
                attributes={"output": str(payload.get("response", ""))[:4096]},
            ))

    def start_trace(self, trace_id: str | None = None) -> None:
        pass

    def end_trace(
        self, trace_id: str | None = None, trace_map: dict[str, list[str]] | None = None,
    ) -> None:
        pass
