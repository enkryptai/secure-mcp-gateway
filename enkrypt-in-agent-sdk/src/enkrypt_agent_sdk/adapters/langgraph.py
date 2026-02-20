"""LangGraph adapter — extends the LangChain callback handler with graph-aware
node and edge tracking.

Works with LangGraph's ``CompiledGraph`` (``langgraph.graph.CompiledStateGraph``).
Emits step events per graph node and tracks edge transitions.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from enkrypt_agent_sdk.adapters.langchain import EnkryptLangChainHandler
from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    new_run_id,
    new_step_id,
    new_tool_call_id,
)
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver


class EnkryptLangGraphHandler(EnkryptLangChainHandler):
    """LangGraph-specific callback handler that tracks graph nodes and edges.

    Inherits all LangChain callback functionality and adds awareness of
    graph topology (node names, transitions).
    """

    def __init__(
        self,
        observer: AgentObserver,
        guard_engine: GuardEngine | None = None,
        agent_id: str = "langgraph-agent",
    ) -> None:
        super().__init__(observer, guard_engine, agent_id=agent_id)
        self._node_spans: dict[str, str] = {}
        self._current_node: str | None = None
        self._visited_nodes: list[str] = []

    def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any],
        *, run_id: UUID | None = None, parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        if run_id is None:
            run_id = uuid4()

        name = (serialized or {}).get("name", "") or kwargs.get("name", "")

        if self._looks_like_node(name, kwargs):
            if self._run_id is None:
                self._run_id = new_run_id()
            self._current_node = name
            self._visited_nodes.append(name)
            sid = new_step_id()
            self._node_spans[name] = sid
            self._observer.emit(AgentEvent(
                name=EventName.STEP_START,
                agent_id=self._agent_id, run_id=self._run_id,
                step_id=sid,
                attributes={"node_name": name, "graph_position": len(self._visited_nodes)},
            ))
        else:
            super().on_chain_start(serialized, inputs, run_id=run_id, parent_run_id=parent_run_id, **kwargs)

    def on_chain_end(
        self, outputs: dict[str, Any], *, run_id: UUID | None = None, **kwargs: Any,
    ) -> None:
        if run_id is None:
            run_id = uuid4()

        if self._current_node and self._current_node in self._node_spans:
            sid = self._node_spans.pop(self._current_node)
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=self._run_id or "",
                step_id=sid, ok=True,
                attributes={"node_name": self._current_node},
            ))
            self._current_node = None
        else:
            super().on_chain_end(outputs, run_id=run_id, **kwargs)

    def on_chain_error(
        self, error: BaseException, *, run_id: UUID | None = None, **kwargs: Any,
    ) -> None:
        if run_id is None:
            run_id = uuid4()

        if self._current_node and self._current_node in self._node_spans:
            sid = self._node_spans.pop(self._current_node)
            self._observer.emit(AgentEvent(
                name=EventName.STEP_END,
                agent_id=self._agent_id, run_id=self._run_id or "",
                step_id=sid, ok=False,
                error_type=type(error).__name__, error_message=str(error)[:4096],
                attributes={"node_name": self._current_node},
            ))
            self._current_node = None
        else:
            super().on_chain_error(error, run_id=run_id, **kwargs)

    @property
    def visited_nodes(self) -> list[str]:
        return list(self._visited_nodes)

    @staticmethod
    def _looks_like_node(name: str, kwargs: dict) -> bool:
        if not name:
            return False
        tags = kwargs.get("tags", [])
        if any("graph:step" in t or "langgraph:node" in t for t in tags):
            return True
        if name in ("__start__", "__end__"):
            return True
        return ":" not in name and name.replace("_", "").isalnum()
