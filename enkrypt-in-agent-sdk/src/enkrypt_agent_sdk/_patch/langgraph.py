"""Auto-patch for LangGraph — patches ``CompiledGraph.invoke`` / ``ainvoke``
to inject guardrail checks at pre_llm and post_llm checkpoints, plus inject
``EnkryptLangGraphHandler`` into the callback chain.

Checkpoints:

1. **pre_llm**:  Check user input (from state messages) BEFORE graph execution.
2. **post_llm**: Check final output AFTER graph execution completes.

Tool-level checkpoints (pre_tool, post_tool) are handled by the LangChain
patch if installed, since LangGraph uses LangChain's BaseTool under the hood.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_user_input,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.langgraph")

_installed = False
_orig_invoke: Any = None
_orig_ainvoke: Any = None

AGENT_ID = "langgraph-auto"


def _extract_graph_input(input: Any) -> str:
    """Extract user text from a LangGraph state dict."""
    if isinstance(input, str):
        return input
    if isinstance(input, dict):
        msgs = input.get("messages", [])
        if msgs:
            return extract_user_input(msgs)
        for key in ("input", "query", "question", "text", "content"):
            if key in input:
                return str(input[key])
    return str(input) if input else ""


def _extract_graph_output(result: Any) -> str:
    """Extract text from a LangGraph result state."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        msgs = result.get("messages", [])
        if msgs:
            last = msgs[-1]
            if hasattr(last, "content"):
                return str(last.content)
            if isinstance(last, dict):
                return str(last.get("content", ""))
        for key in ("output", "result", "response", "answer"):
            if key in result:
                return str(result[key])
    return extract_output(result)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_invoke, _orig_ainvoke
    if _installed:
        return
    set_on_block(on_block)

    try:
        from langgraph.graph.state import CompiledStateGraph
    except ImportError:
        try:
            from langgraph.graph import CompiledGraph as CompiledStateGraph
        except ImportError:
            return

    from enkrypt_agent_sdk.adapters.langgraph import EnkryptLangGraphHandler

    _orig_invoke = CompiledStateGraph.invoke
    _orig_ainvoke = CompiledStateGraph.ainvoke

    def _patched_invoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
        config = _ensure_callback(config, observer, guard_engine)
        user_text = _extract_graph_input(input)
        if user_text:
            sync_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)
        result = _orig_invoke(self, input, config, **kwargs)
        output_text = _extract_graph_output(result)
        if output_text:
            sync_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)
        return result

    async def _patched_ainvoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
        config = _ensure_callback(config, observer, guard_engine)
        user_text = _extract_graph_input(input)
        if user_text:
            await async_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)
        result = await _orig_ainvoke(self, input, config, **kwargs)
        output_text = _extract_graph_output(result)
        if output_text:
            await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)
        return result

    CompiledStateGraph.invoke = _patched_invoke  # type: ignore[assignment]
    CompiledStateGraph.ainvoke = _patched_ainvoke  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from langgraph.graph.state import CompiledStateGraph
    except ImportError:
        try:
            from langgraph.graph import CompiledGraph as CompiledStateGraph
        except ImportError:
            return
    if _orig_invoke is not None:
        CompiledStateGraph.invoke = _orig_invoke  # type: ignore[assignment]
    if _orig_ainvoke is not None:
        CompiledStateGraph.ainvoke = _orig_ainvoke  # type: ignore[assignment]
    _installed = False


def _ensure_callback(
    config: Any, observer: AgentObserver, guard_engine: GuardEngine | None,
) -> dict[str, Any]:
    from enkrypt_agent_sdk.adapters.langgraph import EnkryptLangGraphHandler

    if config is None:
        config = {}
    if isinstance(config, dict):
        callbacks = config.get("callbacks", [])
        if not any(isinstance(cb, EnkryptLangGraphHandler) for cb in callbacks):
            callbacks = [*callbacks, EnkryptLangGraphHandler(observer, guard_engine)]
            config = {**config, "callbacks": callbacks}
    return config
