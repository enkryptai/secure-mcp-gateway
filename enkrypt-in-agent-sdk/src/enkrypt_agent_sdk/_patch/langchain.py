"""Auto-patch for LangChain -- monkey-patches ``Runnable.invoke`` / ``ainvoke``
AND ``BaseTool.invoke`` / ``ainvoke`` to inject guardrail checks at multiple
checkpoints in the pipeline.

Four configurable checkpoints (controlled by ``GuardEngine.check_*`` flags):

1. **pre_llm**:   Check user input BEFORE it reaches the LLM.
2. **pre_tool**:  Check tool input BEFORE the tool executes.
3. **post_tool**: Check tool output AFTER the tool executes.
4. **post_llm**:  Check LLM response BEFORE it reaches the user.

When a check fails, ``GuardrailBlockedError`` is raised and the operation
is halted at that checkpoint.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_user_input as _extract_user_input,
    extract_text as _extract_input_text,
    default_on_block,
    set_on_block,
    extract_output as _extract_llm_response_text,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.langchain")

_installed = False
_originals: dict[str, Any] = {}


def _extract_llm_response(result: Any) -> str:
    """Extract text content from an LLM response."""
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed
    if _installed:
        return
    set_on_block(on_block)

    try:
        from langchain_core.runnables import Runnable
    except ImportError:
        return

    from enkrypt_agent_sdk.adapters.langchain import EnkryptLangChainHandler

    _originals["Runnable.invoke"] = Runnable.invoke
    _originals["Runnable.ainvoke"] = Runnable.ainvoke

    def _patched_runnable_invoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
        config = _ensure_callback(config, observer, guard_engine, self)
        return _originals["Runnable.invoke"](self, input, config, **kwargs)

    async def _patched_runnable_ainvoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
        config = _ensure_callback(config, observer, guard_engine, self)
        return await _originals["Runnable.ainvoke"](self, input, config, **kwargs)

    Runnable.invoke = _patched_runnable_invoke  # type: ignore[assignment]
    Runnable.ainvoke = _patched_runnable_ainvoke  # type: ignore[assignment]

    # --- Patch RunnableBindingBase (wraps LLM after .bind_tools()) ---
    try:
        from langchain_core.runnables.base import RunnableBindingBase

        _originals["Binding.invoke"] = RunnableBindingBase.invoke
        _originals["Binding.ainvoke"] = RunnableBindingBase.ainvoke

        def _patched_binding_invoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
            config = _ensure_callback(config, observer, guard_engine, self)
            if guard_engine and _is_llm(self):
                log.debug("[pre_llm] Detected LLM binding: %s -> %s",
                          type(self).__name__, type(getattr(self, "bound", None)).__name__)
                sync_checkpoint(guard_engine, "pre_llm", input, "__user_input__")
                result = _originals["Binding.invoke"](self, input, config, **kwargs)
                sync_checkpoint(guard_engine, "post_llm", _extract_llm_response(result), "__llm_output__")
                return result
            return _originals["Binding.invoke"](self, input, config, **kwargs)

        async def _patched_binding_ainvoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
            config = _ensure_callback(config, observer, guard_engine, self)
            if guard_engine and _is_llm(self):
                await async_checkpoint(guard_engine, "pre_llm", input, "__user_input__")
                result = await _originals["Binding.ainvoke"](self, input, config, **kwargs)
                await async_checkpoint(guard_engine, "post_llm", _extract_llm_response(result), "__llm_output__")
                return result
            return await _originals["Binding.ainvoke"](self, input, config, **kwargs)

        RunnableBindingBase.invoke = _patched_binding_invoke  # type: ignore[assignment]
        RunnableBindingBase.ainvoke = _patched_binding_ainvoke  # type: ignore[assignment]
    except ImportError:
        pass

    # --- Patch BaseTool ---
    try:
        from langchain_core.tools import BaseTool

        _originals["Tool.invoke"] = BaseTool.invoke
        _originals["Tool.ainvoke"] = BaseTool.ainvoke

        def _patched_tool_invoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
            config = _ensure_callback(config, observer, guard_engine, self)
            sync_checkpoint(guard_engine, "pre_tool", input, _get_tool_name(self))
            result = _originals["Tool.invoke"](self, input, config, **kwargs)
            sync_checkpoint(guard_engine, "post_tool", result, _get_tool_name(self))
            return result

        async def _patched_tool_ainvoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:
            config = _ensure_callback(config, observer, guard_engine, self)
            await async_checkpoint(guard_engine, "pre_tool", input, _get_tool_name(self))
            result = await _originals["Tool.ainvoke"](self, input, config, **kwargs)
            await async_checkpoint(guard_engine, "post_tool", result, _get_tool_name(self))
            return result

        BaseTool.invoke = _patched_tool_invoke  # type: ignore[assignment]
        BaseTool.ainvoke = _patched_tool_ainvoke  # type: ignore[assignment]
    except ImportError:
        pass

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return

    try:
        from langchain_core.runnables import Runnable
        if "Runnable.invoke" in _originals:
            Runnable.invoke = _originals["Runnable.invoke"]  # type: ignore[assignment]
        if "Runnable.ainvoke" in _originals:
            Runnable.ainvoke = _originals["Runnable.ainvoke"]  # type: ignore[assignment]
    except ImportError:
        pass

    try:
        from langchain_core.runnables.base import RunnableBindingBase
        if "Binding.invoke" in _originals:
            RunnableBindingBase.invoke = _originals["Binding.invoke"]  # type: ignore[assignment]
        if "Binding.ainvoke" in _originals:
            RunnableBindingBase.ainvoke = _originals["Binding.ainvoke"]  # type: ignore[assignment]
    except ImportError:
        pass

    try:
        from langchain_core.tools import BaseTool
        if "Tool.invoke" in _originals:
            BaseTool.invoke = _originals["Tool.invoke"]  # type: ignore[assignment]
        if "Tool.ainvoke" in _originals:
            BaseTool.ainvoke = _originals["Tool.ainvoke"]  # type: ignore[assignment]
    except ImportError:
        pass

    _originals.clear()
    _installed = False


# ---------------------------------------------------------------------------
# LLM detection
# ---------------------------------------------------------------------------

def _is_llm(runnable: Any) -> bool:
    """Detect if a Runnable is an LLM / ChatModel (including bound variants)."""
    cls_name = type(runnable).__name__

    llm_keywords = ("ChatModel", "ChatOpenAI", "ChatAnthropic", "ChatGoogle",
                     "LLM", "BaseChatModel", "BaseLanguageModel")
    if any(kw in cls_name for kw in llm_keywords):
        return True

    if cls_name == "RunnableBinding":
        bound = getattr(runnable, "bound", None)
        if bound is not None:
            return _is_llm(bound)

    try:
        from langchain_core.language_models import BaseLanguageModel
        return isinstance(runnable, BaseLanguageModel)
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_tool_name(runnable: Any) -> str:
    return getattr(runnable, "name", None) or type(runnable).__name__


def _ensure_callback(
    config: Any,
    observer: AgentObserver,
    guard_engine: GuardEngine | None,
    runnable: Any,
) -> dict[str, Any]:
    from enkrypt_agent_sdk.adapters.langchain import EnkryptLangChainHandler

    if config is None:
        config = {}
    if isinstance(config, dict):
        callbacks = config.get("callbacks", [])
        if not any(isinstance(cb, EnkryptLangChainHandler) for cb in callbacks):
            agent_id = getattr(runnable, "name", None) or type(runnable).__name__
            callbacks = [*callbacks, EnkryptLangChainHandler(observer, guard_engine, agent_id=agent_id)]
            config = {**config, "callbacks": callbacks}
    return config
