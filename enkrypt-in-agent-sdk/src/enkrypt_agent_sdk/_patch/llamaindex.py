"""Auto-patch for LlamaIndex — injects ``EnkryptLlamaIndexHandler`` into the
global callback manager AND patches ``BaseTool.call()`` for pre_tool / post_tool
checkpoints and ``FunctionCallingAgent.chat()`` for pre_llm / post_llm.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE the agent chat executes.
2. **pre_tool**: Check tool input BEFORE the tool executes.
3. **post_tool**: Check tool output AFTER the tool executes.
4. **post_llm**: Check agent response AFTER execution completes.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.llamaindex")

_installed = False
_handler: Any = None
_orig_tool_call: Any = None
_orig_agent_chat: Any = None
_orig_agent_achat: Any = None

AGENT_ID = "llamaindex-auto"


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _handler, _orig_tool_call, _orig_agent_chat, _orig_agent_achat
    if _installed:
        return
    set_on_block(on_block)

    try:
        from llama_index.core import Settings
        from llama_index.core.callbacks import CallbackManager
    except ImportError:
        return

    from enkrypt_agent_sdk.adapters.llamaindex import EnkryptLlamaIndexHandler

    _handler = EnkryptLlamaIndexHandler(observer, guard_engine)

    if Settings.callback_manager is None:
        Settings.callback_manager = CallbackManager([_handler])
    else:
        Settings.callback_manager.add_handler(_handler)

    # --- Patch BaseTool.call for pre_tool / post_tool ---
    try:
        from llama_index.core.tools import BaseTool as LIBaseTool

        _orig_tool_call = LIBaseTool.call
        if _orig_tool_call is not None:
            def _patched_tool_call(self: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self, "metadata", None)
                if tool_name and hasattr(tool_name, "name"):
                    tool_name = tool_name.name
                else:
                    tool_name = getattr(self, "name", None) or type(self).__name__
                tool_input = str(args[0]) if args else str(kwargs)
                sync_checkpoint(guard_engine, "pre_tool", tool_input, tool_name)
                result = _orig_tool_call(self, *args, **kwargs)
                result_str = str(result)
                sync_checkpoint(guard_engine, "post_tool", result_str, tool_name)
                return result

            LIBaseTool.call = _patched_tool_call  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    # --- Patch FunctionCallingAgent / ReActAgent for pre_llm / post_llm ---
    _patch_agent_chat(guard_engine)

    _installed = True


def _patch_agent_chat(guard_engine: GuardEngine | None) -> None:
    global _orig_agent_chat, _orig_agent_achat

    agent_cls = None
    try:
        from llama_index.core.agent import AgentRunner
        agent_cls = AgentRunner
    except ImportError:
        pass

    if agent_cls is None:
        return

    _orig_agent_chat = getattr(agent_cls, "chat", None)
    _orig_agent_achat = getattr(agent_cls, "achat", None)

    if _orig_agent_chat is not None:
        def _patched_chat(self: Any, message: str, *args: Any, **kwargs: Any) -> Any:
            sync_checkpoint(guard_engine, "pre_llm", message, AGENT_ID)
            result = _orig_agent_chat(self, message, *args, **kwargs)
            output_text = extract_output(result)
            if output_text:
                sync_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)
            return result

        agent_cls.chat = _patched_chat  # type: ignore[assignment]

    if _orig_agent_achat is not None:
        async def _patched_achat(self: Any, message: str, *args: Any, **kwargs: Any) -> Any:
            await async_checkpoint(guard_engine, "pre_llm", message, AGENT_ID)
            result = await _orig_agent_achat(self, message, *args, **kwargs)
            output_text = extract_output(result)
            if output_text:
                await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)
            return result

        agent_cls.achat = _patched_achat  # type: ignore[assignment]


def uninstall() -> None:
    global _installed, _handler
    if not _installed:
        return
    try:
        from llama_index.core import Settings
    except ImportError:
        return
    if _handler is not None and Settings.callback_manager is not None:
        try:
            Settings.callback_manager.remove_handler(_handler)
        except (ValueError, AttributeError):
            pass

    try:
        from llama_index.core.tools import BaseTool as LIBaseTool
        if _orig_tool_call is not None:
            LIBaseTool.call = _orig_tool_call  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    try:
        from llama_index.core.agent import AgentRunner
        if _orig_agent_chat is not None:
            AgentRunner.chat = _orig_agent_chat  # type: ignore[assignment]
        if _orig_agent_achat is not None:
            AgentRunner.achat = _orig_agent_achat  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    _handler = None
    _installed = False
