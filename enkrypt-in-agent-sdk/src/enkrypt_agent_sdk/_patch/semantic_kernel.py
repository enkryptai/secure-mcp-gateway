"""Auto-patch for Semantic Kernel — registers ``EnkryptSKFilter`` as a
function invocation filter AND patches ``ChatCompletionClientBase.get_chat_message_contents``
for pre_llm / post_llm checkpoints.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE the chat completion call.
2. **post_llm**: Check assistant response AFTER the call returns.
3. **pre_tool / post_tool**: Handled by the ``EnkryptSKFilter`` around function invocations.

Use ``get_filter()`` to retrieve the filter for manual ``kernel.add_filter()``
registration if auto-detection doesn't work.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    async_checkpoint,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.semantic_kernel")

_installed = False
_filter: Any = None
_orig_get_chat: Any = None

AGENT_ID = "semantic-kernel-auto"


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _filter, _orig_get_chat
    if _installed:
        return
    set_on_block(on_block)

    try:
        import semantic_kernel  # noqa: F401
    except ImportError:
        return

    from enkrypt_agent_sdk.adapters.semantic_kernel import EnkryptSKFilter
    _filter = EnkryptSKFilter(observer, guard_engine)

    # --- Patch ChatCompletionClientBase for pre_llm / post_llm ---
    try:
        from semantic_kernel.connectors.ai.chat_completion_client_base import ChatCompletionClientBase
        _orig_get_chat = ChatCompletionClientBase.get_chat_message_contents

        if _orig_get_chat is not None:
            async def _patched_get_chat(self: Any, *args: Any, **kwargs: Any) -> Any:
                chat_history = kwargs.get("chat_history") or (args[0] if args else None)
                user_text = _extract_sk_user_input(chat_history)
                if user_text:
                    await async_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)

                result = await _orig_get_chat(self, *args, **kwargs)

                if result:
                    response_text = _extract_sk_response(result)
                    if response_text:
                        await async_checkpoint(guard_engine, "post_llm", response_text, AGENT_ID)

                return result

            ChatCompletionClientBase.get_chat_message_contents = _patched_get_chat  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    _installed = True


def uninstall() -> None:
    global _installed, _filter
    if not _installed:
        return

    if _orig_get_chat is not None:
        try:
            from semantic_kernel.connectors.ai.chat_completion_client_base import ChatCompletionClientBase
            ChatCompletionClientBase.get_chat_message_contents = _orig_get_chat  # type: ignore[assignment]
        except (ImportError, AttributeError):
            pass

    _filter = None
    _installed = False


def get_filter() -> Any:
    """Return the filter instance for manual ``kernel.add_filter()`` registration."""
    return _filter


def _extract_sk_user_input(chat_history: Any) -> str:
    """Extract the last user message from a Semantic Kernel ChatHistory."""
    if chat_history is None:
        return ""
    messages = getattr(chat_history, "messages", None)
    if messages is None and isinstance(chat_history, list):
        messages = chat_history
    if messages:
        for msg in reversed(messages):
            role = getattr(msg, "role", None)
            if role is not None:
                role_name = role.name if hasattr(role, "name") else str(role)
                if role_name.lower() == "user":
                    return str(getattr(msg, "content", ""))
    return ""


def _extract_sk_response(result: Any) -> str:
    """Extract text from SK chat completion result list."""
    if isinstance(result, list) and result:
        last = result[-1]
        if hasattr(last, "content"):
            return str(last.content)
        return str(last)
    return ""
