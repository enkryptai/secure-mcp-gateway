"""Auto-patch for the Anthropic SDK — wraps ``Messages.create`` and
``AsyncMessages.create`` to inject guardrail checks at pre_llm and post_llm
checkpoints, plus emit LLM call lifecycle events.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE the API call (from ``messages`` kwarg).
2. **post_llm**: Check the assistant response AFTER the API returns.

When a check fails, ``GuardrailBlockedError`` is raised and the API call
is either never made (pre_llm) or the response is blocked (post_llm).
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import (
    AgentEvent,
    EventName,
    new_llm_call_id,
    new_run_id,
)
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.anthropic")

_installed = False
_orig_create: Any = None
_orig_async_create: Any = None


def _extract_user_text_from_messages(kwargs: dict) -> str:
    """Extract text of the last user message from Anthropic's messages kwarg."""
    messages = kwargs.get("messages", [])
    for msg in reversed(messages):
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts = [b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text"]
                return " ".join(parts)
    return ""


def _extract_response_text(result: Any) -> str:
    """Extract text from an Anthropic Message response."""
    if result is None:
        return ""
    content_blocks = getattr(result, "content", None)
    if isinstance(content_blocks, list):
        parts = []
        for block in content_blocks:
            if hasattr(block, "text"):
                parts.append(block.text)
        return " ".join(parts)
    return str(result)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_create, _orig_async_create
    if _installed:
        return
    set_on_block(on_block)

    try:
        from anthropic.resources import Messages, AsyncMessages
    except ImportError:
        return

    _orig_create = Messages.create
    _orig_async_create = AsyncMessages.create

    agent_id = "anthropic-auto"

    def _patched_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        run_id = new_run_id()
        lc_id = new_llm_call_id()
        model = kwargs.get("model", "unknown")

        # pre_llm checkpoint
        user_text = _extract_user_text_from_messages(kwargs)
        if user_text:
            sync_checkpoint(guard_engine, "pre_llm", user_text, agent_id)

        observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=agent_id, run_id=run_id, llm_call_id=lc_id,
            model_name=model,
        ))
        error_type: str | None = None
        error_msg: str | None = None
        result = None
        try:
            result = _orig_create(self, *args, **kwargs)

            # post_llm checkpoint
            response_text = _extract_response_text(result)
            if response_text:
                sync_checkpoint(guard_engine, "post_llm", response_text, agent_id)

            return result
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            attrs: dict[str, Any] = {}
            if result is not None and hasattr(result, "usage"):
                attrs["tokens"] = {
                    "input": getattr(result.usage, "input_tokens", 0),
                    "output": getattr(result.usage, "output_tokens", 0),
                }
            observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=agent_id, run_id=run_id, llm_call_id=lc_id,
                model_name=model, ok=error_type is None,
                error_type=error_type, error_message=error_msg,
                attributes=attrs,
            ))

    async def _patched_async_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        run_id = new_run_id()
        lc_id = new_llm_call_id()
        model = kwargs.get("model", "unknown")

        # pre_llm checkpoint
        user_text = _extract_user_text_from_messages(kwargs)
        if user_text:
            await async_checkpoint(guard_engine, "pre_llm", user_text, agent_id)

        observer.emit(AgentEvent(
            name=EventName.LLM_CALL_START,
            agent_id=agent_id, run_id=run_id, llm_call_id=lc_id,
            model_name=model,
        ))
        error_type: str | None = None
        error_msg: str | None = None
        result = None
        try:
            result = await _orig_async_create(self, *args, **kwargs)

            # post_llm checkpoint
            response_text = _extract_response_text(result)
            if response_text:
                await async_checkpoint(guard_engine, "post_llm", response_text, agent_id)

            return result
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            attrs: dict[str, Any] = {}
            if result is not None and hasattr(result, "usage"):
                attrs["tokens"] = {
                    "input": getattr(result.usage, "input_tokens", 0),
                    "output": getattr(result.usage, "output_tokens", 0),
                }
            observer.emit(AgentEvent(
                name=EventName.LLM_CALL_END,
                agent_id=agent_id, run_id=run_id, llm_call_id=lc_id,
                model_name=model, ok=error_type is None,
                error_type=error_type, error_message=error_msg,
                attributes=attrs,
            ))

    Messages.create = _patched_create  # type: ignore[assignment]
    AsyncMessages.create = _patched_async_create  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from anthropic.resources import Messages, AsyncMessages
    except ImportError:
        return
    if _orig_create is not None:
        Messages.create = _orig_create  # type: ignore[assignment]
    if _orig_async_create is not None:
        AsyncMessages.create = _orig_async_create  # type: ignore[assignment]
    _installed = False
