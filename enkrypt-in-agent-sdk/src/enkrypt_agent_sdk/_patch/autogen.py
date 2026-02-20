"""Auto-patch for AutoGen (``autogen-agentchat`` >= 0.4) — wraps
``BaseChatAgent.run()`` to inject guardrail checks at pre_llm and
post_llm checkpoints, plus emit lifecycle events.

Supports both the **new** ``autogen_agentchat`` API and the legacy
``pyautogen`` (< 0.4) ``ConversableAgent.initiate_chat()`` API.

Checkpoints:

1. **pre_llm**:  Check the task / initial message BEFORE the agent runs.
2. **post_llm**: Check the agent response AFTER execution completes.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import AgentEvent, EventName, new_run_id
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.autogen")

_installed = False
_orig_run: Any = None
_orig_initiate_chat: Any = None
_orig_a_initiate_chat: Any = None
_api_version: str = ""  # "new" or "legacy"

AGENT_ID = "autogen-auto"


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------

def _extract_task_text(args: tuple, kwargs: dict) -> str:
    """Extract the task/message text from run(task=...) or initiate_chat(message=...)."""
    task = kwargs.get("task") or kwargs.get("message", "")
    if not task and args:
        task = args[0]
    if task is None:
        return ""
    if isinstance(task, str):
        return task
    if isinstance(task, list):
        texts = []
        for m in task:
            if isinstance(m, str):
                texts.append(m)
            elif hasattr(m, "content"):
                texts.append(str(m.content))
        return " ".join(texts)
    if hasattr(task, "content"):
        return str(task.content)
    return str(task)


def _extract_task_result(result: Any) -> str:
    """Extract text from an AutoGen TaskResult or legacy ChatResult."""
    if result is None:
        return ""
    if hasattr(result, "messages") and result.messages:
        last = result.messages[-1]
        if hasattr(last, "content"):
            return str(last.content)
        return str(last)
    for attr in ("summary", "content", "chat_history"):
        val = getattr(result, attr, None)
        if val is not None:
            if isinstance(val, str):
                return val
            if isinstance(val, list) and val:
                last = val[-1]
                if isinstance(last, dict):
                    return str(last.get("content", ""))
                return str(last)
    return str(result)


# ---------------------------------------------------------------------------
# Install / Uninstall
# ---------------------------------------------------------------------------

def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run, _orig_initiate_chat, _orig_a_initiate_chat, _api_version
    if _installed:
        return
    set_on_block(on_block)

    # --- Try new autogen_agentchat API first ---
    _base_cls = None
    try:
        from autogen_agentchat.agents._base_chat_agent import BaseChatAgent
        _base_cls = BaseChatAgent
        _api_version = "new"
    except ImportError:
        pass

    if _base_cls is not None:
        _orig_run = _base_cls.run

        async def _patched_run(self: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            agent_name = getattr(self, "name", AGENT_ID)
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
                attributes={"agent_name": agent_name},
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                msg_text = _extract_task_text(args, kwargs)
                if msg_text:
                    await async_checkpoint(guard_engine, "pre_llm", msg_text, AGENT_ID)

                result = await _orig_run(self, *args, **kwargs)

                output_text = _extract_task_result(result)
                if output_text:
                    await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

                return result
            except Exception as exc:
                error_type = type(exc).__name__
                error_msg = str(exc)
                raise
            finally:
                observer.emit(AgentEvent(
                    name=EventName.LIFECYCLE_END,
                    agent_id=AGENT_ID, run_id=rid,
                    ok=error_type is None,
                    error_type=error_type, error_message=error_msg,
                ))

        _base_cls.run = _patched_run  # type: ignore[assignment]
        _installed = True
        return

    # --- Fallback: legacy pyautogen API ---
    try:
        from autogen import ConversableAgent  # type: ignore[import-untyped]
    except ImportError:
        return

    _api_version = "legacy"
    _orig_initiate_chat = ConversableAgent.initiate_chat
    _orig_a_initiate_chat = getattr(ConversableAgent, "a_initiate_chat", None)

    def _extract_chat_message(args: tuple, kwargs: dict) -> str:
        msg = kwargs.get("message", "")
        if not msg and len(args) >= 1:
            msg = args[0]
        return str(msg) if msg else ""

    def _patched_initiate_chat(self: Any, recipient: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            msg_text = _extract_chat_message(args, kwargs)
            if msg_text:
                sync_checkpoint(guard_engine, "pre_llm", msg_text, AGENT_ID)

            result = _orig_initiate_chat(self, recipient, *args, **kwargs)

            output_text = _extract_task_result(result)
            if output_text:
                sync_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

            return result
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_END,
                agent_id=AGENT_ID, run_id=rid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
            ))

    ConversableAgent.initiate_chat = _patched_initiate_chat  # type: ignore[assignment]

    if _orig_a_initiate_chat is not None:
        async def _patched_a_initiate_chat(self: Any, recipient: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                msg_text = _extract_chat_message(args, kwargs)
                if msg_text:
                    await async_checkpoint(guard_engine, "pre_llm", msg_text, AGENT_ID)

                result = await _orig_a_initiate_chat(self, recipient, *args, **kwargs)

                output_text = _extract_task_result(result)
                if output_text:
                    await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

                return result
            except Exception as exc:
                error_type = type(exc).__name__
                error_msg = str(exc)
                raise
            finally:
                observer.emit(AgentEvent(
                    name=EventName.LIFECYCLE_END,
                    agent_id=AGENT_ID, run_id=rid,
                    ok=error_type is None,
                    error_type=error_type, error_message=error_msg,
                ))

        ConversableAgent.a_initiate_chat = _patched_a_initiate_chat  # type: ignore[assignment]

    _installed = True


def uninstall() -> None:
    global _installed, _api_version
    if not _installed:
        return

    if _api_version == "new":
        try:
            from autogen_agentchat.agents._base_chat_agent import BaseChatAgent
            if _orig_run is not None:
                BaseChatAgent.run = _orig_run  # type: ignore[assignment]
        except ImportError:
            pass
    elif _api_version == "legacy":
        try:
            from autogen import ConversableAgent  # type: ignore[import-untyped]
            if _orig_initiate_chat is not None:
                ConversableAgent.initiate_chat = _orig_initiate_chat  # type: ignore[assignment]
            if _orig_a_initiate_chat is not None:
                ConversableAgent.a_initiate_chat = _orig_a_initiate_chat  # type: ignore[assignment]
        except ImportError:
            pass

    _installed = False
    _api_version = ""
