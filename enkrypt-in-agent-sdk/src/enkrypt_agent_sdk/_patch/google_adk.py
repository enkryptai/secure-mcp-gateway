"""Auto-patch for Google ADK — wraps ``Runner.run()`` (sync generator) and
``Runner.run_async()`` (async generator) to inject guardrail checks at
pre_llm checkpoints.

``Runner.run()`` is a **synchronous** function that returns
``Generator[Event, None, None]``.  ``Runner.run_async()`` is an
**async-generator** function returning ``AsyncGenerator[Event, None]``.
The patches must preserve these signatures exactly.

Checkpoints:

1. **pre_llm**:  Check user message BEFORE the runner executes.
2. **post_llm**: Not practical for streaming generators — skipped.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import AgentEvent, EventName, new_run_id
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    async_checkpoint,
    sync_checkpoint,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.google_adk")

_installed = False
_orig_run: Any = None
_orig_run_async: Any = None

AGENT_ID = "google-adk-auto"


def _extract_adk_input(args: tuple, kwargs: dict) -> str:
    """Extract user message from Runner.run/run_async kwargs."""
    msg = kwargs.get("new_message", "")
    if not msg and args:
        msg = args[0]
    return str(msg) if msg else ""


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run, _orig_run_async
    if _installed:
        return
    set_on_block(on_block)

    try:
        from google.adk.runners import Runner
    except ImportError:
        return

    _orig_run = getattr(Runner, "run", None)
    _orig_run_async = getattr(Runner, "run_async", None)

    # Runner.run() is synchronous and returns a Generator[Event, None, None].
    if _orig_run is not None:
        def _patched_run(self: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                user_text = _extract_adk_input(args, kwargs)
                if user_text:
                    sync_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)

                return _orig_run(self, *args, **kwargs)
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

        Runner.run = _patched_run  # type: ignore[assignment]

    # Runner.run_async() is an async-generator returning AsyncGenerator[Event].
    if _orig_run_async is not None:
        async def _patched_run_async(self: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                user_text = _extract_adk_input(args, kwargs)
                if user_text:
                    await async_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)

                async for event in _orig_run_async(self, *args, **kwargs):
                    yield event
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

        Runner.run_async = _patched_run_async  # type: ignore[assignment]

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from google.adk.runners import Runner
    except ImportError:
        return
    if _orig_run is not None:
        Runner.run = _orig_run  # type: ignore[assignment]
    if _orig_run_async is not None:
        Runner.run_async = _orig_run_async  # type: ignore[assignment]
    _installed = False
