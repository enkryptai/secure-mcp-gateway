"""Auto-patch for PydanticAI — wraps ``Agent.run()`` and ``Agent.run_sync()``
to inject guardrail checks at pre_llm and post_llm checkpoints, plus emit
lifecycle events.

Checkpoints:

1. **pre_llm**:  Check user prompt BEFORE the agent runs.
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

log = logging.getLogger("enkrypt_agent_sdk.patch.pydantic_ai")

_installed = False
_orig_run: Any = None
_orig_run_sync: Any = None

AGENT_ID = "pydantic-ai-auto"


def _extract_prompt(args: tuple, kwargs: dict) -> str:
    """Extract user prompt from Agent.run(prompt, ...) or Agent.run(user_prompt=...)."""
    prompt = kwargs.get("user_prompt", "")
    if not prompt and args:
        prompt = args[0]
    return str(prompt) if prompt else ""


def _extract_result_text(result: Any) -> str:
    """Extract text from a PydanticAI RunResult."""
    for attr in ("data", "output", "content", "text"):
        val = getattr(result, attr, None)
        if val is not None:
            return str(val)
    return str(result)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run, _orig_run_sync
    if _installed:
        return
    set_on_block(on_block)

    try:
        from pydantic_ai import Agent
    except ImportError:
        return

    _orig_run = Agent.run
    _orig_run_sync = getattr(Agent, "run_sync", None)

    async def _patched_run(self: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        agent_name = getattr(self, "name", "") or "pydantic-ai"
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
            attributes={"agent_name": agent_name},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            prompt = _extract_prompt(args, kwargs)
            if prompt:
                await async_checkpoint(guard_engine, "pre_llm", prompt, AGENT_ID)

            result = await _orig_run(self, *args, **kwargs)

            output_text = _extract_result_text(result)
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

    Agent.run = _patched_run  # type: ignore[assignment]
    # run_sync delegates to run internally, so patching run covers both paths
    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from pydantic_ai import Agent
    except ImportError:
        return
    if _orig_run is not None:
        Agent.run = _orig_run  # type: ignore[assignment]
    if _orig_run_sync is not None:
        Agent.run_sync = _orig_run_sync  # type: ignore[assignment]
    _installed = False
