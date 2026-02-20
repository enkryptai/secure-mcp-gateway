"""Auto-patch for the OpenAI Agents SDK — wraps ``Runner.run()`` to inject
guardrail checks at pre_llm and post_llm checkpoints, plus inject
``EnkryptRunHooks`` for lifecycle events.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE ``Runner.run()`` executes.
2. **post_llm**: Check the agent output AFTER ``Runner.run()`` completes.

``Runner.run`` is a ``@classmethod``, so the patch must save/restore the raw
descriptor (via ``inspect.getattr_static``) to avoid losing the classmethod
wrapper on uninstall.

Note: Only ``Runner.run`` (async) is patched.  For ``Runner.run_sync``, the
SDK relies on the fact that ``run_sync`` internally delegates to ``run``,
so the async patch covers both paths.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.openai_agents")

_installed = False
_orig_run_descriptor: Any = None
_orig_run_bound: Any = None

AGENT_ID = "openai-agents-auto"


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run_descriptor, _orig_run_bound
    if _installed:
        return
    set_on_block(on_block)

    try:
        from agents import Runner
    except ImportError:
        return

    from enkrypt_agent_sdk.adapters.openai_agents import EnkryptRunHooks

    _orig_run_descriptor = inspect.getattr_static(Runner, "run")
    _orig_run_bound = Runner.run

    @classmethod  # type: ignore[misc]
    async def _patched_run(cls: Any, *args: Any, **kwargs: Any) -> Any:
        if "hooks" not in kwargs or kwargs["hooks"] is None:
            kwargs["hooks"] = EnkryptRunHooks(observer, guard_engine)

        # Extract user input: Runner.run(agent, input=...) or Runner.run(agent, "input")
        user_input = kwargs.get("input", "")
        if not user_input and len(args) >= 2:
            user_input = args[1]
        if user_input:
            await async_checkpoint(guard_engine, "pre_llm", str(user_input), AGENT_ID)

        result = await _orig_run_bound(*args, **kwargs)

        # post_llm checkpoint
        output_text = extract_output(result)
        if output_text:
            await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

        return result

    Runner.run = _patched_run  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    global _installed, _orig_run_descriptor, _orig_run_bound
    if not _installed:
        return
    try:
        from agents import Runner
    except ImportError:
        return
    if _orig_run_descriptor is not None:
        Runner.run = _orig_run_descriptor  # type: ignore[assignment]
    _orig_run_descriptor = None
    _orig_run_bound = None
    _installed = False
