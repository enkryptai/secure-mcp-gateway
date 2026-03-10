"""Auto-patch for Strands Agents — injects ``EnkryptStrandsAdapter`` into
``Agent.__init__`` so that every agent automatically gets observability and
guardrail checks without requiring manual hook registration.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE the agent is invoked.
2. **post_llm**: Check the agent output AFTER invocation completes.

The patch wraps ``Agent.__call__`` (the async invocation method) to apply
guardrail checks around each agent call, and injects ``EnkryptStrandsAdapter``
into the agent's hook list via the original ``__init__``.
"""

from __future__ import annotations

import logging
from typing import Any

from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.observer import AgentObserver
from enkryptai_agent_security.sdk._patch._checkpoint import (
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkryptai_agent_security.sdk.patch.strands")

_installed = False
_orig_agent_init: Any = None
_orig_agent_call: Any = None

AGENT_ID = "strands-auto"


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
    agent_id: str = "",
) -> None:
    global _installed, _orig_agent_init, _orig_agent_call, AGENT_ID
    if _installed:
        return
    if agent_id:
        AGENT_ID = agent_id
    set_on_block(on_block)

    try:
        from strands import Agent
    except ImportError:
        return

    from enkryptai_agent_security.sdk.adapters.strands import EnkryptStrandsAdapter

    _orig_agent_init = Agent.__init__
    _orig_agent_call = Agent.__call__

    def _patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        _orig_agent_init(self, *args, **kwargs)
        # Inject the adapter hook if not already present
        adapter = EnkryptStrandsAdapter(observer, guard_engine, agent_id=AGENT_ID)
        existing_hooks = getattr(self, "_hooks", None) or []
        # Register via hook registry if available
        hook_registry = getattr(self, "hook_registry", None) or getattr(self, "_hook_registry", None)
        if hook_registry is not None:
            adapter.register_hooks(hook_registry)
        else:
            log.debug(
                "Strands Agent has no hook_registry attribute; "
                "adapter hooks could not be registered automatically."
            )

    async def _patched_call(self: Any, prompt: Any, *args: Any, **kwargs: Any) -> Any:
        # pre_llm guardrail check
        if prompt:
            await async_checkpoint(guard_engine, "pre_llm", str(prompt), AGENT_ID)

        result = await _orig_agent_call(self, prompt, *args, **kwargs)

        # post_llm guardrail check
        output_text = extract_output(result)
        if output_text:
            await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

        return result

    Agent.__init__ = _patched_init  # type: ignore[assignment]
    Agent.__call__ = _patched_call  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    global _installed, _orig_agent_init, _orig_agent_call
    if not _installed:
        return
    try:
        from strands import Agent
    except ImportError:
        return
    if _orig_agent_init is not None:
        Agent.__init__ = _orig_agent_init  # type: ignore[assignment]
    if _orig_agent_call is not None:
        Agent.__call__ = _orig_agent_call  # type: ignore[assignment]
    _orig_agent_init = None
    _orig_agent_call = None
    _installed = False
