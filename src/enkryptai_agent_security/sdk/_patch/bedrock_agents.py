"""Auto-patch for Amazon Bedrock Agents — stub that registers in the
framework list.  Bedrock Agents are typically used via the adapter directly
since ``invoke_agent`` returns streaming responses that vary.

The adapter itself should use ``sync_checkpoint`` / ``async_checkpoint``
from ``_checkpoint`` for guardrail enforcement.
"""

from __future__ import annotations

from typing import Any

from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.observer import AgentObserver
from enkryptai_agent_security.sdk._patch._checkpoint import default_on_block, set_on_block

_installed = False


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
    agent_id: str = "",
) -> None:
    global _installed
    if _installed:
        return
    set_on_block(on_block)
    _installed = True


def uninstall() -> None:
    global _installed
    _installed = False
