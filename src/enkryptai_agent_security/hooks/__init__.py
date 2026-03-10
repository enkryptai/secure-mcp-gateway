"""Enkrypt hooks — shared infrastructure and IDE platform providers.

Centralises config loading, API calls, response parsing, logging,
and metrics for IDE platform hooks (Claude, Claude Code, Copilot, Cursor, Kiro).

**Core (shared)**::

    from enkryptai_agent_security.hooks import HooksCore
    core = HooksCore.from_config_file("guardrails_config.json")
    should_block, violations, raw = core.check(text, hook_name="on_llm_start")

**Providers** (IDE platform-specific thin wrappers)::

    from enkryptai_agent_security.hooks.providers import cursor, claude, copilot, ...

For agent framework integrations (LangChain, LangGraph, OpenAI Agents, Strands, CrewAI),
use ``sdk.framework_hooks`` instead::

    from enkryptai_agent_security.sdk.framework_hooks.langchain_handler import EnkryptGuardrailsHandler
    from enkryptai_agent_security.sdk.framework_hooks.openai_hook import EnkryptRunHooks
    from enkryptai_agent_security.sdk.framework_hooks.strands_hook import EnkryptGuardrailsHook
"""

from enkryptai_agent_security.hooks.core import (
    BufferedLogger,
    HookMetrics,
    HookPolicy,
    HooksCore,
    MetricsCollector,
    find_guardrails_config,
    format_violation_message,
)

__all__ = [
    "BufferedLogger",
    "HookMetrics",
    "HookPolicy",
    "HooksCore",
    "MetricsCollector",
    "find_guardrails_config",
    "format_violation_message",
]
