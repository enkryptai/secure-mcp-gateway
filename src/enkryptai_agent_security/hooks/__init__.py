"""Enkrypt hooks — shared infrastructure and platform providers.

Centralises config loading, API calls, response parsing, logging,
and metrics that were previously duplicated across 11 hook providers
(~7,000 lines total).

**Core (shared)**::

    from enkryptai_agent_security.hooks import HooksCore
    core = HooksCore.from_config_file("guardrails_config.json")
    should_block, violations, raw = core.check(text, hook_name="on_llm_start")

**Providers** (platform-specific thin wrappers)::

    from enkryptai_agent_security.hooks.providers import cursor, claude, copilot, ...

**Framework wrappers** (LangChain, LangGraph, OpenAI Agents, Strands)::

    from enkryptai_agent_security.hooks.wrappers.langchain_handler import EnkryptGuardrailsHandler
    from enkryptai_agent_security.hooks.wrappers.openai_hook import EnkryptRunHooks
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
