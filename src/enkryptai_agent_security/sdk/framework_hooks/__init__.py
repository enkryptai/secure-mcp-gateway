"""Enkrypt SDK framework hooks — guardrail integrations for agent frameworks.

Provides native hook/callback implementations that integrate Enkrypt guardrails
directly into agent framework execution pipelines (real-time guardrails blocking).

This is distinct from ``sdk.adapters``, which provides observability/event-tracking
adapters. Framework hooks do guardrails enforcement; adapters do event streaming.

**LangChain**::

    from enkryptai_agent_security.sdk.framework_hooks.langchain_handler import (
        EnkryptGuardrailsHandler,
    )
    handler = EnkryptGuardrailsHandler()

**LangGraph**::

    from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import (
        create_protected_agent,
        enkrypt_pre_model_hook,
        enkrypt_post_model_hook,
    )

**OpenAI Agents**::

    from enkryptai_agent_security.sdk.framework_hooks.openai_hook import (
        EnkryptRunHooks,
        EnkryptAgentHooks,
    )

**Strands**::

    from enkryptai_agent_security.sdk.framework_hooks.strands_hook import (
        EnkryptGuardrailsHook,
        create_protected_agent,
    )

**CrewAI**::

    from enkryptai_agent_security.sdk.framework_hooks.crewai import (
        EnkryptGuardrailsContext,
        check_guardrails,
    )

Provider helpers (config/API wrappers) are also available per framework::

    from enkryptai_agent_security.sdk.framework_hooks import langchain, strands, ...
"""

from enkryptai_agent_security.sdk.framework_hooks.langchain_handler import (
    EnkryptGuardrailsHandler,
    GuardrailsViolationError as LangChainGuardrailsViolationError,
    SensitiveToolBlockedError,
    create_guardrails_handler,
    flush_guardrails_logs,
    get_guardrails_metrics,
)
from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import (
    EnkryptToolWrapper,
    GuardrailsViolationError as LangGraphGuardrailsViolationError,
    create_audit_only_agent,
    create_blocking_agent,
    create_post_model_hook,
    create_pre_model_hook,
    create_protected_agent as create_protected_langgraph_agent,
    enkrypt_post_model_hook,
    enkrypt_pre_model_hook,
)
from enkryptai_agent_security.sdk.framework_hooks.openai_hook import (
    EnkryptAgentHooks,
    EnkryptAuditRunHooks,
    EnkryptBlockingRunHooks,
    EnkryptRunHooks,
    GuardrailsViolationError as OpenAIGuardrailsViolationError,
)
from enkryptai_agent_security.sdk.framework_hooks.strands_hook import (
    EnkryptGuardrailsAuditHook,
    EnkryptGuardrailsBlockingHook,
    EnkryptGuardrailsHook,
    GuardrailsViolationError as StrandsGuardrailsViolationError,
    create_protected_agent as create_protected_strands_agent,
)

__all__ = [
    # LangChain
    "EnkryptGuardrailsHandler",
    "LangChainGuardrailsViolationError",
    "SensitiveToolBlockedError",
    "create_guardrails_handler",
    "flush_guardrails_logs",
    "get_guardrails_metrics",
    # LangGraph
    "EnkryptToolWrapper",
    "LangGraphGuardrailsViolationError",
    "create_audit_only_agent",
    "create_blocking_agent",
    "create_post_model_hook",
    "create_pre_model_hook",
    "create_protected_langgraph_agent",
    "enkrypt_post_model_hook",
    "enkrypt_pre_model_hook",
    # OpenAI Agents
    "EnkryptAgentHooks",
    "EnkryptAuditRunHooks",
    "EnkryptBlockingRunHooks",
    "EnkryptRunHooks",
    "OpenAIGuardrailsViolationError",
    # Strands
    "EnkryptGuardrailsAuditHook",
    "EnkryptGuardrailsBlockingHook",
    "EnkryptGuardrailsHook",
    "StrandsGuardrailsViolationError",
    "create_protected_strands_agent",
]
