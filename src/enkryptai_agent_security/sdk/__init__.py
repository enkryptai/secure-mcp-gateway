"""Enkrypt In-Agent Security SDK — embed guardrails, observability, and PII
protection directly inside AI agents.

Quick-start (keyword shorthand)::

    from enkryptai_agent_security.sdk import auto_secure

    auto_secure(
        enkrypt_api_key="ek-...",
        guardrail_policy="Sample Airline Guardrail",
        block=["injection_attack", "pii", "toxicity"],
        pii_redaction=True,
    )

Quick-start (manual integration)::

    from enkryptai_agent_security.sdk import AgentGuard, init_telemetry
    from enkryptai_agent_security.sdk.adapters.generic import GenericAgentAdapter

    ctx = init_telemetry(service_name="my-agent")
    guard = AgentGuard(enkrypt_api_key="...", guardrail_policy="My Policy")
    agent = GenericAgentAdapter(guard, agent_id="my-agent")
"""

from enkryptai_agent_security.sdk._state import (
    get_config,
    get_guard_engine,
    get_observer,
    initialize,
    shutdown,
)
from enkryptai_agent_security.sdk.adapters.generic import GenericAgentAdapter
from enkryptai_agent_security.sdk.auto import auto_secure, available_frameworks, unsecure
from enkryptai_agent_security.sdk.compliance import (
    get_all_compliance_mappings,
    get_compliance_mapping,
)
from enkryptai_agent_security.sdk.config import GuardrailConfig, SDKConfig
from enkryptai_agent_security.sdk.encoding import decode, decode_if_encoded, is_encoded
from enkryptai_agent_security.sdk.events import (
    AgentEvent,
    EventName,
    GuardrailAction,
    GuardrailVerdict,
)
from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.observer import AgentObserver
from enkryptai_agent_security.sdk.otel_setup import ExporterType, TelemetryContext, init_telemetry
from enkryptai_agent_security.sdk.redaction import PayloadPolicy

AgentGuard = GuardEngine

__version__ = "0.1.0"

__all__ = [
    # One-liner entry points
    "auto_secure",
    "unsecure",
    "available_frameworks",
    "initialize",
    "shutdown",
    # Configuration
    "SDKConfig",
    "GuardrailConfig",
    "PayloadPolicy",
    "ExporterType",
    "TelemetryContext",
    # Core objects
    "AgentObserver",
    "GuardEngine",
    "AgentGuard",
    "GenericAgentAdapter",
    "init_telemetry",
    # Events
    "AgentEvent",
    "EventName",
    "GuardrailAction",
    "GuardrailVerdict",
    # Encoding detection (from Sentry)
    "is_encoded",
    "decode",
    "decode_if_encoded",
    # Compliance mapping (from Sentry)
    "get_compliance_mapping",
    "get_all_compliance_mappings",
    # State accessors
    "get_observer",
    "get_guard_engine",
    "get_config",
]
