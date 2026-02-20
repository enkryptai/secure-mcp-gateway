"""Enkrypt In-Agent Security SDK — embed guardrails, observability, and PII
protection directly inside AI agents.

Quick-start (keyword shorthand)::

    from enkrypt_agent_sdk import auto_secure

    auto_secure(
        enkrypt_api_key="ek-...",
        guardrail_policy="Sample Airline Guardrail",
        block=["injection_attack", "pii", "toxicity"],
        pii_redaction=True,
    )

Quick-start (manual integration)::

    from enkrypt_agent_sdk import AgentGuard, init_telemetry
    from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter

    tp, mp = init_telemetry(service_name="my-agent")
    guard = AgentGuard(enkrypt_api_key="...", guardrail_policy="My Policy")
    agent = GenericAgentAdapter(guard, agent_id="my-agent")
"""

from enkrypt_agent_sdk.auto import auto_secure, unsecure, available_frameworks
from enkrypt_agent_sdk.config import GuardrailConfig, SDKConfig
from enkrypt_agent_sdk.events import AgentEvent, EventName, GuardrailAction, GuardrailVerdict
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.redaction import PayloadPolicy
from enkrypt_agent_sdk.otel_setup import ExporterType, init_telemetry
from enkrypt_agent_sdk.encoding import is_encoded, decode, decode_if_encoded
from enkrypt_agent_sdk.compliance import get_compliance_mapping, get_all_compliance_mappings
from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter
from enkrypt_agent_sdk._state import (
    initialize,
    shutdown,
    get_observer,
    get_guard_engine,
    get_config,
)

# Convenience alias matching the document's proposed API
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
