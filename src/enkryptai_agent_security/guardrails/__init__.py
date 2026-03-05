"""Enkrypt guardrails — canonical client, parser, and types.

Usage::

    from enkryptai_agent_security.guardrails import EnkryptGuardrailClient

    client = EnkryptGuardrailClient(
        api_key="ek_...",
        guardrail_name="My Policy",
        block=["injection_attack", "pii", "toxicity"],
    )

    result = client.check_input("some user text")
    if not result.is_safe:
        print("Blocked:", [v.detector for v in result.violations])
"""

from enkryptai_agent_security.guardrails.client import EnkryptGuardrailClient
from enkryptai_agent_security.guardrails.parser import parse_detect_response
from enkryptai_agent_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)

__all__ = [
    "EnkryptGuardrailClient",
    "GuardrailAction",
    "GuardrailResult",
    "GuardrailViolation",
    "ViolationType",
    "parse_detect_response",
]
