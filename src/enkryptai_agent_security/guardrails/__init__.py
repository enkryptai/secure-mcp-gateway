"""Enkrypt guardrails — canonical client, parser, types, and streaming.

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

Streaming guardrails::

    from enkryptai_agent_security.guardrails import StreamGuard, StreamViolationError

    guard = StreamGuard(
        api_key="ek-...",
        guardrail_policy="My Policy",
        block=["injection_attack", "toxicity"],
        original_input=prompt,
    )

    try:
        async for chunk in guard.shield(text_stream):
            await send(chunk)
    except StreamViolationError as e:
        handle_violation(e.violation)
"""

from enkryptai_agent_security.guardrails.client import EnkryptGuardrailClient
from enkryptai_agent_security.guardrails.parser import parse_detect_response
from enkryptai_agent_security.guardrails.streaming import (
    StreamGuard,
    StreamViolation,
    StreamViolationError,
)
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
    "StreamGuard",
    "StreamViolation",
    "StreamViolationError",
]
