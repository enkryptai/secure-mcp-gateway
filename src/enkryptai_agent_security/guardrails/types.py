"""Unified guardrail types used by Gateway, SDK, and Hooks.

This module is the single source of truth for violation types, actions,
and result dataclasses. All three products import from here instead of
defining their own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ViolationType(str, Enum):
    """Every detector the Enkrypt API can return."""

    PII = "pii"
    INJECTION_ATTACK = "injection_attack"
    TOXICITY = "toxicity"
    NSFW = "nsfw"
    KEYWORD_VIOLATION = "keyword_violation"
    POLICY_VIOLATION = "policy_violation"
    BIAS = "bias"
    SPONGE_ATTACK = "sponge_attack"
    TOPIC_VIOLATION = "topic_violation"
    RELEVANCY_FAILURE = "relevancy"
    ADHERENCE_FAILURE = "adherence"
    HALLUCINATION = "hallucination"
    CUSTOM = "custom"


class GuardrailAction(str, Enum):
    """What to do with the request/response."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    MODIFY = "modify"


@dataclass(frozen=True)
class GuardrailViolation:
    """A single detector that fired during a guardrail check."""

    detector: str
    violation_type: ViolationType
    action: GuardrailAction
    severity: float
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GuardrailResult:
    """The outcome of a guardrail check — block/allow plus all violations."""

    action: GuardrailAction
    is_safe: bool
    violations: tuple[GuardrailViolation, ...] = ()
    raw_response: dict[str, Any] = field(default_factory=dict)
