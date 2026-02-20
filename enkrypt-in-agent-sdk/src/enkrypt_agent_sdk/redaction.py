"""Payload sanitization for telemetry spans — inspired by AgentSight's redaction module.

The ``PayloadPolicy`` controls what ends up in OTel span attributes.  Unlike
AgentSight (regex-only), this module can optionally delegate to the Enkrypt PII
API for AI-powered detection when a ``PIIHandler`` is available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(secret|token)\s*[:=]\s*\S+"),
    re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),  # credit cards
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"(?i)(bearer\s+)\S+"),
]

_DEFAULT_REDACT_KEYS: set[str] = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "authorization", "cookie",
    "x-api-key", "x-auth-token",
}

_REDACTED = "[REDACTED]"


@dataclass
class PayloadPolicy:
    """Controls what data is safe to attach to OTel spans."""

    max_str_len: int = 4096
    max_attr_count: int = 64
    redact_patterns: list[re.Pattern[str]] = field(default_factory=lambda: list(_DEFAULT_PATTERNS))
    redact_keys: set[str] = field(default_factory=lambda: set(_DEFAULT_REDACT_KEYS))
    allow_keys: set[str] = field(default_factory=set)
    drop_keys: set[str] = field(default_factory=set)


def sanitize_attributes(
    attrs: dict[str, Any],
    policy: PayloadPolicy,
) -> dict[str, Any]:
    """Return a sanitized copy of *attrs* according to *policy*."""
    result: dict[str, Any] = {}
    count = 0
    for key, value in attrs.items():
        if count >= policy.max_attr_count:
            break

        low = key.lower()
        if low in policy.drop_keys:
            continue
        if policy.allow_keys and low not in policy.allow_keys:
            continue
        if low in policy.redact_keys:
            result[key] = _REDACTED
            count += 1
            continue

        result[key] = _sanitize_value(value, policy)
        count += 1
    return result


def _sanitize_value(value: Any, policy: PayloadPolicy) -> Any:
    if isinstance(value, str):
        return _sanitize_string(value, policy)
    if isinstance(value, dict):
        return sanitize_attributes(value, policy)
    if isinstance(value, (list, tuple)):
        return type(value)(_sanitize_value(v, policy) for v in value)
    return value


def _sanitize_string(value: str, policy: PayloadPolicy) -> str:
    for pat in policy.redact_patterns:
        value = pat.sub(_REDACTED, value)
    if len(value) > policy.max_str_len:
        value = value[: policy.max_str_len] + f"... [truncated, original length: {len(value)}]"
    return value
