"""OTel span-attribute sanitisation.

Provides :class:`PayloadPolicy` and :func:`sanitize_attributes` to truncate,
redact, and limit data before attaching it to OpenTelemetry span attributes.

This is separate from the *logging*-level masking functions in
``secure_mcp_gateway.utils`` (``mask_sensitive_headers``, etc.) which operate
on plain dicts destined for log lines.  The functions here are specifically
for OTel spans where large or sensitive payloads could leak to trace backends.

Aligned with ``enkryptai-agent-security.telemetry.redaction``.
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

_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_token", "refresh_token",
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "session", "credentials", "private_key", "client_secret",
})

_REDACTED = "[REDACTED]"


@dataclass
class PayloadPolicy:
    """Controls what data is safe to attach to OTel span attributes.

    Attributes:
        max_str_len: Maximum length for string values (truncated beyond).
        max_attr_count: Maximum number of attributes kept.
        redact_patterns: Regex patterns whose matches are replaced with
            ``[REDACTED]`` in string values.
        redact_keys: Attribute key names (lower-cased) whose values are
            fully replaced with ``[REDACTED]``.
        allow_keys: If non-empty, only these keys are kept (allowlist mode).
        drop_keys: Keys to silently remove.
    """

    max_str_len: int = 4096
    max_attr_count: int = 64
    redact_patterns: list[re.Pattern[str]] = field(
        default_factory=lambda: list(_DEFAULT_PATTERNS)
    )
    redact_keys: set[str] = field(
        default_factory=lambda: set(_SENSITIVE_KEYS)
    )
    allow_keys: set[str] = field(default_factory=set)
    drop_keys: set[str] = field(default_factory=set)


def sanitize_attributes(
    attrs: dict[str, Any],
    policy: PayloadPolicy | None = None,
) -> dict[str, Any]:
    """Return a sanitised copy of *attrs* according to *policy*.

    Safe to call on any dict that will be passed to
    ``span.set_attribute()`` or similar OTel APIs.
    """
    if policy is None:
        policy = PayloadPolicy()

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
        value = (
            value[: policy.max_str_len]
            + f"... [truncated, original length: {len(value)}]"
        )
    return value


__all__ = [
    "PayloadPolicy",
    "sanitize_attributes",
]
