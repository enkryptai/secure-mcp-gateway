"""Unified sensitive-data masking for telemetry and logging.

Merges:
  - SDK's ``PayloadPolicy`` + ``sanitize_attributes`` (OTel span sanitization)
  - Gateway's ``mask_sensitive_data``, ``mask_sensitive_headers``,
    ``mask_sensitive_env_vars`` (log-level masking)

One module, used by all three products.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Default patterns and key sets
# ---------------------------------------------------------------------------

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

_SENSITIVE_HEADER_PATTERNS: frozenset[str] = frozenset({
    "authorization", "bearer", "cookie", "session",
    "apikey", "api-key", "x-api-key", "x-auth-token",
    "token", "secret", "proxy-authorization",
})

_SENSITIVE_ENV_KEYS: frozenset[str] = frozenset({
    "token", "key", "secret", "password", "auth",
    "credential", "private", "cert", "api_key",
})

_REDACTED = "[REDACTED]"


# ---------------------------------------------------------------------------
# PayloadPolicy (from SDK, controls OTel span attribute sanitisation)
# ---------------------------------------------------------------------------

@dataclass
class PayloadPolicy:
    """Controls what data is safe to attach to OTel span attributes."""

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
    """Return a sanitised copy of *attrs* according to *policy*."""
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


# ---------------------------------------------------------------------------
# Gateway-style masking functions (for logging, not OTel attributes)
# ---------------------------------------------------------------------------

def mask_key_value(value: str) -> str:
    """Mask a sensitive value, showing first 2 and last 2 chars."""
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]


def mask_sensitive_headers(
    headers: dict[str, str] | dict[str, Any],
) -> dict[str, str]:
    """Mask sensitive HTTP headers for safe logging."""
    if not headers:
        return {}

    masked: dict[str, str] = {}
    for key, val in headers.items():
        if key.lower() in _SENSITIVE_HEADER_PATTERNS:
            masked[key] = mask_key_value(str(val)) if val else ""
        else:
            masked[key] = str(val)
    return masked


def mask_sensitive_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Mask sensitive environment variables for safe logging."""
    if not env_vars:
        return {}

    masked: dict[str, str] = {}
    for key, val in env_vars.items():
        key_lower = key.lower()
        is_sensitive = any(s in key_lower for s in _SENSITIVE_ENV_KEYS)
        masked[key] = mask_key_value(str(val)) if is_sensitive else str(val)
    return masked


def mask_sensitive_data(
    data: dict[str, Any],
    sensitive_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Recursively mask sensitive keys in a dict for safe logging."""
    if not data:
        return {}

    keys_to_check = set(sensitive_keys) if sensitive_keys else _SENSITIVE_KEYS
    masked: dict[str, Any] = {}

    for key, val in data.items():
        key_lower = key.lower()
        is_sensitive = key_lower in keys_to_check or any(
            s in key_lower for s in keys_to_check
        )

        if is_sensitive and isinstance(val, str):
            masked[key] = mask_key_value(val)
        elif isinstance(val, dict):
            masked[key] = mask_sensitive_data(val, sensitive_keys)
        else:
            masked[key] = val

    return masked
