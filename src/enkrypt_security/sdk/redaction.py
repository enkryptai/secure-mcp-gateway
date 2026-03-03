"""Payload sanitization for telemetry spans.

Delegates to the shared ``enkrypt_security`` package.  All original
public names (``PayloadPolicy``, ``sanitize_attributes``) are re-exported
so existing imports continue to work.
"""

from enkrypt_security.telemetry.redaction import (
    PayloadPolicy,
    sanitize_attributes,
)

__all__ = ["PayloadPolicy", "sanitize_attributes"]
