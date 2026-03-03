"""Encoding detection and decoding — ported from Sentry's ``encoding_detector.py``.

Attackers frequently encode malicious payloads in base64, hex, URL-encoding,
etc. to bypass guardrails.  This module detects common encodings and decodes
them so the guardrail engine can inspect the actual content.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import string
import urllib.parse


def is_encoded(text: str) -> str | None:
    """Detect if *text* is encoded in a common format.

    Returns the encoding name (``'base64'``, ``'hex'``, ``'url'``, etc.)
    or ``None`` if the text appears to be plain.
    """
    stripped = text.strip()
    if not stripped:
        return None

    # Base64
    try:
        if (
            len(stripped) >= 8
            and len(stripped) % 4 == 0
            and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in stripped)
        ):
            raw = base64.b64decode(stripped, validate=True)
            if base64.b64encode(raw).decode().rstrip("=") == stripped.rstrip("="):
                return "base64"
    except Exception:
        pass

    # Hexadecimal
    try:
        if len(stripped) >= 8 and len(stripped) % 2 == 0 and all(c in string.hexdigits for c in stripped):
            raw = binascii.unhexlify(stripped)
            if binascii.hexlify(raw).decode().lower() == stripped.lower():
                return "hex"
    except Exception:
        pass

    # URL encoding
    decoded_url = urllib.parse.unquote_plus(text)
    if decoded_url != text and len(decoded_url) < len(text):
        if any(c.isalnum() for c in decoded_url):
            return "url"

    # Binary (space-separated 8-bit values)
    if re.fullmatch(r"(0|1|\s)+", stripped):
        parts = stripped.split()
        if parts and all(len(b) == 8 for b in parts):
            try:
                "".join(chr(int(b, 2)) for b in parts)
                return "binary"
            except ValueError:
                pass

    # HTML entities
    decoded_html = html.unescape(text)
    if decoded_html != text and any(c.isalnum() for c in decoded_html):
        return "html"

    return None


def decode(encoding_format: str, text: str) -> str | None:
    """Decode *text* given a detected *encoding_format*."""
    try:
        if encoding_format == "base64":
            return base64.b64decode(text).decode("utf-8")
        if encoding_format == "hex":
            return binascii.unhexlify(text.strip()).decode("utf-8")
        if encoding_format == "url":
            return urllib.parse.unquote_plus(text)
        if encoding_format == "binary":
            parts = text.strip().split()
            return "".join(chr(int(b, 2)) for b in parts)
        if encoding_format == "html":
            return html.unescape(text)
    except Exception:
        return None
    return None


def decode_if_encoded(text: str) -> tuple[str, str | None]:
    """Convenience: detect + decode in one call.

    Returns ``(decoded_text, encoding_format)`` where *encoding_format*
    is ``None`` when the text was not encoded.
    """
    fmt = is_encoded(text)
    if fmt is None:
        return text, None
    decoded = decode(fmt, text)
    if decoded is None:
        return text, None
    return decoded, fmt
