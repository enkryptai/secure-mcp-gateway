"""Keyword-based guardrail provider — ported from Sentry's ``keyword_detector``.

Supports:
- Exact keyword matching with word-boundary awareness
- Wildcard patterns (``*`` matches any characters) — e.g. ``hack*`` matches
  ``hacking``, ``hacker``, etc.
- Case-insensitive matching (configurable)
- Keyword redaction (replaces matches with ``[KEYWORD_N]``)
- Keyword counting
"""

from __future__ import annotations

import re
from typing import Any

from enkrypt_agent_sdk.guardrails.base import (
    GuardrailAction,
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
    ViolationType,
)


def _build_pattern(keyword: str, case_sensitive: bool = False) -> re.Pattern[str]:
    """Build a regex from a keyword, supporting ``*`` wildcards.

    Mirrors Sentry's ``KeywordDetector.detect_keywords`` pattern:
    ``r"\\b(?:{kw}\\b|\\b{kw_dotstar})"`` where ``*`` becomes ``\\w*`` in the
    first branch and ``.*`` in the second.
    """
    escaped = re.escape(keyword)
    word_branch = escaped.replace(r"\*", r"\w*")
    greedy_branch = escaped.replace(r"\*", r".*")
    pattern = rf"\b(?:{word_branch}\b|\b{greedy_branch})"
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(pattern, flags)


class KeywordGuardrail:
    """Blocks content that contains any of the configured keywords."""

    def __init__(self, config: dict[str, Any]) -> None:
        raw: list[str] = config.get("blocked_keywords", [])
        self._case_sensitive: bool = config.get("case_sensitive", False)
        self._keywords = raw
        self._patterns = [_build_pattern(kw, self._case_sensitive) for kw in raw]

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        return self._check(request.content)

    async def validate_output(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        return self._check(response_content)

    def detect_keywords(self, text: str) -> tuple[list[str], dict[str, int]]:
        """Return ``(matched_keywords, counts)`` — mirrors Sentry API."""
        detected: list[str] = []
        counts: dict[str, int] = {}
        for kw, pat in zip(self._keywords, self._patterns):
            matches = pat.findall(text)
            if matches:
                detected.append(kw)
                counts[kw] = len(matches)
        return detected, counts

    def redact_text(self, text: str) -> str:
        """Replace matched keywords with ``[KEYWORD_N]`` — mirrors Sentry API."""
        result = text
        detected, _ = self.detect_keywords(text)
        for idx, kw in enumerate(detected, 1):
            pat = _build_pattern(kw, self._case_sensitive)
            result = pat.sub(f"[KEYWORD_{idx}]", result)
        return result

    def _check(self, text: str) -> GuardrailResponse:
        detected, counts = self.detect_keywords(text)
        violations: list[GuardrailViolation] = []
        for kw in detected:
            violations.append(
                GuardrailViolation(
                    violation_type=ViolationType.KEYWORD_VIOLATION,
                    severity=1.0,
                    message=f"Blocked keyword matched: {kw} (count: {counts.get(kw, 1)})",
                    action=GuardrailAction.BLOCK,
                )
            )
        blocked = len(violations) > 0
        return GuardrailResponse(
            is_safe=not blocked,
            action=GuardrailAction.BLOCK if blocked else GuardrailAction.ALLOW,
            violations=violations,
            modified_content=self.redact_text(text) if blocked else None,
        )

    def get_supported_detectors(self) -> list[ViolationType]:
        return [ViolationType.KEYWORD_VIOLATION]


class _KeywordOutputGuardrailAdapter:
    """Wraps ``KeywordGuardrail`` to satisfy the ``OutputGuardrail`` protocol."""

    def __init__(self, inner: KeywordGuardrail) -> None:
        self._inner = inner

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        return await self._inner.validate_output(response_content, original_request)

    def get_supported_detectors(self) -> list[ViolationType]:
        return self._inner.get_supported_detectors()


class KeywordGuardrailProvider(GuardrailProvider):
    def get_name(self) -> str:
        return "keyword"

    def get_version(self) -> str:
        return "1.1.0"

    def create_input_guardrail(self, config: dict[str, Any]) -> InputGuardrail | None:
        if not config.get("enabled", False):
            return None
        return KeywordGuardrail(config)  # type: ignore[return-value]

    def create_output_guardrail(self, config: dict[str, Any]) -> OutputGuardrail | None:
        if not config.get("enabled", False):
            return None
        return _KeywordOutputGuardrailAdapter(KeywordGuardrail(config))  # type: ignore[return-value]

    def create_pii_handler(self, config: dict[str, Any]) -> PIIHandler | None:
        return None

    def validate_config(self, config: dict[str, Any]) -> bool:
        return isinstance(config.get("blocked_keywords", []), list)

    def get_required_config_keys(self) -> list[str]:
        return ["enabled", "blocked_keywords"]
