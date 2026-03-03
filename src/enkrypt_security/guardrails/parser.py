"""Canonical parser for the Enkrypt /guardrails/policy/detect response.

This replaces three divergent parsers (Gateway, SDK, Hooks) with one
implementation that handles every known edge case:

- ``bool`` summary values  (from Hooks' explicit handling)
- ``on_topic == 0`` means violation  (from Hooks' inversion logic)
- ``keyword_detected`` / ``keyword_detector`` alias  (from SDK + Hooks)
- Non-block-list items emitted as WARN, not silently dropped  (from SDK)
- ``int >= 1`` instead of ``== 1``  (future-proof for count values)
- Detail key fallback: tries detector name, then summary key  (from Hooks)
"""

from __future__ import annotations

from typing import Any

from enkrypt_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)

# Maps every key that can appear in ``summary`` to the canonical detector
# name used in block lists and ``details``.
#
# The Enkrypt API has naming mismatches between summary and details:
#   summary "on_topic"        -> details "topic_detector"
#   summary "keyword_detected" -> details "keyword_detector"
SUMMARY_KEY_TO_DETECTOR: dict[str, str] = {
    "nsfw": "nsfw",
    "toxicity": "toxicity",
    "pii": "pii",
    "injection_attack": "injection_attack",
    "keyword_detected": "keyword_detector",
    "keyword_detector": "keyword_detector",
    "policy_violation": "policy_violation",
    "bias": "bias",
    "sponge_attack": "sponge_attack",
    "on_topic": "topic_detector",
}

_DETECTOR_TO_VIOLATION_TYPE: dict[str, ViolationType] = {
    "nsfw": ViolationType.NSFW,
    "toxicity": ViolationType.TOXICITY,
    "pii": ViolationType.PII,
    "injection_attack": ViolationType.INJECTION_ATTACK,
    "keyword_detector": ViolationType.KEYWORD_VIOLATION,
    "policy_violation": ViolationType.POLICY_VIOLATION,
    "bias": ViolationType.BIAS,
    "sponge_attack": ViolationType.SPONGE_ATTACK,
    "topic_detector": ViolationType.TOPIC_VIOLATION,
}


def _detector_fired(summary_key: str, value: Any) -> bool:
    """Determine whether a detector fired from its summary value.

    The Enkrypt API returns mixed types in ``summary``:
      int 0/1  — most detectors (0 = safe, 1 = violation)
      list     — toxicity returns a list of triggered sub-types
      bool     — possible for some detectors
      special  — ``on_topic: 0`` means OFF-topic (= violation)
    """
    if summary_key == "on_topic":
        # Inverted: 0 means the text is OFF topic → violation
        return isinstance(value, int) and value == 0
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value >= 1
    if isinstance(value, list):
        return len(value) > 0
    if value is not None:
        return bool(value)
    return False


def parse_detect_response(
    data: dict[str, Any],
    block_list: list[str],
) -> GuardrailResult:
    """Parse an Enkrypt ``/guardrails/policy/detect`` response.

    Args:
        data: Raw JSON response from the API.
        block_list: Detector names that should result in BLOCK.
            Use canonical names: ``"keyword_detector"``, ``"topic_detector"``,
            etc.  The parser also accepts the summary aliases
            (``"keyword_detected"``, ``"on_topic"``) for backward compat.

    Returns:
        A :class:`GuardrailResult` with all violations and the overall action.
    """
    summary = data.get("summary", {})
    details = data.get("details", {})
    violations: list[GuardrailViolation] = []

    # Normalize block_list so both alias forms match
    normalized_block: set[str] = set()
    for item in block_list:
        normalized_block.add(item)
        canonical = SUMMARY_KEY_TO_DETECTOR.get(item)
        if canonical:
            normalized_block.add(canonical)

    for summary_key, detector_name in SUMMARY_KEY_TO_DETECTOR.items():
        value = summary.get(summary_key)

        if not _detector_fired(summary_key, value):
            continue

        in_block_list = detector_name in normalized_block
        action = GuardrailAction.BLOCK if in_block_list else GuardrailAction.WARN

        # Details may be keyed by the detector name OR the summary key
        detail = details.get(detector_name) or details.get(summary_key) or {}

        violations.append(
            GuardrailViolation(
                detector=detector_name,
                violation_type=_DETECTOR_TO_VIOLATION_TYPE.get(
                    detector_name, ViolationType.CUSTOM
                ),
                action=action,
                severity=1.0 if in_block_list else 0.5,
                message=f"{detector_name} detected",
                details=detail,
            )
        )

    has_block = any(v.action == GuardrailAction.BLOCK for v in violations)
    return GuardrailResult(
        action=GuardrailAction.BLOCK if has_block else GuardrailAction.ALLOW,
        is_safe=not has_block,
        violations=tuple(violations),
        raw_response=data,
    )
