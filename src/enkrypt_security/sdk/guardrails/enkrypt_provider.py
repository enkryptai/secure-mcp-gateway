"""Enkrypt AI guardrail provider — thin wrapper over the shared client.

Delegates all HTTP/retry/parsing logic to
``enkrypt_security.guardrails.EnkryptGuardrailClient`` while preserving the
SDK's protocol interfaces (``InputGuardrail``, ``OutputGuardrail``,
``PIIHandler``).
"""

from __future__ import annotations

import time
from typing import Any

from enkrypt_security.guardrails import EnkryptGuardrailClient
from enkrypt_security.guardrails.types import (
    GuardrailResult as SharedResult,
)

from enkrypt_security.sdk.guardrails.base import (
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

# ---------------------------------------------------------------------------
# Shared-result → SDK-response converter
# ---------------------------------------------------------------------------

_VTYPE_MAP: dict[str, ViolationType] = {
    "pii": ViolationType.PII,
    "injection_attack": ViolationType.INJECTION_ATTACK,
    "toxicity": ViolationType.TOXICITY,
    "nsfw": ViolationType.NSFW,
    "keyword_detector": ViolationType.KEYWORD_VIOLATION,
    "keyword_detected": ViolationType.KEYWORD_VIOLATION,
    "policy_violation": ViolationType.POLICY_VIOLATION,
    "bias": ViolationType.BIAS,
    "relevancy": ViolationType.RELEVANCY_FAILURE,
    "adherence": ViolationType.ADHERENCE_FAILURE,
    "hallucination": ViolationType.HALLUCINATION,
}


def _to_sdk_response(result: SharedResult, t0: float) -> GuardrailResponse:
    """Convert a shared ``GuardrailResult`` into the SDK's ``GuardrailResponse``."""
    violations: list[GuardrailViolation] = []
    for v in result.violations:
        vtype = _VTYPE_MAP.get(v.violation_type.value, ViolationType.CUSTOM)
        action = GuardrailAction(v.action.value)
        violations.append(
            GuardrailViolation(
                violation_type=vtype,
                severity=v.severity,
                message=v.message,
                action=action,
                metadata=v.details if hasattr(v, "details") else {},
            )
        )

    sdk_action = GuardrailAction(result.action.value)
    elapsed = (time.monotonic() - t0) * 1000

    return GuardrailResponse(
        is_safe=result.is_safe,
        action=sdk_action,
        violations=violations,
        processing_time_ms=elapsed,
        metadata={"raw": result.raw_response},
    )


# ---------------------------------------------------------------------------
# Input guardrail
# ---------------------------------------------------------------------------

class EnkryptInputGuardrail:
    def __init__(self, config: dict[str, Any], api_key: str, base_url: str) -> None:
        block_list: list[str] = config.get("block", [])
        gname = config.get("guardrail_name") or config.get("policy_name", "")
        self._client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            guardrail_name=gname,
            block=block_list,
            fail_open=True,
            source_name="enkrypt-agent-sdk",
        )

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        t0 = time.monotonic()
        result = await self._client.acheck_input(
            request.content, source_event="pre-tool"
        )
        return _to_sdk_response(result, t0)

    def get_supported_detectors(self) -> list[ViolationType]:
        return list(_VTYPE_MAP.values())


# ---------------------------------------------------------------------------
# Output guardrail
# ---------------------------------------------------------------------------

class EnkryptOutputGuardrail:
    def __init__(self, config: dict[str, Any], api_key: str, base_url: str) -> None:
        block_list: list[str] = config.get("block", [])
        gname = config.get("guardrail_name") or config.get("policy_name", "")
        self._client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            guardrail_name=gname,
            block=block_list,
            fail_open=True,
            source_name="enkrypt-agent-sdk",
        )
        self.additional_config: dict[str, Any] = config.get("additional_config", {})

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        t0 = time.monotonic()
        all_violations: list[GuardrailViolation] = []
        should_block = False

        # Policy detection
        detect_result = await self._client.acheck_output(
            response_content,
            original_request.content,
            source_event="post-tool",
        )
        resp = _to_sdk_response(detect_result, t0)
        all_violations.extend(resp.violations)
        if not resp.is_safe:
            should_block = True

        # Relevancy
        if self.additional_config.get("relevancy", False):
            threshold = self.additional_config.get("relevancy_threshold", 0.7)
            rel_result = await self._client.acheck_relevancy(
                original_request.content,
                response_content,
                threshold=threshold,
            )
            if not rel_result.is_safe:
                should_block = True
            rel_resp = _to_sdk_response(rel_result, t0)
            all_violations.extend(rel_resp.violations)

        # Adherence
        if self.additional_config.get("adherence", False):
            threshold = self.additional_config.get("adherence_threshold", 0.8)
            adh_result = await self._client.acheck_adherence(
                original_request.content,
                response_content,
                threshold=threshold,
            )
            if not adh_result.is_safe:
                should_block = True
            adh_resp = _to_sdk_response(adh_result, t0)
            all_violations.extend(adh_resp.violations)

        # Hallucination
        if self.additional_config.get("hallucination", False):
            hal_result = await self._client.acheck_hallucination(
                original_request.content,
                response_content,
                context=original_request.content,
            )
            if not hal_result.is_safe:
                should_block = True
            hal_resp = _to_sdk_response(hal_result, t0)
            all_violations.extend(hal_resp.violations)

        elapsed = (time.monotonic() - t0) * 1000
        return GuardrailResponse(
            is_safe=not should_block,
            action=GuardrailAction.BLOCK if should_block else GuardrailAction.ALLOW,
            violations=all_violations,
            processing_time_ms=elapsed,
        )

    def get_supported_detectors(self) -> list[ViolationType]:
        return list(_VTYPE_MAP.values()) + [
            ViolationType.RELEVANCY_FAILURE,
            ViolationType.ADHERENCE_FAILURE,
            ViolationType.HALLUCINATION,
        ]


# ---------------------------------------------------------------------------
# PII handler
# ---------------------------------------------------------------------------

class EnkryptPIIHandler:
    def __init__(self, api_key: str, base_url: str) -> None:
        self._client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            source_name="enkrypt-agent-sdk",
        )

    async def detect_pii(self, content: str) -> list[GuardrailViolation]:
        redacted, _ = await self._client.aredact_pii(content)
        if redacted != content:
            return [
                GuardrailViolation(
                    violation_type=ViolationType.PII,
                    severity=0.8,
                    message="PII detected in content",
                    action=GuardrailAction.MODIFY,
                    redacted_content=redacted,
                )
            ]
        return []

    async def redact_pii(self, content: str) -> tuple[str, dict[str, Any]]:
        return await self._client.aredact_pii(content)

    async def restore_pii(self, content: str, pii_mapping: dict[str, Any]) -> str:
        return await self._client.arestore_pii(content, pii_mapping)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class EnkryptGuardrailProvider(GuardrailProvider):
    """Enkrypt AI cloud guardrail provider — fully compatible with gateway policies."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.enkryptai.com",
        config: dict[str, Any] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.config = config or {}

    def get_name(self) -> str:
        return "enkrypt"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(self, config: dict[str, Any]) -> InputGuardrail | None:
        if not config.get("enabled", False):
            return None
        return EnkryptInputGuardrail(config, self.api_key, self.base_url)  # type: ignore[return-value]

    def create_output_guardrail(self, config: dict[str, Any]) -> OutputGuardrail | None:
        if not config.get("enabled", False):
            return None
        return EnkryptOutputGuardrail(config, self.api_key, self.base_url)  # type: ignore[return-value]

    def create_pii_handler(self, config: dict[str, Any]) -> PIIHandler | None:
        if not config.get("additional_config", {}).get("pii_redaction", False):
            return None
        return EnkryptPIIHandler(self.api_key, self.base_url)  # type: ignore[return-value]

    def validate_config(self, config: dict[str, Any]) -> bool:
        if config.get("enabled", False) and not (config.get("guardrail_name") or config.get("policy_name")):
            return False
        return True

    def get_required_config_keys(self) -> list[str]:
        return ["enabled", "guardrail_name"]
