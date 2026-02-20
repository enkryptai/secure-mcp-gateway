"""Enkrypt AI guardrail provider — calls the Enkrypt Guardrails API.

API surface is identical to ``secure_mcp_gateway.plugins.guardrails.enkrypt_provider``
so policies, keys, and endpoints are fully interchangeable.
"""

from __future__ import annotations

import time
from typing import Any

import aiohttp

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

_VIOLATION_MAP: dict[str, ViolationType] = {
    "pii": ViolationType.PII,
    "injection_attack": ViolationType.INJECTION_ATTACK,
    "toxicity": ViolationType.TOXICITY,
    "nsfw": ViolationType.NSFW,
    "keyword_detector": ViolationType.KEYWORD_VIOLATION,
    "keyword_detected": ViolationType.KEYWORD_VIOLATION,
    "policy_violation": ViolationType.POLICY_VIOLATION,
    "bias": ViolationType.BIAS,
    "sponge_attack": ViolationType.INJECTION_ATTACK,
}

_BLOCK_LIST_ALIASES: dict[str, str] = {
    "keyword_detected": "keyword_detector",
    "keyword_detector": "keyword_detected",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_headers(
    api_key: str,
    *,
    policy_name: str = "",
    source_event: str = "sdk",
) -> dict[str, str]:
    headers: dict[str, str] = {
        "apikey": api_key,
        "Content-Type": "application/json",
        "X-Enkrypt-Source-Name": "enkrypt-agent-sdk",
        "X-Enkrypt-Source-Event": source_event,
    }
    if policy_name:
        headers["X-Enkrypt-Policy"] = policy_name
    return headers


def _parse_policy_response(
    data: dict[str, Any],
    block_list: list[str],
) -> tuple[list[GuardrailViolation], bool]:
    """Parse the ``/guardrails/policy/detect`` response into violations."""
    violations: list[GuardrailViolation] = []
    should_block = False
    summary: dict[str, int] = data.get("summary", {})

    for key, flagged in summary.items():
        if not flagged:
            continue
        vtype = _VIOLATION_MAP.get(key, ViolationType.CUSTOM)
        alias = _BLOCK_LIST_ALIASES.get(key)
        in_block_list = key in block_list or (alias is not None and alias in block_list)
        action = GuardrailAction.BLOCK if in_block_list else GuardrailAction.WARN
        if action == GuardrailAction.BLOCK:
            should_block = True
        violations.append(
            GuardrailViolation(
                violation_type=vtype,
                severity=1.0 if action == GuardrailAction.BLOCK else 0.5,
                message=f"{key} detected",
                action=action,
                metadata=data.get("details", {}).get(key, {}),
            )
        )
    return violations, should_block


# ---------------------------------------------------------------------------
# Input guardrail
# ---------------------------------------------------------------------------

class EnkryptInputGuardrail:
    def __init__(self, config: dict[str, Any], api_key: str, base_url: str) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.policy_name: str = config.get("policy_name", "")
        self.block_list: list[str] = config.get("block", [])
        self._url = f"{self.base_url}/guardrails/policy/detect"

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        import logging
        log = logging.getLogger("enkrypt_agent_sdk.guardrails.enkrypt")

        t0 = time.monotonic()
        headers = _build_headers(self.api_key, policy_name=self.policy_name, source_event="pre-tool")
        payload = {"text": request.content}

        log.debug("[EnkryptInput] POST %s", self._url)
        log.debug("[EnkryptInput] Policy: %s | Block list: %s", self.policy_name, self.block_list)
        log.debug("[EnkryptInput] Payload text: %.100s", payload["text"])

        async with aiohttp.ClientSession() as session:
            async with session.post(self._url, json=payload, headers=headers) as resp:
                status = resp.status
                data = await resp.json()

        elapsed = (time.monotonic() - t0) * 1000
        log.debug("[EnkryptInput] HTTP %s | Response: %s", status, data)

        if status != 200 or data.get("error"):
            error_msg = data.get("message", data.get("error", f"HTTP {status}"))
            raise RuntimeError(
                f"Enkrypt API error (HTTP {status}): {error_msg}"
            )

        violations, should_block = _parse_policy_response(data, self.block_list)

        log.debug("[EnkryptInput] Violations: %s | Block: %s | Elapsed: %.0fms",
                  [str(v) for v in violations], should_block, elapsed)

        return GuardrailResponse(
            is_safe=not should_block,
            action=GuardrailAction.BLOCK if should_block else GuardrailAction.ALLOW,
            violations=violations,
            processing_time_ms=elapsed,
            metadata={"raw": data},
        )

    def get_supported_detectors(self) -> list[ViolationType]:
        return list(_VIOLATION_MAP.values())


# ---------------------------------------------------------------------------
# Output guardrail
# ---------------------------------------------------------------------------

class EnkryptOutputGuardrail:
    def __init__(self, config: dict[str, Any], api_key: str, base_url: str) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.policy_name: str = config.get("policy_name", "")
        self.block_list: list[str] = config.get("block", [])
        self.additional_config: dict[str, Any] = config.get("additional_config", {})

        self._policy_url = f"{self.base_url}/guardrails/policy/detect"
        self._relevancy_url = f"{self.base_url}/guardrails/relevancy"
        self._adherence_url = f"{self.base_url}/guardrails/adherence"
        self._hallucination_url = f"{self.base_url}/guardrails/hallucination"

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        t0 = time.monotonic()
        headers = _build_headers(self.api_key, policy_name=self.policy_name, source_event="post-tool")
        base_headers = _build_headers(self.api_key, source_event="post-tool")

        violations: list[GuardrailViolation] = []
        should_block = False

        async with aiohttp.ClientSession() as session:
            # Policy detection
            async with session.post(
                self._policy_url, json={"text": response_content}, headers=headers,
            ) as resp:
                data = await resp.json()
            v, blocked = _parse_policy_response(data, self.block_list)
            violations.extend(v)
            should_block = should_block or blocked

            # Relevancy
            if self.additional_config.get("relevancy", False):
                threshold = self.additional_config.get("relevancy_threshold", 0.7)
                async with session.post(
                    self._relevancy_url,
                    json={"question": original_request.content, "llm_answer": response_content},
                    headers=base_headers,
                ) as resp:
                    score = (await resp.json()).get("score", 1.0)
                if score < threshold:
                    should_block = should_block or ("relevancy" in self.block_list)
                    violations.append(GuardrailViolation(
                        violation_type=ViolationType.RELEVANCY_FAILURE,
                        severity=1.0 - score,
                        message=f"Relevancy score {score:.2f} below threshold {threshold}",
                        action=GuardrailAction.BLOCK if "relevancy" in self.block_list else GuardrailAction.WARN,
                    ))

            # Adherence
            if self.additional_config.get("adherence", False):
                threshold = self.additional_config.get("adherence_threshold", 0.8)
                async with session.post(
                    self._adherence_url,
                    json={"context": original_request.content, "llm_answer": response_content},
                    headers=base_headers,
                ) as resp:
                    score = (await resp.json()).get("score", 1.0)
                if score < threshold:
                    should_block = should_block or ("adherence" in self.block_list)
                    violations.append(GuardrailViolation(
                        violation_type=ViolationType.ADHERENCE_FAILURE,
                        severity=1.0 - score,
                        message=f"Adherence score {score:.2f} below threshold {threshold}",
                        action=GuardrailAction.BLOCK if "adherence" in self.block_list else GuardrailAction.WARN,
                    ))

            # Hallucination
            if self.additional_config.get("hallucination", False):
                async with session.post(
                    self._hallucination_url,
                    json={
                        "request_text": original_request.content,
                        "response_text": response_content,
                        "context": original_request.content,
                    },
                    headers=base_headers,
                ) as resp:
                    hdata = await resp.json()
                if hdata.get("has_hallucination", False):
                    should_block = should_block or ("hallucination" in self.block_list)
                    violations.append(GuardrailViolation(
                        violation_type=ViolationType.HALLUCINATION,
                        severity=hdata.get("confidence", 0.8),
                        message="Hallucination detected",
                        action=GuardrailAction.BLOCK if "hallucination" in self.block_list else GuardrailAction.WARN,
                    ))

        elapsed = (time.monotonic() - t0) * 1000
        return GuardrailResponse(
            is_safe=not should_block,
            action=GuardrailAction.BLOCK if should_block else GuardrailAction.ALLOW,
            violations=violations,
            processing_time_ms=elapsed,
        )

    def get_supported_detectors(self) -> list[ViolationType]:
        return [*_VIOLATION_MAP.values(), ViolationType.RELEVANCY_FAILURE, ViolationType.ADHERENCE_FAILURE, ViolationType.HALLUCINATION]


# ---------------------------------------------------------------------------
# PII handler
# ---------------------------------------------------------------------------

class EnkryptPIIHandler:
    def __init__(self, api_key: str, base_url: str) -> None:
        self.api_key = api_key
        self._url = f"{base_url.rstrip('/')}/guardrails/pii"

    async def detect_pii(self, content: str) -> list[GuardrailViolation]:
        headers = _build_headers(self.api_key, source_event="pii-detect")
        async with aiohttp.ClientSession() as session:
            async with session.post(self._url, json={"text": content, "mode": "request", "key": "null"}, headers=headers) as resp:
                data = await resp.json()
        if data.get("text") != content:
            return [GuardrailViolation(
                violation_type=ViolationType.PII,
                severity=0.8,
                message="PII detected in content",
                action=GuardrailAction.MODIFY,
                redacted_content=data.get("text", content),
            )]
        return []

    async def redact_pii(self, content: str) -> tuple[str, dict[str, Any]]:
        headers = _build_headers(self.api_key, source_event="pii-detect")
        async with aiohttp.ClientSession() as session:
            async with session.post(self._url, json={"text": content, "mode": "request", "key": "null"}, headers=headers) as resp:
                data = await resp.json()
        return data.get("text", content), {"key": data.get("key", "null")}

    async def restore_pii(self, content: str, pii_mapping: dict[str, Any]) -> str:
        headers = _build_headers(self.api_key, source_event="pii-restore")
        async with aiohttp.ClientSession() as session:
            async with session.post(self._url, json={"text": content, "mode": "response", "key": pii_mapping.get("key", "null")}, headers=headers) as resp:
                data = await resp.json()
        return data.get("text", content)


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
        if config.get("enabled", False) and not config.get("policy_name"):
            return False
        return True

    def get_required_config_keys(self) -> list[str]:
        return ["enabled", "policy_name"]
