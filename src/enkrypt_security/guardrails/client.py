"""Unified guardrail HTTP client — sync and async.

Used by Gateway, SDK, and Hooks.  Replaces ~2,900 lines of duplicated
guardrail logic with one client that all three products import from.

Sync transport uses ``urllib.request`` (stdlib).  If ``requests`` is
installed it is preferred for connection pooling and richer retry.
Async transport requires ``aiohttp`` (gated behind ``[sdk]`` extra).
"""

from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from enkrypt_security.guardrails.parser import parse_detect_response
from enkrypt_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)

logger = logging.getLogger("enkrypt_security.guardrails")

# Re-usable across retries to avoid import overhead on every call
_HAS_REQUESTS: bool | None = None


def _check_requests() -> bool:
    global _HAS_REQUESTS
    if _HAS_REQUESTS is None:
        import importlib.util

        _HAS_REQUESTS = importlib.util.find_spec("requests") is not None
    return _HAS_REQUESTS


# ---------------------------------------------------------------------------
# Error-path result builder
# ---------------------------------------------------------------------------

def _safe_result(
    fail_open: bool,
    error_msg: str,
    raw: dict[str, Any] | None = None,
) -> GuardrailResult:
    """Build a result when the guardrail API is unavailable."""
    if fail_open:
        return GuardrailResult(
            action=GuardrailAction.WARN,
            is_safe=True,
            violations=(
                GuardrailViolation(
                    detector="system",
                    violation_type=ViolationType.CUSTOM,
                    action=GuardrailAction.WARN,
                    severity=0.0,
                    message=error_msg,
                ),
            ),
            raw_response=raw or {},
        )
    return GuardrailResult(
        action=GuardrailAction.BLOCK,
        is_safe=False,
        violations=(
            GuardrailViolation(
                detector="system",
                violation_type=ViolationType.CUSTOM,
                action=GuardrailAction.BLOCK,
                severity=1.0,
                message=error_msg,
            ),
        ),
        raw_response=raw or {},
    )


# ---------------------------------------------------------------------------
# Supplementary-check result builder (relevancy / adherence / hallucination)
# ---------------------------------------------------------------------------

def _supplementary_result(
    detector: str,
    violation_type: ViolationType,
    in_block_list: bool,
    severity: float,
    message: str,
    raw: dict[str, Any],
) -> GuardrailResult:
    action = GuardrailAction.BLOCK if in_block_list else GuardrailAction.WARN
    return GuardrailResult(
        action=action,
        is_safe=not in_block_list,
        violations=(
            GuardrailViolation(
                detector=detector,
                violation_type=violation_type,
                action=action,
                severity=severity,
                message=message,
                details=raw,
            ),
        ),
        raw_response=raw,
    )


_PASS = GuardrailResult(
    action=GuardrailAction.ALLOW, is_safe=True, violations=()
)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class EnkryptGuardrailClient:
    """Unified guardrail client for all Enkrypt security products.

    Provides sync (``check_input``) and async (``acheck_input``) methods
    so the same client works in blocking hook scripts and async gateways.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.enkryptai.com",
        guardrail_name: str = "",
        block: list[str] | None = None,
        fail_open: bool = True,
        timeout: float = 15.0,
        ssl_verify: bool = True,
        source_name: str = "enkrypt-security",
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.guardrail_name = guardrail_name
        self.block = list(block) if block else []
        self.fail_open = fail_open
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.source_name = source_name
        self.max_retries = max_retries

        # Pre-compute endpoint URLs
        self._detect_url = f"{self.base_url}/guardrails/policy/detect"
        self._relevancy_url = f"{self.base_url}/guardrails/relevancy"
        self._adherence_url = f"{self.base_url}/guardrails/adherence"
        self._hallucination_url = f"{self.base_url}/guardrails/hallucination"
        self._pii_url = f"{self.base_url}/guardrails/pii"
        self._batch_url = f"{self.base_url}/guardrails/batch/detect"

    # ------------------------------------------------------------------
    # Header builder
    # ------------------------------------------------------------------

    def _headers(self, source_event: str = "") -> dict[str, str]:
        h: dict[str, str] = {
            "apikey": self.api_key,
            "Content-Type": "application/json",
            "X-Enkrypt-Source-Name": self.source_name,
        }
        if source_event:
            h["X-Enkrypt-Source-Event"] = source_event
        if self.guardrail_name:
            h["X-Enkrypt-Policy"] = self.guardrail_name
        return h

    # ------------------------------------------------------------------
    # Sync HTTP transport
    # ------------------------------------------------------------------

    def _post_json(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        if _check_requests():
            return self._post_with_requests(url, payload, headers)
        return self._post_with_urllib(url, payload, headers)

    def _post_with_requests(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        import requests as req_lib

        resp = req_lib.post(
            url,
            json=payload,
            headers=headers,
            timeout=self.timeout,
            verify=self.ssl_verify,
        )
        return resp.status_code, resp.json()

    def _post_with_urllib(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        ctx: ssl.SSLContext | None = None
        if not self.ssl_verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=ctx
            ) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body = {"error": str(exc)}
            return exc.code, body

    # ------------------------------------------------------------------
    # Async HTTP transport
    # ------------------------------------------------------------------

    async def _apost_json(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        try:
            import aiohttp
        except ImportError as exc:
            raise ImportError(
                "aiohttp is required for async guardrail checks. "
                "Install with: pip install enkrypt-security[sdk]"
            ) from exc

        ssl_ctx: Any = None
        if not self.ssl_verify:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None
        client_timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            connector=connector, timeout=client_timeout
        ) as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                data = await resp.json()
                return resp.status, data

    # ------------------------------------------------------------------
    # Core detect — sync
    # ------------------------------------------------------------------

    def _detect_sync(self, text: str, source_event: str) -> GuardrailResult:
        headers = self._headers(source_event)
        payload = {"text": text}
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                status, data = self._post_json(self._detect_url, payload, headers)

                if status != 200 or data.get("error"):
                    msg = data.get("message", data.get("error", f"HTTP {status}"))
                    logger.warning(
                        "Enkrypt API HTTP %s: %s (attempt %d/%d)",
                        status, msg, attempt, self.max_retries,
                    )
                    last_error = RuntimeError(msg)
                    if status < 500:
                        break
                    continue

                return parse_detect_response(data, self.block)

            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Enkrypt API call failed (attempt %d/%d): %s",
                    attempt, self.max_retries, exc,
                )
                if attempt < self.max_retries:
                    time.sleep(min(2 ** (attempt - 1), 8))

        error_msg = (
            f"Guardrail check failed after {self.max_retries} attempts: {last_error}"
        )
        logger.error(error_msg)
        return _safe_result(self.fail_open, error_msg)

    # ------------------------------------------------------------------
    # Core detect — async
    # ------------------------------------------------------------------

    async def _adetect(self, text: str, source_event: str) -> GuardrailResult:
        import asyncio

        headers = self._headers(source_event)
        payload = {"text": text}
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                status, data = await self._apost_json(
                    self._detect_url, payload, headers
                )

                if status != 200 or data.get("error"):
                    msg = data.get("message", data.get("error", f"HTTP {status}"))
                    logger.warning(
                        "Enkrypt API HTTP %s: %s (attempt %d/%d)",
                        status, msg, attempt, self.max_retries,
                    )
                    last_error = RuntimeError(msg)
                    if status < 500:
                        break
                    continue

                return parse_detect_response(data, self.block)

            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Enkrypt API call failed (attempt %d/%d): %s",
                    attempt, self.max_retries, exc,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(min(2 ** (attempt - 1), 8))

        error_msg = (
            f"Guardrail check failed after {self.max_retries} attempts: {last_error}"
        )
        logger.error(error_msg)
        return _safe_result(self.fail_open, error_msg)

    # ==================================================================
    # Public API — /guardrails/policy/detect
    # ==================================================================

    def check_input(
        self, text: str, *, source_event: str = "pre-tool"
    ) -> GuardrailResult:
        """Sync input guardrail check."""
        return self._detect_sync(text, source_event=source_event)

    async def acheck_input(
        self, text: str, *, source_event: str = "pre-tool"
    ) -> GuardrailResult:
        """Async input guardrail check."""
        return await self._adetect(text, source_event=source_event)

    def check_output(
        self,
        text: str,
        original_input: str = "",
        *,
        source_event: str = "post-tool",
    ) -> GuardrailResult:
        """Sync output guardrail check."""
        return self._detect_sync(text, source_event=source_event)

    async def acheck_output(
        self,
        text: str,
        original_input: str = "",
        *,
        source_event: str = "post-tool",
    ) -> GuardrailResult:
        """Async output guardrail check."""
        return await self._adetect(text, source_event=source_event)

    # ==================================================================
    # Supplementary checks — relevancy, adherence, hallucination
    # ==================================================================

    def check_relevancy(
        self,
        question: str,
        answer: str,
        *,
        threshold: float = 0.7,
    ) -> GuardrailResult:
        """Check whether ``answer`` is relevant to ``question``."""
        headers = self._headers("post-tool")
        payload = {"question": question, "llm_answer": answer}
        try:
            status, data = self._post_json(self._relevancy_url, payload, headers)
            if status != 200:
                return _safe_result(self.fail_open, f"Relevancy check HTTP {status}")
            score = data.get("score", 1.0)
            if score < threshold:
                return _supplementary_result(
                    "relevancy",
                    ViolationType.RELEVANCY_FAILURE,
                    "relevancy" in self.block,
                    1.0 - score,
                    f"Relevancy score {score:.2f} below threshold {threshold}",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Relevancy check failed: {exc}")

    async def acheck_relevancy(
        self,
        question: str,
        answer: str,
        *,
        threshold: float = 0.7,
    ) -> GuardrailResult:
        """Async version of :meth:`check_relevancy`."""
        headers = self._headers("post-tool")
        payload = {"question": question, "llm_answer": answer}
        try:
            status, data = await self._apost_json(
                self._relevancy_url, payload, headers
            )
            if status != 200:
                return _safe_result(self.fail_open, f"Relevancy check HTTP {status}")
            score = data.get("score", 1.0)
            if score < threshold:
                return _supplementary_result(
                    "relevancy",
                    ViolationType.RELEVANCY_FAILURE,
                    "relevancy" in self.block,
                    1.0 - score,
                    f"Relevancy score {score:.2f} below threshold {threshold}",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Relevancy check failed: {exc}")

    def check_adherence(
        self,
        context: str,
        answer: str,
        *,
        threshold: float = 0.8,
    ) -> GuardrailResult:
        """Check whether ``answer`` adheres to the given ``context``."""
        headers = self._headers("post-tool")
        payload = {"context": context, "llm_answer": answer}
        try:
            status, data = self._post_json(self._adherence_url, payload, headers)
            if status != 200:
                return _safe_result(self.fail_open, f"Adherence check HTTP {status}")
            score = data.get("score", 1.0)
            if score < threshold:
                return _supplementary_result(
                    "adherence",
                    ViolationType.ADHERENCE_FAILURE,
                    "adherence" in self.block,
                    1.0 - score,
                    f"Adherence score {score:.2f} below threshold {threshold}",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Adherence check failed: {exc}")

    async def acheck_adherence(
        self,
        context: str,
        answer: str,
        *,
        threshold: float = 0.8,
    ) -> GuardrailResult:
        """Async version of :meth:`check_adherence`."""
        headers = self._headers("post-tool")
        payload = {"context": context, "llm_answer": answer}
        try:
            status, data = await self._apost_json(
                self._adherence_url, payload, headers
            )
            if status != 200:
                return _safe_result(self.fail_open, f"Adherence check HTTP {status}")
            score = data.get("score", 1.0)
            if score < threshold:
                return _supplementary_result(
                    "adherence",
                    ViolationType.ADHERENCE_FAILURE,
                    "adherence" in self.block,
                    1.0 - score,
                    f"Adherence score {score:.2f} below threshold {threshold}",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Adherence check failed: {exc}")

    def check_hallucination(
        self,
        request_text: str,
        response_text: str,
        context: str = "",
    ) -> GuardrailResult:
        """Check whether ``response_text`` contains hallucinations."""
        headers = self._headers("post-tool")
        payload = {
            "request_text": request_text,
            "response_text": response_text,
            "context": context or request_text,
        }
        try:
            status, data = self._post_json(self._hallucination_url, payload, headers)
            if status != 200:
                return _safe_result(
                    self.fail_open, f"Hallucination check HTTP {status}"
                )
            if data.get("has_hallucination", False):
                return _supplementary_result(
                    "hallucination",
                    ViolationType.HALLUCINATION,
                    "hallucination" in self.block,
                    data.get("confidence", 0.8),
                    "Hallucination detected",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Hallucination check failed: {exc}")

    async def acheck_hallucination(
        self,
        request_text: str,
        response_text: str,
        context: str = "",
    ) -> GuardrailResult:
        """Async version of :meth:`check_hallucination`."""
        headers = self._headers("post-tool")
        payload = {
            "request_text": request_text,
            "response_text": response_text,
            "context": context or request_text,
        }
        try:
            status, data = await self._apost_json(
                self._hallucination_url, payload, headers
            )
            if status != 200:
                return _safe_result(
                    self.fail_open, f"Hallucination check HTTP {status}"
                )
            if data.get("has_hallucination", False):
                return _supplementary_result(
                    "hallucination",
                    ViolationType.HALLUCINATION,
                    "hallucination" in self.block,
                    data.get("confidence", 0.8),
                    "Hallucination detected",
                    data,
                )
            return GuardrailResult(
                action=GuardrailAction.ALLOW,
                is_safe=True,
                violations=(),
                raw_response=data,
            )
        except Exception as exc:
            return _safe_result(self.fail_open, f"Hallucination check failed: {exc}")

    # ==================================================================
    # PII redaction / restoration
    # ==================================================================

    def redact_pii(self, text: str) -> tuple[str, dict[str, Any]]:
        """Redact PII server-side.  Returns ``(redacted_text, pii_mapping)``."""
        headers = self._headers("pii-detect")
        payload = {"text": text, "mode": "request", "key": "null"}
        status, data = self._post_json(self._pii_url, payload, headers)
        if status != 200:
            raise RuntimeError(f"PII redaction failed: HTTP {status}")
        return data.get("text", text), {"key": data.get("key", "null")}

    def restore_pii(self, text: str, pii_mapping: dict[str, Any]) -> str:
        """Restore previously redacted PII."""
        headers = self._headers("pii-restore")
        payload = {
            "text": text,
            "mode": "response",
            "key": pii_mapping.get("key", "null"),
        }
        status, data = self._post_json(self._pii_url, payload, headers)
        if status != 200:
            raise RuntimeError(f"PII restoration failed: HTTP {status}")
        return data.get("text", text)

    async def aredact_pii(self, text: str) -> tuple[str, dict[str, Any]]:
        """Async version of :meth:`redact_pii`."""
        headers = self._headers("pii-detect")
        payload = {"text": text, "mode": "request", "key": "null"}
        status, data = await self._apost_json(self._pii_url, payload, headers)
        if status != 200:
            raise RuntimeError(f"PII redaction failed: HTTP {status}")
        return data.get("text", text), {"key": data.get("key", "null")}

    async def arestore_pii(self, text: str, pii_mapping: dict[str, Any]) -> str:
        """Async version of :meth:`restore_pii`."""
        headers = self._headers("pii-restore")
        payload = {
            "text": text,
            "mode": "response",
            "key": pii_mapping.get("key", "null"),
        }
        status, data = await self._apost_json(self._pii_url, payload, headers)
        if status != 200:
            raise RuntimeError(f"PII restoration failed: HTTP {status}")
        return data.get("text", text)

    # ==================================================================
    # Batch detection (Gateway-specific, server/tool registration)
    # ==================================================================

    def batch_detect(
        self,
        texts: list[str],
        *,
        source_event: str = "registration",
        detectors: dict[str, Any] | None = None,
    ) -> list[GuardrailResult]:
        """Run policy detection on multiple texts in a single request.

        Args:
            texts: Texts to check.
            source_event: Value for the ``X-Enkrypt-Source-Event`` header.
            detectors: Optional detector configuration dict.  When provided
                it is included in the payload (used by Gateway's registration
                validation with custom detector overrides).
        """
        headers = self._headers(source_event)
        payload: dict[str, Any] = {"texts": texts}
        if detectors is not None:
            payload["detectors"] = detectors
        try:
            status, data = self._post_json(self._batch_url, payload, headers)
            if status != 200:
                return [
                    _safe_result(self.fail_open, f"Batch detect HTTP {status}")
                    for _ in texts
                ]
            results = data.get("results", [])
            return [
                parse_detect_response(r, self.block) for r in results
            ]
        except Exception as exc:
            return [
                _safe_result(self.fail_open, f"Batch detect failed: {exc}")
                for _ in texts
            ]

    async def abatch_detect(
        self,
        texts: list[str],
        *,
        source_event: str = "registration",
        detectors: dict[str, Any] | None = None,
    ) -> list[GuardrailResult]:
        """Async version of :meth:`batch_detect`."""
        headers = self._headers(source_event)
        payload: dict[str, Any] = {"texts": texts}
        if detectors is not None:
            payload["detectors"] = detectors
        try:
            status, data = await self._apost_json(
                self._batch_url, payload, headers
            )
            if status != 200:
                return [
                    _safe_result(self.fail_open, f"Batch detect HTTP {status}")
                    for _ in texts
                ]
            results = data.get("results", [])
            return [
                parse_detect_response(r, self.block) for r in results
            ]
        except Exception as exc:
            return [
                _safe_result(self.fail_open, f"Batch detect failed: {exc}")
                for _ in texts
            ]
