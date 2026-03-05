"""Enkrypt guardrail provider — backed by ``enkryptai_agent_security.guardrails``.

This is a thin adapter that satisfies the Gateway's ``GuardrailProvider``
interface by delegating HTTP calls and response parsing to the shared
``EnkryptGuardrailClient``.  Gateway-specific concerns remain here:

  * Request/response type conversion (``GuardrailRequest`` ↔ API payload)
  * Error context creation and structured error logging
  * Server/tool registration validation (batch API with custom detectors)
  * ``EnkryptGuardrailProvider`` factory
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

from enkryptai_agent_security.guardrails import (
    EnkryptGuardrailClient,
)
from enkryptai_agent_security.guardrails import (
    GuardrailResult as SharedResult,
)
from enkryptai_agent_security.gateway.error_handling import error_handling_context, error_logger
from enkryptai_agent_security.gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_guardrail_error,
)
from enkryptai_agent_security.gateway.plugins.guardrails.base import (
    GuardrailAction,
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
    ServerRegistrationRequest,
    ToolRegistrationRequest,
    ViolationType,
)
from enkryptai_agent_security.gateway.utils import logger

# ===================================================================
# Helpers
# ===================================================================


def _map_violation_type(enkrypt_type: str) -> ViolationType:
    """Map an Enkrypt detector name to the Gateway's ViolationType enum."""
    _MAP = {
        "pii": ViolationType.PII,
        "injection_attack": ViolationType.INJECTION_ATTACK,
        "toxicity": ViolationType.TOXIC_CONTENT,
        "nsfw": ViolationType.NSFW_CONTENT,
        "keyword_detector": ViolationType.KEYWORD_VIOLATION,
        "keyword_detected": ViolationType.KEYWORD_VIOLATION,
        "policy_violation": ViolationType.POLICY_VIOLATION,
        "bias": ViolationType.BIAS,
        "sponge_attack": ViolationType.SPONGE_ATTACK,
        "relevancy": ViolationType.RELEVANCY_FAILURE,
        "adherence": ViolationType.ADHERENCE_FAILURE,
        "hallucination": ViolationType.HALLUCINATION,
        "topic_detector": ViolationType.CUSTOM,
    }
    return _MAP.get(enkrypt_type, ViolationType.CUSTOM)


def _shared_to_gateway_response(
    result: SharedResult,
    *,
    start_time: float,
    metadata: dict[str, Any] | None = None,
) -> GuardrailResponse:
    """Convert a shared ``GuardrailResult`` into the Gateway's ``GuardrailResponse``."""
    violations = [
        GuardrailViolation(
            violation_type=_map_violation_type(v.detector),
            severity=v.severity,
            message=v.message,
            action=GuardrailAction(v.action) if v.action else GuardrailAction.BLOCK,
            metadata=v.details or {},
        )
        for v in result.violations
    ]

    has_blocking = any(v.action == GuardrailAction.BLOCK for v in violations)
    is_safe = result.is_safe
    action = (
        GuardrailAction.BLOCK
        if has_blocking
        else (GuardrailAction.WARN if violations else GuardrailAction.ALLOW)
    )

    return GuardrailResponse(
        is_safe=is_safe,
        action=action,
        violations=violations,
        metadata=metadata or {},
        processing_time_ms=(time.time() - start_time) * 1000,
    )


def _make_client(api_key: str, base_url: str, block: list[str], policy_name: str) -> EnkryptGuardrailClient:
    return EnkryptGuardrailClient(
        api_key=api_key,
        base_url=base_url,
        guardrail_name=policy_name,
        block=block,
        fail_open=False,
        source_name="mcp-gateway",
    )


# ===================================================================
# Input Guardrail
# ===================================================================


class EnkryptInputGuardrail:
    """Gateway input guardrail delegating to ``EnkryptGuardrailClient``."""

    def __init__(self, config: dict[str, Any], api_key: str, base_url: str):
        self.config = config
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self._client = _make_client(api_key, base_url, self.block_list, self.policy_name)
        self.debug = config.get("debug", False)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        start_time = time.time()
        context = ErrorContext(
            operation="input_guardrail_validation",
            server_name=getattr(request, "server_name", None),
            tool_name=request.tool_name,
            additional_context={
                "policy_name": self.policy_name,
                "content_length": len(request.content),
            },
        )
        async with error_handling_context("input_guardrail_validation", context):
            try:
                if self.debug:
                    logger.debug(
                        "[EnkryptInputGuardrail] Validating with policy: %s",
                        self.policy_name,
                    )

                result = await self._client.acheck_input(
                    request.content, source_event="pre-tool"
                )

                return _shared_to_gateway_response(
                    result,
                    start_time=start_time,
                    metadata={
                        "policy_name": self.policy_name,
                        "enkrypt_response": result.raw_response,
                    },
                )

            except Exception as e:
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                    message=f"Input guardrail validation failed: {e!s}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)
                return GuardrailResponse(
                    is_safe=False,
                    action=GuardrailAction.BLOCK,
                    violations=[
                        GuardrailViolation(
                            violation_type=ViolationType.CUSTOM,
                            severity=1.0,
                            message=f"Validation error: {e!s}",
                            action=GuardrailAction.BLOCK,
                            metadata={
                                "exception": str(e),
                                "correlation_id": context.correlation_id,
                            },
                        )
                    ],
                    metadata={
                        "exception": str(e),
                        "correlation_id": context.correlation_id,
                        "error_code": error.code.value,
                    },
                    processing_time_ms=(time.time() - start_time) * 1000,
                )

    def get_supported_detectors(self) -> list[ViolationType]:
        return [
            ViolationType.PII,
            ViolationType.INJECTION_ATTACK,
            ViolationType.TOXIC_CONTENT,
            ViolationType.NSFW_CONTENT,
            ViolationType.KEYWORD_VIOLATION,
            ViolationType.POLICY_VIOLATION,
            ViolationType.BIAS,
            ViolationType.SPONGE_ATTACK,
        ]


# ===================================================================
# Output Guardrail
# ===================================================================


class EnkryptOutputGuardrail:
    """Gateway output guardrail delegating to ``EnkryptGuardrailClient``."""

    def __init__(self, config: dict[str, Any], api_key: str, base_url: str):
        self.config = config
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self.additional_config = config.get("additional_config", {})
        self._client = _make_client(api_key, base_url, self.block_list, self.policy_name)

        self.relevancy_threshold = self.additional_config.get("relevancy_threshold", 0.7)
        self.adherence_threshold = self.additional_config.get("adherence_threshold", 0.8)
        self.debug = config.get("debug", False)

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        start_time = time.time()
        try:
            violations: list[GuardrailViolation] = []
            additional_metadata: dict[str, Any] = {}

            # 1. Policy detection
            if self.config.get("enabled", False):
                result = await self._client.acheck_output(
                    response_content,
                    original_input=original_request.content,
                    source_event="post-tool",
                )
                additional_metadata["policy"] = result.raw_response
                for v in result.violations:
                    violations.append(
                        GuardrailViolation(
                            violation_type=_map_violation_type(v.detector),
                            severity=v.severity,
                            message=f"Output validation failed: {v.detector}",
                            action=GuardrailAction.BLOCK,
                            metadata=v.details or {},
                        )
                    )

            # 2. Relevancy
            if self.additional_config.get("relevancy", False):
                rel_result = await self._client.acheck_relevancy(
                    original_request.content,
                    response_content,
                    threshold=self.relevancy_threshold,
                )
                additional_metadata["relevancy"] = rel_result.raw_response
                if not rel_result.is_safe:
                    for v in rel_result.violations:
                        violations.append(
                            GuardrailViolation(
                                violation_type=ViolationType.RELEVANCY_FAILURE,
                                severity=v.severity,
                                message=v.message,
                                action=GuardrailAction.WARN,
                                metadata=v.details or {},
                            )
                        )

            # 3. Adherence
            if self.additional_config.get("adherence", False):
                adh_result = await self._client.acheck_adherence(
                    original_request.content,
                    response_content,
                    threshold=self.adherence_threshold,
                )
                additional_metadata["adherence"] = adh_result.raw_response
                if not adh_result.is_safe:
                    for v in adh_result.violations:
                        violations.append(
                            GuardrailViolation(
                                violation_type=ViolationType.ADHERENCE_FAILURE,
                                severity=v.severity,
                                message=v.message,
                                action=GuardrailAction.WARN,
                                metadata=v.details or {},
                            )
                        )

            # 4. Hallucination
            if self.additional_config.get("hallucination", False):
                hal_result = await self._client.acheck_hallucination(
                    original_request.content, response_content
                )
                additional_metadata["hallucination"] = hal_result.raw_response
                if not hal_result.is_safe:
                    for v in hal_result.violations:
                        violations.append(
                            GuardrailViolation(
                                violation_type=ViolationType.HALLUCINATION,
                                severity=v.severity,
                                message=v.message,
                                action=GuardrailAction.WARN,
                                metadata=v.details or {},
                            )
                        )

            has_blocking = any(v.action == GuardrailAction.BLOCK for v in violations)
            is_safe = len(violations) == 0
            action = (
                GuardrailAction.BLOCK
                if has_blocking
                else (GuardrailAction.WARN if violations else GuardrailAction.ALLOW)
            )

            return GuardrailResponse(
                is_safe=is_safe,
                action=action,
                violations=violations,
                metadata=additional_metadata,
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        except Exception as e:
            logger.error("[EnkryptOutputGuardrail] Exception: %s", e)
            return GuardrailResponse(
                is_safe=False,
                action=GuardrailAction.BLOCK,
                violations=[
                    GuardrailViolation(
                        violation_type=ViolationType.CUSTOM,
                        severity=1.0,
                        message=f"Validation error: {e!s}",
                        action=GuardrailAction.BLOCK,
                        metadata={"exception": str(e)},
                    )
                ],
                metadata={"exception": str(e)},
                processing_time_ms=(time.time() - start_time) * 1000,
            )

    def get_supported_detectors(self) -> list[ViolationType]:
        return [
            ViolationType.PII,
            ViolationType.POLICY_VIOLATION,
            ViolationType.RELEVANCY_FAILURE,
            ViolationType.ADHERENCE_FAILURE,
            ViolationType.HALLUCINATION,
            ViolationType.TOXIC_CONTENT,
            ViolationType.NSFW_CONTENT,
        ]


# ===================================================================
# PII Handler
# ===================================================================


class EnkryptPIIHandler:
    """Gateway PII handler delegating to ``EnkryptGuardrailClient``."""

    def __init__(self, api_key: str, base_url: str):
        self._client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            guardrail_name="",
            source_name="mcp-gateway",
        )

    async def detect_pii(self, content: str) -> list[GuardrailViolation]:
        try:
            redacted_text, _ = await self._client.aredact_pii(content)
            if redacted_text != content:
                return [
                    GuardrailViolation(
                        violation_type=ViolationType.PII,
                        severity=0.8,
                        message="PII detected in content",
                        action=GuardrailAction.MODIFY,
                        metadata={
                            "original_length": len(content),
                            "redacted_length": len(redacted_text),
                        },
                    )
                ]
            return []
        except Exception as e:
            logger.error("[EnkryptPIIHandler] PII detection error: %s", e)
            return []

    async def redact_pii(self, content: str) -> tuple[str, dict[str, Any]]:
        try:
            return await self._client.aredact_pii(content)
        except Exception as e:
            logger.error("[EnkryptPIIHandler] PII redaction error: %s", e)
            return content, {}

    async def restore_pii(self, content: str, pii_mapping: dict[str, Any]) -> str:
        try:
            return await self._client.arestore_pii(content, pii_mapping)
        except Exception as e:
            logger.error("[EnkryptPIIHandler] PII restoration error: %s", e)
            return content


# ===================================================================
# Server / Tool Registration Guardrail (Gateway-specific)
# ===================================================================


class EnkryptServerRegistrationGuardrail:
    """Validates server and tool registrations using Enkrypt batch API.

    This is Gateway-specific: it builds custom detector configs from the
    guardrail policy and uses the batch API to check server metadata and
    tool descriptions.  The HTTP call is delegated to the shared client's
    ``abatch_detect()`` method.
    """

    _DETECTOR_DEFAULTS: ClassVar[dict[str, dict[str, Any]]] = {
        "injection_attack": {},
        "policy_violation": {"need_explanation": True},
        "keyword_detector": {
            "banned_keywords": [
                "exec", "shell", "eval", "run_code", "destroy", "wipe",
                "kill", "terminate", "exploit", "hack", "crack", "bypass",
                "override", "escalate", "sudo", "chmod", "chown",
                "mcp.json", "claude_desktop_config.json",
                "enkrypt_mcp_config.json", ".env",
            ],
        },
        "toxicity": {},
        "nsfw": {},
        "topic_detector": {"topic": []},
        "pii": {"entities": []},
        "bias": {},
        "sponge_attack": {},
    }

    @classmethod
    def _build_detectors(
        cls,
        block_list: list[str],
        policy_name: str | None = None,
        context: str = "tool",
    ) -> dict[str, Any]:
        detectors: dict[str, Any] = {}
        for name, defaults in cls._DETECTOR_DEFAULTS.items():
            is_enabled = name in block_list
            config = {"enabled": is_enabled, **defaults}
            if name == "policy_violation" and is_enabled:
                config["policy_text"] = (
                    policy_name
                    if policy_name
                    else (
                        f"Allow only safe {context}s to be registered for this MCP "
                        f"server and find any malicious {context}s to be blocked"
                    )
                )
            detectors[name] = config
        return detectors

    def __init__(self, api_key: str, base_url: str, config: dict[str, Any] | None = None):
        self.api_key = api_key
        self.base_url = base_url
        self.config = config or {}
        self.debug = (
            self.config.get("debug", False)
            or self.config.get("enkrypt_log_level", "").upper() == "DEBUG"
        )

        self._client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            guardrail_name="",
            source_name="mcp-gateway",
            fail_open=False,
        )

        registration_config = self.config.get("registration_validation", {})
        if registration_config.get("custom_detectors"):
            self._custom_server_detectors = registration_config.get("server_detectors")
            self._custom_tool_detectors = registration_config.get("tool_detectors")
        else:
            self._custom_server_detectors = None
            self._custom_tool_detectors = None

    # ------------------------------------------------------------------
    # Server validation
    # ------------------------------------------------------------------

    async def validate_server(self, request: ServerRegistrationRequest) -> GuardrailResponse:
        start_time = time.time()
        try:
            server_text = f"MCP Server: {request.server_name}"
            if request.server_description:
                server_text += f" - {request.server_description}"

            policy = getattr(request, "tool_guardrails_policy", None) or {}
            block_list = policy.get("block", [])

            if not block_list and not self._custom_server_detectors:
                return GuardrailResponse(
                    is_safe=True,
                    action=GuardrailAction.ALLOW,
                    violations=[],
                    metadata={
                        "provider": "enkrypt", "mode": "monitor",
                        "server_name": request.server_name,
                        "message": "No detectors configured, server allowed",
                        "processing_time": time.time() - start_time,
                    },
                )

            detectors = (
                self._custom_server_detectors
                if self._custom_server_detectors
                else self._build_detectors(
                    block_list=block_list,
                    policy_name=policy.get("policy_name"),
                    context="server",
                )
            )

            response = await self._call_batch_api(
                texts=[server_text], detectors=detectors
            )

            result = response[0]
            violations = self._check_server_violations(result)
            is_safe = len(violations) == 0

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=violations,
                processing_time_ms=(time.time() - start_time) * 1000,
                metadata={
                    "server_name": request.server_name,
                    "detection_details": result,
                },
            )

        except Exception as e:
            logger.error("[EnkryptServerRegistration] Error validating server: %s", e)
            cfg_enabled = bool(self.config.get("enkrypt_guardrails_enabled", True))
            if cfg_enabled and "UNAUTHORIZED:" in str(e):
                return GuardrailResponse(
                    is_safe=False,
                    action=GuardrailAction.BLOCK,
                    violations=[
                        GuardrailViolation(
                            violation_type=ViolationType.POLICY_VIOLATION,
                            severity=1.0,
                            message="Guardrail authorization failed",
                            action=GuardrailAction.BLOCK,
                            metadata={"error": str(e)},
                        )
                    ],
                    metadata={"error": str(e)},
                )
            return GuardrailResponse(
                is_safe=True,
                action=GuardrailAction.ALLOW,
                violations=[],
                metadata={"error": str(e)},
            )

    def _check_server_violations(self, result: dict[str, Any]) -> list[GuardrailViolation]:
        """Extract violations from a single batch API result."""
        violations: list[GuardrailViolation] = []
        summary = result.get("summary", {})
        details = result.get("details", {})

        _DETECTORS = [
            ("injection_attack", ViolationType.INJECTION_ATTACK, "Injection attack detected in server metadata", 1.0),
            ("toxicity", ViolationType.TOXIC_CONTENT, "Toxic content detected in server description", 0.8),
            ("nsfw", ViolationType.NSFW_CONTENT, "NSFW content detected in server description", 0.8),
            ("bias", ViolationType.BIAS, "Bias detected in server description", 0.8),
            ("sponge_attack", ViolationType.SPONGE_ATTACK, "Sponge attack detected in server description", 0.8),
            ("keyword_detector", ViolationType.KEYWORD_VIOLATION, "Keyword violation detected in server description", 0.8),
            ("pii", ViolationType.PII, "PII detected in server description", 0.8),
            ("topic_detector", ViolationType.CUSTOM, "Topic detector triggered in server description", 0.8),
        ]

        for detector, vtype, msg, severity in _DETECTORS:
            if summary.get(detector, 0) == 1:
                violations.append(GuardrailViolation(
                    violation_type=vtype,
                    severity=severity,
                    message=msg,
                    action=GuardrailAction.BLOCK,
                    metadata=details.get(detector, {}),
                ))

        if summary.get("policy_violation", 0) == 1:
            policy_details = details.get("policy_violation", {})
            explanation = policy_details.get("explanation", "Policy violation detected")
            violations.append(GuardrailViolation(
                violation_type=ViolationType.POLICY_VIOLATION,
                severity=1.0,
                message=f"Policy violation: {explanation}",
                action=GuardrailAction.BLOCK,
                metadata=policy_details,
            ))

        return violations

    # ------------------------------------------------------------------
    # Tool validation
    # ------------------------------------------------------------------

    async def validate_tools(self, request: ToolRegistrationRequest) -> GuardrailResponse:
        start_time = time.time()
        try:
            texts = []
            for tool in request.tools:
                if isinstance(tool, dict):
                    name = tool.get("name", "unknown")
                    desc = tool.get("description", "")
                    annotations = tool.get("annotations", {})
                else:
                    name = getattr(tool, "name", "unknown")
                    desc = getattr(tool, "description", "")
                    annotations = getattr(tool, "annotations", {}) or {}

                text = f"Tool: {name}"
                if desc:
                    text += f" - {desc}"
                if isinstance(annotations, dict):
                    if annotations.get("destructiveHint"):
                        text += " [DESTRUCTIVE]"
                    if annotations.get("readOnlyHint"):
                        text += " [READ-ONLY]"
                texts.append(text)

            policy = getattr(request, "tool_guardrails_policy", None) or {}
            block_list = policy.get("block", [])

            if not block_list and not self._custom_tool_detectors:
                return GuardrailResponse(
                    is_safe=True,
                    action=GuardrailAction.ALLOW,
                    violations=[],
                    metadata={
                        "provider": "enkrypt", "mode": "monitor",
                        "server_name": request.server_name,
                        "tools_count": len(texts),
                        "message": "No detectors configured, all tools allowed",
                        "processing_time": time.time() - start_time,
                    },
                )

            detectors = (
                self._custom_tool_detectors
                if self._custom_tool_detectors
                else self._build_detectors(
                    block_list=block_list,
                    policy_name=policy.get("policy_name"),
                    context="tool",
                )
            )

            response = await self._call_batch_api(texts=texts, detectors=detectors)

            safe_tools: list[Any] = []
            blocked_tools: list[dict[str, Any]] = []
            all_violations: list[GuardrailViolation] = []

            for tool, result in zip(request.tools, response):
                tool_violations = self._check_tool_violations(result)
                tool_name = tool.get("name", "unknown") if isinstance(tool, dict) else getattr(tool, "name", "unknown")

                if not tool_violations:
                    safe_tools.append(tool)
                else:
                    blocked_tools.append({
                        "name": tool_name,
                        "reasons": tool_violations,
                        "detection_details": result,
                    })
                    for reason in tool_violations:
                        all_violations.append(
                            GuardrailViolation(
                                violation_type=ViolationType.POLICY_VIOLATION,
                                severity=1.0,
                                message=f"Blocked tool '{tool_name}': {reason}",
                                action=GuardrailAction.BLOCK,
                                metadata={"tool": tool_name, "reason": reason},
                            )
                        )

            if request.validation_mode == "block_all":
                is_safe = len(blocked_tools) == 0
            else:
                is_safe = True

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=all_violations,
                processing_time_ms=(time.time() - start_time) * 1000,
                metadata={
                    "server_name": request.server_name,
                    "total_tools": len(request.tools),
                    "safe_tools_count": len(safe_tools),
                    "blocked_tools_count": len(blocked_tools),
                    "blocked_tools": blocked_tools,
                    "filtered_tools": safe_tools,
                    "validation_mode": request.validation_mode,
                },
            )

        except Exception as e:
            logger.error("[EnkryptToolRegistration] Error validating tools: %s", e)
            return self._handle_tool_validation_error(e)

    @staticmethod
    def _check_tool_violations(result: dict[str, Any]) -> list[str]:
        """Extract violation reason strings from a batch API per-tool result."""
        violations: list[str] = []
        summary = result.get("summary", {})
        details = result.get("details", {})

        if summary.get("injection_attack", 0) == 1:
            violations.append("injection attack detected")
        if summary.get("policy_violation", 0) == 1:
            explanation = details.get("policy_violation", {}).get("explanation", "policy violation")
            violations.append(explanation)
        if summary.get("toxicity", 0) == 1:
            violations.append("toxic content")
        if summary.get("nsfw", 0) == 1:
            violations.append("NSFW content")
        if summary.get("topic_detector", 0) == 1:
            violations.append("dangerous topic detected")
        if summary.get("bias", 0) == 1:
            violations.append("bias detected")
        if summary.get("sponge_attack", 0) == 1:
            violations.append("sponge attack detected")
        if summary.get("keyword_detector", 0) == 1:
            violations.append("keyword violation detected")
        if summary.get("pii", 0) == 1:
            violations.append("PII detected")
        return violations

    def _handle_tool_validation_error(self, e: Exception) -> GuardrailResponse:
        """Standardized error handling for tool validation failures."""
        cfg_enabled = bool(self.config.get("enkrypt_guardrails_enabled", True))

        from enkryptai_agent_security.gateway.exceptions import TimeoutError as GWTimeoutError

        if isinstance(e, GWTimeoutError) or "GUARDRAIL_TIMEOUT:" in str(e) or "timed out" in str(e).lower():
            timeout_duration = getattr(e, "timeout_duration", "unknown")
            return GuardrailResponse(
                is_safe=False,
                action=GuardrailAction.BLOCK,
                violations=[
                    GuardrailViolation(
                        violation_type=ViolationType.CUSTOM, severity=1.0,
                        message=f"Guardrail validation timed out after {timeout_duration}s",
                        action=GuardrailAction.BLOCK,
                        metadata={"error": str(e), "timeout": True},
                    )
                ],
                metadata={"error": str(e), "timeout": True},
            )

        if cfg_enabled and "UNAUTHORIZED:" in str(e):
            return GuardrailResponse(
                is_safe=False,
                action=GuardrailAction.BLOCK,
                violations=[
                    GuardrailViolation(
                        violation_type=ViolationType.POLICY_VIOLATION, severity=1.0,
                        message="Guardrail authorization failed",
                        action=GuardrailAction.BLOCK,
                        metadata={"error": str(e)},
                    )
                ],
                metadata={"error": str(e)},
            )

        context = ErrorContext(operation="guardrail.tool_validation_error")
        error = create_guardrail_error(
            code=ErrorCode.GUARDRAIL_VALIDATION_ERROR,
            message=f"Tool validation failed (fail-closed): {e}",
            context=context,
            cause=e,
        )
        error_logger.log_error(error)

        return GuardrailResponse(
            is_safe=False,
            action=GuardrailAction.BLOCK,
            violations=[
                GuardrailViolation(
                    violation_type=ViolationType.CUSTOM, severity=1.0,
                    message=f"Guardrail validation error: {e}",
                    action=GuardrailAction.BLOCK,
                    metadata={"error": str(e)},
                )
            ],
            metadata={"error": str(e), "filtered_tools": []},
        )

    # ------------------------------------------------------------------
    # Batch API call
    # ------------------------------------------------------------------

    async def _call_batch_api(
        self, texts: list[str], detectors: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Call Enkrypt batch detection API via the shared client."""
        try:
            from enkryptai_agent_security.gateway.services.timeout import get_timeout_manager

            timeout_manager = get_timeout_manager()

            async def _make_api_call() -> list[dict[str, Any]]:
                results = await self._client.abatch_detect(
                    texts=texts,
                    source_event="registration",
                    detectors=detectors,
                )
                return [r.raw_response for r in results]

            timeout_result = await timeout_manager.execute_with_timeout(
                _make_api_call, "guardrail", f"batch_api_{len(texts)}_texts"
            )

            if not timeout_result.success:
                if timeout_result.error:
                    raise timeout_result.error
                raise Exception("API call failed")

            return timeout_result.result

        except Exception as e:
            logger.error("[EnkryptBatchAPI] Batch API call failed: %s", e)

            context = ErrorContext(operation="guardrail_batch_api")

            if "UNAUTHORIZED:" in str(e):
                raise
            elif "timeout" in str(e).lower() or "timed out" in str(e).lower():
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_TIMEOUT,
                    message=f"Guardrail API call timed out: {e}",
                    context=context, cause=e,
                )
                error_logger.log_error(error)
                raise error
            else:
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_API_ERROR,
                    message=f"Guardrail API call failed: {e}",
                    context=context, cause=e,
                )
                error_logger.log_error(error)
                raise error


# ===================================================================
# Provider Factory
# ===================================================================


class EnkryptGuardrailProvider(GuardrailProvider):
    """Enkrypt AI guardrail provider (factory for input/output/PII/registration)."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.enkryptai.com",
        config: dict[str, Any] | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.config = config or {}

        if not self.api_key or str(self.api_key).lower() == "null":
            fetched_key, fetched_base = self._get_api_credentials()
            if fetched_key:
                self.api_key = fetched_key
            if fetched_base:
                self.base_url = fetched_base

        self.registration_guardrail = EnkryptServerRegistrationGuardrail(
            api_key=self.api_key, base_url=self.base_url, config=self.config
        )

    def get_name(self) -> str:
        return "enkrypt"

    def get_version(self) -> str:
        return "2.0.0"

    def _get_api_credentials(self) -> tuple[str, str]:
        from enkryptai_agent_security.config.loader import load_config

        ec = load_config()
        api_key = ec.api.api_key or self.api_key
        base_url = ec.api.base_url or self.base_url
        return api_key, base_url

    def create_input_guardrail(self, config: dict[str, Any]) -> InputGuardrail | None:
        if not config.get("enabled", False):
            return None
        api_key, base_url = self._get_api_credentials()
        return EnkryptInputGuardrail(config, api_key, base_url)

    def create_output_guardrail(self, config: dict[str, Any]) -> OutputGuardrail | None:
        if not config.get("enabled", False):
            return None
        api_key, base_url = self._get_api_credentials()
        return EnkryptOutputGuardrail(config, api_key, base_url)

    def create_pii_handler(self, config: dict[str, Any]) -> PIIHandler | None:
        if config.get("pii_redaction", False):
            api_key, base_url = self._get_api_credentials()
            return EnkryptPIIHandler(api_key, base_url)
        return None

    def validate_config(self, config: dict[str, Any]) -> bool:
        if config.get("enabled", False):
            if not config.get("policy_name"):
                return False
        return True

    def get_required_config_keys(self) -> list[str]:
        return ["enabled", "policy_name"]

    async def validate_server_registration(
        self, request: ServerRegistrationRequest
    ) -> GuardrailResponse | None:
        return await self.registration_guardrail.validate_server(request)

    async def validate_tool_registration(
        self, request: ToolRegistrationRequest
    ) -> GuardrailResponse | None:
        return await self.registration_guardrail.validate_tools(request)

    def get_metadata(self) -> dict[str, Any]:
        base_metadata = super().get_metadata()
        base_metadata.update({
            "api_url": self.base_url,
            "supports_async": True,
            "supports_batch": True,
            "max_content_length": 100000,
            "supports_policy_detection": True,
            "supports_relevancy": True,
            "supports_adherence": True,
            "supports_hallucination": True,
            "supports_pii_redaction": True,
            "supports_registration_validation": True,
            "supports_server_validation": True,
            "supports_tool_validation": True,
        })
        return base_metadata
