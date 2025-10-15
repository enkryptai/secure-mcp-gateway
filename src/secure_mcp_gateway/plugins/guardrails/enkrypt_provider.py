"""Enkrypt guardrail provider."""

import asyncio
import time
from typing import Any, ClassVar, Dict, List, Optional

import aiohttp

from secure_mcp_gateway.error_handling import error_handling_context, error_logger
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    ErrorSeverity,
    GuardrailError,
    create_guardrail_error,
)
from secure_mcp_gateway.plugins.guardrails.base import (
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
from secure_mcp_gateway.utils import logger


class EnkryptInputGuardrail:
    """
    Enkrypt implementation of InputGuardrail.

    This class is fully self-contained and makes direct API calls to Enkrypt.
    """

    def __init__(self, config: Dict[str, Any], api_key: str, base_url: str):
        self.config = config
        self.api_key = api_key
        self.base_url = base_url
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self.additional_config = config.get("additional_config", {})

        # API endpoints
        self.guardrail_url = f"{base_url}/guardrails/policy/detect"

        # Debug mode
        self.debug = config.get("debug", False)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate input using Enkrypt guardrails."""
        start_time = time.time()

        # Create error context for correlation tracking
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
                # Prepare payload
                payload = {"text": request.content}
                headers = {
                    "X-Enkrypt-Policy": self.policy_name,
                    "apikey": self.api_key,
                    "Content-Type": "application/json",
                }

                if self.debug:
                    logger.debug(
                        f"[EnkryptInputGuardrail] Validating with policy: {self.policy_name}"
                    )
                    logger.debug(f"[EnkryptInputGuardrail] Payload: {payload}")

                # Make API call
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.guardrail_url, json=payload, headers=headers
                    ) as response:
                        resp_json = await response.json()

                if self.debug:
                    logger.debug(f"[EnkryptInputGuardrail] Response: {resp_json}")

                # Check for API errors
                if resp_json.get("error"):
                    error = create_guardrail_error(
                        code=ErrorCode.GUARDRAIL_API_ERROR,
                        message=f"Enkrypt API error: {resp_json.get('error')}",
                        context=context,
                    )
                    error_logger.log_error(error)

                    return GuardrailResponse(
                        is_safe=False,
                        action=GuardrailAction.BLOCK,
                        violations=[
                            GuardrailViolation(
                                violation_type=ViolationType.CUSTOM,
                                severity=1.0,
                                message=f"API Error: {resp_json.get('error')}",
                                action=GuardrailAction.BLOCK,
                                metadata={"error": resp_json.get("error")},
                            )
                        ],
                        metadata={
                            "api_error": True,
                            "correlation_id": context.correlation_id,
                        },
                        processing_time_ms=(time.time() - start_time) * 1000,
                    )

                # Parse violations from Enkrypt response
                violations = []
                violations_detected = False

                if "summary" in resp_json:
                    summary = resp_json["summary"]
                    for policy_type in self.block_list:
                        value = summary.get(policy_type)

                        if value == 1 or (isinstance(value, list) and len(value) > 0):
                            violations_detected = True
                        violations.append(
                            GuardrailViolation(
                                violation_type=self._map_violation_type(policy_type),
                                severity=0.8,  # Default severity
                                message=f"Input validation failed: {policy_type}",
                                action=GuardrailAction.BLOCK,
                                metadata={
                                    "policy_type": policy_type,
                                    "value": value,
                                    "details": resp_json.get("details", {}).get(
                                        policy_type, {}
                                    ),
                                },
                            )
                        )

                # Determine overall safety
                is_safe = not violations_detected
                action = GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK

                processing_time_ms = (time.time() - start_time) * 1000

                return GuardrailResponse(
                    is_safe=is_safe,
                    action=action,
                    violations=violations,
                    modified_content=None,
                    metadata={
                        "policy_name": self.policy_name,
                        "enkrypt_response": resp_json,
                    },
                    processing_time_ms=processing_time_ms,
                )

            except Exception as e:
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                    message=f"Input guardrail validation failed: {e!s}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)

                processing_time_ms = (time.time() - start_time) * 1000

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
                    processing_time_ms=processing_time_ms,
                )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported violation types for input."""
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

    def _map_violation_type(self, enkrypt_type: str) -> ViolationType:
        """Map Enkrypt violation types to standard ViolationType enum."""
        mapping = {
            "pii": ViolationType.PII,
            "injection_attack": ViolationType.INJECTION_ATTACK,
            "toxicity": ViolationType.TOXIC_CONTENT,
            "nsfw": ViolationType.NSFW_CONTENT,
            "keyword_detector": ViolationType.KEYWORD_VIOLATION,
            "policy_violation": ViolationType.POLICY_VIOLATION,
            "bias": ViolationType.BIAS,
            "sponge_attack": ViolationType.SPONGE_ATTACK,
        }
        return mapping.get(enkrypt_type, ViolationType.CUSTOM)


class EnkryptOutputGuardrail:
    """
    Enkrypt implementation of OutputGuardrail.

    This class is fully self-contained and makes direct API calls to Enkrypt.
    Includes ALL checks: policy, relevancy, adherence, hallucination.
    """

    def __init__(self, config: Dict[str, Any], api_key: str, base_url: str):
        self.config = config
        self.api_key = api_key
        self.base_url = base_url
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self.additional_config = config.get("additional_config", {})

        # API endpoints
        self.guardrail_url = f"{base_url}/guardrails/policy/detect"
        self.relevancy_url = f"{base_url}/guardrails/relevancy"
        self.adherence_url = f"{base_url}/guardrails/adherence"
        self.hallucination_url = f"{base_url}/guardrails/hallucination"

        # Thresholds
        self.relevancy_threshold = self.additional_config.get(
            "relevancy_threshold", 0.7
        )
        self.adherence_threshold = self.additional_config.get(
            "adherence_threshold", 0.8
        )

        # Debug mode
        self.debug = config.get("debug", False)

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        """
        Validate output using Enkrypt guardrails with ALL checks.

        Performs:
        1. Policy detection (if enabled)
        2. Relevancy check (if enabled)
        3. Adherence check (if enabled)
        4. Hallucination check (if enabled)
        """
        start_time = time.time()

        try:
            violations = []
            additional_metadata = {}

            # 1. Policy Detection (if enabled)
            if self.config.get("enabled", False):
                policy_result = await self._check_policy(response_content)
                additional_metadata["policy"] = policy_result

                if "summary" in policy_result:
                    summary = policy_result["summary"]
                    for policy_type in self.block_list:
                        value = summary.get(policy_type)

                        if value == 1 or (isinstance(value, list) and len(value) > 0):
                            violations.append(
                                GuardrailViolation(
                                    violation_type=self._map_violation_type(
                                        policy_type
                                    ),
                                    severity=0.8,
                                    message=f"Output validation failed: {policy_type}",
                                    action=GuardrailAction.BLOCK,
                                    metadata={
                                        "policy_type": policy_type,
                                        "value": value,
                                        "details": policy_result.get("details", {}).get(
                                            policy_type, {}
                                        ),
                                    },
                                )
                            )

            # 2. Relevancy Check (if enabled)
            if self.additional_config.get("relevancy", False):
                relevancy_result = await self._check_relevancy(
                    original_request.content, response_content
                )
                additional_metadata["relevancy"] = relevancy_result

                relevancy_score = relevancy_result.get("score", 1.0)
                if relevancy_score < self.relevancy_threshold:
                    violations.append(
                        GuardrailViolation(
                            violation_type=ViolationType.RELEVANCY_FAILURE,
                            severity=1.0 - relevancy_score,
                            message=f"Response not relevant (score: {relevancy_score:.2f})",
                            action=GuardrailAction.WARN,
                            metadata=relevancy_result,
                        )
                    )

            # 3. Adherence Check (if enabled)
            if self.additional_config.get("adherence", False):
                adherence_result = await self._check_adherence(
                    original_request.content, response_content
                )
                additional_metadata["adherence"] = adherence_result

                adherence_score = adherence_result.get("score", 1.0)
                if adherence_score < self.adherence_threshold:
                    violations.append(
                        GuardrailViolation(
                            violation_type=ViolationType.ADHERENCE_FAILURE,
                            severity=1.0 - adherence_score,
                            message=f"Response doesn't adhere to context (score: {adherence_score:.2f})",
                            action=GuardrailAction.WARN,
                            metadata=adherence_result,
                        )
                    )

            # 4. Hallucination Check (if enabled)
            if self.additional_config.get("hallucination", False):
                hallucination_result = await self._check_hallucination(
                    original_request.content, response_content
                )
                additional_metadata["hallucination"] = hallucination_result

                if hallucination_result.get("has_hallucination", False):
                    violations.append(
                        GuardrailViolation(
                            violation_type=ViolationType.HALLUCINATION,
                            severity=hallucination_result.get("confidence", 0.5),
                            message="Potential hallucination detected",
                            action=GuardrailAction.WARN,
                            metadata=hallucination_result,
                        )
                    )

            # Determine overall safety
            # Block if there are blocking violations, warn otherwise
            has_blocking_violations = any(
                v.action == GuardrailAction.BLOCK for v in violations
            )

            is_safe = len(violations) == 0
            action = (
                GuardrailAction.BLOCK
                if has_blocking_violations
                else (
                    GuardrailAction.WARN
                    if len(violations) > 0
                    else GuardrailAction.ALLOW
                )
            )

            processing_time_ms = (time.time() - start_time) * 1000

            return GuardrailResponse(
                is_safe=is_safe,
                action=action,
                violations=violations,
                modified_content=None,
                metadata=additional_metadata,
                processing_time_ms=processing_time_ms,
            )

        except Exception as e:
            logger.error(f"[EnkryptOutputGuardrail] Exception: {e}")
            processing_time_ms = (time.time() - start_time) * 1000

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
                processing_time_ms=processing_time_ms,
            )

    async def _check_policy(self, text: str) -> Dict[str, Any]:
        """Check against policy using Enkrypt API."""
        try:
            payload = {"text": text}
            headers = {
                "X-Enkrypt-Policy": self.policy_name,
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            if self.debug:
                logger.debug(
                    f"[EnkryptOutputGuardrail] Policy check for: {self.policy_name}"
                )

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.guardrail_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                logger.debug(f"[EnkryptOutputGuardrail] Policy result: {result}")

            return result

        except Exception as e:
            logger.error(f"[EnkryptOutputGuardrail] Policy check error: {e}")
            return {"error": str(e)}

    async def _check_relevancy(self, question: str, answer: str) -> Dict[str, Any]:
        """Check relevancy using Enkrypt API."""
        try:
            payload = {"question": question, "llm_answer": answer}
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            if self.debug:
                logger.debug("[EnkryptOutputGuardrail] Checking relevancy")

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.relevancy_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                logger.debug(f"[EnkryptOutputGuardrail] Relevancy result: {result}")

            return result

        except Exception as e:
            logger.error(f"[EnkryptOutputGuardrail] Relevancy check error: {e}")
            return {"error": str(e), "score": 1.0}  # Default to passing

    async def _check_adherence(self, context: str, answer: str) -> Dict[str, Any]:
        """Check adherence using Enkrypt API."""
        try:
            payload = {"context": context, "llm_answer": answer}
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            if self.debug:
                logger.debug("[EnkryptOutputGuardrail] Checking adherence")

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.adherence_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                logger.debug(f"[EnkryptOutputGuardrail] Adherence result: {result}")

            return result

        except Exception as e:
            logger.error(f"[EnkryptOutputGuardrail] Adherence check error: {e}")
            return {"error": str(e), "score": 1.0}  # Default to passing

    async def _check_hallucination(
        self, request: str, response: str, context: str = ""
    ) -> Dict[str, Any]:
        """Check hallucination using Enkrypt API."""
        try:
            payload = {
                "request_text": request,
                "response_text": response,
                "context": context,
            }
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            if self.debug:
                logger.debug("[EnkryptOutputGuardrail] Checking hallucination")

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.hallucination_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                logger.debug(f"[EnkryptOutputGuardrail] Hallucination result: {result}")

            return result

        except Exception as e:
            logger.error(f"[EnkryptOutputGuardrail] Hallucination check error: {e}")
            return {"error": str(e), "has_hallucination": False}  # Default to passing

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported violation types for output."""
        return [
            ViolationType.PII,
            ViolationType.POLICY_VIOLATION,
            ViolationType.RELEVANCY_FAILURE,
            ViolationType.ADHERENCE_FAILURE,
            ViolationType.HALLUCINATION,
            ViolationType.TOXIC_CONTENT,
            ViolationType.NSFW_CONTENT,
        ]

    def _map_violation_type(self, enkrypt_type: str) -> ViolationType:
        """Map Enkrypt violation types to standard ViolationType enum."""
        mapping = {
            "pii": ViolationType.PII,
            "policy_violation": ViolationType.POLICY_VIOLATION,
            "relevancy": ViolationType.RELEVANCY_FAILURE,
            "adherence": ViolationType.ADHERENCE_FAILURE,
            "toxicity": ViolationType.TOXIC_CONTENT,
            "nsfw": ViolationType.NSFW_CONTENT,
            "hallucination": ViolationType.HALLUCINATION,
        }
        return mapping.get(enkrypt_type, ViolationType.CUSTOM)


class EnkryptPIIHandler:
    """
    Enkrypt implementation of PIIHandler.

    This class is fully self-contained and makes direct API calls to Enkrypt.
    """

    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.pii_url = f"{base_url}/guardrails/pii"

    async def detect_pii(self, content: str) -> List[GuardrailViolation]:
        """Detect PII using Enkrypt."""
        try:
            # Use the redact endpoint to detect PII
            payload = {"text": content, "mode": "request", "key": "null"}
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.pii_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            violations = []

            # If text was modified, PII was detected
            if result.get("text") != content:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.PII,
                        severity=0.8,
                        message="PII detected in content",
                        action=GuardrailAction.MODIFY,
                        metadata={
                            "original_length": len(content),
                            "redacted_length": len(result.get("text", "")),
                        },
                    )
                )

            return violations

        except Exception as e:
            logger.error(f"[EnkryptPIIHandler] PII detection error: {e}")
            return []

    async def redact_pii(self, content: str) -> tuple[str, Dict[str, Any]]:
        """Redact PII using Enkrypt."""
        try:
            payload = {"text": content, "mode": "request", "key": "null"}
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.pii_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            redacted_text = result.get("text", content)
            pii_key = result.get("key", "")

            return redacted_text, {"key": pii_key}

        except Exception as e:
            logger.error(f"[EnkryptPIIHandler] PII redaction error: {e}")
            return content, {}

    async def restore_pii(self, content: str, pii_mapping: Dict[str, Any]) -> str:
        """Restore PII using Enkrypt."""
        try:
            pii_key = pii_mapping.get("key", "")
            if not pii_key:
                return content

            payload = {"text": content, "mode": "response", "key": pii_key}
            headers = {
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.pii_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            return result.get("text", content)

        except Exception as e:
            logger.error(f"[EnkryptPIIHandler] PII restoration error: {e}")
            return content


class EnkryptServerRegistrationGuardrail:
    """
    Handles server and tool registration validation using Enkrypt batch API.

    This class validates servers and tools during discovery to prevent
    malicious or unsafe MCP servers/tools from being registered.
    """

    # Server validation detector config
    SERVER_DETECTORS: ClassVar[Dict[str, Any]] = {
        "injection_attack": {"enabled": True},
        "policy_violation": {
            "enabled": True,
            # "coc_policy_name": "Safe Server Registration Policy",
            "policy_text": "Allow only safe servers to be registered for this MCP server and find any malicious servers to be blocked",
            "need_explanation": True,
        },
        "keyword_detector": {
            "enabled": True,
            "banned_keywords": [
                "exec",
                "shell",
                "eval",
                "sudo",
                "rm -rf",
                "delete_all",
                # Secret files
                "mcp.json",
                "claude_desktop_config.json",
                "enkrypt_mcp_config.json",
                ".env",
            ],
        },
        "toxicity": {"enabled": True},
        "nsfw": {"enabled": True},
        "topic_detector": {"enabled": False, "topic": []},
        "pii": {"enabled": False, "entities": []},
        # "system_prompt": {"enabled": False},
        # "copyright_ip": {"enabled": False},
        "bias": {"enabled": True},
        "sponge_attack": {"enabled": True},
    }

    # Tool validation detector config
    TOOL_DETECTORS: ClassVar[Dict[str, Any]] = {
        "injection_attack": {"enabled": True},
        "policy_violation": {
            "enabled": True,
            # "coc_policy_name": "Safe Tool Registration Policy",
            "policy_text": "Allow only safe tools to be registered for this MCP server and find any malicious tools to be blocked",
            "need_explanation": True,
        },
        "keyword_detector": {
            "enabled": True,
            "banned_keywords": [
                "exec",
                "shell",
                "eval",
                # "system",
                # "command",
                # "execute",
                "run_code",
                # "delete",
                # "drop",
                # "truncate",
                # "remove",
                "destroy",
                "wipe",
                # "format",
                "kill",
                "terminate",
                "exploit",
                "hack",
                "crack",
                "bypass",
                "override",
                # "privilege",
                "escalate",
                # "root",
                # "admin",
                "sudo",
                "chmod",
                "chown",
                # Secret files
                "mcp.json",
                "claude_desktop_config.json",
                "enkrypt_mcp_config.json",
                ".env",
            ],
        },
        "toxicity": {"enabled": True},
        "nsfw": {"enabled": True},
        "topic_detector": {
            "enabled": False,
            "topic": [],
        },
        "pii": {"enabled": False, "entities": []},
        # "system_prompt": {"enabled": True},
        # "copyright_ip": {"enabled": False},
        "bias": {"enabled": True},
        "sponge_attack": {"enabled": True},
    }

    def __init__(self, api_key: str, base_url: str, config: Dict[str, Any] = None):
        import sys

        self.api_key = api_key
        self.base_url = base_url
        self.config = config or {}
        self.batch_url = f"{base_url}/guardrails/batch/detect"
        # Check both "debug" field and "enkrypt_log_level" for DEBUG
        self.debug = (
            self.config.get("debug", False)
            or self.config.get("enkrypt_log_level", "").upper() == "DEBUG"
        )
        logger.info(
            f"[EnkryptServerRegistrationGuardrail] Initialized with debug={self.debug}"
        )
        logger.info(
            f"[EnkryptServerRegistrationGuardrail] Config keys: {list(self.config.keys())}"
        )
        logger.info(
            f"[EnkryptServerRegistrationGuardrail] enkrypt_log_level={self.config.get('enkrypt_log_level')}"
        )

        # Get custom detectors from config if provided
        registration_config = self.config.get("registration_validation", {})
        if registration_config.get("custom_detectors"):
            self.SERVER_DETECTORS = registration_config.get(
                "server_detectors", self.SERVER_DETECTORS
            )
            self.TOOL_DETECTORS = registration_config.get(
                "tool_detectors", self.TOOL_DETECTORS
            )

    async def validate_server(
        self, request: ServerRegistrationRequest
    ) -> GuardrailResponse:
        """Validate server registration."""
        start_time = time.time()

        try:
            # Build text from server metadata
            server_text = f"MCP Server: {request.server_name}"
            if request.server_description:
                server_text += f" - {request.server_description}"
            # Command triggers injection attacks. So only checking with name and description
            # if request.server_command:
            #     server_text += f" | Command: {request.server_command}"

            if self.debug:
                logger.debug(
                    f"[EnkryptServerRegistration] Validating server: {request.server_name}"
                )
                logger.debug(f"[EnkryptServerRegistration] Text: {server_text}")

            # Call Enkrypt batch API
            response = await self._call_batch_api(
                texts=[server_text], detectors=self.SERVER_DETECTORS
            )

            if self.debug:
                logger.debug(
                    f"[EnkryptServerRegistration] Guardrail Response: {response}"
                )

            # Analyze response
            result = response[0]
            violations = []

            # Check each detector
            if result["summary"].get("injection_attack", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.INJECTION_ATTACK,
                        severity=1.0,
                        message="Injection attack detected in server metadata",
                        action=GuardrailAction.BLOCK,
                        metadata=result["details"].get("injection_attack", {}),
                    )
                )

            if result["summary"].get("policy_violation", 0) == 1:
                policy_details = result["details"].get("policy_violation", {})
                explanation = policy_details.get(
                    "explanation", "Policy violation detected"
                )
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.POLICY_VIOLATION,
                        severity=1.0,
                        message=f"Policy violation: {explanation}",
                        action=GuardrailAction.BLOCK,
                        metadata=policy_details,
                    )
                )

            if result["summary"].get("toxicity", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.TOXIC_CONTENT,
                        severity=0.8,
                        message="Toxic content detected in server description",
                        action=GuardrailAction.BLOCK,
                        metadata=result["details"].get("toxicity", {}),
                    )
                )

            if result["summary"].get("nsfw", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.NSFW_CONTENT,
                        severity=0.8,
                        message="NSFW content detected in server description",
                        action=GuardrailAction.BLOCK,
                        metadata=result["details"].get("nsfw", {}),
                    )
                )

            if result["summary"].get("bias", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.BIAS,
                        severity=0.8,
                        message="Bias detected in server description",
                    )
                )

            if result["summary"].get("sponge_attack", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.SPONGE_ATTACK,
                        severity=0.8,
                        message="Sponge attack detected in server description",
                    )
                )

            if result["summary"].get("keyword_detector", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.KEYWORD_VIOLATION,
                        severity=0.8,
                        message="Keyword violation detected in server description",
                    )
                )

            if result["summary"].get("pii", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.PII,
                        severity=0.8,
                        message="PII detected in server description",
                    )
                )

            if result["summary"].get("topic_detector", 0) == 1:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.TOPIC_DETECTOR,
                        severity=0.8,
                        message="Topic detector detected in server description",
                    )
                )

            is_safe = len(violations) == 0
            processing_time = (time.time() - start_time) * 1000

            if self.debug:
                logger.debug(
                    f"[EnkryptServerRegistration] Server validation result: {'SAFE' if is_safe else 'BLOCKED'}"
                )
                if not is_safe:
                    logger.debug(
                        f"[EnkryptServerRegistration] Violations: {[v.message for v in violations]}"
                    )

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=violations,
                processing_time_ms=processing_time,
                metadata={
                    "server_name": request.server_name,
                    "detection_details": result,
                },
            )

        except Exception as e:
            logger.error(f"[EnkryptServerRegistration] Error validating server: {e}")
            # If guardrails enabled and auth failed, fail-closed to avoid approving unsafe
            cfg_enabled = bool(self.config.get("enkrypt_guardrails_enabled", True))
            if cfg_enabled and ("UNAUTHORIZED:" in str(e)):
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
            # Otherwise fail-open
            return GuardrailResponse(
                is_safe=True,
                action=GuardrailAction.ALLOW,
                violations=[],
                metadata={"error": str(e)},
            )

    async def validate_tools(
        self, request: ToolRegistrationRequest
    ) -> GuardrailResponse:
        """Validate and filter tools."""
        start_time = time.time()

        try:
            # Build texts array from tool descriptions
            texts = []
            for tool in request.tools:
                # Handle both dict and Tool object
                if isinstance(tool, dict):
                    tool_name = tool.get("name", "unknown")
                    tool_desc = tool.get("description", "")
                    annotations = tool.get("annotations", {})
                else:
                    # Tool object (has attributes)
                    tool_name = getattr(tool, "name", "unknown")
                    tool_desc = getattr(tool, "description", "")
                    annotations = getattr(tool, "annotations", {}) or {}

                tool_text = f"Tool: {tool_name}"

                if tool_desc:
                    tool_text += f" - {tool_desc}"

                # Add annotations
                if isinstance(annotations, dict):
                    if annotations.get("destructiveHint"):
                        tool_text += " [DESTRUCTIVE]"
                    if annotations.get("readOnlyHint"):
                        tool_text += " [READ-ONLY]"

                texts.append(tool_text)

            if self.debug:
                logger.debug(
                    f"[EnkryptToolRegistration] Validating {len(texts)} tools for {request.server_name}"
                )

            # Call Enkrypt batch API
            response = await self._call_batch_api(
                texts=texts, detectors=self.TOOL_DETECTORS
            )

            if self.debug:
                logger.debug(
                    f"[EnkryptToolRegistration] Guardrail Response: {response}"
                )

            logger.debug(f"[EnkryptToolRegistration] Guardrail Response: {response}")
            # Analyze results
            safe_tools = []
            blocked_tools = []
            all_violations = []

            for i, (tool, result) in enumerate(zip(request.tools, response)):
                # Check all enabled detectors
                tool_violations = []

                if result["summary"].get("injection_attack", 0) == 1:
                    tool_violations.append("injection attack detected")
                if result["summary"].get("policy_violation", 0) == 1:
                    explanation = (
                        result["details"]
                        .get("policy_violation", {})
                        .get("explanation", "policy violation")
                    )
                    tool_violations.append(explanation)
                if result["summary"].get("toxicity", 0) == 1:
                    tool_violations.append("toxic content")
                if result["summary"].get("nsfw", 0) == 1:
                    tool_violations.append("NSFW content")
                if result["summary"].get("topic_detector", 0) == 1:
                    tool_violations.append("dangerous topic detected")
                if result["summary"].get("bias", 0) == 1:
                    tool_violations.append("bias detected")
                if result["summary"].get("sponge_attack", 0) == 1:
                    tool_violations.append("sponge attack detected")
                if result["summary"].get("keyword_detector", 0) == 1:
                    tool_violations.append("keyword violation detected")
                if result["summary"].get("pii", 0) == 1:
                    tool_violations.append("PII detected")

                # Get tool name for reporting
                if isinstance(tool, dict):
                    tool_name = tool.get("name", "unknown")
                else:
                    tool_name = getattr(tool, "name", "unknown")

                if len(tool_violations) == 0:
                    safe_tools.append(tool)
                else:
                    blocked_tool_info = {
                        "name": tool_name,
                        "reasons": tool_violations,
                        "detection_details": result,
                    }
                    blocked_tools.append(blocked_tool_info)

                    # Create violation objects
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

            # Determine overall safety based on mode
            if request.validation_mode == "block_all":
                # Block all if any tool is unsafe
                is_safe = len(blocked_tools) == 0
            else:
                # Filter mode: allow but filter unsafe tools
                is_safe = True

            processing_time = (time.time() - start_time) * 1000

            if self.debug:
                logger.debug("[EnkryptToolRegistration] Validation complete:")
                logger.debug(f"  - Total tools: {len(request.tools)}")
                logger.debug(f"  - Safe tools: {len(safe_tools)}")
                logger.debug(f"  - Blocked tools: {len(blocked_tools)}")
                if blocked_tools:
                    logger.debug(f"  - Blocked: {[t['name'] for t in blocked_tools]}")

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=all_violations,
                processing_time_ms=processing_time,
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
            logger.error(f"[EnkryptToolRegistration] Error validating tools: {e}")
            cfg_enabled = bool(self.config.get("enkrypt_guardrails_enabled", True))

            # Handle timeout errors - fail closed to prevent tool registration
            from secure_mcp_gateway.exceptions import TimeoutError

            if (
                isinstance(e, TimeoutError)
                or "GUARDRAIL_TIMEOUT:" in str(e)
                or "timed out" in str(e).lower()
            ):
                logger.error(
                    f"[EnkryptToolRegistration] Guardrail timeout - blocking tool registration: {e}"
                )

                # Extract timeout details if available
                timeout_duration = getattr(e, "timeout_duration", "unknown")
                timeout_type = getattr(e, "timeout_type", "guardrail")

                return GuardrailResponse(
                    is_safe=False,
                    action=GuardrailAction.BLOCK,
                    violations=[
                        GuardrailViolation(
                            violation_type=ViolationType.CUSTOM,
                            severity=1.0,
                            message=f"Guardrail validation timed out after {timeout_duration}s",
                            action=GuardrailAction.BLOCK,
                            metadata={
                                "error": str(e),
                                "timeout": True,
                                "timeout_duration": timeout_duration,
                                "timeout_type": timeout_type,
                            },
                        )
                    ],
                    metadata={
                        "error": str(e),
                        "timeout": True,
                        "timeout_duration": timeout_duration,
                        "timeout_type": timeout_type,
                    },
                )

            if cfg_enabled and ("UNAUTHORIZED:" in str(e)):
                # Fail closed: do not approve tools when guardrails enabled but unauthorized
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
            # FAIL CLOSED for other errors
            # Log with standardized error handling
            from secure_mcp_gateway.error_handling import error_logger
            from secure_mcp_gateway.exceptions import (
                ErrorCode,
                ErrorContext,
                create_guardrail_error,
            )

            context = ErrorContext(
                operation="guardrail.tool_validation_error",
                request_id=getattr(self, "request_id", None),
                server_name=getattr(self, "server_name", None),
            )

            error = create_guardrail_error(
                code=ErrorCode.GUARDRAIL_VALIDATION_ERROR,
                message=f"Tool validation failed (fail-closed): {e}",
                context=context,
                cause=e,
            )
            error_logger.log_error(error)

            # Block all tools on validation error
            return GuardrailResponse(
                is_safe=False,
                action=GuardrailAction.BLOCK,
                violations=[
                    GuardrailViolation(
                        violation_type=ViolationType.CUSTOM,
                        severity=1.0,
                        message=f"Guardrail validation error: {e}",
                        action=GuardrailAction.BLOCK,
                        metadata={"error": str(e)},
                    )
                ],
                metadata={
                    "error": str(e),
                    "filtered_tools": [],  # Block all tools
                },
            )

    async def _call_batch_api(
        self, texts: List[str], detectors: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Call Enkrypt batch detection API."""
        try:

            def _sanitize_for_json(value):
                """Recursively sanitize values so they can be JSON-serialized.
                - Ensure dict keys are strings (drop None keys)
                - Convert non-serializable simple types to strings
                """
                if isinstance(value, dict):
                    clean = {}
                    for k, v in value.items():
                        if k is None:
                            continue
                        sk = str(k)
                        clean[sk] = _sanitize_for_json(v)
                    return clean
                if isinstance(value, list):
                    return [_sanitize_for_json(v) for v in value]
                if isinstance(value, (str, int, float, bool)) or value is None:
                    return value
                # Fallback to string
                return str(value)

            safe_texts = ["" if t is None else str(t) for t in (texts or [])]
            safe_detectors = _sanitize_for_json(detectors or {})

            payload = {"texts": safe_texts, "detectors": safe_detectors}

            headers = {
                "apikey": str(self.api_key or ""),
                "Content-Type": "application/json",
            }

            if self.debug:
                logger.debug(
                    f"[EnkryptBatchAPI] Calling batch API with {len(texts)} texts"
                )

            # Get configurable timeout from TimeoutManager
            from secure_mcp_gateway.services.timeout import get_timeout_manager

            timeout_manager = get_timeout_manager()
            timeout_value = timeout_manager.get_timeout("guardrail")

            # Use TimeoutManager to execute the API call with proper timeout handling
            async def _make_api_call():
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.batch_url,
                        json=payload,
                        headers=headers,
                        # Remove aiohttp.ClientTimeout - let TimeoutManager handle timeout
                    ) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            if response.status in (401, 403):
                                # Mark explicitly as unauthorized so callers can fail-closed
                                raise Exception(
                                    f"UNAUTHORIZED: API error {response.status}: {error_text}"
                                )
                            raise Exception(
                                f"API error {response.status}: {error_text}"
                            )

                        result = await response.json()
                        return result

            # Execute with TimeoutManager for proper metrics and escalation
            timeout_result = await timeout_manager.execute_with_timeout(
                _make_api_call, "guardrail", f"batch_api_{len(texts)}_texts"
            )

            if not timeout_result.success:
                if timeout_result.error:
                    raise timeout_result.error
                else:
                    raise Exception("API call failed")

            result = timeout_result.result

            if self.debug:
                logger.debug("[EnkryptBatchAPI] Batch API response received")

            return result

        except Exception as e:
            logger.error(f"[EnkryptBatchAPI] Batch API call failed: {e}")

            # Use standardized error handling
            from secure_mcp_gateway.error_handling import error_logger
            from secure_mcp_gateway.exceptions import (
                ErrorCode,
                ErrorContext,
                create_guardrail_error,
            )

            # Create error context for proper tracing
            context = ErrorContext(
                operation="guardrail_batch_api",
                request_id=getattr(self, "request_id", None),
                server_name=getattr(self, "server_name", None),
            )

            # Handle different error types with proper error codes
            if "UNAUTHORIZED:" in str(e):
                # Propagate unauthorized marker via exception so upper layers can block
                raise
            elif "timeout" in str(e).lower() or "timed out" in str(e).lower():
                # Create standardized timeout error
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_TIMEOUT,
                    message=f"Guardrail API call timed out: {e}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)
                raise error
            else:
                # Create standardized API error
                error = create_guardrail_error(
                    code=ErrorCode.GUARDRAIL_API_ERROR,
                    message=f"Guardrail API call failed: {e}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)
                # FAIL CLOSED: Raise error instead of returning safe default
                raise error


class EnkryptGuardrailProvider(GuardrailProvider):
    """
    Enkrypt AI guardrail provider implementation.

    This provider is fully self-contained with NO dependency on guardrail_service.
    All API calls are made directly from this provider.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.enkryptai.com",
        config: Dict[str, Any] = None,
    ):
        # Use provided credentials; if missing, fetch from full config as fallback
        self.api_key = api_key
        self.base_url = base_url
        self.config = config or {}

        # Initialize registration guardrail
        # If api_key not set or is literal 'null', fallback to config values
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
        """Get provider name."""
        return "enkrypt"

    def get_version(self) -> str:
        """Get provider version."""
        return "2.0.0"

    def _get_api_credentials(self) -> tuple[str, str]:
        """Get API key and base URL from plugin configuration."""
        import json

        from secure_mcp_gateway.utils import (
            CONFIG_PATH,
            DOCKER_CONFIG_PATH,
            does_file_exist,
            is_docker,
        )

        # Load the full configuration file directly
        is_running_in_docker = is_docker()
        picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH

        if does_file_exist(picked_config_path):
            with open(picked_config_path, encoding="utf-8") as f:
                full_config = json.load(f)
        else:
            # Fallback to self values if config file not found
            return self.api_key, self.base_url

        plugins_config = full_config.get("plugins", {})
        guardrails_config = plugins_config.get("guardrails", {}).get("config", {})
        auth_config = plugins_config.get("auth", {}).get("config", {})

        api_key = guardrails_config.get(
            "api_key", auth_config.get("api_key", self.api_key)
        )
        base_url = guardrails_config.get(
            "base_url", auth_config.get("base_url", self.base_url)
        )

        return api_key, base_url

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create Enkrypt input guardrail."""
        if not config.get("enabled", False):
            return None

        api_key, base_url = self._get_api_credentials()
        return EnkryptInputGuardrail(config, api_key, base_url)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """Create Enkrypt output guardrail."""
        if not config.get("enabled", False):
            return None

        api_key, base_url = self._get_api_credentials()
        return EnkryptOutputGuardrail(config, api_key, base_url)

    def create_pii_handler(self, config: Dict[str, Any]) -> Optional[PIIHandler]:
        """Create Enkrypt PII handler."""
        if config.get("pii_redaction", False):
            api_key, base_url = self._get_api_credentials()
            return EnkryptPIIHandler(api_key, base_url)
        return None

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate Enkrypt configuration."""
        if config.get("enabled", False):
            # Policy name is required when enabled
            if not config.get("policy_name"):
                return False
        return True

    def get_required_config_keys(self) -> List[str]:
        """Get required config keys."""
        return ["enabled", "policy_name"]

    async def validate_server_registration(
        self, request: ServerRegistrationRequest
    ) -> Optional[GuardrailResponse]:
        """Validate server registration using Enkrypt batch API."""
        return await self.registration_guardrail.validate_server(request)

    async def validate_tool_registration(
        self, request: ToolRegistrationRequest
    ) -> Optional[GuardrailResponse]:
        """Validate tool registration using Enkrypt batch API."""
        return await self.registration_guardrail.validate_tools(request)

    def get_metadata(self) -> Dict[str, Any]:
        """Get provider metadata."""
        base_metadata = super().get_metadata()
        base_metadata.update(
            {
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
            }
        )
        return base_metadata
