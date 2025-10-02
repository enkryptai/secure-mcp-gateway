"""
Enkrypt Guardrail Provider Implementation

This module implements the GuardrailProvider interface for Enkrypt AI guardrails.
It is now fully self-contained with NO dependency on guardrail_service.

All Enkrypt API calls are made directly from this module.

Example Usage:
    ```python
    # Register Enkrypt provider
    from secure_mcp_gateway.plugins.guardrails import (
        EnkryptGuardrailProvider,
        GuardrailRequest,
    )

    provider = EnkryptGuardrailProvider(
        api_key="your-api-key",
        base_url="https://api.enkryptai.com"
    )

    # Create input guardrail
    input_guardrail = provider.create_input_guardrail({
        "enabled": True,
        "policy_name": "My Policy",
        "block": ["policy_violation", "pii"],
        "additional_config": {
            "pii_redaction": True
        }
    })

    # Validate input
    request = GuardrailRequest(
        content="Some text to validate",
        tool_name="my_tool",
        tool_args={"param": "value"}
    )

    response = await input_guardrail.validate(request)
    if not response.is_safe:
        print(f"Violations: {response.violations}")
    ```
"""

import time
from typing import Any, Dict, List, Optional

import aiohttp

from secure_mcp_gateway.plugins.guardrails.base import (
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
from secure_mcp_gateway.utils import sys_print


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

        try:
            # Prepare payload
            payload = {"text": request.content}
            headers = {
                "X-Enkrypt-Policy": self.policy_name,
                "apikey": self.api_key,
                "Content-Type": "application/json",
            }

            if self.debug:
                sys_print(
                    f"[EnkryptInputGuardrail] Validating with policy: {self.policy_name}",
                    is_debug=True,
                )
                sys_print(f"[EnkryptInputGuardrail] Payload: {payload}", is_debug=True)

            # Make API call
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.guardrail_url, json=payload, headers=headers
                ) as response:
                    resp_json = await response.json()

            if self.debug:
                sys_print(
                    f"[EnkryptInputGuardrail] Response: {resp_json}", is_debug=True
                )

            # Check for API errors
            if resp_json.get("error"):
                sys_print(
                    f"[EnkryptInputGuardrail] API error: {resp_json.get('error')}",
                    is_error=True,
                )
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
                    metadata={"api_error": True},
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
            sys_print(f"[EnkryptInputGuardrail] Exception: {e}", is_error=True)
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
            sys_print(f"[EnkryptOutputGuardrail] Exception: {e}", is_error=True)
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
                sys_print(
                    f"[EnkryptOutputGuardrail] Policy check for: {self.policy_name}",
                    is_debug=True,
                )

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.guardrail_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                sys_print(
                    f"[EnkryptOutputGuardrail] Policy result: {result}", is_debug=True
                )

            return result

        except Exception as e:
            sys_print(
                f"[EnkryptOutputGuardrail] Policy check error: {e}", is_error=True
            )
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
                sys_print("[EnkryptOutputGuardrail] Checking relevancy", is_debug=True)

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.relevancy_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                sys_print(
                    f"[EnkryptOutputGuardrail] Relevancy result: {result}",
                    is_debug=True,
                )

            return result

        except Exception as e:
            sys_print(
                f"[EnkryptOutputGuardrail] Relevancy check error: {e}", is_error=True
            )
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
                sys_print("[EnkryptOutputGuardrail] Checking adherence", is_debug=True)

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.adherence_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                sys_print(
                    f"[EnkryptOutputGuardrail] Adherence result: {result}",
                    is_debug=True,
                )

            return result

        except Exception as e:
            sys_print(
                f"[EnkryptOutputGuardrail] Adherence check error: {e}", is_error=True
            )
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
                sys_print(
                    "[EnkryptOutputGuardrail] Checking hallucination", is_debug=True
                )

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.hallucination_url, json=payload, headers=headers
                ) as response:
                    result = await response.json()

            if self.debug:
                sys_print(
                    f"[EnkryptOutputGuardrail] Hallucination result: {result}",
                    is_debug=True,
                )

            return result

        except Exception as e:
            sys_print(
                f"[EnkryptOutputGuardrail] Hallucination check error: {e}",
                is_error=True,
            )
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
            sys_print(f"[EnkryptPIIHandler] PII detection error: {e}", is_error=True)
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
            sys_print(f"[EnkryptPIIHandler] PII redaction error: {e}", is_error=True)
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
            sys_print(f"[EnkryptPIIHandler] PII restoration error: {e}", is_error=True)
            return content


class EnkryptGuardrailProvider(GuardrailProvider):
    """
    Enkrypt AI guardrail provider implementation.

    This provider is fully self-contained with NO dependency on guardrail_service.
    All API calls are made directly from this provider.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.enkryptai.com"):
        self.api_key = api_key
        self.base_url = base_url

    def get_name(self) -> str:
        """Get provider name."""
        return "enkrypt"

    def get_version(self) -> str:
        """Get provider version."""
        return "2.0.0"

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create Enkrypt input guardrail."""
        if not config.get("enabled", False):
            return None

        return EnkryptInputGuardrail(config, self.api_key, self.base_url)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """Create Enkrypt output guardrail."""
        if not config.get("enabled", False):
            return None

        return EnkryptOutputGuardrail(config, self.api_key, self.base_url)

    def create_pii_handler(self, config: Dict[str, Any]) -> Optional[PIIHandler]:
        """Create Enkrypt PII handler."""
        if config.get("pii_redaction", False):
            return EnkryptPIIHandler(self.api_key, self.base_url)
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

    def get_metadata(self) -> Dict[str, Any]:
        """Get provider metadata."""
        base_metadata = super().get_metadata()
        base_metadata.update(
            {
                "api_url": self.base_url,
                "supports_async": True,
                "supports_batch": False,
                "max_content_length": 100000,
                "supports_policy_detection": True,
                "supports_relevancy": True,
                "supports_adherence": True,
                "supports_hallucination": True,
                "supports_pii_redaction": True,
            }
        )
        return base_metadata
