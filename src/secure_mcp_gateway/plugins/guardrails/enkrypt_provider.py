"""
Enkrypt Guardrail Provider Implementation

This module implements the GuardrailProvider interface for Enkrypt AI guardrails.
It wraps the existing Enkrypt guardrail service to work with the plugin architecture.

Example Usage:
    ```python
    # Register Enkrypt provider
    registry = GuardrailRegistry()
    enkrypt_provider = EnkryptGuardrailProvider(
        api_key="your-api-key",
        base_url="https://api.enkryptai.com"
    )
    registry.register(enkrypt_provider)

    # Create guardrails via factory
    factory = GuardrailFactory(registry)
    input_guardrail = factory.create_input_guardrail("enkrypt", {
        "policy_name": "My Policy",
        "enabled": True,
        "block": ["policy_violation", "pii"]
    })
    ```
"""

from typing import Any, Dict, List, Optional

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
from secure_mcp_gateway.services.guardrails.guardrail_service import GuardrailService


class EnkryptInputGuardrail:
    """Enkrypt implementation of InputGuardrail."""

    def __init__(self, config: Dict[str, Any], guardrail_service: GuardrailService):
        self.config = config
        self.guardrail_service = guardrail_service
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self.additional_config = config.get("additional_config", {})

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate input using Enkrypt guardrails."""
        # Call existing Enkrypt guardrail service
        result = await self.guardrail_service.check_input_guardrails(
            tool_name=request.tool_name or "",
            tool_args=request.tool_args or {},
            policy_name=self.policy_name,
            block_list=self.block_list,
            additional_config=self.additional_config,
        )

        # Transform Enkrypt response to standard format
        violations = []
        is_safe = result.get("status") == "success"
        action = GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK

        # Parse Enkrypt violations
        if "violations" in result:
            for violation in result["violations"]:
                violations.append(
                    GuardrailViolation(
                        violation_type=self._map_violation_type(
                            violation.get("type", "")
                        ),
                        severity=violation.get("severity", 0.5),
                        message=violation.get("message", ""),
                        action=GuardrailAction.BLOCK
                        if violation.get("type") in self.block_list
                        else GuardrailAction.WARN,
                        metadata=violation.get("metadata", {}),
                    )
                )

        return GuardrailResponse(
            is_safe=is_safe,
            action=action,
            violations=violations,
            modified_content=result.get("modified_content"),
            metadata=result.get("metadata", {}),
            processing_time_ms=result.get("processing_time_ms"),
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
    """Enkrypt implementation of OutputGuardrail."""

    def __init__(self, config: Dict[str, Any], guardrail_service: GuardrailService):
        self.config = config
        self.guardrail_service = guardrail_service
        self.policy_name = config.get("policy_name", "")
        self.block_list = config.get("block", [])
        self.additional_config = config.get("additional_config", {})

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        """Validate output using Enkrypt guardrails."""
        # Call existing Enkrypt guardrail service
        result = await self.guardrail_service.check_output_guardrails(
            response_content=response_content,
            original_prompt=original_request.content,
            policy_name=self.policy_name,
            block_list=self.block_list,
            additional_config=self.additional_config,
        )

        # Transform Enkrypt response to standard format
        violations = []
        is_safe = result.get("status") == "success"
        action = GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK

        # Parse Enkrypt violations
        if "violations" in result:
            for violation in result["violations"]:
                violations.append(
                    GuardrailViolation(
                        violation_type=self._map_violation_type(
                            violation.get("type", "")
                        ),
                        severity=violation.get("severity", 0.5),
                        message=violation.get("message", ""),
                        action=GuardrailAction.BLOCK
                        if violation.get("type") in self.block_list
                        else GuardrailAction.WARN,
                        metadata=violation.get("metadata", {}),
                    )
                )

        return GuardrailResponse(
            is_safe=is_safe,
            action=action,
            violations=violations,
            modified_content=result.get("modified_content"),
            metadata=result.get("metadata", {}),
            processing_time_ms=result.get("processing_time_ms"),
        )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported violation types for output."""
        return [
            ViolationType.PII,
            ViolationType.POLICY_VIOLATION,
            ViolationType.RELEVANCY_FAILURE,
            ViolationType.ADHERENCE_FAILURE,
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
    """Enkrypt implementation of PIIHandler."""

    def __init__(self, guardrail_service: GuardrailService):
        self.guardrail_service = guardrail_service

    async def detect_pii(self, content: str) -> List[GuardrailViolation]:
        """Detect PII using Enkrypt."""
        result = await self.guardrail_service.detect_pii(content)
        violations = []

        if result.get("has_pii"):
            for pii_item in result.get("pii_items", []):
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.PII,
                        severity=pii_item.get("confidence", 0.5),
                        message=f"PII detected: {pii_item.get('type')}",
                        action=GuardrailAction.MODIFY,
                        metadata=pii_item,
                    )
                )

        return violations

    async def redact_pii(self, content: str) -> tuple[str, Dict[str, Any]]:
        """Redact PII using Enkrypt."""
        result = await self.guardrail_service.redact_pii(content)
        return result.get("redacted_content", content), result.get("pii_mapping", {})

    async def restore_pii(self, content: str, pii_mapping: Dict[str, Any]) -> str:
        """Restore PII using Enkrypt."""
        result = await self.guardrail_service.restore_pii(content, pii_mapping)
        return result.get("restored_content", content)


class EnkryptGuardrailProvider(GuardrailProvider):
    """
    Enkrypt AI guardrail provider implementation.

    This wraps the existing GuardrailService to work with the
    plugin architecture while maintaining backward compatibility.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.enkryptai.com"):
        self.api_key = api_key
        self.base_url = base_url
        self.guardrail_service = GuardrailService(api_key, base_url)

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

        return EnkryptInputGuardrail(config, self.guardrail_service)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """Create Enkrypt output guardrail."""
        if not config.get("enabled", False):
            return None

        return EnkryptOutputGuardrail(config, self.guardrail_service)

    def create_pii_handler(self, config: Dict[str, Any]) -> Optional[PIIHandler]:
        """Create Enkrypt PII handler."""
        if config.get("pii_redaction", False):
            return EnkryptPIIHandler(self.guardrail_service)
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
                "max_content_length": 100000,  # Example limit
            }
        )
        return base_metadata
