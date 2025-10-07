"""
Example Custom Guardrail Providers

This module shows how to implement custom guardrail providers for different
services like OpenAI Moderation, AWS Comprehend, or completely custom solutions.

These are example implementations to demonstrate the plugin architecture.
"""

from typing import Any, Dict, List, Optional

import httpx

from secure_mcp_gateway.plugins.guardrails.base import (
    GuardrailAction,
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    InputGuardrail,
    OutputGuardrail,
    ViolationType,
)

# ============================================================================
# OpenAI Moderation API Provider
# ============================================================================


class OpenAIInputGuardrail:
    """OpenAI Moderation API input guardrail implementation."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get("api_key", "")
        self.threshold = config.get("threshold", 0.7)
        self.block_categories = config.get(
            "block_categories", ["hate", "violence", "sexual"]
        )

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate using OpenAI Moderation API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/moderations",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"input": request.content},
            )

            result = response.json()
            moderation_result = result["results"][0]

            violations = []
            is_safe = True

            # Check categories
            categories = moderation_result.get("categories", {})
            category_scores = moderation_result.get("category_scores", {})

            for category, flagged in categories.items():
                if flagged and category in self.block_categories:
                    score = category_scores.get(category, 0.0)
                    if score >= self.threshold:
                        is_safe = False
                        violations.append(
                            GuardrailViolation(
                                violation_type=self._map_category_to_violation(
                                    category
                                ),
                                severity=score,
                                message=f"Content flagged for {category}",
                                action=GuardrailAction.BLOCK,
                                metadata={"category": category, "score": score},
                            )
                        )

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=violations,
                metadata={"provider": "openai-moderation"},
            )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported detectors."""
        return [
            ViolationType.TOXIC_CONTENT,
            ViolationType.NSFW_CONTENT,
            ViolationType.CUSTOM,
        ]

    def _map_category_to_violation(self, category: str) -> ViolationType:
        """Map OpenAI categories to violation types."""
        mapping = {
            "hate": ViolationType.TOXIC_CONTENT,
            "violence": ViolationType.TOXIC_CONTENT,
            "sexual": ViolationType.NSFW_CONTENT,
            "self-harm": ViolationType.TOXIC_CONTENT,
        }
        return mapping.get(category, ViolationType.CUSTOM)


class OpenAIGuardrailProvider(GuardrailProvider):
    """OpenAI Moderation API provider."""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_name(self) -> str:
        return "openai-moderation"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create OpenAI input guardrail."""
        if not config.get("enabled", False):
            return None

        config["api_key"] = self.api_key
        return OpenAIInputGuardrail(config)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """OpenAI Moderation can also work on outputs."""
        if not config.get("enabled", False):
            return None

        # Reuse the same implementation for output
        config["api_key"] = self.api_key

        class OpenAIOutputGuardrail:
            def __init__(self, input_guardrail):
                self._input_guardrail = input_guardrail

            async def validate(
                self, response_content: str, original_request: GuardrailRequest
            ) -> GuardrailResponse:
                # Create a new request with the response content
                return await self._input_guardrail.validate(
                    GuardrailRequest(content=response_content)
                )

            def get_supported_detectors(self) -> List[ViolationType]:
                return self._input_guardrail.get_supported_detectors()

        return OpenAIOutputGuardrail(OpenAIInputGuardrail(config))

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration."""
        if config.get("enabled", False):
            if not self.api_key:
                return False
        return True

    def get_required_config_keys(self) -> List[str]:
        """Get required config keys."""
        return ["enabled"]


# ============================================================================
# AWS Comprehend Provider (Example)
# ============================================================================


class AWSComprehendInputGuardrail:
    """AWS Comprehend sentiment/PII detection guardrail."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.region = config.get("region", "us-east-1")
        self.detect_pii = config.get("detect_pii", True)
        self.detect_sentiment = config.get("detect_sentiment", True)
        self.negative_threshold = config.get("negative_threshold", 0.8)

        # In real implementation, initialize boto3 client here
        # import boto3
        # self.client = boto3.client('comprehend', region_name=self.region)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate using AWS Comprehend."""
        violations = []
        is_safe = True

        # Example implementation (would need boto3 in real use)
        # This is pseudo-code to show the structure

        # Detect PII
        if self.detect_pii:
            # pii_result = await self._detect_pii_entities(request.content)
            # if pii_result['Entities']:
            #     violations.append(GuardrailViolation(...))
            pass

        # Detect sentiment
        if self.detect_sentiment:
            # sentiment_result = await self._detect_sentiment(request.content)
            # if sentiment_result['Sentiment'] == 'NEGATIVE':
            #     score = sentiment_result['SentimentScore']['Negative']
            #     if score >= self.negative_threshold:
            #         violations.append(GuardrailViolation(...))
            pass

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.WARN,
            violations=violations,
            metadata={"provider": "aws-comprehend", "region": self.region},
        )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported detectors."""
        return [ViolationType.PII, ViolationType.TOXIC_CONTENT]


class AWSComprehendProvider(GuardrailProvider):
    """AWS Comprehend provider."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region

    def get_name(self) -> str:
        return "aws-comprehend"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create AWS Comprehend input guardrail."""
        if not config.get("enabled", False):
            return None

        config["region"] = self.region
        return AWSComprehendInputGuardrail(config)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """AWS Comprehend can work on outputs too."""
        # Similar to input, can be reused
        return None

    def get_required_config_keys(self) -> List[str]:
        return ["enabled"]


# ============================================================================
# Custom Regex/Keyword Based Provider (Simple Example)
# ============================================================================


class CustomKeywordGuardrail:
    """Simple keyword-based guardrail."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocked_keywords = config.get("blocked_keywords", [])
        self.case_sensitive = config.get("case_sensitive", False)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate using keyword matching."""
        violations = []
        content = request.content
        if not self.case_sensitive:
            content = content.lower()
            blocked_keywords = [kw.lower() for kw in self.blocked_keywords]
        else:
            blocked_keywords = self.blocked_keywords

        for keyword in blocked_keywords:
            if keyword in content:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.KEYWORD_VIOLATION,
                        severity=1.0,
                        message=f"Blocked keyword detected: {keyword}",
                        action=GuardrailAction.BLOCK,
                        metadata={"keyword": keyword},
                    )
                )

        is_safe = len(violations) == 0

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=violations,
            metadata={"provider": "custom-keyword"},
        )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get supported detectors."""
        return [ViolationType.KEYWORD_VIOLATION]


class CustomKeywordProvider(GuardrailProvider):
    """Custom keyword-based provider."""

    def __init__(self, blocked_keywords: List[str]):
        self.blocked_keywords = blocked_keywords

    def get_name(self) -> str:
        return "custom-keyword"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create keyword input guardrail."""
        if not config.get("enabled", False):
            return None

        config["blocked_keywords"] = self.blocked_keywords
        return CustomKeywordGuardrail(config)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """Create keyword output guardrail."""
        if not config.get("enabled", False):
            return None

        config["blocked_keywords"] = self.blocked_keywords

        class CustomKeywordOutputGuardrail:
            def __init__(self, input_guardrail):
                self._input_guardrail = input_guardrail

            async def validate(
                self, response_content: str, original_request: GuardrailRequest
            ) -> GuardrailResponse:
                return await self._input_guardrail.validate(
                    GuardrailRequest(content=response_content)
                )

            def get_supported_detectors(self) -> List[ViolationType]:
                return self._input_guardrail.get_supported_detectors()

        return CustomKeywordOutputGuardrail(CustomKeywordGuardrail(config))

    def get_required_config_keys(self) -> List[str]:
        return ["enabled", "blocked_keywords"]


# ============================================================================
# Composite Provider (Combines Multiple Providers)
# ============================================================================


class CompositeGuardrail:
    """Combines multiple guardrails with AND/OR logic."""

    def __init__(self, guardrails: List[InputGuardrail], logic: str = "OR"):
        """
        Args:
            guardrails: List of guardrails to combine
            logic: "OR" (any violation blocks) or "AND" (all must violate to block)
        """
        self.guardrails = guardrails
        self.logic = logic.upper()

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate using all guardrails."""
        all_violations = []
        all_safe = []

        for guardrail in self.guardrails:
            result = await guardrail.validate(request)
            all_violations.extend(result.violations)
            all_safe.append(result.is_safe)

        # Apply logic
        is_safe = all(all_safe) if self.logic == "OR" else any(all_safe)

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=all_violations,
            metadata={"provider": "composite", "logic": self.logic},
        )

    def get_supported_detectors(self) -> List[ViolationType]:
        """Get all supported detectors from all guardrails."""
        all_detectors = set()
        for guardrail in self.guardrails:
            all_detectors.update(guardrail.get_supported_detectors())
        return list(all_detectors)


class CompositeGuardrailProvider(GuardrailProvider):
    """
    Composite provider that combines multiple providers.

    This is useful when you want to use multiple guardrail services together.
    For example: Use Enkrypt for policy violations AND OpenAI for moderation.
    """

    def __init__(self, providers: List[GuardrailProvider], logic: str = "OR"):
        self.providers = providers
        self.logic = logic

    def get_name(self) -> str:
        provider_names = "_".join([p.get_name() for p in self.providers])
        return f"composite_{provider_names}"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """Create composite input guardrail."""
        if not config.get("enabled", False):
            return None

        guardrails = []
        for provider in self.providers:
            guardrail = provider.create_input_guardrail(config)
            if guardrail:
                guardrails.append(guardrail)

        if not guardrails:
            return None

        return CompositeGuardrail(guardrails, self.logic)

    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """Create composite output guardrail."""
        if not config.get("enabled", False):
            return None

        guardrails = []
        for provider in self.providers:
            guardrail = provider.create_output_guardrail(config)
            if guardrail:
                guardrails.append(guardrail)

        if not guardrails:
            return None

        class CompositeOutputGuardrail:
            def __init__(self, guardrails_list, logic):
                self.guardrails = guardrails_list
                self.logic = logic

            async def validate(
                self, response_content: str, original_request: GuardrailRequest
            ) -> GuardrailResponse:
                all_violations = []
                all_safe = []

                for guardrail in self.guardrails:
                    result = await guardrail.validate(
                        response_content, original_request
                    )
                    all_violations.extend(result.violations)
                    all_safe.append(result.is_safe)

                # Apply logic
                is_safe = all(all_safe) if self.logic == "OR" else any(all_safe)

                return GuardrailResponse(
                    is_safe=is_safe,
                    action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                    violations=all_violations,
                    metadata={"provider": "composite", "logic": self.logic},
                )

            def get_supported_detectors(self) -> List[ViolationType]:
                all_detectors = set()
                for guardrail in self.guardrails:
                    all_detectors.update(guardrail.get_supported_detectors())
                return list(all_detectors)

        return CompositeOutputGuardrail(guardrails, self.logic)

    def get_required_config_keys(self) -> List[str]:
        return ["enabled"]

    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata including all provider metadata."""
        base = super().get_metadata()
        base["providers"] = [p.get_metadata() for p in self.providers]
        base["logic"] = self.logic
        return base
