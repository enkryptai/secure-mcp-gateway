"""Abstract guardrail interfaces — ported from the Secure MCP Gateway.

The provider / factory / registry pattern is intentionally identical to
``secure_mcp_gateway.plugins.guardrails.base`` so that future providers
written for the gateway can be reused in the SDK with minimal effort.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GuardrailAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    MODIFY = "modify"


class ViolationType(str, Enum):
    PII = "pii"
    INJECTION_ATTACK = "injection_attack"
    TOXICITY = "toxicity"
    NSFW = "nsfw"
    KEYWORD_VIOLATION = "keyword_detector"
    POLICY_VIOLATION = "policy_violation"
    BIAS = "bias"
    RELEVANCY_FAILURE = "relevancy"
    ADHERENCE_FAILURE = "adherence"
    HALLUCINATION = "hallucination"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GuardrailViolation:
    violation_type: ViolationType
    severity: float  # 0.0 – 1.0
    message: str
    action: GuardrailAction = GuardrailAction.BLOCK
    metadata: dict[str, Any] = field(default_factory=dict)
    redacted_content: str | None = None


@dataclass
class GuardrailRequest:
    content: str
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    server_name: str | None = None
    context: dict[str, Any] | None = None


@dataclass
class GuardrailResponse:
    is_safe: bool
    action: GuardrailAction
    violations: list[GuardrailViolation] = field(default_factory=list)
    modified_content: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Protocols (structural typing — any object matching the shape works)
# ---------------------------------------------------------------------------

@runtime_checkable
class InputGuardrail(Protocol):
    async def validate(self, request: GuardrailRequest) -> GuardrailResponse: ...
    def get_supported_detectors(self) -> list[ViolationType]: ...


@runtime_checkable
class OutputGuardrail(Protocol):
    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse: ...

    def get_supported_detectors(self) -> list[ViolationType]: ...


@runtime_checkable
class PIIHandler(Protocol):
    async def detect_pii(self, content: str) -> list[GuardrailViolation]: ...
    async def redact_pii(self, content: str) -> tuple[str, dict[str, Any]]: ...
    async def restore_pii(self, content: str, pii_mapping: dict[str, Any]) -> str: ...


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------

class GuardrailProvider(ABC):
    """A provider bundles an input guardrail, output guardrail, and optional
    PII handler behind a single configuration surface."""

    @abstractmethod
    def get_name(self) -> str: ...

    @abstractmethod
    def get_version(self) -> str: ...

    @abstractmethod
    def create_input_guardrail(self, config: dict[str, Any]) -> InputGuardrail | None: ...

    @abstractmethod
    def create_output_guardrail(self, config: dict[str, Any]) -> OutputGuardrail | None: ...

    def create_pii_handler(self, config: dict[str, Any]) -> PIIHandler | None:
        return None

    def validate_config(self, config: dict[str, Any]) -> bool:
        return True

    def get_required_config_keys(self) -> list[str]:
        return []

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": self.get_name(),
            "version": self.get_version(),
        }


# ---------------------------------------------------------------------------
# Registry + Factory (Dependency-Inversion-Principle compliant)
# ---------------------------------------------------------------------------

class GuardrailRegistry:
    """Holds the active guardrail provider.  Only one at a time for
    simplicity; swap in a ``dict`` keyed by name if multi-provider is needed.
    """

    def __init__(self) -> None:
        self._provider: GuardrailProvider | None = None

    def register(self, provider: GuardrailProvider) -> None:
        self._provider = provider

    def get_provider(self) -> GuardrailProvider | None:
        return self._provider

    def clear(self) -> None:
        self._provider = None


class GuardrailFactory:
    """Creates guardrail instances from a registered provider."""

    def __init__(self, registry: GuardrailRegistry) -> None:
        self._registry = registry

    def create_input_guardrail(self, config: dict[str, Any]) -> InputGuardrail | None:
        provider = self._registry.get_provider()
        if provider is None:
            return None
        if not provider.validate_config(config):
            return None
        return provider.create_input_guardrail(config)

    def create_output_guardrail(self, config: dict[str, Any]) -> OutputGuardrail | None:
        provider = self._registry.get_provider()
        if provider is None:
            return None
        if not provider.validate_config(config):
            return None
        return provider.create_output_guardrail(config)

    def create_pii_handler(self, config: dict[str, Any]) -> PIIHandler | None:
        provider = self._registry.get_provider()
        if provider is None:
            return None
        return provider.create_pii_handler(config)
