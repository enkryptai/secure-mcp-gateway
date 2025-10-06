"""
Guardrail Plugin Base Module

This module defines the base interfaces and abstract classes for guardrail plugins
following SOLID principles:

- Single Responsibility: Each interface handles one aspect of guardrails
- Open/Closed: Open for extension (new plugins), closed for modification
- Liskov Substitution: All plugins can be used interchangeably
- Interface Segregation: Separate interfaces for input/output guardrails
- Dependency Inversion: Depend on abstractions, not concrete implementations

Example Usage:
    ```python
    # Implement a custom guardrail provider
    class MyGuardrailProvider(GuardrailProvider):
        def get_name(self) -> str:
            return "my-guardrails"

        def create_input_guardrail(self, config: Dict[str, Any]) -> InputGuardrail:
            return MyInputGuardrail(config)

        def create_output_guardrail(self, config: Dict[str, Any]) -> OutputGuardrail:
            return MyOutputGuardrail(config)

    # Register the provider
    registry = GuardrailRegistry()
    registry.register(MyGuardrailProvider())

    # Use via factory
    factory = GuardrailFactory(registry)
    input_guardrail = factory.create_input_guardrail("my-guardrails", config)
    ```
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

# ============================================================================
# Domain Models (Shared Data Structures)
# ============================================================================


class GuardrailAction(Enum):
    """Actions that can be taken when a guardrail is triggered."""

    ALLOW = "allow"  # Continue processing
    BLOCK = "block"  # Stop processing and return error
    WARN = "warn"  # Log warning but continue
    MODIFY = "modify"  # Modify content and continue


class ViolationType(Enum):
    """Types of violations that can be detected."""

    # Input violations
    PII = "pii"
    INJECTION_ATTACK = "injection_attack"
    TOXIC_CONTENT = "toxicity"
    NSFW_CONTENT = "nsfw"
    KEYWORD_VIOLATION = "keyword_detector"
    POLICY_VIOLATION = "policy_violation"
    BIAS = "bias"
    SPONGE_ATTACK = "sponge_attack"
    SYSTEM_PROMPT_PROTECTION = "system_prompt_protection"
    COPYRIGHT_PROTECTION = "copyright_protection"

    # Output violations
    RELEVANCY_FAILURE = "relevancy"
    ADHERENCE_FAILURE = "adherence"
    HALLUCINATION = "hallucination"

    # Generic
    CUSTOM = "custom"


@dataclass
class GuardrailViolation:
    """Represents a detected violation."""

    violation_type: ViolationType
    severity: float  # 0.0 (low) to 1.0 (high)
    message: str
    action: GuardrailAction
    metadata: Dict[str, Any]  # Additional context
    suggested_action: Optional[str] = None
    redacted_content: Optional[str] = None  # For PII redaction


@dataclass
class GuardrailRequest:
    """Input data for guardrail evaluation."""

    content: str  # The content to evaluate
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    server_name: Optional[str] = None
    context: Optional[Dict[str, Any]] = None  # Additional context


@dataclass
class ServerRegistrationRequest:
    """Request for server registration validation."""

    server_name: str
    server_config: Dict[str, Any]
    server_description: Optional[str] = None
    server_command: Optional[str] = None
    server_metadata: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None


@dataclass
class ToolRegistrationRequest:
    """Request for tool registration validation."""

    server_name: str
    tools: List[Dict[str, Any]]  # List of tool schemas with name, description, etc.
    validation_mode: str = "filter"  # "filter" or "block_all"
    context: Optional[Dict[str, Any]] = None


@dataclass
class GuardrailResponse:
    """Result of guardrail evaluation."""

    is_safe: bool
    action: GuardrailAction
    violations: List[GuardrailViolation]
    modified_content: Optional[str] = None  # If content was modified
    metadata: Dict[str, Any] = None  # Provider-specific metadata
    processing_time_ms: Optional[float] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# ============================================================================
# Core Interfaces (Interface Segregation Principle)
# ============================================================================


@runtime_checkable
class InputGuardrail(Protocol):
    """
    Interface for input guardrails that validate requests before execution.

    Input guardrails check content that is sent TO the MCP server.
    """

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """
        Validate input content before it's sent to the MCP server.

        Args:
            request: The guardrail request containing content to validate

        Returns:
            GuardrailResponse with validation results
        """
        ...

    def get_supported_detectors(self) -> List[ViolationType]:
        """
        Get list of violation types this guardrail can detect.

        Returns:
            List of supported ViolationType enums
        """
        ...


@runtime_checkable
class OutputGuardrail(Protocol):
    """
    Interface for output guardrails that validate responses after execution.

    Output guardrails check content that is returned FROM the MCP server.
    """

    async def validate(
        self, response_content: str, original_request: GuardrailRequest
    ) -> GuardrailResponse:
        """
        Validate output content after it's received from the MCP server.

        Args:
            response_content: The content returned from the MCP server
            original_request: The original request for context

        Returns:
            GuardrailResponse with validation results
        """
        ...

    def get_supported_detectors(self) -> List[ViolationType]:
        """
        Get list of violation types this guardrail can detect.

        Returns:
            List of supported ViolationType enums
        """
        ...


@runtime_checkable
class PIIHandler(Protocol):
    """
    Interface for PII detection and redaction.

    Separate interface following Interface Segregation Principle.
    """

    async def detect_pii(self, content: str) -> List[GuardrailViolation]:
        """Detect PII in content."""
        ...

    async def redact_pii(self, content: str) -> tuple[str, Dict[str, Any]]:
        """
        Redact PII from content and return mapping for restoration.

        Returns:
            Tuple of (redacted_content, pii_mapping)
        """
        ...

    async def restore_pii(self, content: str, pii_mapping: Dict[str, Any]) -> str:
        """Restore PII using the mapping from redaction."""
        ...


# ============================================================================
# Provider Interface (Open/Closed Principle)
# ============================================================================


class GuardrailProvider(ABC):
    """
    Abstract base class for guardrail providers.

    This follows the Open/Closed Principle - open for extension by creating
    new providers, closed for modification of the base system.

    Each provider (Enkrypt, OpenAI Moderation, AWS Comprehend, custom, etc.)
    implements this interface to provide their guardrail implementation.
    """

    @abstractmethod
    def get_name(self) -> str:
        """
        Get the unique name/identifier for this provider.

        Returns:
            Provider name (e.g., "enkrypt", "openai", "aws-comprehend")
        """
        pass

    @abstractmethod
    def get_version(self) -> str:
        """
        Get the version of this provider.

        Returns:
            Version string (e.g., "1.0.0")
        """
        pass

    @abstractmethod
    def create_input_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """
        Create an input guardrail instance.

        Args:
            config: Provider-specific configuration

        Returns:
            InputGuardrail instance or None if not supported
        """
        pass

    @abstractmethod
    def create_output_guardrail(
        self, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """
        Create an output guardrail instance.

        Args:
            config: Provider-specific configuration

        Returns:
            OutputGuardrail instance or None if not supported
        """
        pass

    def create_pii_handler(self, config: Dict[str, Any]) -> Optional[PIIHandler]:
        """
        Create a PII handler instance (optional).

        Args:
            config: Provider-specific configuration

        Returns:
            PIIHandler instance or None if not supported
        """
        return None

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate provider-specific configuration.

        Args:
            config: Configuration to validate

        Returns:
            True if valid, False otherwise
        """
        return True

    def get_required_config_keys(self) -> List[str]:
        """
        Get list of required configuration keys.

        Returns:
            List of required config key names
        """
        return []

    def validate_server_registration(
        self, request: ServerRegistrationRequest
    ) -> Optional[GuardrailResponse]:
        """
        Validate a server during registration/discovery (optional).

        Args:
            request: Server registration request

        Returns:
            GuardrailResponse or None if not supported
        """
        return None

    def validate_tool_registration(
        self, request: ToolRegistrationRequest
    ) -> Optional[GuardrailResponse]:
        """
        Validate tools during discovery (optional).

        Args:
            request: Tool registration request

        Returns:
            GuardrailResponse or None if not supported
        """
        return None

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get provider metadata (capabilities, limits, etc.).

        Returns:
            Dictionary with provider metadata
        """
        return {
            "name": self.get_name(),
            "version": self.get_version(),
            "supports_input": self.create_input_guardrail({}) is not None,
            "supports_output": self.create_output_guardrail({}) is not None,
            "supports_pii": self.create_pii_handler({}) is not None,
            "supports_registration": True,  # All providers can override this
        }


# ============================================================================
# Registry (Dependency Inversion Principle)
# ============================================================================


class GuardrailRegistry:
    """
    Registry for managing guardrail providers.

    This follows the Dependency Inversion Principle - high-level modules
    depend on this abstraction, not on concrete provider implementations.
    """

    def __init__(self):
        self._provider: Optional[GuardrailProvider] = None

    def register(self, provider: GuardrailProvider) -> None:
        """
        Register a guardrail provider.

        Args:
            provider: The provider to register
        """
        self._provider = provider

    def unregister(self, name: str = None) -> None:
        """
        Unregister the guardrail provider.

        Args:
            name: Provider name (for compatibility, but ignored since only one provider)
        """
        self._provider = None

    def get_provider(self, name: str = None) -> Optional[GuardrailProvider]:
        """
        Get the registered provider.

        Args:
            name: Provider name (for compatibility, but ignored since only one provider)

        Returns:
            GuardrailProvider instance or None if not registered
        """
        return self._provider

    def list_providers(self) -> List[str]:
        """
        Get list of registered provider names.

        Returns:
            List containing the provider name if registered, empty list otherwise
        """
        if self._provider:
            return [self._provider.get_name()]
        return []


# ============================================================================
# Factory (Single Responsibility Principle)
# ============================================================================


class GuardrailFactory:
    """
    Factory for creating guardrail instances.

    This follows the Single Responsibility Principle - its only job is to
    create guardrail instances using the registered providers.
    """

    def __init__(self, registry: GuardrailRegistry):
        self._registry = registry

    def create_input_guardrail(
        self, provider_name: str, config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """
        Create an input guardrail.

        Args:
            provider_name: Name of the provider
            config: Configuration for the guardrail

        Returns:
            InputGuardrail instance or None if provider not found

        Raises:
            ValueError: If provider doesn't support input guardrails
        """
        provider = self._registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        if not provider.validate_config(config):
            raise ValueError(f"Invalid configuration for provider '{provider_name}'")

        guardrail = provider.create_input_guardrail(config)
        if guardrail is None:
            raise ValueError(
                f"Provider '{provider_name}' does not support input guardrails"
            )

        return guardrail

    def create_output_guardrail(
        self, provider_name: str, config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """
        Create an output guardrail.

        Args:
            provider_name: Name of the provider
            config: Configuration for the guardrail

        Returns:
            OutputGuardrail instance or None if provider not found

        Raises:
            ValueError: If provider doesn't support output guardrails
        """
        provider = self._registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        if not provider.validate_config(config):
            raise ValueError(f"Invalid configuration for provider '{provider_name}'")

        guardrail = provider.create_output_guardrail(config)
        if guardrail is None:
            raise ValueError(
                f"Provider '{provider_name}' does not support output guardrails"
            )

        return guardrail

    def create_pii_handler(
        self, provider_name: str, config: Dict[str, Any]
    ) -> Optional[PIIHandler]:
        """
        Create a PII handler.

        Args:
            provider_name: Name of the provider
            config: Configuration for the handler

        Returns:
            PIIHandler instance or None if not supported
        """
        provider = self._registry.get_provider(provider_name)
        if not provider:
            return None

        return provider.create_pii_handler(config)
