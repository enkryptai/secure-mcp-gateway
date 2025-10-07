"""
Guardrail Plugin System for Enkrypt MCP Gateway

This package provides a pluggable architecture for guardrails, allowing
integration of multiple guardrail providers (Enkrypt, OpenAI, AWS, custom).

Main Components:
- base.py: Core interfaces and abstractions (SOLID principles)
- enkrypt_provider.py: Enkrypt AI guardrail provider implementation
- example_providers.py: Example implementations (OpenAI, AWS, custom)
- config_manager.py: Configuration and provider management
- usage_guide.py: Comprehensive usage examples

Quick Start:
    ```python
    from secure_mcp_gateway.plugins.guardrails import (
        initialize_guardrail_system,
        get_guardrail_config_manager
    )

    # Initialize with Enkrypt
    manager = initialize_guardrail_system(
        enkrypt_api_key="your-key"
    )

    # Register custom provider
    from mypackage import MyCustomProvider
    manager.register_provider(MyCustomProvider())

    # Use in server config
    server_config = {
        "input_guardrails_policy": {
            "enabled": True,
            "provider": "my-custom-provider",
            ...
        }
    }

    guardrail = manager.get_input_guardrail(server_config)
    ```

Architecture:
    The system follows SOLID principles:

    - Single Responsibility: Each class has one job
    - Open/Closed: Extend via new providers, don't modify base
    - Liskov Substitution: All providers interchangeable
    - Interface Segregation: Separate interfaces for input/output/PII
    - Dependency Inversion: Depend on abstractions (GuardrailProvider)
"""

from secure_mcp_gateway.plugins.guardrails.base import (
    GuardrailAction,
    GuardrailFactory,
    GuardrailProvider,
    GuardrailRegistry,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
    ViolationType,
)
from secure_mcp_gateway.plugins.guardrails.config_manager import (
    GuardrailConfigManager,
    get_guardrail_config_manager,
    get_guardrail_config_schema,
    initialize_guardrail_system,
    migrate_legacy_config,
    validate_guardrail_config,
)
from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import (
    EnkryptGuardrailProvider,
    EnkryptInputGuardrail,
    EnkryptOutputGuardrail,
    EnkryptPIIHandler,
)

__all__ = [
    # Core Abstractions
    "GuardrailProvider",
    "InputGuardrail",
    "OutputGuardrail",
    "PIIHandler",
    # Data Models
    "GuardrailRequest",
    "GuardrailResponse",
    "GuardrailViolation",
    "ViolationType",
    "GuardrailAction",
    # Registry and Factory
    "GuardrailRegistry",
    "GuardrailFactory",
    # Configuration Manager
    "GuardrailConfigManager",
    "get_guardrail_config_manager",
    "initialize_guardrail_system",
    "migrate_legacy_config",
    "validate_guardrail_config",
    "get_guardrail_config_schema",
    # Enkrypt Provider
    "EnkryptGuardrailProvider",
    "EnkryptInputGuardrail",
    "EnkryptOutputGuardrail",
    "EnkryptPIIHandler",
]

__version__ = "1.0.0"
