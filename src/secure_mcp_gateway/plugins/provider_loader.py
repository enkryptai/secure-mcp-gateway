"""Dynamic provider loader."""

from __future__ import annotations

import importlib
from typing import Any

from secure_mcp_gateway.error_handling import error_logger
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_configuration_error,
)
from secure_mcp_gateway.utils import logger


def load_provider_class(class_path: str) -> type:
    """
    Dynamically load a provider class from its module path.

    Args:
        class_path: Full path to class (e.g., "module.submodule.ClassName")

    Returns:
        The provider class

    Raises:
        ImportError: If module or class cannot be found

    Example:
        >>> cls = load_provider_class("secure_mcp_gateway.plugins.guardrails.example_providers.OpenAIGuardrailProvider")
        >>> provider = cls(api_key="xxx")
    """
    try:
        # Split the class path into module and class name
        module_path, class_name = class_path.rsplit(".", 1)

        # Import the module
        module = importlib.import_module(module_path)

        # Get the class from the module
        provider_class = getattr(module, class_name)

        return provider_class

    except (ValueError, ImportError, AttributeError) as e:
        raise ImportError(f"Cannot load provider class '{class_path}': {e}") from e


def create_provider_from_config(
    provider_config: dict[str, Any], plugin_type: str = "guardrail"
) -> Any:
    """
    Create a provider instance from configuration.

    Args:
        provider_config: Provider configuration dict with:
            - class: Full class path (required)
            - config: Provider-specific config (optional)
        plugin_type: Type of plugin (guardrail, auth, telemetry)

    Returns:
        Provider instance

    Example Config:
        {
            "name": "my-openai-provider",
            "class": "secure_mcp_gateway.plugins.guardrails.example_providers.OpenAIGuardrailProvider",
            "config": {
                "api_key": "sk-xxx"
            }
        }
    """
    provider_name = provider_config.get("name", "unknown")
    class_path = provider_config.get("class")
    config = provider_config.get("config", {})

    if not class_path:
        context = ErrorContext(
            operation="provider_loader.missing_class",
            additional_context={
                "provider_name": provider_name,
                "plugin_type": plugin_type,
            },
        )
        err = create_configuration_error(
            code=ErrorCode.CONFIG_MISSING_REQUIRED,
            message=f"Provider '{provider_name}' missing 'class' field",
            context=context,
        )
        error_logger.log_error(err)
        raise err

    try:
        # Load the provider class
        provider_class = load_provider_class(class_path)

        # Create instance with config
        # Try different initialization patterns
        try:
            # Pattern 1: Pass entire config dict
            provider = provider_class(**config)
        except TypeError:
            try:
                # Pattern 2: Pass config as single argument
                provider = provider_class(config)
            except TypeError:
                # Pattern 3: No config needed
                provider = provider_class()

        logger.info(
            f"✓ Loaded {plugin_type} provider: {provider_name} ({provider_class.__name__})"
        )
        return provider

    except Exception as e:
        logger.error(f"✗ Failed to load provider '{provider_name}': {e}")
        context = ErrorContext(
            operation="provider_loader.load_provider",
            additional_context={
                "provider_name": provider_name,
                "plugin_type": plugin_type,
                "class_path": class_path,
            },
        )
        err = create_configuration_error(
            code=ErrorCode.CONFIG_PROVIDER_ERROR,
            message=f"Cannot load provider '{provider_name}'",
            context=context,
            cause=e,
        )
        error_logger.log_error(err)
        raise err


__all__ = [
    "load_provider_class",
    "create_provider_from_config",
]
