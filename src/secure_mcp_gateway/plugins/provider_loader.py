"""
Dynamic Provider Loader

This module provides dynamic provider loading capabilities for all plugin systems.
Allows loading providers by class path without modifying core code.
"""

from __future__ import annotations

import importlib
from typing import Any

from secure_mcp_gateway.utils import sys_print


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
        raise ValueError(f"Provider '{provider_name}' missing 'class' field")

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

        sys_print(
            f"✓ Loaded {plugin_type} provider: {provider_name} ({provider_class.__name__})"
        )
        return provider

    except Exception as e:
        sys_print(f"✗ Failed to load provider '{provider_name}': {e}", is_error=True)
        raise


__all__ = [
    "load_provider_class",
    "create_provider_from_config",
]
