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

        # Reject relative imports, empty segments and paths before the import machinery sees them.
        if not module_path or not all(
            part.isidentifier() for part in module_path.split(".")
        ):
            raise ImportError(f"'{module_path}' is not a valid module path")

        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import - plugin class paths come from the operator-owned config and are shape-validated above
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

        # Construction strategy: prefer kwargs (Pattern 1). Only fall back to
        # other shapes for *expected* errors that clearly indicate the provider
        # uses a non-kwarg init contract.
        #
        # We deliberately do NOT silently fall through to ``provider_class(config)``
        # on a generic ``TypeError``: that pattern silently binds the whole
        # config dict to the first positional argument, which produced the
        # ``api_key={'base_url': ...}`` bug in EnkryptGuardrailProvider where
        # a missing ``api_key`` kwarg caused the entire config dict to be
        # mistaken for the api_key value. Surfacing the real error is much
        # cheaper than tracking down "the gateway blocks every request" later.
        try:
            provider = provider_class(**config)
        except TypeError as kwargs_exc:
            msg = str(kwargs_exc)
            if "unexpected keyword argument" in msg:
                # Pattern 2: legacy provider that takes a single dict argument.
                logger.warning(
                    "Provider %s rejected kwargs (%s); falling back to single-dict init. "
                    "Migrating to explicit kwargs with defaults is recommended.",
                    provider_class.__name__,
                    msg,
                )
                try:
                    provider = provider_class(config)
                except TypeError as positional_exc:
                    # Pattern 3: zero-arg provider.
                    if "positional argument" in str(positional_exc):
                        provider = provider_class()
                    else:
                        raise
            elif "missing" in msg and ("positional argument" in msg or "required argument" in msg):
                # Provider has required positional args that config doesn't
                # supply. Refuse to fall through — the next pattern would
                # silently jam ``config`` into the missing positional slot.
                raise TypeError(
                    f"Provider {provider_class.__name__} requires "
                    f"argument(s) not present in plugin config: {msg}. "
                    "Make all __init__ args keyword-only with defaults, or "
                    "add the missing key to plugins.<type>.config."
                ) from kwargs_exc
            else:
                # Unknown TypeError — re-raise rather than risk a wrong fallback.
                raise

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
