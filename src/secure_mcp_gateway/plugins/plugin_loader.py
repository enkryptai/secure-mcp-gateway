"""
Centralized Plugin Loader with Fallback Mechanism

This module provides a centralized way to load plugin providers with automatic
fallback to default Enkrypt providers when no custom provider is specified.
"""

from typing import Any, ClassVar, Dict, Optional

from secure_mcp_gateway.utils import sys_print


class PluginLoader:
    """
    Centralized plugin loader with fallback to default Enkrypt providers.
    """

    # Default provider mappings
    DEFAULT_PROVIDERS: ClassVar[Dict[str, Dict[str, str]]] = {
        "auth": {
            "class": "secure_mcp_gateway.plugins.auth.enkrypt_provider.EnkryptAuthProvider",
            "name": "enkrypt",
        },
        "guardrails": {
            "class": "secure_mcp_gateway.plugins.guardrails.enkrypt_provider.EnkryptGuardrailProvider",
            "name": "enkrypt",
        },
        "telemetry": {
            "class": "secure_mcp_gateway.plugins.telemetry.opentelemetry_provider.OpenTelemetryProvider",
            "name": "opentelemetry",
        },
    }

    @staticmethod
    def load_plugin_providers(
        config: Dict[str, Any], plugin_type: str, manager: Any
    ) -> None:
        """
        Load plugin providers with fallback to default Enkrypt providers.

        Args:
            config: Full configuration dictionary
            plugin_type: Type of plugin (auth, guardrails, telemetry)
            manager: The plugin manager instance to register providers with
        """
        from secure_mcp_gateway.plugins.provider_loader import (
            create_provider_from_config,
        )

        # Get plugins configuration
        plugins_config = config.get("plugins", {})
        plugin_config = plugins_config.get(plugin_type, {})

        # Check if a custom provider is specified
        if plugin_config and "provider" in plugin_config:
            provider_name = plugin_config["provider"]
            provider_config = plugin_config.get("config", {})

            # Map provider names to their classes
            provider_class_mapping = {
                "enkrypt": PluginLoader.DEFAULT_PROVIDERS[plugin_type]["class"],
                "local_apikey": "secure_mcp_gateway.plugins.auth.local_apikey_provider.LocalApiKeyProvider",
                "otel": PluginLoader.DEFAULT_PROVIDERS["telemetry"]["class"],
                "opentelemetry": PluginLoader.DEFAULT_PROVIDERS["telemetry"]["class"],
            }

            # Get the class path for the provider
            class_path = provider_class_mapping.get(provider_name)
            if not class_path:
                sys_print(
                    f"Unknown {plugin_type} provider: {provider_name}", is_error=True
                )
                class_path = PluginLoader.DEFAULT_PROVIDERS[plugin_type]["class"]
                provider_name = PluginLoader.DEFAULT_PROVIDERS[plugin_type]["name"]
                sys_print(
                    f"Falling back to default {plugin_type} provider: {provider_name}"
                )

            # Create and register the provider
            try:
                provider = create_provider_from_config(
                    {
                        "name": provider_name,
                        "class": class_path,
                        "config": provider_config,
                    },
                    plugin_type=plugin_type,
                )

                # Check if provider is already registered
                if (
                    hasattr(manager, "list_providers")
                    and provider_name in manager.list_providers()
                ):
                    sys_print(
                        f"[i] {plugin_type} provider '{provider_name}' already registered"
                    )
                else:
                    manager.register_provider(provider)
                    sys_print(f"✓ Registered {plugin_type} provider: {provider_name}")

            except Exception as e:
                sys_print(
                    f"Error loading {plugin_type} provider '{provider_name}': {e}",
                    is_error=True,
                )
                # Fall back to default provider
                PluginLoader._load_default_provider(plugin_type, manager, config)
        else:
            # No custom provider specified, use default
            PluginLoader._load_default_provider(plugin_type, manager, config)

    @staticmethod
    def _load_default_provider(
        plugin_type: str, manager: Any, config: Dict[str, Any]
    ) -> None:
        """
        Load the default Enkrypt provider for the given plugin type.

        Args:
            plugin_type: Type of plugin (auth, guardrails, telemetry)
            manager: The plugin manager instance
            config: Full configuration dictionary
        """
        from secure_mcp_gateway.plugins.provider_loader import (
            create_provider_from_config,
        )

        default_provider = PluginLoader.DEFAULT_PROVIDERS[plugin_type]
        provider_name = default_provider["name"]
        class_path = default_provider["class"]

        # Check if already registered
        if (
            hasattr(manager, "list_providers")
            and provider_name in manager.list_providers()
        ):
            sys_print(
                f"[i] Default {plugin_type} provider '{provider_name}' already registered"
            )
            return

        # Prepare config for default provider
        provider_config = {}

        if plugin_type == "auth":
            # Get from plugins.auth.config, fallback to common config for use_remote_config
            auth_plugin_cfg = (
                config.get("plugins", {}).get("auth", {}).get("config", {})
            )
            provider_config = {
                "api_key": auth_plugin_cfg.get("api_key"),
                "base_url": auth_plugin_cfg.get(
                    "base_url", "https://api.enkryptai.com"
                ),
                "use_remote_config": config.get("enkrypt_use_remote_mcp_config", False),
            }
        elif plugin_type == "guardrails":
            # Get from plugins.guardrails.config
            guardrails_plugin_cfg = (
                config.get("plugins", {}).get("guardrails", {}).get("config", {})
            )
            provider_config = {
                "api_key": guardrails_plugin_cfg.get("api_key"),
                "base_url": guardrails_plugin_cfg.get(
                    "base_url", "https://api.enkryptai.com"
                ),
            }
        elif plugin_type == "telemetry":
            # Prefer plugins.telemetry.config; fall back to safe defaults
            telemetry_plugin_cfg = (
                config.get("plugins", {}).get("telemetry", {}).get("config", {})
            )
            provider_config = {
                "url": telemetry_plugin_cfg.get("url", "http://localhost:4317"),
                "insecure": telemetry_plugin_cfg.get("insecure", True),
            }

        try:
            provider = create_provider_from_config(
                {"name": provider_name, "class": class_path, "config": provider_config},
                plugin_type=plugin_type,
            )

            manager.register_provider(provider)
            sys_print(f"✓ Registered default {plugin_type} provider: {provider_name}")

        except Exception as e:
            sys_print(
                f"Error loading default {plugin_type} provider: {e}", is_error=True
            )


__all__ = ["PluginLoader"]
