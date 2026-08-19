"""Plugin loader with fallback mechanism."""

from typing import Any, ClassVar, Dict, Optional, Tuple

from secure_mcp_gateway.utils import logger


def _resolve_enkrypt_credentials(
    full_config: Dict[str, Any], plugin_config: Dict[str, Any]
) -> Tuple[str, str]:
    """Resolve Enkrypt API key and base URL with fallback chain.

    Priority: per-plugin config -> root enkrypt_config -> default.
    """
    enkrypt_cfg = full_config.get("enkrypt_config", {})
    api_key = (
        plugin_config.get("api_key")
        or plugin_config.get("apikey")
        or enkrypt_cfg.get("api_key", "")
    )
    base_url = plugin_config.get("base_url") or enkrypt_cfg.get(
        "base_url", "https://api.enkryptai.com"
    )
    return api_key, base_url


class PluginLoader:
    """
    Centralized plugin loader with fallback to default Enkrypt providers.
    """

    # Default provider mappings
    DEFAULT_PROVIDERS: ClassVar[Dict[str, Dict[str, str]]] = {
        "auth": {
            "class": "secure_mcp_gateway.plugins.auth.local_apikey_provider.LocalApiKeyProvider",
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

            # Map provider names to their classes.
            #
            # The default fallback (when no provider is specified) is still
            # ``LocalApiKeyProvider`` for backwards compatibility, but
            # ``provider: "enkrypt"`` now explicitly resolves to the cloud-
            # backed ``EnkryptAuthProvider`` introduced in v2.2 (see
            # ``plugins/auth/enkrypt_provider.py``).
            provider_class_mapping = {
                "enkrypt": (
                    "secure_mcp_gateway.plugins.auth.enkrypt_provider.EnkryptAuthProvider"
                    if plugin_type == "auth"
                    else PluginLoader.DEFAULT_PROVIDERS[plugin_type]["class"]
                ),
                "local_apikey": "secure_mcp_gateway.plugins.auth.local_apikey_provider.LocalApiKeyProvider",
                "otel": PluginLoader.DEFAULT_PROVIDERS["telemetry"]["class"],
                "opentelemetry": PluginLoader.DEFAULT_PROVIDERS["telemetry"]["class"],
            }

            # Get the class path for the provider
            class_path = provider_class_mapping.get(provider_name)
            if not class_path:
                # Unknown provider name (e.g. legacy "stdout" telemetry).
                # Delegate to ``_load_default_provider`` rather than
                # continuing inline: the inline path would carry the
                # caller's (possibly empty) ``provider_config`` over to the
                # default provider class, leaving the fallback provider
                # un-initialized. ``_load_default_provider`` already knows
                # how to populate plugin-specific defaults (enabled/url/
                # insecure for telemetry, api_key/base_url for auth +
                # guardrails) so the fallback comes up fully configured.
                default_name = PluginLoader.DEFAULT_PROVIDERS[plugin_type]["name"]
                logger.error(f"Unknown {plugin_type} provider: {provider_name}")
                logger.info(
                    f"Falling back to default {plugin_type} provider: {default_name}"
                )
                PluginLoader._load_default_provider(plugin_type, manager, config)
                return

            # Inject centralized Enkrypt credentials for auth/guardrails providers.
            #
            # We inject api_key/apikey even when empty so the provider's
            # __init__ always sees the parameter as a kwarg. Without this,
            # an empty api_key was skipped, the provider's required positional
            # ``api_key`` arg was unfilled, kwargs init failed, and the legacy
            # fallback silently bound the whole config dict to ``api_key`` —
            # producing the ``api_key={'base_url': ...}`` corruption that
            # crashed every guardrail call in cloud-auth setups where no
            # static api_key is configured. The provider's own runtime
            # fallback (e.g. per-request apikey forwarding) handles the
            # empty case correctly.
            if plugin_type in ("auth", "guardrails"):
                api_key, base_url = _resolve_enkrypt_credentials(config, provider_config)
                if "api_key" not in provider_config and "apikey" not in provider_config:
                    key_name = "apikey" if plugin_type == "auth" else "api_key"
                    provider_config[key_name] = api_key
                if "base_url" not in provider_config:
                    provider_config["base_url"] = base_url

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
                    logger.info(
                        f"[i] {plugin_type} provider '{provider_name}' already registered"
                    )
                else:
                    manager.register_provider(provider)
                    logger.info(f"✓ Registered {plugin_type} provider: {provider_name}")

            except Exception as e:
                logger.error(
                    f"Error loading {plugin_type} provider '{provider_name}': {e}"
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
            logger.info(
                f"[i] Default {plugin_type} provider '{provider_name}' already registered"
            )
            return

        # Prepare config for default provider
        provider_config = {}

        if plugin_type == "auth":
            auth_plugin_cfg = (
                config.get("plugins", {}).get("auth", {}).get("config", {})
            )
            api_key, base_url = _resolve_enkrypt_credentials(config, auth_plugin_cfg)
            provider_config = {
                "api_key": api_key,
                "base_url": base_url,
                "use_remote_config": config.get("enkrypt_use_remote_mcp_config", False),
            }
        elif plugin_type == "guardrails":
            guardrails_plugin_cfg = (
                config.get("plugins", {}).get("guardrails", {}).get("config", {})
            )
            api_key, base_url = _resolve_enkrypt_credentials(config, guardrails_plugin_cfg)
            provider_config = {
                "api_key": api_key,
                "base_url": base_url,
            }
        elif plugin_type == "telemetry":
            # Prefer plugins.telemetry.config; fall back to safe defaults
            telemetry_plugin_cfg = (
                config.get("plugins", {}).get("telemetry", {}).get("config", {})
            )
            provider_config = {
                "enabled": telemetry_plugin_cfg.get("enabled", True),
                "url": telemetry_plugin_cfg.get("url", "http://localhost:4317"),
                "insecure": telemetry_plugin_cfg.get("insecure", True),
            }

        try:
            provider = create_provider_from_config(
                {"name": provider_name, "class": class_path, "config": provider_config},
                plugin_type=plugin_type,
            )

            manager.register_provider(provider)
            logger.info(f"✓ Registered default {plugin_type} provider: {provider_name}")

        except Exception as e:
            logger.error(f"Error loading default {plugin_type} provider: {e}")


__all__ = ["PluginLoader", "_resolve_enkrypt_credentials"]
