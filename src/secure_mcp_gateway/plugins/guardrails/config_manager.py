"""
Guardrail Configuration Manager

This module provides utilities for managing guardrail configurations and
integrating the plugin system with the existing MCP gateway configuration.

It handles:
- Loading guardrail provider configurations
- Creating and managing provider instances
- Integrating with the existing enkrypt_mcp_config.json structure
- Providing backward compatibility with existing Enkrypt guardrails
"""

from typing import Any, Dict, List, Optional

from secure_mcp_gateway.plugins.guardrails.base import (
    GuardrailFactory,
    GuardrailProvider,
    GuardrailRegistry,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
)
from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import (
    EnkryptGuardrailProvider,
)
from secure_mcp_gateway.utils import sys_print


class GuardrailConfigManager:
    """
    Manages guardrail configuration and provider instantiation.

    This class bridges the existing MCP gateway configuration with the
    new plugin-based guardrail system, providing backward compatibility
    while enabling extensibility.

    Example:
        ```python
        manager = GuardrailConfigManager()

        # Register custom provider
        manager.register_provider(MyCustomProvider())

        # Load from config
        config = {
            "server_name": "github_server",
            "input_guardrails_policy": {
                "enabled": True,
                "provider": "enkrypt",  # New field
                "policy_name": "GitHub Policy",
                "block": ["policy_violation"]
            }
        }

        input_guardrail = manager.get_input_guardrail(config)
        ```
    """

    def __init__(self):
        self.registry = GuardrailRegistry()
        self.factory = GuardrailFactory(self.registry)
        self._initialize_default_providers()

    def _initialize_default_providers(self):
        """Initialize default providers (Enkrypt)."""
        # Enkrypt provider will be registered when API key is available
        # This happens during gateway initialization
        pass

    def register_provider(self, provider: GuardrailProvider) -> None:
        """
        Register a new guardrail provider.

        Args:
            provider: The provider instance to register
        """
        try:
            self.registry.register(provider)
            sys_print(
                f"[GuardrailConfigManager] Registered provider: {provider.get_name()} v{provider.get_version()}"
            )
        except ValueError as e:
            sys_print(f"[GuardrailConfigManager] {e}", is_error=True)

    def register_enkrypt_provider(
        self,
        api_key: str,
        base_url: str = "https://api.enkryptai.com",
        config: Dict[str, Any] = None,
    ) -> None:
        """
        Register the Enkrypt provider with credentials.

        Args:
            api_key: Enkrypt API key
            base_url: Enkrypt API base URL
            config: Optional provider configuration (e.g., debug flags, custom detectors)
        """
        enkrypt_provider = EnkryptGuardrailProvider(api_key, base_url, config)
        self.register_provider(enkrypt_provider)

    def get_input_guardrail(
        self, server_config: Dict[str, Any]
    ) -> Optional[InputGuardrail]:
        """
        Get input guardrail instance from server configuration.

        Args:
            server_config: Server configuration dict (from mcp_config)

        Returns:
            InputGuardrail instance or None if not enabled
        """
        policy_config = server_config.get("input_guardrails_policy", {})

        if not policy_config.get("enabled", False):
            return None

        # Determine provider (default to enkrypt for backward compatibility)
        provider_name = policy_config.get("provider", "enkrypt")

        try:
            return self.factory.create_input_guardrail(provider_name, policy_config)
        except ValueError as e:
            sys_print(
                f"[GuardrailConfigManager] Error creating input guardrail: {e}",
                is_error=True,
            )
            return None

    def get_output_guardrail(
        self, server_config: Dict[str, Any]
    ) -> Optional[OutputGuardrail]:
        """
        Get output guardrail instance from server configuration.

        Args:
            server_config: Server configuration dict (from mcp_config)

        Returns:
            OutputGuardrail instance or None if not enabled
        """
        policy_config = server_config.get("output_guardrails_policy", {})

        if not policy_config.get("enabled", False):
            return None

        # Determine provider (default to enkrypt for backward compatibility)
        provider_name = policy_config.get("provider", "enkrypt")

        try:
            return self.factory.create_output_guardrail(provider_name, policy_config)
        except ValueError as e:
            sys_print(
                f"[GuardrailConfigManager] Error creating output guardrail: {e}",
                is_error=True,
            )
            return None

    def get_pii_handler(self, server_config: Dict[str, Any]) -> Optional[PIIHandler]:
        """
        Get PII handler instance from server configuration.

        Args:
            server_config: Server configuration dict (from mcp_config)

        Returns:
            PIIHandler instance or None if not enabled
        """
        input_policy = server_config.get("input_guardrails_policy", {})
        additional_config = input_policy.get("additional_config", {})

        if not additional_config.get("pii_redaction", False):
            return None

        provider_name = input_policy.get("provider", "enkrypt")

        try:
            return self.factory.create_pii_handler(provider_name, input_policy)
        except Exception as e:
            sys_print(
                f"[GuardrailConfigManager] Error creating PII handler: {e}",
                is_error=True,
            )
            return None

    def list_providers(self) -> List[str]:
        """
        Get list of registered provider names.

        Returns:
            List of provider names
        """
        return self.registry.list_providers()

    def get_provider_metadata(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific provider.

        Args:
            provider_name: Name of the provider

        Returns:
            Provider metadata dict or None if not found
        """
        provider = self.registry.get_provider(provider_name)
        if provider:
            return provider.get_metadata()
        return None

    def get_all_providers_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Get metadata for all registered providers.

        Returns:
            Dictionary mapping provider names to their metadata
        """
        metadata = {}
        provider = self.registry.get_provider()
        if provider:
            provider_metadata = self.get_provider_metadata(provider.get_name())
            if provider_metadata:
                metadata[provider.get_name()] = provider_metadata
        return metadata

    async def validate_server_registration(
        self, server_name: str, server_config: Dict[str, Any]
    ) -> Optional[Any]:  # GuardrailResponse
        """
        Validate a server during registration/discovery.

        Args:
            server_name: Name of the server
            server_config: Server configuration dictionary

        Returns:
            GuardrailResponse or None if no provider supports registration
        """
        from secure_mcp_gateway.plugins.guardrails.base import ServerRegistrationRequest

        # Use the registered provider
        provider = self.registry.get_provider()
        if not provider:
            return None

        request = ServerRegistrationRequest(
            server_name=server_name,
            server_config=server_config,
            server_description=server_config.get("description"),
            server_command=server_config.get("command"),
            server_metadata=server_config,
        )

        return await provider.validate_server_registration(request)

    async def validate_tool_registration(
        self, server_name: str, tools: List[Dict[str, Any]], mode: str = "filter"
    ) -> Optional[Any]:  # GuardrailResponse
        """
        Validate and filter tools during discovery.

        Args:
            server_name: Name of the server
            tools: List of tool dictionaries
            mode: "filter" to filter unsafe tools, "block_all" to block if any unsafe

        Returns:
            GuardrailResponse or None if no provider supports registration
        """
        from secure_mcp_gateway.plugins.guardrails.base import ToolRegistrationRequest

        # Use the registered provider
        provider = self.registry.get_provider()
        if not provider:
            return None

        sys_print(f"[GuardrailConfigManager] Using provider: {provider.get_name()}")
        request = ToolRegistrationRequest(
            server_name=server_name, tools=tools, validation_mode=mode
        )

        return await provider.validate_tool_registration(request)


# ============================================================================
# Configuration Schema Helpers
# ============================================================================


def get_guardrail_config_schema() -> Dict[str, Any]:
    """
    Get the JSON schema for guardrail configuration.

    This helps with validation and documentation.

    Returns:
        JSON schema dict
    """
    return {
        "type": "object",
        "properties": {
            "enabled": {"type": "boolean", "description": "Enable guardrails"},
            "provider": {
                "type": "string",
                "description": "Guardrail provider name (e.g., 'enkrypt', 'openai-moderation')",
                "default": "enkrypt",
            },
            "policy_name": {
                "type": "string",
                "description": "Name of the guardrail policy",
            },
            "block": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of violation types to block",
            },
            "additional_config": {
                "type": "object",
                "description": "Provider-specific additional configuration",
                "properties": {
                    "pii_redaction": {
                        "type": "boolean",
                        "description": "Enable PII redaction",
                    }
                },
            },
        },
        "required": ["enabled"],
    }


def validate_guardrail_config(config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate guardrail configuration.

    Args:
        config: Configuration dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(config, dict):
        return False, "Configuration must be a dictionary"

    if "enabled" not in config:
        return False, "Missing required field: 'enabled'"

    if not isinstance(config["enabled"], bool):
        return False, "'enabled' must be a boolean"

    if config.get("enabled") and not config.get("policy_name"):
        # Some providers might not need policy_name
        provider = config.get("provider", "enkrypt")
        if provider == "enkrypt" and not config.get("policy_name"):
            return False, "Enkrypt provider requires 'policy_name' when enabled"

    return True, None


# ============================================================================
# Migration Helper for Existing Configs
# ============================================================================


def migrate_legacy_config(server_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Migrate legacy guardrail configuration to new format.

    This adds the 'provider' field if missing, defaulting to 'enkrypt'
    for backward compatibility.

    Args:
        server_config: Server configuration dict

    Returns:
        Migrated configuration dict
    """
    migrated = server_config.copy()

    # Migrate input guardrails
    if "input_guardrails_policy" in migrated:
        input_policy = migrated["input_guardrails_policy"]
        if "provider" not in input_policy:
            input_policy["provider"] = "enkrypt"

    # Migrate output guardrails
    if "output_guardrails_policy" in migrated:
        output_policy = migrated["output_guardrails_policy"]
        if "provider" not in output_policy:
            output_policy["provider"] = "enkrypt"

    return migrated


# ============================================================================
# Global Instance
# ============================================================================

# Singleton instance for global access
_guardrail_config_manager: Optional[GuardrailConfigManager] = None


def get_guardrail_config_manager() -> GuardrailConfigManager:
    """
    Get or create the global GuardrailConfigManager instance.

    Returns:
        GuardrailConfigManager instance
    """
    global _guardrail_config_manager
    if _guardrail_config_manager is None:
        _guardrail_config_manager = GuardrailConfigManager()
    return _guardrail_config_manager


def initialize_guardrail_system(
    config_or_api_key=None,
    enkrypt_base_url: str = "https://api.enkryptai.com",
) -> GuardrailConfigManager:
    """
    Initialize the guardrail system with default providers.

    Args:
        config_or_api_key: Either:
            - Dict: Complete common_config dict
            - str: Enkrypt API key
            - None: No initialization
        enkrypt_base_url: Enkrypt API base URL

    Returns:
        Initialized GuardrailConfigManager instance
    """
    manager = get_guardrail_config_manager()

    # Convert API key string to config dict for consistency
    if isinstance(config_or_api_key, str):
        config = {
            "enkrypt_api_key": config_or_api_key,
            "enkrypt_base_url": enkrypt_base_url,
        }
    elif isinstance(config_or_api_key, dict):
        config = config_or_api_key
    else:
        config = {}

    # Use the new centralized plugin loader with fallback mechanism
    from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

    PluginLoader.load_plugin_providers(config, "guardrails", manager)

    return manager
