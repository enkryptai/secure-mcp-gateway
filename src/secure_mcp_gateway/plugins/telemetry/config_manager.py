"""
Telemetry Config Manager

Central configuration and management for the telemetry plugin system.
Handles provider registration, initialization, and switching.
"""

from __future__ import annotations

# Avoid circular import by defining sys_print locally
import sys
from typing import Any, Dict

from secure_mcp_gateway.plugins.telemetry.base import (
    TelemetryProvider,
    TelemetryRegistry,
    TelemetryResult,
)


def sys_print(message: str, is_error: bool = False, is_debug: bool = False):
    """Local sys_print to avoid circular imports."""
    if is_error:
        print(f"[ERROR] {message}", file=sys.stderr)
    elif is_debug:
        print(f"[DEBUG] {message}", file=sys.stderr)
    else:
        print(message, file=sys.stderr)


class TelemetryConfigManager:
    """
    Manages telemetry provider configuration and lifecycle.

    This class is the main entry point for using the telemetry plugin system.
    It handles:
    - Provider registration
    - Provider initialization
    - Provider switching
    - Logger/tracer creation

    Example:
        ```python
        manager = TelemetryConfigManager()

        # Register providers
        manager.register_provider(OpenTelemetryProvider())

        # Initialize a provider
        result = manager.initialize_provider("opentelemetry", config)

        # Get logger/tracer
        logger = manager.get_logger()
        tracer = manager.get_tracer()
        ```
    """

    def __init__(self):
        """Initialize the config manager"""
        self.registry = TelemetryRegistry()
        self._active_provider: str | None = None
        self._provider_initialized: bool = False

    def register_provider(self, provider: TelemetryProvider) -> TelemetryResult:
        """
        Register a telemetry provider.

        Args:
            provider: Provider instance to register

        Returns:
            TelemetryResult: Registration result
        """
        try:
            self.registry.register(provider)
            self._provider_initialized = False

            sys_print(
                f"[TelemetryConfigManager] Registered provider: {provider.name} v{provider.version}"
            )

            return TelemetryResult(
                success=True,
                provider_name=provider.name,
                message=f"Provider '{provider.name}' registered successfully",
            )

        except ValueError as e:
            # Provider already registered
            sys_print(
                f"[TelemetryConfigManager] Provider already registered: {provider.name}"
            )
            return TelemetryResult(
                success=False,
                provider_name=provider.name,
                error=str(e),
            )

    def initialize_provider(
        self,
        provider_name: str,
        config: dict[str, Any],
    ) -> TelemetryResult:
        """
        Initialize a specific provider.

        Args:
            provider_name: Name of provider to initialize
            config: Provider configuration

        Returns:
            TelemetryResult: Initialization result
        """
        provider = self.registry.get()

        if not provider:
            return TelemetryResult(
                success=False,
                provider_name=provider_name,
                error="No provider registered",
            )

        # Initialize the provider
        result = provider.initialize(config)

        if result.success:
            self._provider_initialized = True

            # Set as active if no active provider
            if self._active_provider is None:
                self._active_provider = provider_name

        return result

    def set_active_provider(self, provider_name: str) -> TelemetryResult:
        """
        Set the active telemetry provider.

        Args:
            provider_name: Name of provider to activate

        Returns:
            TelemetryResult: Activation result
        """
        provider = self.registry.get()
        if not provider:
            return TelemetryResult(
                success=False,
                provider_name=provider_name,
                error="No provider registered",
            )

        if not self._provider_initialized:
            return TelemetryResult(
                success=False,
                provider_name=provider_name,
                error=f"Provider '{provider_name}' not initialized",
            )

        self._active_provider = provider_name

        sys_print(f"[TelemetryConfigManager] Active provider set to: {provider_name}")

        return TelemetryResult(
            success=True,
            provider_name=provider_name,
            message=f"Provider '{provider_name}' is now active",
        )

    def get_active_provider(self) -> TelemetryProvider | None:
        """
        Get the currently active provider.

        Returns:
            Optional[TelemetryProvider]: Active provider or None
        """
        return self.registry.get()

    def get_logger(self, name: str = "enkrypt-mcp-gateway") -> Any:
        """
        Get a logger from the active provider.

        Args:
            name: Logger name

        Returns:
            Logger instance

        Raises:
            RuntimeError: If no active provider
        """
        provider = self.get_active_provider()

        if not provider:
            raise RuntimeError(
                "No active telemetry provider. Call initialize_provider() first."
            )

        return provider.create_logger(name)

    def get_tracer(self, name: str = "enkrypt-mcp-gateway") -> Any:
        """
        Get a tracer from the active provider.

        Args:
            name: Tracer name

        Returns:
            Tracer instance

        Raises:
            RuntimeError: If no active provider
        """
        provider = self.get_active_provider()

        if not provider:
            raise RuntimeError(
                "No active telemetry provider. Call initialize_provider() first."
            )

        return provider.create_tracer(name)

    def get_meter(self, name: str = "enkrypt-mcp-gateway") -> Any:
        """
        Get a meter from the active provider (if supported).

        Args:
            name: Meter name

        Returns:
            Meter instance or None
        """
        provider = self.get_active_provider()

        if not provider:
            return None

        # Check if provider has create_meter method
        if hasattr(provider, "create_meter"):
            return provider.create_meter(name)

        return None

    def list_providers(self) -> list[str]:
        """
        List all registered providers.

        Returns:
            list[str]: Provider names
        """
        return self.registry.list_providers()

    def get_provider_status(self) -> dict[str, dict[str, Any]]:
        """
        Get status of the registered provider.

        Returns:
            Dict with provider status
        """
        status = {}
        provider = self.registry.get()

        if provider:
            provider_name = provider.name
            status[provider_name] = {
                "version": provider.version,
                "initialized": self._provider_initialized,
                "active": provider_name == self._active_provider,
            }

        return status

    # ========================================================================
    # BACKWARD-COMPATIBLE METRIC ACCESSORS
    # ========================================================================

    def _get_metric_from_provider(self, metric_name: str) -> Any:
        """
        Get a metric from the active provider.

        Args:
            metric_name: Name of the metric attribute

        Returns:
            Metric object or None
        """
        provider = self.get_active_provider()
        if provider and hasattr(provider, metric_name):
            return getattr(provider, metric_name)
        return None

    @property
    def list_servers_call_count(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("list_servers_call_count")

    @property
    def servers_discovered_count(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("servers_discovered_count")

    @property
    def cache_hit_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("cache_hit_counter")

    @property
    def cache_miss_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("cache_miss_counter")

    @property
    def tool_call_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_counter")

    @property
    def tool_call_duration(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_duration")

    @property
    def guardrail_api_request_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("guardrail_api_request_counter")

    @property
    def guardrail_api_request_duration(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("guardrail_api_request_duration")

    @property
    def guardrail_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("guardrail_violation_counter")

    @property
    def tool_call_success_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_success_counter")

    @property
    def tool_call_failure_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_failure_counter")

    @property
    def tool_call_error_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_error_counter")

    @property
    def tool_call_blocked_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("tool_call_blocked_counter")

    @property
    def input_guardrail_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("input_guardrail_violation_counter")

    @property
    def output_guardrail_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("output_guardrail_violation_counter")

    @property
    def relevancy_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("relevancy_violation_counter")

    @property
    def adherence_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("adherence_violation_counter")

    @property
    def hallucination_violation_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("hallucination_violation_counter")

    @property
    def auth_success_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("auth_success_counter")

    @property
    def auth_failure_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("auth_failure_counter")

    @property
    def active_sessions_gauge(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("active_sessions_gauge")

    @property
    def active_users_gauge(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("active_users_gauge")

    @property
    def pii_redactions_counter(self):
        """Backward-compatible metric accessor"""
        return self._get_metric_from_provider("pii_redactions_counter")


# ============================================================================
# Global Instance
# ============================================================================

_telemetry_config_manager: TelemetryConfigManager | None = None


def get_telemetry_config_manager() -> TelemetryConfigManager:
    """
    Get or create the global TelemetryConfigManager instance.

    Auto-initializes with OpenTelemetry provider if not already initialized.

    Returns:
        TelemetryConfigManager: Global instance
    """
    global _telemetry_config_manager
    if _telemetry_config_manager is None:
        _telemetry_config_manager = TelemetryConfigManager()

        # Auto-initialize with OpenTelemetry provider
        try:
            from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
                OpenTelemetryProvider,
            )

            provider = OpenTelemetryProvider()
            _telemetry_config_manager.register_provider(provider)
            _telemetry_config_manager.initialize_provider("opentelemetry", {})
        except Exception:
            # Silently fail - telemetry is optional
            pass

    return _telemetry_config_manager


def initialize_telemetry_system(
    config: dict[str, Any] | None = None,
) -> TelemetryConfigManager:
    """
    Initialize the telemetry system with providers.

    Args:
        config: Configuration dict containing telemetry settings

    Returns:
        TelemetryConfigManager: Initialized manager
    """
    manager = get_telemetry_config_manager()

    if config is None:
        return manager

    # Use the new centralized plugin loader with fallback mechanism
    from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

    PluginLoader.load_plugin_providers(config, "telemetry", manager)

    return manager


__all__ = [
    "TelemetryConfigManager",
    "get_telemetry_config_manager",
    "initialize_telemetry_system",
]
