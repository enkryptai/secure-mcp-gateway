"""Telemetry configuration manager."""

from __future__ import annotations

from typing import Any, Dict

from secure_mcp_gateway.log import get_logger
from secure_mcp_gateway.plugins.telemetry.base import (
    TelemetryProvider,
    TelemetryRegistry,
    TelemetryResult,
)

logger = get_logger("enkrypt.telemetry")


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

            logger.info(
                f"[TelemetryConfigManager] Registered provider: {provider.name} v{provider.version}"
            )

            return TelemetryResult(
                success=True,
                provider_name=provider.name,
                message=f"Provider '{provider.name}' registered successfully",
            )

        except ValueError as e:
            # Provider already registered
            logger.info(
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

        logger.info(f"[TelemetryConfigManager] Active provider set to: {provider_name}")

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

    @property
    def guardrail_pii_entity_counter(self):
        """Per-entity PII counter ``enkrypt.guardrail.pii_entity``."""
        return self._get_metric_from_provider("guardrail_pii_entity_counter")

    @property
    def guardrail_toxicity_subtype_counter(self):
        """Toxicity subtype counter ``enkrypt.guardrail.toxicity_subtype``."""
        return self._get_metric_from_provider("guardrail_toxicity_subtype_counter")

    # Timeout management metrics
    @property
    def timeout_operations_total(self):
        """Backward-compatible metric accessor for timeout operations total"""
        return self._get_metric_from_provider("timeout_operations_total")

    @property
    def timeout_operations_successful(self):
        """Backward-compatible metric accessor for timeout operations successful"""
        return self._get_metric_from_provider("timeout_operations_successful")

    @property
    def timeout_operations_timed_out(self):
        """Backward-compatible metric accessor for timeout operations timed out"""
        return self._get_metric_from_provider("timeout_operations_timed_out")

    @property
    def timeout_operations_cancelled(self):
        """Backward-compatible metric accessor for timeout operations cancelled"""
        return self._get_metric_from_provider("timeout_operations_cancelled")

    @property
    def timeout_escalation_warn(self):
        """Backward-compatible metric accessor for timeout escalation warnings"""
        return self._get_metric_from_provider("timeout_escalation_warn")

    @property
    def timeout_escalation_timeout(self):
        """Backward-compatible metric accessor for timeout escalations"""
        return self._get_metric_from_provider("timeout_escalation_timeout")

    @property
    def timeout_escalation_fail(self):
        """Backward-compatible metric accessor for timeout escalation failures"""
        return self._get_metric_from_provider("timeout_escalation_fail")

    @property
    def timeout_operation_duration(self):
        """Backward-compatible metric accessor for timeout operation duration"""
        return self._get_metric_from_provider("timeout_operation_duration")

    @property
    def timeout_active_operations(self):
        """Backward-compatible metric accessor for timeout active operations"""
        return self._get_metric_from_provider("timeout_active_operations")

    # ------------------------------------------------------------------
    # Health-check API metrics (REST endpoints under /api/v1/health/mcp/*)
    # ------------------------------------------------------------------
    @property
    def health_request_counter(self):
        """Backward-compatible metric accessor for health-check request count."""
        return self._get_metric_from_provider("health_request_counter")

    @property
    def health_request_duration(self):
        """Backward-compatible metric accessor for health-check request duration."""
        return self._get_metric_from_provider("health_request_duration")

    @property
    def health_success_counter(self):
        """Backward-compatible metric accessor for health-check successful requests."""
        return self._get_metric_from_provider("health_success_counter")

    @property
    def health_failure_counter(self):
        """Backward-compatible metric accessor for health-check failed requests."""
        return self._get_metric_from_provider("health_failure_counter")

    # ------------------------------------------------------------------
    # Tier-1 additions (PR #41) -- compliance, errors, permission_denied,
    # degradation, transport_errors, discovery_failures.
    #
    # These exist on the underlying OpenTelemetryProvider but the manager
    # exposes every metric via an explicit ``@property`` that proxies to
    # ``_get_metric_from_provider``.  ``metrics_helpers._add`` does
    # ``getattr(mgr, "<counter>", None)`` -- without a property defined
    # here that returns ``None`` and the emission is silently skipped.
    # Adding the proxies wires the new counters into the same emission
    # pipeline as the pre-existing ones.
    # ------------------------------------------------------------------
    @property
    def guardrail_compliance_hit_counter(self):
        """Tier-1 metric accessor for ``enkrypt.guardrail.compliance_hit``."""
        return self._get_metric_from_provider("guardrail_compliance_hit_counter")

    @property
    def tool_permission_denied_counter(self):
        """Tier-1 metric accessor for ``enkrypt.tool.permission_denied``."""
        return self._get_metric_from_provider("tool_permission_denied_counter")

    @property
    def errors_by_code_counter(self):
        """Tier-1 metric accessor for ``enkrypt.errors.by_code``."""
        return self._get_metric_from_provider("errors_by_code_counter")

    @property
    def degradation_fail_open_counter(self):
        """Tier-1 metric accessor for ``enkrypt.degradation.fail_open``."""
        return self._get_metric_from_provider("degradation_fail_open_counter")

    @property
    def degradation_fail_closed_counter(self):
        """Tier-1 metric accessor for ``enkrypt.degradation.fail_closed``."""
        return self._get_metric_from_provider("degradation_fail_closed_counter")

    @property
    def transport_error_counter(self):
        """Tier-1 metric accessor for ``enkrypt.transport.errors``."""
        return self._get_metric_from_provider("transport_error_counter")

    @property
    def discovery_server_failure_counter(self):
        """Tier-1 metric accessor for ``enkrypt.discovery.server_failures``."""
        return self._get_metric_from_provider("discovery_server_failure_counter")

    # ------------------------------------------------------------------
    # Audit / compliance accessors (Audit Trail dashboard).
    #
    # Same silent-no-op trap applies here as for the Tier-1 counters: if
    # the @property is missing, ``metrics_helpers._add(getattr(mgr,
    # "<counter>", None), ...)`` returns None and the emission is dropped
    # without any error.  Every audit counter declared in
    # opentelemetry_provider.py MUST have a property below.
    # ------------------------------------------------------------------
    @property
    def admin_actions_counter(self):
        """Audit accessor for ``enkrypt.admin.actions``."""
        return self._get_metric_from_provider("admin_actions_counter")

    @property
    def privileged_operations_counter(self):
        """Audit accessor for ``enkrypt.privileged.operations``."""
        return self._get_metric_from_provider("privileged_operations_counter")

    @property
    def admin_cache_flush_counter(self):
        """Audit accessor for ``enkrypt.admin.cache_flush``."""
        return self._get_metric_from_provider("admin_cache_flush_counter")

    @property
    def apikey_rotations_counter(self):
        """Audit accessor for ``enkrypt.apikey.rotations``."""
        return self._get_metric_from_provider("apikey_rotations_counter")

    @property
    def audit_apikey_created_counter(self):
        """Audit accessor for ``enkrypt.audit.apikey.created``."""
        return self._get_metric_from_provider("audit_apikey_created_counter")

    @property
    def audit_apikey_deleted_counter(self):
        """Audit accessor for ``enkrypt.audit.apikey.deleted``."""
        return self._get_metric_from_provider("audit_apikey_deleted_counter")

    @property
    def audit_apikey_disabled_counter(self):
        """Audit accessor for ``enkrypt.audit.apikey.disabled``."""
        return self._get_metric_from_provider("audit_apikey_disabled_counter")

    @property
    def audit_apikey_rotated_counter(self):
        """Audit accessor for ``enkrypt.audit.apikey.rotated``."""
        return self._get_metric_from_provider("audit_apikey_rotated_counter")

    @property
    def audit_config_modified_counter(self):
        """Audit accessor for ``enkrypt.audit.config.modified``."""
        return self._get_metric_from_provider("audit_config_modified_counter")

    @property
    def audit_settings_enkrypt_api_key_set_counter(self):
        """Audit accessor for ``enkrypt.audit.settings.enkrypt_api_key_set``."""
        return self._get_metric_from_provider(
            "audit_settings_enkrypt_api_key_set_counter"
        )

    @property
    def audit_settings_telemetry_changed_counter(self):
        """Audit accessor for ``enkrypt.audit.settings.telemetry_changed``."""
        return self._get_metric_from_provider(
            "audit_settings_telemetry_changed_counter"
        )

    @property
    def audit_user_created_counter(self):
        """Audit accessor for ``enkrypt.audit.user.created``."""
        return self._get_metric_from_provider("audit_user_created_counter")

    @property
    def audit_user_deleted_counter(self):
        """Audit accessor for ``enkrypt.audit.user.deleted``."""
        return self._get_metric_from_provider("audit_user_deleted_counter")

    @property
    def projects_created_counter(self):
        """Audit accessor for ``enkrypt.projects.created``."""
        return self._get_metric_from_provider("projects_created_counter")

    @property
    def system_backup_completed_counter(self):
        """Audit accessor for ``enkrypt.system.backup.completed``."""
        return self._get_metric_from_provider("system_backup_completed_counter")

    @property
    def system_reset_counter(self):
        """Audit accessor for ``enkrypt.system.reset``."""
        return self._get_metric_from_provider("system_reset_counter")

    @property
    def system_restore_counter(self):
        """Audit accessor for ``enkrypt.system.restore``."""
        return self._get_metric_from_provider("system_restore_counter")

    @property
    def auth_unauthorized_http_counter(self):
        """Audit accessor for ``enkrypt.auth.unauthorized_http``."""
        return self._get_metric_from_provider("auth_unauthorized_http_counter")

    def reload(self, config: dict[str, Any]) -> None:
        """Rebuild telemetry providers from the latest config without restart.

        Caveat: OpenTelemetry's global TracerProvider / MeterProvider can
        only be set once per process. The SDK explicitly rejects subsequent
        ``set_tracer_provider`` calls (it logs "Overriding of current
        TracerProvider is not allowed"). Trying to re-initialize on reload
        therefore produces noise without taking effect.

        If telemetry is not yet initialized, we run the plugin loader so
        callers that flipped ``enabled: true`` after startup get a working
        provider. Otherwise the endpoint / enabled fields effectively
        require a restart (documented in README).
        """
        logger.info("[TelemetryConfigManager] reload triggered")
        provider = self.get_active_provider()
        if provider is None or not self._provider_initialized:
            from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

            PluginLoader.load_plugin_providers(config, "telemetry", self)
            return

        logger.info(
            "[TelemetryConfigManager] provider already initialized; "
            "skipping re-init (OTel global providers cannot be replaced "
            "at runtime - endpoint/enabled changes require restart)"
        )


# ============================================================================
# Global Instance
# ============================================================================

_telemetry_config_manager: TelemetryConfigManager | None = None


def get_telemetry_config_manager() -> TelemetryConfigManager:
    """
    Get or create the global TelemetryConfigManager instance.

    Returns:
        TelemetryConfigManager: Global instance
    """
    global _telemetry_config_manager
    if _telemetry_config_manager is None:
        _telemetry_config_manager = TelemetryConfigManager()

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
