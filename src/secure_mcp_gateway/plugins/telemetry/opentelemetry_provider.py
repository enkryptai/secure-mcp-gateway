"""
OpenTelemetry Provider for Telemetry Plugin System

This provider wraps the existing OpenTelemetry implementation and makes it
compatible with the telemetry plugin system.
"""

from __future__ import annotations

from typing import Any, Dict

from secure_mcp_gateway.plugins.telemetry.base import (
    TelemetryLevel,
    TelemetryProvider,
    TelemetryResult,
)
from secure_mcp_gateway.utils import sys_print


class OpenTelemetryProvider(TelemetryProvider):
    """
    OpenTelemetry telemetry provider.

    Wraps the existing OpenTelemetry implementation from telemetry_service.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the OpenTelemetry provider.

        Args:
            config: Provider configuration (optional, can initialize later)
        """
        self._initialized = False
        self._logger = None
        self._tracer = None
        self._meter = None

        if config:
            self.initialize(config)

    @property
    def name(self) -> str:
        """Provider name"""
        return "opentelemetry"

    @property
    def version(self) -> str:
        """Provider version"""
        return "1.0.0"

    def initialize(self, config: dict[str, Any]) -> TelemetryResult:
        """
        Initialize OpenTelemetry.

        Args:
            config: Configuration dict with:
                - enabled: Whether telemetry is enabled
                - endpoint: OTLP endpoint URL
                - insecure: Whether to use insecure connection
                - service_name: Name of the service
                - service_version: Version of the service

        Returns:
            TelemetryResult: Initialization result
        """
        try:
            sys_print(f"[{self.name}] Initializing OpenTelemetry provider...")

            # Import existing telemetry service
            from secure_mcp_gateway.services.telemetry.telemetry_service import (
                logger,
                tracer,
            )

            self._logger = logger
            self._tracer = tracer
            self._initialized = True

            sys_print(f"[{self.name}] ✓ Initialized OpenTelemetry provider")

            return TelemetryResult(
                success=True,
                provider_name=self.name,
                message="OpenTelemetry initialized successfully",
                data={
                    "endpoint": config.get("endpoint", "unknown"),
                    "enabled": config.get("enabled", True),
                },
            )

        except Exception as e:
            sys_print(f"[{self.name}] ✗ Failed to initialize: {e}", is_error=True)
            return TelemetryResult(
                success=False,
                provider_name=self.name,
                message="Failed to initialize OpenTelemetry",
                error=str(e),
            )

    def create_logger(self, name: str) -> Any:
        """
        Create a logger instance.

        Args:
            name: Logger name

        Returns:
            Logger instance
        """
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")

        return self._logger

    def create_tracer(self, name: str) -> Any:
        """
        Create a tracer instance.

        Args:
            name: Tracer name

        Returns:
            Tracer instance
        """
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")

        return self._tracer

    def create_meter(self, name: str) -> Any:
        """
        Create a meter instance.

        Args:
            name: Meter name

        Returns:
            Meter instance
        """
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")

        # Return the meter from telemetry service if available
        try:
            from secure_mcp_gateway.services.telemetry.telemetry_service import meter

            return meter
        except ImportError:
            return None

    def is_initialized(self) -> bool:
        """Check if provider is initialized"""
        return self._initialized


__all__ = ["OpenTelemetryProvider"]
