"""
Telemetry Plugin System

A flexible, extensible telemetry system following SOLID principles.

This plugin system allows you to:
- Switch between different telemetry providers (OpenTelemetry, Datadog, New Relic, etc.)
- Create custom telemetry providers
- Configure telemetry through config files
- Use multiple telemetry backends simultaneously

Quick Start:
    ```python
    from secure_mcp_gateway.plugins.telemetry import (
        get_telemetry_config_manager,
        initialize_telemetry_system,
    )

    # Initialize with config
    manager = initialize_telemetry_system(config)

    # Get logger and tracer
    logger = manager.get_logger()
    tracer = manager.get_tracer()
    ```

Example Config:
    ```json
    {
      "enkrypt_telemetry": {
        "enabled": true,
        "endpoint": "http://localhost:4317",
        "insecure": true
      },
      "telemetry_plugins": {
        "enabled": false,
        "providers": [
          {
            "name": "console-logger",
            "type": "console",
            "config": {"level": "INFO"}
          }
        ]
      }
    }
    ```
"""

from secure_mcp_gateway.plugins.telemetry.base import (
    TelemetryLevel,
    TelemetryProvider,
    TelemetryRegistry,
    TelemetryResult,
)
from secure_mcp_gateway.plugins.telemetry.config_manager import (
    TelemetryConfigManager,
    get_telemetry_config_manager,
    initialize_telemetry_system,
)
from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
    OpenTelemetryProvider,
)

__all__ = [
    # Base classes
    "TelemetryProvider",
    "TelemetryRegistry",
    "TelemetryResult",
    "TelemetryLevel",
    # Config manager
    "TelemetryConfigManager",
    "get_telemetry_config_manager",
    "initialize_telemetry_system",
    # Providers
    "OpenTelemetryProvider",
]
