"""OpenTelemetry bootstrap — delegates to the shared ``enkrypt_security`` package.

All original public names are re-exported for backward compatibility.
The ``init_telemetry`` wrapper preserves the SDK's calling convention
while using the shared implementation under the hood.
"""

from __future__ import annotations

from typing import Any

from enkrypt_security.config.models import ExporterType
from enkrypt_security.telemetry.setup import TelemetryContext, is_otel_available
from enkrypt_security.telemetry.setup import init_telemetry as _shared_init_telemetry


def init_telemetry(
    *,
    service_name: str = "enkrypt-agent-sdk",
    exporter: ExporterType | str = ExporterType.CONSOLE,
    otlp_endpoint: str | None = None,
    otlp_headers: dict[str, str] | None = None,
    metric_export_interval_ms: int = 10_000,
) -> TelemetryContext:
    """Initialise OTel providers and return a :class:`TelemetryContext`.

    Falls back to no-ops when the ``otel`` extra is not installed.
    """
    return _shared_init_telemetry(
        service_name=service_name,
        exporter=exporter,
        endpoint=otlp_endpoint or "",
        headers=otlp_headers,
        metric_export_interval_ms=metric_export_interval_ms,
    )


def shutdown_telemetry(ctx: Any) -> None:
    """Shut down providers.  Accepts a TelemetryContext or legacy (tp, mp) tuple."""
    if isinstance(ctx, TelemetryContext):
        ctx.shutdown()
    elif hasattr(ctx, "shutdown"):
        ctx.shutdown()


__all__ = [
    "ExporterType",
    "TelemetryContext",
    "init_telemetry",
    "is_otel_available",
    "shutdown_telemetry",
]
