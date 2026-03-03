"""Unified telemetry initialisation for all Enkrypt security products.

Replaces:
  - Gateway's ``OpenTelemetryProvider`` (700+ lines)
  - SDK's ``otel_setup.py`` (143 lines)
  - Both products' custom no-op classes

When ``opentelemetry-sdk`` is not installed, returns no-op objects from
stdlib — no custom classes needed.  This keeps the core zero-dependency.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from enkrypt_security.config.models import ExporterType

logger = logging.getLogger("enkrypt_security.telemetry")

# ---------------------------------------------------------------------------
# Detect whether OpenTelemetry SDK is available
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )

    _OTEL_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# No-op fallbacks (used when OTel is not installed or disabled)
# ---------------------------------------------------------------------------

class _NoOpSpan:
    """Minimal stand-in for ``opentelemetry.trace.Span``."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *a: Any, **kw: Any) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass

    def end(self) -> None:
        pass

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *_: Any) -> None:
        pass


class _NoOpTracer:
    def start_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()

    def start_as_current_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()


class _NoOpCounter:
    def add(self, amount: int = 1, attributes: dict[str, str] | None = None) -> None:
        pass


class _NoOpHistogram:
    def record(
        self, value: float, attributes: dict[str, str] | None = None
    ) -> None:
        pass


class _NoOpMeter:
    def create_counter(self, name: str, **kw: Any) -> _NoOpCounter:
        return _NoOpCounter()

    def create_histogram(self, name: str, **kw: Any) -> _NoOpHistogram:
        return _NoOpHistogram()

    def create_up_down_counter(self, name: str, **kw: Any) -> _NoOpCounter:
        return _NoOpCounter()


class _NoOpLogger:
    """Absorbs all log calls when no logger is configured."""

    def debug(self, *a: Any, **kw: Any) -> None:
        pass

    def info(self, *a: Any, **kw: Any) -> None:
        pass

    def warning(self, *a: Any, **kw: Any) -> None:
        pass

    def error(self, *a: Any, **kw: Any) -> None:
        pass

    def critical(self, *a: Any, **kw: Any) -> None:
        pass


_NOOP_TRACER = _NoOpTracer()
_NOOP_METER = _NoOpMeter()
_NOOP_LOGGER = _NoOpLogger()


# ---------------------------------------------------------------------------
# Telemetry context — the single return type from init_telemetry()
# ---------------------------------------------------------------------------

@dataclass
class TelemetryContext:
    """Holds the tracer, meter, and logger for an application.

    All three are guaranteed non-None (no-ops when disabled).
    """

    tracer: Any = field(default_factory=lambda: _NOOP_TRACER)
    meter: Any = field(default_factory=lambda: _NOOP_METER)
    log: Any = field(default_factory=lambda: _NOOP_LOGGER)
    enabled: bool = False

    # Keep references for shutdown
    _tracer_provider: Any = field(default=None, repr=False)
    _meter_provider: Any = field(default=None, repr=False)

    def shutdown(self) -> None:
        """Flush and shut down OTel providers."""
        if self._tracer_provider and hasattr(self._tracer_provider, "shutdown"):
            self._tracer_provider.shutdown()
        if self._meter_provider and hasattr(self._meter_provider, "shutdown"):
            self._meter_provider.shutdown()


# ---------------------------------------------------------------------------
# Exporter factories
# ---------------------------------------------------------------------------

def _create_span_exporter(
    exporter: ExporterType,
    endpoint: str,
    headers: dict[str, str] | None,
    insecure: bool,
) -> Any:
    if exporter == ExporterType.OTLP_GRPC:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        return OTLPSpanExporter(
            endpoint=endpoint, headers=headers, insecure=insecure
        )
    if exporter == ExporterType.OTLP_HTTP:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        return OTLPSpanExporter(
            endpoint=f"{endpoint}/v1/traces", headers=dict(headers or {})
        )
    return ConsoleSpanExporter()


def _create_metric_exporter(
    exporter: ExporterType,
    endpoint: str,
    headers: dict[str, str] | None,
    insecure: bool,
) -> Any:
    if exporter == ExporterType.OTLP_GRPC:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )

        return OTLPMetricExporter(
            endpoint=endpoint, headers=headers, insecure=insecure
        )
    if exporter == ExporterType.OTLP_HTTP:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )

        return OTLPMetricExporter(
            endpoint=f"{endpoint}/v1/metrics", headers=dict(headers or {})
        )
    return ConsoleMetricExporter()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_telemetry(
    *,
    service_name: str = "enkrypt-security",
    exporter: ExporterType | str = ExporterType.NONE,
    endpoint: str = "",
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    metric_export_interval_ms: int = 10_000,
) -> TelemetryContext:
    """Initialise OpenTelemetry tracing + metrics and return a context.

    When ``opentelemetry-sdk`` is not installed or ``exporter`` is
    ``"none"``, everything is a no-op — safe to call unconditionally.

    Args:
        service_name: OTel ``service.name`` resource attribute.
        exporter: One of ``"none"``, ``"console"``, ``"otlp_grpc"``,
            ``"otlp_http"`` (or the :class:`ExporterType` enum).
        endpoint: OTLP collector endpoint. Falls back to
            ``OTEL_EXPORTER_OTLP_ENDPOINT`` env var.
        headers: Extra headers for the OTLP exporter.
        insecure: Whether to use insecure (non-TLS) gRPC.
        metric_export_interval_ms: How often to push metrics.

    Returns:
        :class:`TelemetryContext` with ``tracer``, ``meter``, and ``log``.
    """
    # Normalize string → enum
    if isinstance(exporter, str):
        try:
            exporter = ExporterType(exporter)
        except ValueError:
            logger.warning("Unknown exporter %r, disabling telemetry", exporter)
            exporter = ExporterType.NONE

    if not _OTEL_AVAILABLE:
        if exporter != ExporterType.NONE:
            logger.info(
                "opentelemetry-sdk not installed; telemetry disabled. "
                "Install with: pip install enkrypt-security[otel]"
            )
        return TelemetryContext()

    if exporter == ExporterType.NONE:
        return TelemetryContext()

    # Resolve endpoint
    resolved_endpoint = (
        endpoint
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    )
    if not resolved_endpoint and exporter in (
        ExporterType.OTLP_GRPC,
        ExporterType.OTLP_HTTP,
    ):
        logger.warning(
            "OTLP exporter selected but no endpoint configured; "
            "set 'endpoint' or OTEL_EXPORTER_OTLP_ENDPOINT"
        )

    resource = Resource.create({"service.name": service_name})

    # --- Tracing ---
    tracer_provider = TracerProvider(resource=resource)
    span_exp = _create_span_exporter(exporter, resolved_endpoint, headers, insecure)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exp))
    otel_trace.set_tracer_provider(tracer_provider)
    tracer = tracer_provider.get_tracer("enkrypt_security")

    # --- Metrics ---
    metric_exp = _create_metric_exporter(
        exporter, resolved_endpoint, headers, insecure
    )
    reader = PeriodicExportingMetricReader(
        metric_exp, export_interval_millis=metric_export_interval_ms
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    otel_metrics.set_meter_provider(meter_provider)
    meter = meter_provider.get_meter("enkrypt_security")

    # --- Structured logging (optional, uses structlog if available) ---
    log = _create_logger(service_name)

    logger.info(
        "Telemetry initialised: exporter=%s endpoint=%s service=%s",
        exporter.value,
        resolved_endpoint,
        service_name,
    )

    return TelemetryContext(
        tracer=tracer,
        meter=meter,
        log=log,
        enabled=True,
        _tracer_provider=tracer_provider,
        _meter_provider=meter_provider,
    )


def _create_logger(service_name: str) -> Any:
    """Create a structured logger, preferring structlog if available."""
    try:
        import structlog

        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.PrintLoggerFactory(),
        )
        return structlog.get_logger(service=service_name)
    except ImportError:
        return logging.getLogger(service_name)


def is_otel_available() -> bool:
    """Check if OpenTelemetry SDK is importable."""
    return _OTEL_AVAILABLE
