"""OpenTelemetry bootstrap — sets up TracerProvider, MeterProvider, and exporters.

Closely mirrors the gateway's ``opentelemetry_provider.py`` and AgentSight's
``otel_setup.py``, but kept dependency-light: OTel packages are optional (the
``otel`` extra).  When they are missing the public functions return no-ops.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Any


class ExporterType(str, Enum):
    NONE = "none"
    CONSOLE = "console"
    OTLP_GRPC = "otlp_grpc"
    OTLP_HTTP = "otlp_http"


# ---------------------------------------------------------------------------
# No-op fallbacks (when OTel deps are not installed)
# ---------------------------------------------------------------------------

class _NoOpSpan:
    def set_attribute(self, key: str, value: Any) -> None: ...
    def set_status(self, *a: Any, **kw: Any) -> None: ...
    def record_exception(self, exc: BaseException) -> None: ...
    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None: ...
    def end(self) -> None: ...
    def __enter__(self) -> _NoOpSpan:
        return self
    def __exit__(self, *_: Any) -> None: ...


class _NoOpTracer:
    def start_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()
    def start_as_current_span(self, name: str, **kw: Any) -> _NoOpSpan:
        return _NoOpSpan()


class _NoOpCounter:
    def add(self, amount: int = 1, attributes: dict[str, str] | None = None) -> None: ...


class _NoOpHistogram:
    def record(self, value: float, attributes: dict[str, str] | None = None) -> None: ...


class _NoOpMeter:
    def create_counter(self, name: str, **kw: Any) -> _NoOpCounter:
        return _NoOpCounter()
    def create_histogram(self, name: str, **kw: Any) -> _NoOpHistogram:
        return _NoOpHistogram()
    def create_up_down_counter(self, name: str, **kw: Any) -> _NoOpCounter:
        return _NoOpCounter()


_OTEL_AVAILABLE = False

try:
    from opentelemetry import trace, metrics  # noqa: F401
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import Resource

    _OTEL_AVAILABLE = True
except ImportError:
    pass


def init_telemetry(
    *,
    service_name: str = "enkrypt-agent-sdk",
    exporter: ExporterType = ExporterType.CONSOLE,
    otlp_endpoint: str | None = None,
    otlp_headers: dict[str, str] | None = None,
    metric_export_interval_ms: int = 10_000,
) -> tuple[Any, Any]:
    """Initialise OTel providers and return ``(TracerProvider, MeterProvider)``.

    Falls back to no-ops when the ``otel`` extra is not installed.
    """
    if not _OTEL_AVAILABLE or exporter == ExporterType.NONE:
        return _NoOpTracer(), _NoOpMeter()  # type: ignore[return-value]

    endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    resource = Resource.create({"service.name": service_name})

    # --- Tracing ----------------------------------------------------------
    tracer_provider = TracerProvider(resource=resource)
    span_exporter = _create_span_exporter(exporter, endpoint, otlp_headers)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # --- Metrics ----------------------------------------------------------
    metric_exporter = _create_metric_exporter(exporter, endpoint, otlp_headers)
    reader = PeriodicExportingMetricReader(
        metric_exporter, export_interval_millis=metric_export_interval_ms,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(meter_provider)

    return tracer_provider, meter_provider


def shutdown_telemetry(tracer_provider: Any, meter_provider: Any) -> None:
    if hasattr(tracer_provider, "shutdown"):
        tracer_provider.shutdown()
    if hasattr(meter_provider, "shutdown"):
        meter_provider.shutdown()


# ---------------------------------------------------------------------------
# Exporter factories
# ---------------------------------------------------------------------------

def _create_span_exporter(exporter: ExporterType, endpoint: str, headers: dict[str, str] | None) -> Any:
    if exporter == ExporterType.OTLP_GRPC:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        return OTLPSpanExporter(endpoint=endpoint, headers=headers, insecure=not endpoint.startswith("https"))
    if exporter == ExporterType.OTLP_HTTP:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        return OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", headers=headers)
    return ConsoleSpanExporter()


def _create_metric_exporter(exporter: ExporterType, endpoint: str, headers: dict[str, str] | None) -> Any:
    if exporter == ExporterType.OTLP_GRPC:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        return OTLPMetricExporter(endpoint=endpoint, headers=headers, insecure=not endpoint.startswith("https"))
    if exporter == ExporterType.OTLP_HTTP:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        return OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics", headers=headers)
    return ConsoleMetricExporter()
