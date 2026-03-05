"""Tests for telemetry/setup.py — init_telemetry and no-op fallbacks."""

import importlib.util
import logging
import sys
from unittest.mock import patch

import pytest

from enkryptai_agent_security.config.models import ExporterType
from enkryptai_agent_security.telemetry.setup import (
    TelemetryContext,
    _NoOpCounter,
    _NoOpHistogram,
    _NoOpLogger,
    _NoOpMeter,
    _NoOpSpan,
    _NoOpTracer,
    _create_logger,
    init_telemetry,
    is_otel_available,
)

_HAS_OTEL = is_otel_available()
_HAS_STRUCTLOG = importlib.util.find_spec("structlog") is not None


class TestNoOpImplementations:
    def test_noop_span_context_manager(self):
        span = _NoOpSpan()
        with span as s:
            s.set_attribute("key", "value")
            s.set_status("OK")
            s.add_event("test_event")
            s.end()

    def test_noop_span_record_exception(self):
        span = _NoOpSpan()
        span.record_exception(ValueError("test"))

    def test_noop_tracer(self):
        tracer = _NoOpTracer()
        span = tracer.start_span("test")
        assert isinstance(span, _NoOpSpan)
        span2 = tracer.start_as_current_span("test2")
        assert isinstance(span2, _NoOpSpan)

    def test_noop_meter(self):
        meter = _NoOpMeter()
        counter = meter.create_counter("test_counter")
        assert isinstance(counter, _NoOpCounter)
        counter.add(1)

        histogram = meter.create_histogram("test_hist")
        assert isinstance(histogram, _NoOpHistogram)
        histogram.record(1.5)

        up_down = meter.create_up_down_counter("test_updown")
        assert isinstance(up_down, _NoOpCounter)

    def test_noop_logger(self):
        log = _NoOpLogger()
        log.debug("test")
        log.info("test")
        log.warning("test")
        log.error("test")
        log.critical("test")


class TestTelemetryContext:
    def test_default_context_has_noops(self):
        ctx = TelemetryContext()
        assert ctx.enabled is False
        assert isinstance(ctx.tracer, _NoOpTracer)
        assert isinstance(ctx.meter, _NoOpMeter)
        assert isinstance(ctx.log, _NoOpLogger)

    def test_shutdown_safe_on_noop(self):
        ctx = TelemetryContext()
        ctx.shutdown()


class TestInitTelemetry:
    def test_none_exporter_returns_noop(self):
        ctx = init_telemetry(exporter=ExporterType.NONE)
        assert ctx.enabled is False
        assert isinstance(ctx.tracer, _NoOpTracer)

    def test_string_none_exporter(self):
        ctx = init_telemetry(exporter="none")
        assert ctx.enabled is False

    def test_invalid_exporter_string_falls_back(self):
        ctx = init_telemetry(exporter="invalid_type")
        assert ctx.enabled is False

    def test_is_otel_available_returns_bool(self):
        result = is_otel_available()
        assert isinstance(result, bool)


# ===================================================================
# Traces pillar — InMemorySpanExporter (no global state mutation)
# ===================================================================

@pytest.mark.skipif(not _HAS_OTEL, reason="opentelemetry-sdk not installed")
class TestInMemorySpanExporter:
    """Verify actual OTel span creation using in-memory exporter."""

    def _make_provider(self, resource=None):
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        exporter = InMemorySpanExporter()
        res = resource or Resource.create({"service.name": "test"})
        provider = TracerProvider(resource=res)
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        return provider, exporter

    def test_span_creation_with_attributes(self):
        from enkryptai_agent_security.telemetry.conventions import SpanAttributes

        provider, exporter = self._make_provider()
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("enkrypt.guardrail.check") as span:
            span.set_attribute(SpanAttributes.GUARDRAIL_NAME, "test-policy")
        provider.shutdown()

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "enkrypt.guardrail.check"
        assert spans[0].attributes[SpanAttributes.GUARDRAIL_NAME] == "test-policy"

    def test_span_records_exception(self):
        provider, exporter = self._make_provider()
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("test.op") as span:
            span.record_exception(ValueError("test error"))
        provider.shutdown()

        spans = exporter.get_finished_spans()
        events = spans[0].events
        assert len(events) == 1
        assert events[0].name == "exception"
        assert "ValueError" in str(events[0].attributes.get("exception.type", ""))

    def test_parent_child_context(self):
        provider, exporter = self._make_provider()
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("parent") as parent_span:
            with tracer.start_as_current_span("child"):
                pass
        provider.shutdown()

        spans = exporter.get_finished_spans()
        assert len(spans) == 2
        child = [s for s in spans if s.name == "child"][0]
        parent = [s for s in spans if s.name == "parent"][0]
        assert child.parent.span_id == parent.context.span_id

    def test_resource_service_name(self):
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": "my-test-svc"})
        provider, exporter = self._make_provider(resource=resource)
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("op"):
            pass
        provider.shutdown()

        spans = exporter.get_finished_spans()
        svc = spans[0].resource.attributes.get("service.name")
        assert svc == "my-test-svc"


# ===================================================================
# Metrics pillar — InMemoryMetricReader (no global state mutation)
# ===================================================================

@pytest.mark.skipif(not _HAS_OTEL, reason="opentelemetry-sdk not installed")
class TestInMemoryMetricReader:
    """Verify actual OTel metric recording using in-memory reader."""

    def _make_provider(self):
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader

        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        return provider, reader

    def _get_metric_value(self, reader, metric_name):
        data = reader.get_metrics_data()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    if metric.name == metric_name:
                        points = list(metric.data.data_points)
                        if points:
                            # Counter → sum, Histogram → sum/count
                            return getattr(points[0], "value", None) or getattr(points[0], "sum", None)
        return None

    def test_counter_records_value(self):
        provider, reader = self._make_provider()
        meter = provider.get_meter("test")
        counter = meter.create_counter("enkrypt.test.counter")
        counter.add(5, {"server": "echo"})

        value = self._get_metric_value(reader, "enkrypt.test.counter")
        assert value == 5
        provider.shutdown()

    def test_histogram_records_value(self):
        provider, reader = self._make_provider()
        meter = provider.get_meter("test")
        hist = meter.create_histogram("enkrypt.test.histogram")
        hist.record(1.5)

        value = self._get_metric_value(reader, "enkrypt.test.histogram")
        assert value == 1.5
        provider.shutdown()

    def test_up_down_counter(self):
        provider, reader = self._make_provider()
        meter = provider.get_meter("test")
        udc = meter.create_up_down_counter("enkrypt.test.updown")
        udc.add(3)
        udc.add(-1)

        value = self._get_metric_value(reader, "enkrypt.test.updown")
        assert value == 2
        provider.shutdown()


# ===================================================================
# Logging pillar — structlog / stdlib fallback
# ===================================================================

@pytest.mark.skipif(not _HAS_STRUCTLOG, reason="structlog not installed")
class TestStructlogIntegration:
    def test_structlog_logger_when_available(self):
        log = _create_logger("test-svc")
        assert not isinstance(log, _NoOpLogger)
        assert hasattr(log, "info")

    def test_structlog_produces_output(self, capsys):
        import structlog
        structlog.reset_defaults()
        log = _create_logger("test-svc")
        log.info("test_msg")
        captured = capsys.readouterr()
        assert "test_msg" in captured.out

    def test_stdlib_fallback(self):
        with patch.dict(sys.modules, {"structlog": None}):
            log = _create_logger("test-svc-fallback")
            assert isinstance(log, logging.Logger)


# ===================================================================
# init_telemetry integration (mock global setters to avoid pollution)
# ===================================================================

@pytest.mark.skipif(not _HAS_OTEL, reason="opentelemetry-sdk not installed")
class TestInitTelemetryIntegration:
    def test_console_returns_enabled_context(self):
        with patch("enkryptai_agent_security.telemetry.setup.otel_trace.set_tracer_provider"), \
             patch("enkryptai_agent_security.telemetry.setup.otel_metrics.set_meter_provider"):
            ctx = init_telemetry(exporter="console")
            assert ctx.enabled is True
            assert not isinstance(ctx.tracer, _NoOpTracer)
            assert not isinstance(ctx.meter, _NoOpMeter)
            ctx.shutdown()

    def test_endpoint_from_env_var(self, monkeypatch):
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://fake:4317")
        with patch("enkryptai_agent_security.telemetry.setup.otel_trace.set_tracer_provider"), \
             patch("enkryptai_agent_security.telemetry.setup.otel_metrics.set_meter_provider"):
            ctx = init_telemetry(exporter="console")
            assert ctx.enabled is True
            ctx.shutdown()

    def test_shutdown_calls_providers(self):
        with patch("enkryptai_agent_security.telemetry.setup.otel_trace.set_tracer_provider"), \
             patch("enkryptai_agent_security.telemetry.setup.otel_metrics.set_meter_provider"):
            ctx = init_telemetry(exporter="console")
            assert ctx._tracer_provider is not None
            assert ctx._meter_provider is not None
            # Should not raise
            ctx.shutdown()

    def test_unknown_exporter_string_disables(self):
        ctx = init_telemetry(exporter="bogus_nonexistent")
        assert ctx.enabled is False


# ===================================================================
# Exporter factory functions
# ===================================================================

@pytest.mark.skipif(not _HAS_OTEL, reason="opentelemetry-sdk not installed")
class TestExporterFactories:
    def test_console_span_exporter_created(self):
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        from enkryptai_agent_security.telemetry.setup import _create_span_exporter

        exp = _create_span_exporter(ExporterType.CONSOLE, "", None, False)
        assert isinstance(exp, ConsoleSpanExporter)

    def test_console_metric_exporter_created(self):
        from opentelemetry.sdk.metrics.export import ConsoleMetricExporter

        from enkryptai_agent_security.telemetry.setup import _create_metric_exporter

        exp = _create_metric_exporter(ExporterType.CONSOLE, "", None, False)
        assert isinstance(exp, ConsoleMetricExporter)

    def test_otlp_grpc_span_exporter_created(self):
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError:
            pytest.skip("opentelemetry-exporter-otlp not installed")

        from enkryptai_agent_security.telemetry.setup import _create_span_exporter

        exp = _create_span_exporter(
            ExporterType.OTLP_GRPC, "http://localhost:4317", None, True
        )
        assert isinstance(exp, OTLPSpanExporter)
