"""
Dummy telemetry emitter mirroring what secure_mcp_gateway emits.

Points at the OpenSearch otel-collector (host port 4317 grpc -- the OTel
default; OpenSearch is the primary backend) and produces realistic
metrics, traces, and logs so the OpenSearch Dashboards can be visually
verified end-to-end without standing up the real gateway.

Matches:
  - Service name:               secure-mcp-gateway
  - Metric names + types:       conventions.py / opentelemetry_provider.py
  - Attribute keys:             enkrypt.server.name, enkrypt.tool.name, ...
  - Temporality:                DELTA for counters + histograms, CUMULATIVE
                                for gauges (matches preferred_temporality
                                in opentelemetry_provider.py)

Run:
  python emit_dummy_telemetry.py
"""

import random
import time

from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics._internal.instrument import (
    Counter,
    Histogram,
    ObservableCounter,
    ObservableGauge,
    ObservableUpDownCounter,
    UpDownCounter,
)
from opentelemetry.sdk.metrics.export import (
    AggregationTemporality,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.metrics.view import View
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Status, StatusCode

OTLP_ENDPOINT = "http://localhost:4317"

# Match opentelemetry_provider.py:_PREFERRED_TEMPORALITY exactly.
PREFERRED_TEMPORALITY = {
    Counter: AggregationTemporality.DELTA,
    Histogram: AggregationTemporality.DELTA,
    ObservableCounter: AggregationTemporality.DELTA,
    UpDownCounter: AggregationTemporality.CUMULATIVE,
    ObservableUpDownCounter: AggregationTemporality.CUMULATIVE,
    ObservableGauge: AggregationTemporality.CUMULATIVE,
}

RESOURCE = Resource.create(
    {
        "service.name": "secure-mcp-gateway",
        "service.version": "2.1.2",
        "deployment.environment": "local-dev",
    }
)

# ---------- Metrics ----------
metric_exporter = OTLPMetricExporter(
    endpoint=OTLP_ENDPOINT, insecure=True, preferred_temporality=PREFERRED_TEMPORALITY
)
reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=2000)
meter_provider = MeterProvider(resource=RESOURCE, metric_readers=[reader])
metrics.set_meter_provider(meter_provider)
meter = meter_provider.get_meter("smg")

tool_calls = meter.create_counter("enkrypt.tool.calls", unit="1")
tool_duration = meter.create_histogram("enkrypt.tool.duration", unit="s")
tool_blocked = meter.create_counter("enkrypt.tool.blocked", unit="1")

guardrail_checks = meter.create_counter("enkrypt.guardrail.checks", unit="1")
guardrail_blocks = meter.create_counter("enkrypt.guardrail.blocks", unit="1")
guardrail_duration = meter.create_histogram("enkrypt.guardrail.duration", unit="s")

cache_hits = meter.create_counter("enkrypt.cache.hits", unit="1")
cache_misses = meter.create_counter("enkrypt.cache.misses", unit="1")

discovery_list = meter.create_counter("enkrypt.discovery.list_servers", unit="1")
discovery_found = meter.create_counter("enkrypt.discovery.servers_found", unit="1")

# ---------- Traces ----------
tracer_provider = TracerProvider(resource=RESOURCE)
tracer_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True))
)
trace.set_tracer_provider(tracer_provider)
tracer = trace.get_tracer("smg")

# ---------- Logs ----------
logger_provider = LoggerProvider(resource=RESOURCE)
logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(OTLPLogExporter(endpoint=OTLP_ENDPOINT, insecure=True))
)
set_logger_provider(logger_provider)

import logging

otel_handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
logging.getLogger().addHandler(otel_handler)
logging.getLogger().setLevel(logging.DEBUG)
log = logging.getLogger("secure-mcp-gateway")


SERVERS = ["echo_server", "github_server", "filesystem_server"]
TOOLS = {
    "echo_server": ["echo", "ping"],
    "github_server": ["list_issues", "create_issue", "search_repos"],
    "filesystem_server": ["read_file", "write_file", "list_dir"],
}
VIOLATION_TYPES = [
    "policy_violation",
    "injection_attack",
    "pii_found",
    "toxicity",
    "nsfw",
]
SEVERITIES = [
    ("INFO", logging.INFO),
    ("WARNING", logging.WARNING),
    ("ERROR", logging.ERROR),
    ("DEBUG", logging.DEBUG),
]


def emit_round(i: int) -> None:
    """One round of realistic gateway-like telemetry."""
    # Discovery (low-frequency)
    if i % 5 == 0:
        discovery_list.add(1, {"enkrypt.gateway.id": "local-dev"})
        discovery_found.add(len(SERVERS), {"enkrypt.gateway.id": "local-dev"})

    # Per-server bursts
    for server in SERVERS:
        n_calls = random.randint(1, 6)
        for _ in range(n_calls):
            tool = random.choice(TOOLS[server])
            attrs = {
                "enkrypt.server.name": server,
                "enkrypt.tool.name": tool,
            }
            tool_calls.add(1, attrs)
            tool_duration.record(random.uniform(0.005, 1.2), attrs)

            # Guardrail input + output check per tool call
            guardrail_checks.add(2, {**attrs, "checkpoint": "input"})
            guardrail_duration.record(
                random.uniform(0.03, 0.5), {**attrs, "checkpoint": "input"}
            )
            guardrail_checks.add(0, attrs)  # no-op to keep series alive
            guardrail_duration.record(
                random.uniform(0.03, 0.5), {**attrs, "checkpoint": "output"}
            )

            # 15% block rate
            if random.random() < 0.15:
                violation = random.choice(VIOLATION_TYPES)
                block_attrs = {**attrs, "violation_type": violation}
                guardrail_blocks.add(1, block_attrs)
                tool_blocked.add(1, block_attrs)

            # 70/30 cache hit/miss
            if random.random() < 0.7:
                cache_hits.add(1, attrs)
            else:
                cache_misses.add(1, attrs)

            # Span per tool call
            with tracer.start_as_current_span(f"forward_tool_call:{tool}") as span:
                span.set_attribute("enkrypt.server.name", server)
                span.set_attribute("enkrypt.tool.name", tool)
                span.set_attribute("enkrypt.gateway.id", "local-dev")
                # ~5% error rate
                if random.random() < 0.05:
                    span.set_status(Status(StatusCode.ERROR, "tool execution failed"))
                    span.record_exception(RuntimeError("dummy upstream error"))
                # Latency
                time.sleep(random.uniform(0.001, 0.02))

            # One log per call, weighted toward INFO
            _sev_name, sev_level = random.choices(
                SEVERITIES, weights=[60, 20, 10, 10], k=1
            )[0]
            log.log(
                sev_level,
                "tool=%s server=%s status=%s",
                tool,
                server,
                "blocked" if random.random() < 0.15 else "ok",
                extra={"enkrypt_server_name": server, "enkrypt_tool_name": tool},
            )


def main():
    print(f"Emitting dummy telemetry to {OTLP_ENDPOINT} ...")
    print("Service: secure-mcp-gateway, DELTA temporality (matches real gateway).")
    print("Ctrl-C to stop. Each round = ~10-15 tool calls across 3 servers.\n")
    round_n = 0
    try:
        while True:
            round_n += 1
            emit_round(round_n)
            print(f"  round {round_n} emitted.")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nFlushing...")
    finally:
        meter_provider.force_flush()
        meter_provider.shutdown()
        tracer_provider.force_flush()
        tracer_provider.shutdown()
        logger_provider.force_flush()
        logger_provider.shutdown()
        print("Done.")


if __name__ == "__main__":
    main()
