"""Enkrypt telemetry — unified OTel setup, conventions, redaction, and OpenLLMetry.

Usage::

    from enkrypt_security.telemetry import init_telemetry, SpanAttributes, MetricNames

    ctx = init_telemetry(
        service_name="my-service",
        exporter="otlp_grpc",
        endpoint="http://localhost:4317",
    )

    tracer = ctx.tracer
    meter = ctx.meter

    with tracer.start_as_current_span("my.operation") as span:
        span.set_attribute(SpanAttributes.GUARDRAIL_NAME, "My Policy")

OpenLLMetry integration::

    from enkrypt_security.telemetry import any_llm_instrumentor_active

    if any_llm_instrumentor_active():
        # OpenLLMetry handles LLM spans — only create guardrail spans
        ...
    else:
        # No LLM observability — create basic LLM spans ourselves
        ...
"""

from enkrypt_security.telemetry.conventions import (
    GenAIAttributes,
    GenAIMetrics,
    MetricNames,
    SourceEvent,
    SourceProduct,
    SpanAttributes,
    SpanNames,
)
from enkrypt_security.telemetry.openllmetry import (
    any_llm_instrumentor_active,
    get_active_instrumentors,
    has_traceloop_sdk,
    init_openllmetry,
    is_instrumentor_active,
)
from enkrypt_security.telemetry.redaction import (
    PayloadPolicy,
    mask_sensitive_data,
    mask_sensitive_env_vars,
    mask_sensitive_headers,
    sanitize_attributes,
)
from enkrypt_security.telemetry.setup import (
    TelemetryContext,
    init_telemetry,
    is_otel_available,
)

__all__ = [
    "GenAIAttributes",
    "GenAIMetrics",
    "MetricNames",
    "PayloadPolicy",
    "SourceEvent",
    "SourceProduct",
    "SpanAttributes",
    "SpanNames",
    "TelemetryContext",
    "any_llm_instrumentor_active",
    "get_active_instrumentors",
    "has_traceloop_sdk",
    "init_openllmetry",
    "init_telemetry",
    "is_instrumentor_active",
    "is_otel_available",
    "mask_sensitive_data",
    "mask_sensitive_env_vars",
    "mask_sensitive_headers",
    "sanitize_attributes",
]
