"""Shared semantic conventions for all Enkrypt security products.

These constants define the canonical span attribute names and metric names
used across Gateway, SDK, and Hooks.  All products MUST use these instead
of inventing their own, so Grafana/Jaeger dashboards show a unified view.

Naming follows OpenTelemetry conventions:
  - Dot-separated namespaces (``enkrypt.guardrail.checks``)
  - Durations in seconds (not milliseconds)
  - Counters have no ``_total`` suffix (OTel adds it automatically)
"""

from __future__ import annotations

# ===================================================================
# Span attribute names
# ===================================================================

class SpanAttributes:
    """Attribute keys attached to Enkrypt spans."""

    # Guardrail attributes
    GUARDRAIL_NAME = "enkrypt.guardrail.name"
    GUARDRAIL_ACTION = "enkrypt.guardrail.action"
    GUARDRAIL_VIOLATIONS = "enkrypt.guardrail.violations"
    GUARDRAIL_DETECTOR = "enkrypt.guardrail.detector"

    # Tool attributes
    TOOL_NAME = "enkrypt.tool.name"
    TOOL_SERVER = "enkrypt.tool.server"

    # Identity attributes
    SERVER_NAME = "enkrypt.server.name"
    PROJECT_ID = "enkrypt.project.id"
    USER_ID = "enkrypt.user.id"
    CONFIG_ID = "enkrypt.config.id"

    # Source attributes (which product emitted the span)
    SOURCE_PRODUCT = "enkrypt.source.product"
    SOURCE_EVENT = "enkrypt.source.event"

    # Error attributes
    ERROR_CODE = "enkrypt.error.code"
    ERROR_MESSAGE = "enkrypt.error.message"


# ===================================================================
# Span names
# ===================================================================

class SpanNames:
    """Canonical span names used by all products."""

    # Guardrail spans
    GUARDRAIL_CHECK = "enkrypt.guardrail.check"

    # Tool execution spans
    TOOL_EXECUTE = "enkrypt.tool.execute"
    TOOL_FORWARD = "enkrypt.tool.forward"
    TOOL_VALIDATE = "enkrypt.tool.validate"

    # Auth spans
    AUTH = "enkrypt.auth"

    # Discovery spans (gateway)
    DISCOVERY = "enkrypt.discovery"
    DISCOVERY_CACHE_CHECK = "enkrypt.discovery.cache_check"
    DISCOVERY_FORWARD = "enkrypt.discovery.forward"
    DISCOVERY_CACHE_STORE = "enkrypt.discovery.cache_store"

    # Server management spans (gateway)
    SERVER_LIST = "enkrypt.server.list"
    SERVER_INFO = "enkrypt.server.info"
    SERVER_PROCESS = "enkrypt.server.process"

    # Cache management spans (gateway)
    CACHE_STATUS = "enkrypt.cache.status"
    CACHE_CLEAR = "enkrypt.cache.clear"

    # Validation span (collapsed from gateway's 10+ validation spans)
    VALIDATION = "enkrypt.validation"

    # PII spans
    PII_REDACT = "enkrypt.pii.redact"
    PII_RESTORE = "enkrypt.pii.restore"


# ===================================================================
# Metric names
# ===================================================================

class MetricNames:
    """Canonical metric names — 12 shared definitions replacing 44 total."""

    # Guardrail metrics (all products)
    GUARDRAIL_CHECKS = "enkrypt.guardrail.checks"
    GUARDRAIL_BLOCKS = "enkrypt.guardrail.blocks"
    GUARDRAIL_DURATION = "enkrypt.guardrail.duration"

    # Tool metrics (all products)
    TOOL_CALLS = "enkrypt.tool.calls"
    TOOL_DURATION = "enkrypt.tool.duration"
    TOOL_ERRORS = "enkrypt.tool.errors"

    # Auth metrics (gateway)
    AUTH_SUCCESS = "enkrypt.auth.success"
    AUTH_FAILURE = "enkrypt.auth.failure"

    # Cache metrics (gateway)
    CACHE_HITS = "enkrypt.cache.hits"
    CACHE_MISSES = "enkrypt.cache.misses"

    # PII metrics (all products)
    PII_REDACTIONS = "enkrypt.pii.redactions"

    # Session metrics (gateway)
    SESSION_ACTIVE = "enkrypt.session.active"

    # Discovery metrics (gateway)
    DISCOVERY_LIST = "enkrypt.discovery.list_servers"
    DISCOVERY_FOUND = "enkrypt.discovery.servers_found"

    # Timeout metrics (gateway)
    TIMEOUT_OPERATIONS = "enkrypt.timeout.operations"


# ===================================================================
# Metric descriptions
# ===================================================================

METRIC_DESCRIPTIONS: dict[str, str] = {
    MetricNames.GUARDRAIL_CHECKS: "Total guardrail API calls",
    MetricNames.GUARDRAIL_BLOCKS: "Total guardrail blocks",
    MetricNames.GUARDRAIL_DURATION: "Guardrail check duration in seconds",
    MetricNames.TOOL_CALLS: "Total tool executions",
    MetricNames.TOOL_DURATION: "Tool execution duration in seconds",
    MetricNames.TOOL_ERRORS: "Total tool execution errors",
    MetricNames.AUTH_SUCCESS: "Successful authentications",
    MetricNames.AUTH_FAILURE: "Failed authentications",
    MetricNames.CACHE_HITS: "Cache hits",
    MetricNames.CACHE_MISSES: "Cache misses",
    MetricNames.PII_REDACTIONS: "PII redaction operations",
    MetricNames.SESSION_ACTIVE: "Currently active sessions",
    MetricNames.DISCOVERY_LIST: "Server list endpoint calls",
    MetricNames.DISCOVERY_FOUND: "Total servers discovered",
    MetricNames.TIMEOUT_OPERATIONS: "Timeout-related operations",
}


# ===================================================================
# Source product identifiers
# ===================================================================

class SourceProduct:
    GATEWAY = "gateway"
    SDK = "sdk"
    HOOKS = "hooks"


# ===================================================================
# Source event identifiers
# ===================================================================

class SourceEvent:
    PRE_LLM = "pre_llm"
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    POST_LLM = "post_llm"
    REGISTRATION = "registration"


# ===================================================================
# gen_ai.* semantic conventions (OpenLLMetry / emerging OTel standard)
# ===================================================================

class GenAIAttributes:
    """``gen_ai.*`` attribute keys used by OpenLLMetry instrumentors.

    Defined here so Enkrypt code can reference them without importing
    the OpenLLMetry packages themselves (e.g., to read attributes from
    parent spans, add context to guardrail spans, or build dashboards).

    See: https://opentelemetry.io/docs/specs/semconv/gen-ai/
    """

    SYSTEM = "gen_ai.system"
    REQUEST_MODEL = "gen_ai.request.model"
    RESPONSE_MODEL = "gen_ai.response.model"
    REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens"
    REQUEST_TEMPERATURE = "gen_ai.request.temperature"
    REQUEST_TOP_P = "gen_ai.request.top_p"
    USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
    USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
    USAGE_TOTAL_TOKENS = "gen_ai.usage.total_tokens"
    OPERATION_NAME = "gen_ai.operation.name"
    RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons"


class GenAIMetrics:
    """``gen_ai.*`` metric names produced by OpenLLMetry.

    Referenced so Enkrypt dashboards can correlate LLM metrics with
    guardrail metrics without depending on OpenLLMetry at import time.
    """

    CLIENT_OPERATION_DURATION = "gen_ai.client.operation.duration"
    CLIENT_TOKEN_USAGE = "gen_ai.client.token.usage"
