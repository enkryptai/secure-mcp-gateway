"""Shared semantic conventions for the Secure MCP Gateway.

These constants define the canonical span attribute names, span names, and
metric names used throughout the gateway.  All modules MUST use these instead
of inventing ad-hoc strings so that Grafana / Jaeger / Prometheus dashboards
show a unified, queryable view.

Naming follows OpenTelemetry conventions:
  - Dot-separated namespaces (``enkrypt.guardrail.checks``)
  - Durations in seconds (not milliseconds)
  - Counters have no ``_total`` suffix (OTel adds it automatically)

Aligned with ``enkryptai-agent-security`` conventions so dashboards work
across Gateway, SDK, and Hooks.
"""

from __future__ import annotations

# ===================================================================
# Span attribute keys
# ===================================================================


class SpanAttributes:
    """Attribute keys attached to Enkrypt spans."""

    # --- Identity ---
    SERVER_NAME = "enkrypt.server.name"
    PROJECT_ID = "enkrypt.project.id"
    PROJECT_NAME = "enkrypt.project.name"
    USER_ID = "enkrypt.user.id"
    USER_EMAIL = "enkrypt.user.email"
    CONFIG_ID = "enkrypt.config.id"
    GATEWAY_KEY = "enkrypt.gateway.key"
    REQUEST_ID = "enkrypt.request.id"
    CUSTOM_ID = "enkrypt.custom.id"
    CORRELATION_ID = "enkrypt.correlation.id"
    SESSION_KEY = "enkrypt.session.key"

    # --- Source ---
    SOURCE_PRODUCT = "enkrypt.source.product"
    SOURCE_EVENT = "enkrypt.source.event"
    JOB = "enkrypt.job"
    ENV = "enkrypt.env"

    # --- Tool ---
    TOOL_NAME = "enkrypt.tool.name"
    TOOL_CALL_INDEX = "enkrypt.tool.call_index"
    TOOL_FOUND = "enkrypt.tool.found"
    NUM_TOOL_CALLS = "enkrypt.tool.num_calls"

    # --- Guardrail ---
    GUARDRAIL_NAME = "enkrypt.guardrail.name"
    GUARDRAIL_ACTION = "enkrypt.guardrail.action"
    GUARDRAIL_VIOLATION_TYPES = "enkrypt.guardrail.violation_types"
    GUARDRAIL_CHECKPOINT = "enkrypt.guardrail.checkpoint"
    GUARDRAIL_BLOCKED = "enkrypt.guardrail.blocked"
    INPUT_GUARDRAILS_ENABLED = "enkrypt.guardrail.input_enabled"
    OUTPUT_GUARDRAILS_ENABLED = "enkrypt.guardrail.output_enabled"
    PII_REDACTION_ENABLED = "enkrypt.guardrail.pii_redaction_enabled"
    RELEVANCY_ENABLED = "enkrypt.guardrail.relevancy_enabled"
    ADHERENCE_ENABLED = "enkrypt.guardrail.adherence_enabled"
    HALLUCINATION_ENABLED = "enkrypt.guardrail.hallucination_enabled"
    ASYNC_GUARDRAILS = "enkrypt.guardrail.async"

    # --- Auth ---
    IS_AUTHENTICATED = "enkrypt.auth.is_authenticated"
    REQUIRED_NEW_AUTH = "enkrypt.auth.required_new_auth"
    AUTH_RESULT = "enkrypt.auth.result"
    REQUIRES_AUTH = "enkrypt.auth.requires"

    # --- Cache / Discovery ---
    CACHE_HIT = "enkrypt.cache.hit"
    HAS_CACHED_TOOLS = "enkrypt.cache.has_tools"
    DISCOVERY_REQUIRED = "enkrypt.discovery.required"
    TOTAL_SERVERS = "enkrypt.discovery.total_servers"
    CACHED_SERVERS = "enkrypt.discovery.cached_servers"
    SERVERS_NEED_DISCOVERY = "enkrypt.discovery.need_discovery"

    # --- Error ---
    ERROR_CODE = "enkrypt.error.code"
    ERROR_MESSAGE = "enkrypt.error.message"
    SUCCESS = "enkrypt.success"


# ===================================================================
# Span names
# ===================================================================


class SpanNames:
    """Canonical span operation names."""

    # Tool execution
    TOOL_EXECUTE = "enkrypt.tool.execute"
    TOOL_CALL = "enkrypt.tool.call"
    TOOL_FORWARD = "enkrypt.tool.forward"
    TOOL_VALIDATE = "enkrypt.tool.validate"

    # Guardrail spans
    GUARDRAIL_INPUT = "enkrypt.guardrail.check.input"
    GUARDRAIL_OUTPUT = "enkrypt.guardrail.check.output"

    # Auth
    AUTH = "enkrypt.auth"

    # Discovery
    DISCOVERY = "enkrypt.discovery"

    # Server management
    SERVER_LIST = "enkrypt.server.list"
    SERVER_INFO = "enkrypt.server.info"
    SERVER_INFO_AUTH = "enkrypt.server.info.auth"
    SERVER_INFO_CHECK = "enkrypt.server.info.check"
    SERVER_INFO_LATEST = "enkrypt.server.info.latest"

    # Cache management
    CACHE_STATUS = "enkrypt.cache.status"
    CACHE_STATUS_AUTH = "enkrypt.cache.status.auth"
    CACHE_STATUS_GLOBAL = "enkrypt.cache.status.global"
    CACHE_STATUS_CONFIG = "enkrypt.cache.status.config"
    CACHE_STATUS_SERVERS = "enkrypt.cache.status.servers"
    CACHE_STATUS_SERVER = "enkrypt.cache.status.server"
    CACHE_CLEAR = "enkrypt.cache.clear"

    # PII
    PII_REDACT = "enkrypt.pii.redact"
    PII_RESTORE = "enkrypt.pii.restore"


# ===================================================================
# Metric names (what OTel exports to Prometheus / Grafana)
# ===================================================================


class MetricNames:
    """Canonical OTel metric names — dot-namespaced per OTel convention."""

    # Guardrail metrics
    GUARDRAIL_CHECKS = "enkrypt.guardrail.checks"
    GUARDRAIL_BLOCKS = "enkrypt.guardrail.blocks"
    GUARDRAIL_DURATION = "enkrypt.guardrail.duration"
    GUARDRAIL_INPUT_BLOCKS = "enkrypt.guardrail.input_blocks"
    GUARDRAIL_OUTPUT_BLOCKS = "enkrypt.guardrail.output_blocks"
    GUARDRAIL_RELEVANCY_BLOCKS = "enkrypt.guardrail.relevancy_blocks"
    GUARDRAIL_ADHERENCE_BLOCKS = "enkrypt.guardrail.adherence_blocks"
    GUARDRAIL_HALLUCINATION_BLOCKS = "enkrypt.guardrail.hallucination_blocks"

    # Tool metrics
    TOOL_CALLS = "enkrypt.tool.calls"
    TOOL_DURATION = "enkrypt.tool.duration"
    TOOL_SUCCESS = "enkrypt.tool.success"
    TOOL_FAILURES = "enkrypt.tool.failures"
    TOOL_ERRORS = "enkrypt.tool.errors"
    TOOL_BLOCKED = "enkrypt.tool.blocked"

    # Auth metrics
    AUTH_SUCCESS = "enkrypt.auth.success"
    AUTH_FAILURE = "enkrypt.auth.failure"

    # Cache metrics
    CACHE_HITS = "enkrypt.cache.hits"
    CACHE_MISSES = "enkrypt.cache.misses"

    # PII metrics
    PII_REDACTIONS = "enkrypt.pii.redactions"

    # Session / user gauges
    SESSION_ACTIVE = "enkrypt.session.active"
    USERS_ACTIVE = "enkrypt.users.active"

    # Discovery metrics
    DISCOVERY_LIST = "enkrypt.discovery.list_servers"
    DISCOVERY_FOUND = "enkrypt.discovery.servers_found"

    # Timeout metrics
    TIMEOUT_OPERATIONS = "enkrypt.timeout.operations"
    TIMEOUT_SUCCESS = "enkrypt.timeout.success"
    TIMEOUT_TIMED_OUT = "enkrypt.timeout.timed_out"
    TIMEOUT_CANCELLED = "enkrypt.timeout.cancelled"
    TIMEOUT_ESCALATION_WARN = "enkrypt.timeout.escalation.warn"
    TIMEOUT_ESCALATION_TIMEOUT = "enkrypt.timeout.escalation.timeout"
    TIMEOUT_ESCALATION_FAIL = "enkrypt.timeout.escalation.fail"
    TIMEOUT_DURATION = "enkrypt.timeout.duration"
    TIMEOUT_ACTIVE = "enkrypt.timeout.active"


# ===================================================================
# Metric descriptions (for OTel registration)
# ===================================================================

METRIC_DESCRIPTIONS: dict[str, str] = {
    MetricNames.GUARDRAIL_CHECKS: "Total guardrail API calls",
    MetricNames.GUARDRAIL_BLOCKS: "Total guardrail blocks",
    MetricNames.GUARDRAIL_DURATION: "Guardrail check duration in seconds",
    MetricNames.GUARDRAIL_INPUT_BLOCKS: "Input guardrail violations",
    MetricNames.GUARDRAIL_OUTPUT_BLOCKS: "Output guardrail violations",
    MetricNames.GUARDRAIL_RELEVANCY_BLOCKS: "Relevancy guardrail violations",
    MetricNames.GUARDRAIL_ADHERENCE_BLOCKS: "Adherence guardrail violations",
    MetricNames.GUARDRAIL_HALLUCINATION_BLOCKS: "Hallucination guardrail violations",
    MetricNames.TOOL_CALLS: "Total tool executions",
    MetricNames.TOOL_DURATION: "Tool execution duration in seconds",
    MetricNames.TOOL_SUCCESS: "Successful tool executions",
    MetricNames.TOOL_FAILURES: "Failed tool executions",
    MetricNames.TOOL_ERRORS: "Tool execution errors",
    MetricNames.TOOL_BLOCKED: "Tool calls blocked by guardrails",
    MetricNames.AUTH_SUCCESS: "Successful authentications",
    MetricNames.AUTH_FAILURE: "Failed authentications",
    MetricNames.CACHE_HITS: "Cache hits",
    MetricNames.CACHE_MISSES: "Cache misses",
    MetricNames.PII_REDACTIONS: "PII redaction operations",
    MetricNames.SESSION_ACTIVE: "Currently active sessions",
    MetricNames.USERS_ACTIVE: "Currently active users",
    MetricNames.DISCOVERY_LIST: "Server list endpoint calls",
    MetricNames.DISCOVERY_FOUND: "Total servers discovered",
    MetricNames.TIMEOUT_OPERATIONS: "Total timeout operations",
    MetricNames.TIMEOUT_SUCCESS: "Successful timeout operations",
    MetricNames.TIMEOUT_TIMED_OUT: "Operations that timed out",
    MetricNames.TIMEOUT_CANCELLED: "Operations that were cancelled",
    MetricNames.TIMEOUT_ESCALATION_WARN: "Timeout escalation warnings",
    MetricNames.TIMEOUT_ESCALATION_TIMEOUT: "Timeout escalations",
    MetricNames.TIMEOUT_ESCALATION_FAIL: "Timeout escalation failures",
    MetricNames.TIMEOUT_DURATION: "Timeout operation duration in seconds",
    MetricNames.TIMEOUT_ACTIVE: "Currently active timeout operations",
}


# ===================================================================
# Source product identifiers
# ===================================================================


class SourceProduct:
    GATEWAY = "gateway"
    SDK = "sdk"
    HOOKS = "hooks"


__all__ = [
    "METRIC_DESCRIPTIONS",
    "MetricNames",
    "SourceProduct",
    "SpanAttributes",
    "SpanNames",
]
