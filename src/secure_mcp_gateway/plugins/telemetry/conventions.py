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
    ORG_ID = "enkrypt.org.id"
    PROJECT_ID = "enkrypt.project.id"
    PROJECT_NAME = "enkrypt.project.name"
    # Cloud `request_context.registry_name`. Nested under `project.` to mirror
    # the cloud data model where every registry belongs to a project.
    PROJECT_REGISTRY = "enkrypt.project.registry"
    USER_ID = "enkrypt.user.id"
    USER_EMAIL = "enkrypt.user.email"
    # True when the apikey belongs to an internal Enkrypt account
    # (dashboard / next-js / staff). Populated from the cloud
    # ``/consumer-info`` response when the playground runs in
    # inline-mode + provider=enkrypt, so dashboards can split internal
    # traffic from real customer traffic.
    USER_IS_INTERNAL_REQ = "enkrypt.user.is_internal_req"
    CONFIG_ID = "enkrypt.config.id"
    GATEWAY_KEY = "enkrypt.gateway.key"
    # Echoes the ``X-Enkrypt-MCP-Gateway`` / ``X-Enkrypt-MCP-Gateway-Version``
    # headers the gateway sends to the cloud's ``get-gateway-config`` API, so
    # OpenSearch / Grafana can pivot per deployed gateway revision.
    GATEWAY_NAME = "enkrypt.gateway.name"
    GATEWAY_VERSION = "enkrypt.gateway.version"
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
    # Cloud get-gateway-config endpoint details (host of ``base_url`` + URL +
    # HTTP status). Useful for splitting dev/staging/prod traffic and for
    # alerting on cloud-side failures.
    AUTH_BASE_URL = "enkrypt.auth.base_url"
    AUTH_FETCH_URL = "enkrypt.auth.fetch_url"
    AUTH_FETCH_STATUS_CODE = "enkrypt.auth.fetch_status_code"

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

    # --- Health (REST health-check endpoints) ---
    HEALTH_ENDPOINT = "enkrypt.health.endpoint"
    HEALTH_STATUS = "enkrypt.health.status"
    HEALTH_RESPONSE_TIME_MS = "enkrypt.health.response_time_ms"
    HEALTH_TOOL_COUNT = "enkrypt.health.tool_count"

    # --- Playground (/mcp-playground/*) ---
    # Set on the parent route span and on the registry-lookup child span so
    # dashboards can split inline-body traffic from registry-header traffic.
    PLAYGROUND_MODE = "enkrypt.playground.mode"  # "inline" | "registry"
    PLAYGROUND_REGISTRY_SAVED_NAME = "enkrypt.playground.registry.saved_name"
    PLAYGROUND_REGISTRY_SERVER_VERSION = "enkrypt.playground.registry.server_version"
    PLAYGROUND_REGISTRY_NAME = "enkrypt.playground.registry.registry_name"
    PLAYGROUND_REGISTRY_ID = "enkrypt.playground.registry.registry_id"
    PLAYGROUND_PROJECT_NAME = "enkrypt.playground.registry.project_name"
    PLAYGROUND_REGISTRY_SERVER_NAME = "enkrypt.playground.registry.server_name"
    PLAYGROUND_REGISTRY_IS_ACTIVE = "enkrypt.playground.registry.is_active"
    PLAYGROUND_REGISTRY_IS_SAMPLE = "enkrypt.playground.registry.is_sample"
    PLAYGROUND_LOOKUP_URL = "enkrypt.playground.lookup.url"
    PLAYGROUND_LOOKUP_STATUS_CODE = "enkrypt.playground.lookup.status_code"
    PLAYGROUND_LOOKUP_DURATION_MS = "enkrypt.playground.lookup.duration_ms"
    PLAYGROUND_LOOKUP_CACHE = "enkrypt.playground.lookup.cache"  # "hit" | "miss"


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
    # Child span around the cloud's ``GET /mcp-gateway/get-gateway-config``
    # HTTP call. Captures the headers sent (masked apikey, gateway name /
    # version, project name) and the response status so we can debug cloud
    # auth failures from Jaeger / OpenSearch traces.
    AUTH_FETCH_CONFIG = "enkrypt.auth.fetch_gateway_config"

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

    # Health-check API (REST endpoints under /api/v1/health/mcp/*)
    HEALTH_SERVER_CHECK = "enkrypt.health.server_check"
    HEALTH_SERVER_INFO = "enkrypt.health.server_info"
    HEALTH_TOOL_CALL = "enkrypt.health.tool_call"

    # Child span around the cloud's ``GET /mcp-registry/get-server`` HTTP
    # call made by the playground routes when in registry-header mode.
    PLAYGROUND_REGISTRY_LOOKUP = "enkrypt.playground.registry_lookup"

    # Child span around the cloud's ``GET /consumer-info`` HTTP call made
    # by the playground routes when in inline-body mode with
    # ``plugins.auth.provider == "enkrypt"``. Cloud 200 is the apikey gate
    # for that path; identity attributes (user.id / org.id / project.name /
    # user.email / user.is_internal_req) are populated from the response
    # body onto the parent route span using the existing identity
    # SpanAttributes so dashboards index playground traffic the same way
    # as gateway traffic.
    PLAYGROUND_CONSUMER_INFO_LOOKUP = "enkrypt.playground.consumer_info_lookup"


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

    # Health-check API metrics
    HEALTH_REQUESTS = "enkrypt.health.requests"
    HEALTH_DURATION = "enkrypt.health.duration"
    HEALTH_SUCCESS = "enkrypt.health.success"
    HEALTH_FAILURES = "enkrypt.health.failures"

    # Playground registry lookup
    PLAYGROUND_REGISTRY_LOOKUP_DURATION = "enkrypt.playground.registry_lookup.duration"

    # Playground consumer-info lookup (inline-mode + provider=enkrypt)
    PLAYGROUND_CONSUMER_INFO_LOOKUP_DURATION = (
        "enkrypt.playground.consumer_info_lookup.duration"
    )

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
    MetricNames.HEALTH_REQUESTS: "Health-check API requests received",
    MetricNames.HEALTH_DURATION: "Health-check API duration in seconds",
    MetricNames.HEALTH_SUCCESS: "Health-check API requests that completed successfully",
    MetricNames.HEALTH_FAILURES: "Health-check API requests that failed",
    MetricNames.PLAYGROUND_REGISTRY_LOOKUP_DURATION: "Duration of GET /mcp-registry/get-server calls made by the /mcp-playground/* routes in registry-header mode (milliseconds)",
    MetricNames.PLAYGROUND_CONSUMER_INFO_LOOKUP_DURATION: "Duration of GET /consumer-info calls made by the /mcp-playground/* routes in inline-body mode when plugins.auth.provider=enkrypt (milliseconds)",
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


# Legacy snake_case aliases kept for OpenSearch filtering compatibility.
_SPAN_LEGACY_ATTR_KEYS: dict[str, str] = {
    SpanAttributes.GATEWAY_NAME: "gateway_name",
    SpanAttributes.ORG_ID: "org_id",
    SpanAttributes.PROJECT_ID: "project_id",
    SpanAttributes.PROJECT_NAME: "project_name",
    SpanAttributes.SERVER_NAME: "server_name",
    SpanAttributes.TOOL_NAME: "tool_name",
    SpanAttributes.USER_ID: "user_id",
}


def set_span_attr_with_legacy(span, attr_key: str, value) -> None:
    """Set canonical span attr and (for key identity fields) legacy alias."""
    span.set_attribute(attr_key, value)
    legacy_key = _SPAN_LEGACY_ATTR_KEYS.get(attr_key)
    if legacy_key is not None:
        span.set_attribute(legacy_key, value)


__all__ = [
    "METRIC_DESCRIPTIONS",
    "MetricNames",
    "SourceProduct",
    "SpanAttributes",
    "SpanNames",
    "set_span_attr_with_legacy",
]
