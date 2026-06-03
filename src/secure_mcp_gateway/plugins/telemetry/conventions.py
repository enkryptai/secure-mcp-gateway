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

    # --- Health (REST health-check endpoints) ---
    HEALTH_ENDPOINT = "enkrypt.health.endpoint"
    HEALTH_STATUS = "enkrypt.health.status"
    HEALTH_RESPONSE_TIME_MS = "enkrypt.health.response_time_ms"
    HEALTH_TOOL_COUNT = "enkrypt.health.tool_count"


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

    # Health-check API (REST endpoints under /api/v1/health/mcp/*)
    HEALTH_SERVER_CHECK = "enkrypt.health.server_check"
    HEALTH_SERVER_INFO = "enkrypt.health.server_info"
    HEALTH_TOOL_CALL = "enkrypt.health.tool_call"


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
    # Compliance-framework attribution per blocked violation. One increment
    # per (framework, framework_id) tuple parsed from the upstream
    # guardrail provider's `compliance_mapping` block (e.g. OWASP LLM01:2025,
    # MITRE ATLAS AML.T0051, NIST AI RMF MAP 2.3, EU AI Act Article 15(4),
    # ISO/IEC 27001 A.14.2). Powers the per-framework heatmaps in the
    # Security Posture dashboard.
    GUARDRAIL_COMPLIANCE_HIT = "enkrypt.guardrail.compliance_hit"

    # Tool metrics
    TOOL_CALLS = "enkrypt.tool.calls"
    TOOL_DURATION = "enkrypt.tool.duration"
    TOOL_SUCCESS = "enkrypt.tool.success"
    TOOL_FAILURES = "enkrypt.tool.failures"
    TOOL_ERRORS = "enkrypt.tool.errors"
    TOOL_BLOCKED = "enkrypt.tool.blocked"
    # Tools refused at the per-server allow-list / deny-list (server-tool
    # guardrail). Distinct from TOOL_BLOCKED, which counts guardrail-API
    # decisions (input/output content); permission_denied counts policy-
    # level allow/deny decisions before the tool even runs.
    TOOL_PERMISSION_DENIED = "enkrypt.tool.permission_denied"

    # Errors (centralised). One increment per MCPGatewayError raised,
    # carrying the ErrorCode enum value + severity + recovery_strategy as
    # attributes. Powers the Error Forensics dashboard's per-code,
    # per-severity, per-recovery_strategy widgets.
    ERRORS_BY_CODE = "enkrypt.errors.by_code"

    # Degradation -- when a guardrail or downstream service errors and the
    # gateway has to fall back to a fail-open (allow the call) or
    # fail-closed (block the call) verdict. Powers the SLO and Error
    # Forensics fail-open/fail-closed widgets and is critical for security
    # auditing (knowing how often you trusted-by-default vs blocked-by-
    # default during partial outages).
    DEGRADATION_FAIL_OPEN = "enkrypt.degradation.fail_open"
    DEGRADATION_FAIL_CLOSED = "enkrypt.degradation.fail_closed"

    # Transport errors at the MCP-client layer (HTTP / stdio session
    # failures forwarding to downstream MCP servers).
    TRANSPORT_ERRORS = "enkrypt.transport.errors"

    # Discovery failures per downstream MCP server (timeout, refused,
    # malformed initialize response, etc.). Distinct from
    # DISCOVERY_FOUND (which counts successful discoveries).
    DISCOVERY_SERVER_FAILURES = "enkrypt.discovery.server_failures"

    # =====================================================================
    # Audit / compliance metrics  (Audit Trail dashboard)
    # =====================================================================
    # Every gateway state-mutation flows through one of these counters so
    # the Audit Trail dashboard can answer SOC2/ISO 27001 review questions
    # like "who rotated which apikey when, from which surface" without
    # log-grep.
    #
    # Two emission layers:
    #   - The "umbrella" counters (ADMIN_ACTIONS, PRIVILEGED_OPERATIONS)
    #     fire on EVERY mutation, with action / resource_type / surface
    #     attributes that the dashboard pivots on.
    #   - The "specific" counters fire alongside for the events the
    #     dashboard surfaces as their own KPI tile (apikey CRUD, project /
    #     user CRUD, cache flush, system backup/restore/reset, settings
    #     changes).  Recording both means the dashboard can show top-N
    #     actors AND per-action drill-downs without re-querying.

    # Umbrella: every admin/audit event increments these.
    ADMIN_ACTIONS = "enkrypt.admin.actions"
    PRIVILEGED_OPERATIONS = "enkrypt.privileged.operations"

    # Specific event categories
    ADMIN_CACHE_FLUSH = "enkrypt.admin.cache_flush"
    APIKEY_ROTATIONS = "enkrypt.apikey.rotations"
    AUDIT_APIKEY_CREATED = "enkrypt.audit.apikey.created"
    AUDIT_APIKEY_DELETED = "enkrypt.audit.apikey.deleted"
    AUDIT_APIKEY_DISABLED = "enkrypt.audit.apikey.disabled"
    AUDIT_APIKEY_ROTATED = "enkrypt.audit.apikey.rotated"
    AUDIT_CONFIG_MODIFIED = "enkrypt.audit.config.modified"
    AUDIT_SETTINGS_ENKRYPT_API_KEY_SET = "enkrypt.audit.settings.enkrypt_api_key_set"
    AUDIT_SETTINGS_TELEMETRY_CHANGED = "enkrypt.audit.settings.telemetry_changed"
    AUDIT_USER_CREATED = "enkrypt.audit.user.created"
    AUDIT_USER_DELETED = "enkrypt.audit.user.deleted"
    PROJECTS_CREATED = "enkrypt.projects.created"
    SYSTEM_BACKUP_COMPLETED = "enkrypt.system.backup.completed"
    SYSTEM_RESET = "enkrypt.system.reset"
    SYSTEM_RESTORE = "enkrypt.system.restore"

    # 401/403 responses from the admin REST / gateway MCP surface.
    # Distinct from AUTH_FAILURE (which is per-apikey, per-provider).
    AUTH_UNAUTHORIZED_HTTP = "enkrypt.auth.unauthorized_http"

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
    MetricNames.GUARDRAIL_COMPLIANCE_HIT: (
        "Compliance framework hits per blocked guardrail call "
        "(one per framework + framework_id pair)"
    ),
    MetricNames.TOOL_CALLS: "Total tool executions",
    MetricNames.TOOL_DURATION: "Tool execution duration in seconds",
    MetricNames.TOOL_SUCCESS: "Successful tool executions",
    MetricNames.TOOL_FAILURES: "Failed tool executions",
    MetricNames.TOOL_ERRORS: "Tool execution errors",
    MetricNames.TOOL_BLOCKED: "Tool calls blocked by guardrails",
    MetricNames.TOOL_PERMISSION_DENIED: (
        "Tools refused by server-level allow/deny policy "
        "(server-tool guardrail, evaluated before tool execution)"
    ),
    MetricNames.ERRORS_BY_CODE: (
        "MCPGatewayErrors emitted, broken down by ErrorCode, "
        "severity, recovery_strategy"
    ),
    MetricNames.DEGRADATION_FAIL_OPEN: (
        "Calls that were allowed after a guardrail/downstream error "
        "(fail-open verdict)"
    ),
    MetricNames.DEGRADATION_FAIL_CLOSED: (
        "Calls that were blocked after a guardrail/downstream error "
        "(fail-closed verdict)"
    ),
    MetricNames.TRANSPORT_ERRORS: (
        "MCP client transport failures (HTTP / stdio) when forwarding to "
        "downstream MCP servers"
    ),
    MetricNames.DISCOVERY_SERVER_FAILURES: (
        "Failed tool discovery attempts against downstream MCP servers"
    ),
    # ---- Audit / compliance (Audit Trail dashboard) -------------------
    MetricNames.ADMIN_ACTIONS: (
        "Every gateway state-mutation (config CRUD, project/user lifecycle, "
        "apikey CRUD, cache flush, system ops, settings change). Attributes: "
        "action, resource_type, surface (cli|rest_api|mcp_gateway), actor, "
        "success."
    ),
    MetricNames.PRIVILEGED_OPERATIONS: (
        "Subset of admin actions that require elevated privileges "
        "(system reset/restore/backup, settings changes, cache flush)."
    ),
    MetricNames.ADMIN_CACHE_FLUSH: (
        "Cache flush requests. Attributes: scope (all|gateway_config|"
        "server_config|tool_cache), surface, actor, authorization_path "
        "(admin_apikey|org_id_allowlist)."
    ),
    MetricNames.APIKEY_ROTATIONS: (
        "Successful apikey rotations (umbrella counter; AUDIT_APIKEY_ROTATED "
        "fires too with apikey-specific attributes)."
    ),
    MetricNames.AUDIT_APIKEY_CREATED: "API key creation events",
    MetricNames.AUDIT_APIKEY_DELETED: "API key deletion events",
    MetricNames.AUDIT_APIKEY_DISABLED: "API key disable events",
    MetricNames.AUDIT_APIKEY_ROTATED: "API key rotation events (per-key)",
    MetricNames.AUDIT_CONFIG_MODIFIED: (
        "MCP config file modification events (any add/update/remove on "
        "mcp_configs / servers / guardrails)"
    ),
    MetricNames.AUDIT_SETTINGS_ENKRYPT_API_KEY_SET: (
        "Enkrypt cloud apikey setting changed via CLI or REST"
    ),
    MetricNames.AUDIT_SETTINGS_TELEMETRY_CHANGED: (
        "Telemetry plugin config changed (provider, endpoint, enabled flag)"
    ),
    MetricNames.AUDIT_USER_CREATED: "User account creation events",
    MetricNames.AUDIT_USER_DELETED: "User account deletion events",
    MetricNames.PROJECTS_CREATED: "Project creation events",
    MetricNames.SYSTEM_BACKUP_COMPLETED: (
        "Successful system backup completions (CLI / REST)"
    ),
    MetricNames.SYSTEM_RESET: "System reset events (destructive!)",
    MetricNames.SYSTEM_RESTORE: "System restore-from-backup events",
    MetricNames.AUTH_UNAUTHORIZED_HTTP: (
        "401/403 responses from the admin REST surface or gateway MCP "
        "surface (per-request, not per-apikey)"
    ),
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
