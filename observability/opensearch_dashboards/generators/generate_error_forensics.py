"""Regenerate ``gateway-error-forensics-dashboard.ndjson``.

"Error Forensics" dashboard — engineering / support view for incident
investigation. Designed to be filtered by a single `correlation_id` or
`request_id` in the OSD filter bar to drill down into one failed request.

Usage workflow:

1. Operator gets an alert / customer complaint with a correlation_id
2. Open this dashboard, paste the id into the filter bar
3. See every log + span + identity context + latency split + recovery
   attempt for that one request
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,LOGS_DATAVIEW_ID,
    METRICS_DATAVIEW_ID,
    TRACES_DATAVIEW_ID,
    area_vis,
    build_dashboard_ndjson,
    data_table_vis,
    horizontal_bar_topN_vis,
    kpi_metric_vis,
    markdown_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-error-forensics-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Error Forensics\n\n"
            "**Pin `log.attributes.correlation_id : \"<id>\"`** (or `request_id`) in "
            "the filter bar above to drill into one failed request. Every panel "
            "below scopes to that single correlation_id and shows the full "
            "request trail: identity, timeline, errors, guardrail decisions, HTTP "
            "calls, recovery attempts.\n\n"
            "Without a filter, the dashboard shows aggregate error trends across "
            "all requests."
        ),
    ), "", LOGS_DATAVIEW_ID, (0, 0, 48, 6)),
    # ============================================================
    # Aggregate error trends (when no filter)
    # ============================================================
    (markdown_vis("Section: Trends", markdown="### 1. Aggregate Error Trends"),
        "", METRICS_DATAVIEW_ID, (0, 6, 48, 2)),
    (kpi_metric_vis("Critical Errors", custom_label="Critical"),
        'name : "enkrypt.errors.by_code" and metric.attributes.severity : "critical"',
        METRICS_DATAVIEW_ID, (0, 8, 8, 6)),
    (kpi_metric_vis("High-Severity Errors", custom_label="High"),
        'name : "enkrypt.errors.by_code" and metric.attributes.severity : "high"',
        METRICS_DATAVIEW_ID, (8, 8, 8, 6)),
    (kpi_metric_vis("Medium-Severity Errors", custom_label="Medium"),
        'name : "enkrypt.errors.by_code" and metric.attributes.severity : "medium"',
        METRICS_DATAVIEW_ID, (16, 8, 8, 6)),
    (kpi_metric_vis("Retry Attempts", custom_label="Retries"),
        'name : "enkrypt.retry.attempts"', METRICS_DATAVIEW_ID, (24, 8, 8, 6)),
    (kpi_metric_vis("Fail-Open Activations", custom_label="Fail-Open"),
        'name : "enkrypt.degradation.fail_open"', METRICS_DATAVIEW_ID, (32, 8, 8, 6)),
    (kpi_metric_vis("Fail-Closed Activations", custom_label="Fail-Closed"),
        'name : "enkrypt.degradation.fail_closed"', METRICS_DATAVIEW_ID, (40, 8, 8, 6)),
    (area_vis(
        "Errors Over Time by Code",
        bucket_field="metric.attributes.error_code",
        bucket_label="Error Code",
        size=10,
    ),
        'name : "enkrypt.errors.by_code"', METRICS_DATAVIEW_ID, (0, 14, 24, 12)),
    (pie_vis(
        "Errors by Severity",
        bucket_field="metric.attributes.severity",
        bucket_label="Severity",
        size=5,
    ),
        'name : "enkrypt.errors.by_code"', METRICS_DATAVIEW_ID, (24, 14, 12, 12)),
    (pie_vis(
        "Recovery Strategies",
        bucket_field="metric.attributes.recovery_strategy",
        bucket_label="Strategy",
        size=8,
    ),
        'name : "enkrypt.errors.by_code"', METRICS_DATAVIEW_ID, (36, 14, 12, 12)),
    # ============================================================
    # When filtered by correlation_id — drill-down panels
    # ============================================================
    (markdown_vis(
        "Section: Drill-Down",
        markdown=(
            "### 2. Single-Request Drill-Down\n\n"
            "All panels below scope to the pinned `correlation_id` / `request_id`. "
            "Without a filter, they show counts across all requests."
        ),
    ), "", LOGS_DATAVIEW_ID, (0, 26, 48, 4)),
    (data_table_vis(
        "Identity Context for this Request",
        bucket_fields=[
            ("log.attributes.user_id", "User ID"),
            ("log.attributes.user_email", "Email"),
            ("log.attributes.project_name", "Project"),
            ("log.attributes.org_id", "Org"),
            ("log.attributes.gateway_name", "Gateway"),
            ("log.attributes.mcp_config_id", "Config ID"),
        ],
        size=1,
        metric_label="Logs",
        aggregation="count",
        field="",
    ),
        'log.attributes.correlation_id : *', LOGS_DATAVIEW_ID, (0, 30, 24, 12)),
    (data_table_vis(
        "Request-Type / Source / MCP Method",
        bucket_fields=[
            ("log.attributes.request_type", "Request Type"),
            ("log.attributes.source_event", "Source Event"),
            ("log.attributes.mcp_method", "MCP Method"),
            ("log.attributes.server_name", "Server"),
            ("log.attributes.tool_name", "Tool"),
        ],
        size=10,
        metric_label="Logs",
        aggregation="count",
        field="",
    ),
        'log.attributes.correlation_id : *', LOGS_DATAVIEW_ID, (24, 30, 24, 12)),
    # ============================================================
    # Latency breakdown for this request
    # ============================================================
    (markdown_vis("Section: Latency", markdown="### 3. Latency Breakdown"),
        "", LOGS_DATAVIEW_ID, (0, 42, 48, 2)),
    (kpi_metric_vis("Total Request (ms)", aggregation="avg",
                     field="log.attributes.total_request_duration_ms",
                     custom_label="Total ms"),
        'log.attributes.total_request_duration_ms : *', LOGS_DATAVIEW_ID, (0, 44, 8, 6)),
    (kpi_metric_vis("Tool Call (ms)", aggregation="avg",
                     field="log.attributes.tool_call_duration_ms",
                     custom_label="Tool ms"),
        'log.attributes.tool_call_duration_ms : *', LOGS_DATAVIEW_ID, (8, 44, 8, 6)),
    (kpi_metric_vis("Forward (MCP) ms", aggregation="avg",
                     field="log.attributes.forward_duration_ms",
                     custom_label="Forward ms"),
        'log.attributes.forward_duration_ms : *', LOGS_DATAVIEW_ID, (16, 44, 8, 6)),
    (kpi_metric_vis("Guardrail (ms)", aggregation="avg",
                     field="log.attributes.guardrail_duration_ms",
                     custom_label="Guardrail ms"),
        'log.attributes.guardrail_duration_ms : *', LOGS_DATAVIEW_ID, (24, 44, 8, 6)),
    (kpi_metric_vis("Cache Lookup (ms)", aggregation="avg",
                     field="log.attributes.cache_lookup_duration_ms",
                     custom_label="Cache ms"),
        'log.attributes.cache_lookup_duration_ms : *', LOGS_DATAVIEW_ID, (32, 44, 8, 6)),
    (kpi_metric_vis("Cloud API (ms)", aggregation="avg",
                     field="log.attributes.cloud_api_duration_ms",
                     custom_label="Cloud ms"),
        'log.attributes.cloud_api_duration_ms : *', LOGS_DATAVIEW_ID, (40, 44, 8, 6)),
    (kpi_metric_vis("Preprocess (ms)", aggregation="avg",
                     field="log.attributes.preprocess_duration_ms",
                     custom_label="Preprocess ms"),
        'log.attributes.preprocess_duration_ms : *', LOGS_DATAVIEW_ID, (0, 50, 12, 6)),
    (kpi_metric_vis("Execute (ms)", aggregation="avg",
                     field="log.attributes.execution_duration_ms",
                     custom_label="Execute ms"),
        'log.attributes.execution_duration_ms : *', LOGS_DATAVIEW_ID, (12, 50, 12, 6)),
    (kpi_metric_vis("Postprocess (ms)", aggregation="avg",
                     field="log.attributes.postprocess_duration_ms",
                     custom_label="Postprocess ms"),
        'log.attributes.postprocess_duration_ms : *', LOGS_DATAVIEW_ID, (24, 50, 12, 6)),
    (kpi_metric_vis("Queue Wait (ms)", aggregation="avg",
                     field="log.attributes.queue_wait_duration_ms",
                     custom_label="Queue ms"),
        'log.attributes.queue_wait_duration_ms : *', LOGS_DATAVIEW_ID, (36, 50, 12, 6)),
    # ============================================================
    # Error log detail
    # ============================================================
    (markdown_vis("Section: Errors", markdown="### 4. Error & Guardrail Detail"),
        "", LOGS_DATAVIEW_ID, (0, 56, 48, 2)),
    (data_table_vis(
        "Errors in this Request",
        bucket_fields=[
            ("log.attributes.error_code", "Error Code"),
            ("log.attributes.severity", "Severity"),
            ("log.attributes.recovery_strategy", "Recovery"),
            ("log.attributes.operation", "Operation"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.error_code : * OR log.attributes.severity : ("error" or "critical" or "high")',
        LOGS_DATAVIEW_ID, (0, 58, 24, 14)),
    (data_table_vis(
        "Guardrail Decisions",
        bucket_fields=[
            ("log.attributes.detector", "Detector"),
            ("log.attributes.direction", "Direction"),
            ("log.attributes.violating_policy", "Policy"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.detector : *', LOGS_DATAVIEW_ID, (24, 58, 24, 14)),
    # ============================================================
    # HTTP calls + retry attempts
    # ============================================================
    (markdown_vis("Section: External", markdown="### 5. Cloud HTTP Calls & Recovery"),
        "", LOGS_DATAVIEW_ID, (0, 72, 48, 2)),
    (data_table_vis(
        "Cloud HTTP Calls",
        bucket_fields=[
            ("log.attributes.endpoint", "Endpoint"),
            ("log.attributes.status", "Status"),
            ("log.attributes.response_time_ms", "Latency ms"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.endpoint : *', LOGS_DATAVIEW_ID, (0, 74, 24, 14)),
    (data_table_vis(
        "Retry Attempts",
        bucket_fields=[
            ("log.attributes.operation", "Operation"),
            ("log.attributes.attempt", "Attempt"),
            ("log.attributes.max_attempts", "Max"),
            ("log.attributes.delay", "Delay (s)"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.attempt : *', LOGS_DATAVIEW_ID, (24, 74, 24, 14)),
    # ============================================================
    # Trace IDs for waterfall jump
    # ============================================================
    (markdown_vis(
        "Section: Trace Link",
        markdown=(
            "### 6. Trace Spans for this Request\n\n"
            "Use `traceId` to jump into the trace waterfall in the OSD trace UI."
        ),
    ), "", TRACES_DATAVIEW_ID, (0, 88, 48, 4)),
    (data_table_vis(
        "Spans in this Request (jump to traceId)",
        bucket_fields=[
            ("traceId", "Trace ID"),
            ("name", "Span Name"),
            ("span.attributes.server_name", "Server"),
            ("span.attributes.tool_name", "Tool"),
        ],
        size=50,
        metric_label="Spans",
        aggregation="count",
        field="",
    ),
        'span.attributes.correlation_id : *', TRACES_DATAVIEW_ID, (0, 92, 48, 16)),
    (data_table_vis(
        "Span Duration Roll-up",
        bucket_fields=[
            ("name", "Span Name"),
        ],
        size=25,
        metric_label="Avg Duration (ns)",
        aggregation="avg",
        field="durationInNanos",
    ),
        'span.attributes.correlation_id : *', TRACES_DATAVIEW_ID, (0, 108, 24, 14)),
    (data_table_vis(
        "Errors in Spans",
        bucket_fields=[
            ("span.attributes.error_code", "Error Code"),
            ("span.attributes.error_message", "Message"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        '(span.attributes.error_code : * OR span.attributes.error : *)',
        TRACES_DATAVIEW_ID, (24, 108, 24, 14)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Error Forensics",
        description=(
            "Engineering/support drill-down for incident investigation. Pin "
            "`correlation_id` or `request_id` in the OSD filter bar to scope every "
            "panel to one failed request. Shows identity context, request/source/"
            "MCP-method metadata, full latency breakdown (12 phases), errors by "
            "severity/recovery_strategy, guardrail decisions, cloud HTTP call "
            "history, retry attempts, and trace span roll-up (with traceId jump-"
            "to-waterfall). Without a filter, displays aggregate error trends."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="forensics:",
    )


if __name__ == "__main__":
    main()
