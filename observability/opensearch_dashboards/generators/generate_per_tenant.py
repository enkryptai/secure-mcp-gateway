"""Regenerate ``gateway-per-tenant-dashboard.ndjson``.

"Per-Tenant" dashboard — customer-success / account management view. Designed
to be filtered (via OSD filter bar) by ``org_id`` / ``project_name`` /
``user_id`` to scope every widget to a single tenant.

Sections:

1. Tenant KPIs (calls, blocks, distinct users, tools)
2. Tool usage (top servers, top tools, latency)
3. Guardrail activity (per direction, per detector)
4. Errors & quality (error types, recovery strategies)
5. Cloud cost attribution
6. Time-of-day usage pattern

The dashboard relies on the global OSD filter bar — pin filters like
`metric.attributes.project_name : "X"` once and every widget scopes
automatically.
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,LOGS_DATAVIEW_ID,
    METRICS_DATAVIEW_ID,
    area_vis,
    build_dashboard_ndjson,
    data_table_vis,
    horizontal_bar_topN_vis,
    kpi_metric_vis,
    markdown_vis,
    percentile_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-per-tenant-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Per-Tenant View\n\n"
            "**Pin a tenant filter** in the OSD filter bar above (`org_id`, "
            "`project_name`, or `user_id`) to scope every widget below to a single "
            "tenant. Unfiltered, the dashboard aggregates across all tenants."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Tenant KPIs
    # ============================================================
    (markdown_vis("Section: KPIs", markdown="### Tenant KPIs"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Tool Calls", custom_label="Calls"),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 6, 8, 6)),
    (kpi_metric_vis("Tool Errors", custom_label="Errors"),
        'name : "enkrypt.tool.failures"', METRICS_DATAVIEW_ID, (8, 6, 8, 6)),
    (kpi_metric_vis("Blocked Calls", custom_label="Blocked"),
        'name : "enkrypt.tool.blocked"', METRICS_DATAVIEW_ID, (16, 6, 8, 6)),
    (kpi_metric_vis("PII Redactions", custom_label="Redacted"),
        'name : "enkrypt.pii.redactions"', METRICS_DATAVIEW_ID, (24, 6, 8, 6)),
    (kpi_metric_vis("Guardrail Checks", custom_label="Checks"),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (32, 6, 8, 6)),
    (kpi_metric_vis("Compliance Hits", custom_label="Compliance"),
        'name : "enkrypt.guardrail.compliance_hit"', METRICS_DATAVIEW_ID, (40, 6, 8, 6)),
    # ============================================================
    # Tool usage
    # ============================================================
    (markdown_vis("Section: Usage", markdown="### 1. Tool Usage"),
        "", METRICS_DATAVIEW_ID, (0, 12, 48, 2)),
    (horizontal_bar_topN_vis(
        "Top Servers Used",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 14, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Tools Called",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (24, 14, 24, 12)),
    (time_series_vis("Tool Calls Over Time", "Calls", chart_type="histogram"),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 26, 24, 12)),
    (percentile_vis("Tool Call p95 (s)", percentile=95, custom_label="p95"),
        'name : "enkrypt.tool.duration"', METRICS_DATAVIEW_ID, (24, 26, 12, 12)),
    (percentile_vis("Tool Call p99 (s)", percentile=99, custom_label="p99"),
        'name : "enkrypt.tool.duration"', METRICS_DATAVIEW_ID, (36, 26, 12, 12)),
    # ============================================================
    # Guardrail activity
    # ============================================================
    (markdown_vis("Section: Guardrails", markdown="### 2. Guardrail Activity"),
        "", METRICS_DATAVIEW_ID, (0, 38, 48, 2)),
    (pie_vis(
        "Blocks by Violation Type",
        bucket_field="metric.attributes.violation_type",
        bucket_label="Violation",
        size=15,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 40, 16, 12)),
    (pie_vis(
        "Checks by Direction",
        bucket_field="metric.attributes.direction",
        bucket_label="Direction",
        size=4,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (16, 40, 16, 12)),
    (pie_vis(
        "Async vs Blocking",
        bucket_field="metric.attributes.async_mode",
        bucket_label="Async?",
        size=4,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (32, 40, 16, 12)),
    (area_vis(
        "Blocks Over Time (by violation_type)",
        bucket_field="metric.attributes.violation_type",
        bucket_label="Violation",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 52, 48, 12)),
    # ============================================================
    # Errors & quality
    # ============================================================
    (markdown_vis("Section: Errors", markdown="### 3. Errors & Quality"),
        "", METRICS_DATAVIEW_ID, (0, 64, 48, 2)),
    (horizontal_bar_topN_vis(
        "Errors by Code",
        bucket_field="metric.attributes.error_code",
        bucket_label="Error Code",
        metric_label="Count",
        size=10,
    ),
        'name : "enkrypt.errors.by_code"', METRICS_DATAVIEW_ID, (0, 66, 24, 12)),
    (pie_vis(
        "Recovery Strategies",
        bucket_field="metric.attributes.recovery_strategy",
        bucket_label="Strategy",
        size=8,
    ),
        'name : "enkrypt.retry.attempts"', METRICS_DATAVIEW_ID, (24, 66, 24, 12)),
    # ============================================================
    # Cloud cost attribution
    # ============================================================
    (markdown_vis("Section: Cloud Cost", markdown="### 4. Cloud Cost Attribution"),
        "", METRICS_DATAVIEW_ID, (0, 78, 48, 2)),
    (kpi_metric_vis("Cloud API Requests", custom_label="Calls"),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 80, 12, 6)),
    (kpi_metric_vis("Bytes Sent (egress)", custom_label="Bytes"),
        'name : "enkrypt.cloud.api.bytes_sent"', METRICS_DATAVIEW_ID, (12, 80, 12, 6)),
    (kpi_metric_vis("Bytes Received", custom_label="Bytes"),
        'name : "enkrypt.cloud.api.bytes_received"', METRICS_DATAVIEW_ID, (24, 80, 12, 6)),
    (kpi_metric_vis("Cloud API Errors", custom_label="Errors"),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (36, 80, 12, 6)),
    (area_vis(
        "Cloud Requests by Endpoint",
        bucket_field="metric.attributes.cloud_endpoint",
        bucket_label="Cloud Endpoint",
        size=10,
    ),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 86, 48, 12)),
    # ============================================================
    # Time-of-day usage pattern
    # ============================================================
    (markdown_vis("Section: Pattern", markdown="### 5. Usage Pattern"),
        "", METRICS_DATAVIEW_ID, (0, 98, 48, 2)),
    (time_series_vis("Requests/sec (hourly)", "Requests", chart_type="histogram"),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 100, 24, 12)),
    (data_table_vis(
        "Activity per User (top 25)",
        bucket_fields=[
            ("metric.attributes.user_id", "User ID"),
            ("metric.attributes.user_email", "Email"),
        ],
        size=25,
        metric_label="Calls",
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (24, 100, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Per-Tenant",
        description=(
            "Customer-success/account-management view scoped by tenant. Pin a "
            "filter on `org_id`, `project_name`, or `user_id` to drill into one "
            "tenant. Surfaces calls/errors/blocks KPIs, top servers/tools, "
            "guardrail activity by direction/violation_type/async mode, error "
            "codes & recovery strategies, cloud cost attribution by cloud_endpoint, "
            "and usage time patterns."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="tenant:",
    )


if __name__ == "__main__":
    main()
