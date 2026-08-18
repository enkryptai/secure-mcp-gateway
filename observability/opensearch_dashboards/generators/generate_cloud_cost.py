"""Regenerate ``gateway-cloud-cost-dashboard.ndjson``.

"Cloud Cost & API Usage" dashboard — FinOps / engineering management view.
Quantifies the gateway's spend on Enkrypt cloud APIs and identifies the
highest-cost flows.
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,METRICS_DATAVIEW_ID,
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

OUT = DASHBOARDS_DIR / "gateway-cloud-cost-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Cloud Cost & API Usage\n\n"
            "FinOps view: Enkrypt cloud API consumption (request volume, payload "
            "sizes, error rate), OAuth token lifecycle, registry / consumer-info "
            "lookups, per-endpoint cost breakdown."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Cost KPIs
    # ============================================================
    (markdown_vis("KPIs", markdown="### Cloud Cost KPIs"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Cloud API Requests", custom_label="Calls"),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 6, 8, 6)),
    (kpi_metric_vis("Total Bytes Sent", aggregation="sum", custom_label="Egress"),
        'name : "enkrypt.cloud.api.bytes_sent"', METRICS_DATAVIEW_ID, (8, 6, 8, 6)),
    (kpi_metric_vis("Total Bytes Received", aggregation="sum", custom_label="Ingress"),
        'name : "enkrypt.cloud.api.bytes_received"', METRICS_DATAVIEW_ID, (16, 6, 8, 6)),
    (kpi_metric_vis("Cloud API Errors", custom_label="Errors"),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (24, 6, 8, 6)),
    (kpi_metric_vis("Guardrail Calls", custom_label="Guardrail"),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (32, 6, 8, 6)),
    (kpi_metric_vis("OAuth Token Ops", custom_label="OAuth"),
        'name : "enkrypt.oauth.token.operations"', METRICS_DATAVIEW_ID, (40, 6, 8, 6)),
    # ============================================================
    # Cloud requests over time + by endpoint
    # ============================================================
    (markdown_vis("Section: Volume", markdown="### 1. Cloud API Volume"),
        "", METRICS_DATAVIEW_ID, (0, 12, 48, 2)),
    (time_series_vis("Cloud Requests Over Time", "Requests", chart_type="histogram"),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 14, 24, 12)),
    (area_vis(
        "Cloud Requests by Endpoint (stacked)",
        bucket_field="metric.attributes.cloud_endpoint",
        bucket_label="Endpoint",
        size=10,
    ),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (24, 14, 24, 12)),
    (pie_vis(
        "Requests by Endpoint",
        bucket_field="metric.attributes.cloud_endpoint",
        bucket_label="Endpoint",
        size=10,
    ),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 26, 16, 12)),
    (horizontal_bar_topN_vis(
        "Top Projects by Cloud Spend",
        bucket_field="metric.attributes.project_name",
        bucket_label="Project",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (16, 26, 32, 12)),
    # ============================================================
    # Payload sizes
    # ============================================================
    (markdown_vis("Section: Payloads", markdown="### 2. Payload Sizes (egress / ingress)"),
        "", METRICS_DATAVIEW_ID, (0, 38, 48, 2)),
    (percentile_vis("Bytes Sent p95 per Call", percentile=95, custom_label="p95 bytes"),
        'name : "enkrypt.cloud.api.bytes_sent"', METRICS_DATAVIEW_ID, (0, 40, 12, 6)),
    (percentile_vis("Bytes Received p95 per Call", percentile=95, custom_label="p95 bytes"),
        'name : "enkrypt.cloud.api.bytes_received"', METRICS_DATAVIEW_ID, (12, 40, 12, 6)),
    (percentile_vis("Bytes Sent p99 per Call", percentile=99, custom_label="p99 bytes"),
        'name : "enkrypt.cloud.api.bytes_sent"', METRICS_DATAVIEW_ID, (24, 40, 12, 6)),
    (percentile_vis("Bytes Received p99 per Call", percentile=99, custom_label="p99 bytes"),
        'name : "enkrypt.cloud.api.bytes_received"', METRICS_DATAVIEW_ID, (36, 40, 12, 6)),
    (time_series_vis("Bytes Sent (rate)", "Bytes/sec", chart_type="line", aggregation="sum"),
        'name : "enkrypt.cloud.api.bytes_sent"', METRICS_DATAVIEW_ID, (0, 46, 24, 12)),
    (time_series_vis("Bytes Received (rate)", "Bytes/sec", chart_type="line", aggregation="sum"),
        'name : "enkrypt.cloud.api.bytes_received"', METRICS_DATAVIEW_ID, (24, 46, 24, 12)),
    # ============================================================
    # Cloud errors
    # ============================================================
    (markdown_vis("Section: Errors", markdown="### 3. Cloud API Errors"),
        "", METRICS_DATAVIEW_ID, (0, 58, 48, 2)),
    (pie_vis(
        "Errors by Class (4xx/5xx/timeout/network)",
        bucket_field="metric.attributes.error_class",
        bucket_label="Error Class",
        size=6,
    ),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (0, 60, 16, 12)),
    (horizontal_bar_topN_vis(
        "Errors by Status Code",
        bucket_field="metric.attributes.status_code",
        bucket_label="Status Code",
        metric_label="Errors",
        size=10,
    ),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (16, 60, 16, 12)),
    (area_vis(
        "Cloud Errors Over Time by Endpoint",
        bucket_field="metric.attributes.cloud_endpoint",
        bucket_label="Endpoint",
        size=10,
    ),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (32, 60, 16, 12)),
    # ============================================================
    # OAuth lifecycle
    # ============================================================
    (markdown_vis("Section: OAuth", markdown="### 4. OAuth Token Lifecycle"),
        "", METRICS_DATAVIEW_ID, (0, 72, 48, 2)),
    (pie_vis(
        "Token Operations",
        bucket_field="metric.attributes.operation",
        bucket_label="Operation",
        size=6,
    ),
        'name : "enkrypt.oauth.token.operations"', METRICS_DATAVIEW_ID, (0, 74, 16, 12)),
    (kpi_metric_vis("Token Cache Hits", custom_label="Hits"),
        'name : "enkrypt.oauth.token.cache.hits"', METRICS_DATAVIEW_ID, (16, 74, 8, 6)),
    (kpi_metric_vis("Token Cache Misses", custom_label="Misses"),
        'name : "enkrypt.oauth.token.cache.misses"', METRICS_DATAVIEW_ID, (24, 74, 8, 6)),
    (kpi_metric_vis("Active Tokens", aggregation="max", custom_label="Active"),
        'name : "enkrypt.oauth.active_tokens"', METRICS_DATAVIEW_ID, (16, 80, 16, 6)),
    (percentile_vis("OAuth Token Latency p95 (ms)", percentile=95, custom_label="p95"),
        'name : "enkrypt.oauth.token.latency"', METRICS_DATAVIEW_ID, (32, 74, 16, 12)),
    # ============================================================
    # Auxiliary cloud lookups
    # ============================================================
    (markdown_vis("Section: Aux", markdown="### 5. Registry / Consumer-Info Lookups"),
        "", METRICS_DATAVIEW_ID, (0, 86, 48, 2)),
    (kpi_metric_vis("Registry Lookups", custom_label="Calls"),
        'name : "enkrypt.playground.registry_lookup.duration"',
        METRICS_DATAVIEW_ID, (0, 88, 12, 6)),
    (kpi_metric_vis("Consumer-Info Lookups", custom_label="Calls"),
        'name : "enkrypt.playground.consumer_info_lookup.duration"',
        METRICS_DATAVIEW_ID, (12, 88, 12, 6)),
    (percentile_vis("Registry Lookup p95", percentile=95, custom_label="p95"),
        'name : "enkrypt.playground.registry_lookup.duration"',
        METRICS_DATAVIEW_ID, (24, 88, 12, 6)),
    (percentile_vis("Consumer-Info Lookup p95", percentile=95, custom_label="p95"),
        'name : "enkrypt.playground.consumer_info_lookup.duration"',
        METRICS_DATAVIEW_ID, (36, 88, 12, 6)),
    (horizontal_bar_topN_vis(
        "Top Registry Lookup Saved Names",
        bucket_field="metric.attributes.saved_name",
        bucket_label="Saved Name",
        metric_label="Lookups",
        size=10,
    ),
        'name : "enkrypt.playground.registry_lookup.duration"',
        METRICS_DATAVIEW_ID, (0, 94, 24, 12)),
    (pie_vis(
        "Cache Hit Ratio (lookups)",
        bucket_field="metric.attributes.cache",
        bucket_label="Cache",
        size=4,
    ),
        'name : ("enkrypt.playground.registry_lookup.duration" or "enkrypt.playground.consumer_info_lookup.duration")',
        METRICS_DATAVIEW_ID, (24, 94, 24, 12)),
    # ============================================================
    # Cost attribution table
    # ============================================================
    (markdown_vis("Section: Attribution", markdown="### 6. Cost Attribution Table"),
        "", METRICS_DATAVIEW_ID, (0, 106, 48, 2)),
    (data_table_vis(
        "Cloud Spend by Project × Endpoint",
        bucket_fields=[
            ("metric.attributes.project_name", "Project"),
            ("metric.attributes.cloud_endpoint", "Endpoint"),
        ],
        size=25,
        metric_label="Calls",
    ),
        'name : "enkrypt.cloud.api.requests"', METRICS_DATAVIEW_ID, (0, 108, 24, 16)),
    (data_table_vis(
        "Cloud Errors by Project × Endpoint",
        bucket_fields=[
            ("metric.attributes.project_name", "Project"),
            ("metric.attributes.cloud_endpoint", "Endpoint"),
        ],
        size=25,
        metric_label="Errors",
    ),
        'name : "enkrypt.cloud.api.errors"', METRICS_DATAVIEW_ID, (24, 108, 24, 16)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Cloud Cost & API Usage",
        description=(
            "FinOps/engineering-management view. Enkrypt cloud API consumption "
            "(request volume, payload sizes p95/p99, error rate by class/status), "
            "OAuth token lifecycle (acquisitions/cache hits/active token gauge/"
            "latency), registry & consumer-info lookups, cost attribution table by "
            "project × cloud_endpoint."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="cloudCost:",
    )


if __name__ == "__main__":
    main()
