"""Regenerate ``gateway-sandbox-mcp-protocol-dashboard.ndjson``.

"Sandbox & MCP Protocol" dashboard — platform / security view. Focuses on
two deep-dive concerns:

- **Sandbox runtime** — which runtime is active (docker/podman/bwrap/microsandbox/
  novavm), availability, wrap success/failure, scope (global vs per-server)
- **MCP protocol** — methods (initialize/list_tools/call_tool/...), versions,
  handshake latency, capability negotiation, tool annotations
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
    multi_series_time_vis,
    percentile_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-sandbox-mcp-protocol-dashboard.ndjson"

LATENCY_P_SERIES = [
    {"label": "p50", "type": "percentiles", "field": "value", "params": {"percents": [50]}},
    {"label": "p95", "type": "percentiles", "field": "value", "params": {"percents": [95]}},
    {"label": "p99", "type": "percentiles", "field": "value", "params": {"percents": [99]}},
]

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Sandbox & MCP Protocol\n\n"
            "Two-section deep-dive: (1) sandbox runtime selection, availability, "
            "wrap success/failure, scope (global vs per-server); (2) MCP protocol "
            "stats — methods, versions, handshake latency, capability negotiation, "
            "tool annotation distribution."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Sandbox section
    # ============================================================
    (markdown_vis("Section: Sandbox", markdown="### 1. Sandbox Runtime"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Sandbox Wraps", custom_label="Wraps"),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (0, 6, 12, 6)),
    (kpi_metric_vis("Sandbox Wrap Failures", custom_label="Failures"),
        'name : "enkrypt.sandbox.wrap.invocations" and metric.attributes.outcome : "error"',
        METRICS_DATAVIEW_ID, (12, 6, 12, 6)),
    (kpi_metric_vis("Sandbox Unavailable Events", custom_label="Unavailable"),
        'name : "enkrypt.sandbox.wrap.invocations" and metric.attributes.outcome : "unavailable"',
        METRICS_DATAVIEW_ID, (24, 6, 12, 6)),
    (kpi_metric_vis("Sandbox Runtime Healthy", aggregation="max", custom_label="0/1"),
        'name : "enkrypt.sandbox.availability"', METRICS_DATAVIEW_ID, (36, 6, 12, 6)),
    (pie_vis(
        "Sandbox Runtimes in Use",
        bucket_field="metric.attributes.sandbox_runtime",
        bucket_label="Runtime",
        size=6,
    ),
        'name : "enkrypt.sandbox.availability"', METRICS_DATAVIEW_ID, (0, 12, 16, 12)),
    (pie_vis(
        "Sandbox Scope (global vs per-server)",
        bucket_field="metric.attributes.sandbox_scope",
        bucket_label="Scope",
        size=4,
    ),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (16, 12, 16, 12)),
    (horizontal_bar_topN_vis(
        "Sandboxed Servers",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Wraps",
        size=10,
    ),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (32, 12, 16, 12)),
    (area_vis(
        "Sandbox Wraps Over Time by Runtime",
        bucket_field="metric.attributes.sandbox_runtime",
        bucket_label="Runtime",
        size=6,
    ),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (0, 24, 48, 12)),
    # ============================================================
    # MCP protocol section
    # ============================================================
    (markdown_vis("Section: MCP Protocol", markdown="### 2. MCP Protocol Stats"),
        "", METRICS_DATAVIEW_ID, (0, 36, 48, 2)),
    (kpi_metric_vis("MCP Method Calls", custom_label="Calls"),
        'name : "enkrypt.mcp.method.calls"', METRICS_DATAVIEW_ID, (0, 38, 12, 6)),
    (kpi_metric_vis("MCP Protocol Errors", custom_label="Errors"),
        'name : "enkrypt.mcp.protocol.errors"', METRICS_DATAVIEW_ID, (12, 38, 12, 6)),
    (kpi_metric_vis("Tool Not Found", custom_label="404s"),
        'name : "enkrypt.mcp.tool_not_found"', METRICS_DATAVIEW_ID, (24, 38, 12, 6)),
    (kpi_metric_vis("Invalid Args", custom_label="400s"),
        'name : "enkrypt.mcp.invalid_args"', METRICS_DATAVIEW_ID, (36, 38, 12, 6)),
    (pie_vis(
        "MCP Methods Distribution",
        bucket_field="metric.attributes.mcp_method",
        bucket_label="Method",
        size=10,
    ),
        'name : "enkrypt.mcp.method.calls"', METRICS_DATAVIEW_ID, (0, 44, 16, 12)),
    (pie_vis(
        "MCP Protocol Versions",
        bucket_field="metric.attributes.mcp_protocol_version",
        bucket_label="Version",
        size=5,
    ),
        'name : "enkrypt.mcp.method.calls"', METRICS_DATAVIEW_ID, (16, 44, 16, 12)),
    (pie_vis(
        "Transport Types",
        bucket_field="metric.attributes.transport_type",
        bucket_label="Transport",
        size=8,
    ),
        'name : "enkrypt.mcp.connection.events"', METRICS_DATAVIEW_ID, (32, 44, 16, 12)),
    # ============================================================
    # Handshake & initialize latency
    # ============================================================
    (markdown_vis("Section: Handshake", markdown="### 3. Handshake & Initialize Latency"),
        "", METRICS_DATAVIEW_ID, (0, 56, 48, 2)),
    (percentile_vis("MCP Handshake p95 (s)", percentile=95, custom_label="p95"),
        'name : "enkrypt.mcp.connection.handshake.duration"',
        METRICS_DATAVIEW_ID, (0, 58, 16, 6)),
    (percentile_vis("MCP Initialize p95 (s)", percentile=95, custom_label="p95"),
        'name : "enkrypt.mcp.initialize.duration"',
        METRICS_DATAVIEW_ID, (16, 58, 16, 6)),
    (kpi_metric_vis("Distinct Server Versions", aggregation="cardinality",
                     field="metric.attributes.server_version", custom_label="Versions"),
        'name : "enkrypt.mcp.initialize.duration"',
        METRICS_DATAVIEW_ID, (32, 58, 16, 6)),
    (multi_series_time_vis(
        "MCP Handshake Latency (p50/p95/p99 s)",
        LATENCY_P_SERIES,
        chart_type="line",
    ),
        'name : "enkrypt.mcp.connection.handshake.duration"',
        METRICS_DATAVIEW_ID, (0, 64, 24, 12)),
    (multi_series_time_vis(
        "MCP Initialize Latency (p50/p95/p99 s)",
        LATENCY_P_SERIES,
        chart_type="line",
    ),
        'name : "enkrypt.mcp.initialize.duration"',
        METRICS_DATAVIEW_ID, (24, 64, 24, 12)),
    (pie_vis(
        "Handshake — Reused Session?",
        bucket_field="metric.attributes.session_reused",
        bucket_label="Reused?",
        size=4,
    ),
        'name : "enkrypt.mcp.connection.handshake.duration"',
        METRICS_DATAVIEW_ID, (0, 76, 24, 12)),
    (data_table_vis(
        "Top Server Versions by Handshake p95",
        bucket_fields=[
            ("metric.attributes.server_name", "Server"),
            ("metric.attributes.server_version", "Version"),
        ],
        size=25,
        metric_label="Count",
    ),
        'name : "enkrypt.mcp.initialize.duration"',
        METRICS_DATAVIEW_ID, (24, 76, 24, 12)),
    # ============================================================
    # Capabilities + annotations
    # ============================================================
    (markdown_vis(
        "Section: Capabilities",
        markdown="### 4. Capabilities & Tool Annotations",
    ), "", METRICS_DATAVIEW_ID, (0, 88, 48, 2)),
    (pie_vis(
        "Capability Negotiation Outcomes",
        bucket_field="metric.attributes.capability_outcome",
        bucket_label="Outcome",
        size=4,
    ),
        'name : "enkrypt.mcp.capabilities.negotiation"', METRICS_DATAVIEW_ID, (0, 90, 16, 12)),
    (horizontal_bar_topN_vis(
        "Capabilities by Frequency",
        bucket_field="metric.attributes.mcp_capability",
        bucket_label="Capability",
        metric_label="Count",
        size=15,
    ),
        'name : "enkrypt.mcp.capabilities.negotiation"', METRICS_DATAVIEW_ID, (16, 90, 32, 12)),
    (pie_vis(
        "Destructive Tool Calls",
        bucket_field="metric.attributes.destructive_hint",
        bucket_label="Destructive?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 102, 12, 12)),
    (pie_vis(
        "Read-Only Tool Calls",
        bucket_field="metric.attributes.read_only_hint",
        bucket_label="Read-Only?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (12, 102, 12, 12)),
    (pie_vis(
        "Idempotent Tool Calls",
        bucket_field="metric.attributes.idempotent_hint",
        bucket_label="Idempotent?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (24, 102, 12, 12)),
    (pie_vis(
        "Open-World Tool Calls",
        bucket_field="metric.attributes.open_world_hint",
        bucket_label="Open-World?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (36, 102, 12, 12)),
    # ============================================================
    # Notifications
    # ============================================================
    (markdown_vis("Section: Notifications", markdown="### 5. MCP Notifications"),
        "", METRICS_DATAVIEW_ID, (0, 114, 48, 2)),
    (horizontal_bar_topN_vis(
        "MCP Notification Methods Received",
        bucket_field="metric.attributes.mcp_notification_method",
        bucket_label="Method",
        metric_label="Count",
        size=10,
    ),
        'name : "enkrypt.mcp.notifications.received"', METRICS_DATAVIEW_ID, (0, 116, 24, 12)),
    (time_series_vis("Notifications Over Time", "Count", chart_type="histogram"),
        'name : "enkrypt.mcp.notifications.received"',
        METRICS_DATAVIEW_ID, (24, 116, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Sandbox & MCP Protocol",
        description=(
            "Platform/security deep-dive on (1) sandbox runtime — which runtime is "
            "active (docker/podman/bwrap/microsandbox/novavm), availability gauge, "
            "wrap success/failure, scope (global vs per-server); (2) MCP protocol — "
            "methods/versions distribution, handshake & initialize latency p50/p95/p99, "
            "capability negotiation outcomes, tool annotation matrix (destructive / "
            "read_only / idempotent / open_world hints), notifications received."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="sandboxMcp:",
    )


if __name__ == "__main__":
    main()
