"""Regenerate ``gateway-tools-servers-dashboard.ndjson``.

"Tools & MCP Servers" dashboard — platform/integration view. Surfaces every
signal about the MCP servers and tools the gateway proxies.

Sections:

1. Server inventory & health state
2. Top tools by call count + latency
3. Discovery activity
4. MCP handshake & protocol stats
5. Connection lifecycle & flapping detector
6. Transport / sandbox runtime
7. Tool annotations distribution
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,METRICS_DATAVIEW_ID,
    area_vis,
    build_dashboard_ndjson,
    data_table_vis,
    heatmap_vis,
    horizontal_bar_topN_vis,
    kpi_metric_vis,
    markdown_vis,
    percentile_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-tools-servers-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Tools & MCP Servers\n\n"
            "Server inventory, health state, tool usage, MCP protocol stats, "
            "connection lifecycle, transport breakdown. Filter by `server_name` / "
            "`tool_name` / `mcp_config_id` for scoped views."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Inventory & health
    # ============================================================
    (markdown_vis("Section: Inventory", markdown="### 1. Server Inventory & Health State"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Servers Configured", aggregation="max", custom_label="Configured"),
        'name : "enkrypt.servers.configured"', METRICS_DATAVIEW_ID, (0, 6, 12, 6)),
    (kpi_metric_vis("Connection Events", custom_label="Events"),
        'name : "enkrypt.mcp.connection.events"', METRICS_DATAVIEW_ID, (12, 6, 12, 6)),
    (kpi_metric_vis("Transport Errors", custom_label="Errors"),
        'name : "enkrypt.transport.errors"', METRICS_DATAVIEW_ID, (24, 6, 12, 6)),
    (kpi_metric_vis("Sandbox Wrap Invocations", custom_label="Wraps"),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (36, 6, 12, 6)),
    (pie_vis(
        "Server Health State Distribution",
        bucket_field="metric.attributes.server_health_state",
        bucket_label="State",
        size=5,
    ),
        'name : "enkrypt.server.health.state"', METRICS_DATAVIEW_ID, (0, 12, 16, 12)),
    (horizontal_bar_topN_vis(
        "Servers Down (current)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Down events",
        size=10,
    ),
        'name : "enkrypt.server.health.state" and metric.attributes.server_health_state : "down"',
        METRICS_DATAVIEW_ID, (16, 12, 16, 12)),
    (horizontal_bar_topN_vis(
        "Flapping Detector (crashed events)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Crashes",
        size=10,
    ),
        'name : "enkrypt.mcp.connection.events" and metric.attributes.event : "crashed"',
        METRICS_DATAVIEW_ID, (32, 12, 16, 12)),
    # ============================================================
    # Top tools by call count + latency
    # ============================================================
    (markdown_vis("Section: Tools", markdown="### 2. Tools — Calls & Latency"),
        "", METRICS_DATAVIEW_ID, (0, 24, 48, 2)),
    (horizontal_bar_topN_vis(
        "Top 15 Tools by Call Count",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
        metric_label="Calls",
        size=15,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 26, 24, 14)),
    (horizontal_bar_topN_vis(
        "Top 10 Tools by p95 Latency (s)",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
        metric_label="p95 seconds",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.tool.duration"', METRICS_DATAVIEW_ID, (24, 26, 24, 14)),
    (horizontal_bar_topN_vis(
        "Top 10 Servers by Call Count",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 40, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Tools with Errors",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
        metric_label="Errors",
        size=10,
    ),
        'name : "enkrypt.tool.failures"', METRICS_DATAVIEW_ID, (24, 40, 24, 12)),
    # ============================================================
    # Discovery activity
    # ============================================================
    (markdown_vis("Section: Discovery", markdown="### 3. Discovery Activity"),
        "", METRICS_DATAVIEW_ID, (0, 52, 48, 2)),
    (kpi_metric_vis("Total Discovery Calls", custom_label="Calls"),
        'name : "enkrypt.discovery.list_servers"', METRICS_DATAVIEW_ID, (0, 54, 12, 6)),
    (kpi_metric_vis("Servers Found", aggregation="max", custom_label="Found"),
        'name : "enkrypt.discovery.servers_found"', METRICS_DATAVIEW_ID, (12, 54, 12, 6)),
    (kpi_metric_vis("Discovery Failures", custom_label="Failures"),
        'name : "enkrypt.discovery.server_failures"', METRICS_DATAVIEW_ID, (24, 54, 12, 6)),
    (kpi_metric_vis("Tools Blocked at Registration", custom_label="Reg Blocks"),
        'name : "enkrypt.discovery.tools_blocked_registration"',
        METRICS_DATAVIEW_ID, (36, 54, 12, 6)),
    (horizontal_bar_topN_vis(
        "Per-Server Discovery Duration (max p95)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="p95 seconds",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.discovery.per_server.duration"', METRICS_DATAVIEW_ID, (0, 60, 24, 12)),
    (pie_vis(
        "Discovery Failure Reasons",
        bucket_field="metric.attributes.error_kind",
        bucket_label="Error Kind",
        size=10,
    ),
        'name : "enkrypt.discovery.server_failures"', METRICS_DATAVIEW_ID, (24, 60, 24, 12)),
    # ============================================================
    # MCP protocol stats
    # ============================================================
    (markdown_vis("Section: MCP Protocol", markdown="### 4. MCP Protocol & Handshake"),
        "", METRICS_DATAVIEW_ID, (0, 72, 48, 2)),
    (pie_vis(
        "MCP Methods Distribution",
        bucket_field="metric.attributes.mcp_method",
        bucket_label="Method",
        size=8,
    ),
        'name : "enkrypt.mcp.method.calls"', METRICS_DATAVIEW_ID, (0, 74, 16, 12)),
    (pie_vis(
        "MCP Protocol Versions",
        bucket_field="metric.attributes.mcp_protocol_version",
        bucket_label="Version",
        size=5,
    ),
        'name : "enkrypt.mcp.method.calls"', METRICS_DATAVIEW_ID, (16, 74, 16, 12)),
    (percentile_vis("MCP Handshake p95 (s)", percentile=95, custom_label="p95"),
        'name : "enkrypt.mcp.connection.handshake.duration"',
        METRICS_DATAVIEW_ID, (32, 74, 16, 12)),
    (time_series_vis("MCP Protocol Errors", "Errors", chart_type="histogram"),
        'name : "enkrypt.mcp.protocol.errors"', METRICS_DATAVIEW_ID, (0, 86, 24, 12)),
    (horizontal_bar_topN_vis(
        "MCP Errors by Server",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Errors",
        size=10,
    ),
        'name : "enkrypt.mcp.protocol.errors"', METRICS_DATAVIEW_ID, (24, 86, 24, 12)),
    # ============================================================
    # Connection lifecycle
    # ============================================================
    (markdown_vis("Section: Lifecycle", markdown="### 5. Connection Lifecycle"),
        "", METRICS_DATAVIEW_ID, (0, 98, 48, 2)),
    (area_vis(
        "Connection Events Over Time",
        bucket_field="metric.attributes.event",
        bucket_label="Event",
        size=8,
    ),
        'name : "enkrypt.mcp.connection.events"', METRICS_DATAVIEW_ID, (0, 100, 48, 14)),
    # ============================================================
    # Transport & sandbox
    # ============================================================
    (markdown_vis("Section: Transport", markdown="### 6. Transport & Sandbox"),
        "", METRICS_DATAVIEW_ID, (0, 114, 48, 2)),
    (pie_vis(
        "Transport Types",
        bucket_field="metric.attributes.transport_type",
        bucket_label="Transport",
        size=8,
    ),
        'name : "enkrypt.mcp.connection.events"', METRICS_DATAVIEW_ID, (0, 116, 16, 12)),
    (pie_vis(
        "Sandbox Runtimes",
        bucket_field="metric.attributes.sandbox_runtime",
        bucket_label="Runtime",
        size=8,
    ),
        'name : "enkrypt.sandbox.availability"', METRICS_DATAVIEW_ID, (16, 116, 16, 12)),
    (kpi_metric_vis("Sandbox Wrap Errors", custom_label="Errors"),
        'name : "enkrypt.sandbox.wrap.invocations" and metric.attributes.outcome : "error"',
        METRICS_DATAVIEW_ID, (32, 116, 16, 12)),
    # ============================================================
    # Tool annotations
    # ============================================================
    (markdown_vis(
        "Section: Annotations",
        markdown=(
            "### 7. Tool Annotations\n\n"
            "MCP tool hints: `destructive_hint`, `read_only_hint`, `idempotent_hint`, "
            "`open_world_hint`. Useful for risk-tier dashboards."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 128, 48, 4)),
    (pie_vis(
        "Destructive vs Read-Only Calls",
        bucket_field="metric.attributes.destructive_hint",
        bucket_label="Destructive?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 132, 12, 12)),
    (pie_vis(
        "Read-Only Calls",
        bucket_field="metric.attributes.read_only_hint",
        bucket_label="Read-Only?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (12, 132, 12, 12)),
    (pie_vis(
        "Idempotent Calls",
        bucket_field="metric.attributes.idempotent_hint",
        bucket_label="Idempotent?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (24, 132, 12, 12)),
    (pie_vis(
        "Open-World Calls",
        bucket_field="metric.attributes.open_world_hint",
        bucket_label="Open-World?",
        size=4,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (36, 132, 12, 12)),
    (heatmap_vis(
        "Annotation Matrix (destructive × read_only)",
        x_field="metric.attributes.destructive_hint",
        y_field="metric.attributes.read_only_hint",
        x_size=2,
        y_size=2,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 144, 24, 12)),
    (data_table_vis(
        "Tool not_found / invalid_args breakdown",
        bucket_fields=[
            ("metric.attributes.server_name", "Server"),
            ("metric.attributes.tool_name", "Tool"),
        ],
        size=25,
        metric_label="Errors",
    ),
        'name : ("enkrypt.mcp.tool_not_found" or "enkrypt.mcp.invalid_args")',
        METRICS_DATAVIEW_ID, (24, 144, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Tools & MCP Servers",
        description=(
            "Platform/integration view of MCP servers and tools. "
            "Server inventory + health state, top tools by calls/latency/errors, "
            "discovery activity, MCP protocol stats (methods/versions/handshake), "
            "connection lifecycle & flapping detector, transport + sandbox runtime, "
            "tool annotation distribution (destructive/read_only/idempotent/open_world)."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="toolsServers:",
    )


if __name__ == "__main__":
    main()
