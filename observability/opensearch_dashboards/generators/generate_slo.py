"""Regenerate ``gateway-slo-dashboard.ndjson``.

"SLO & Reliability" dashboard organized around the **Four Golden Signals**
(Latency, Traffic, Errors, Saturation) plus the RED method (Rate, Errors,
Duration). Targets the SRE / on-call audience.

Sections (rows):

1. **Latency** — p50/p95/p99 KPI cards + per-operation latency histograms
2. **Traffic** — RPS over time, split by endpoint / server / direction
3. **Errors** — error rates, fail-open / fail-closed activations, auth failures
4. **Saturation** — in-flight, pool, FD, event-loop lag, process metrics

Run::

    python observability/opensearch_dashboards/generate_slo.py
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,LOGS_DATAVIEW_ID,
    METRICS_DATAVIEW_ID,
    area_vis,
    build_dashboard_ndjson,
    gauge_vis,
    horizontal_bar_topN_vis,
    kpi_metric_vis,
    markdown_vis,
    multi_series_time_vis,
    percentile_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-slo-dashboard.ndjson"

P95_LATENCY_SERIES = [
    {"label": "p50", "type": "percentiles", "field": "value", "params": {"percents": [50]}},
    {"label": "p95", "type": "percentiles", "field": "value", "params": {"percents": [95]}},
    {"label": "p99", "type": "percentiles", "field": "value", "params": {"percents": [99]}},
]


def _ms(label: str) -> dict:
    return {"label": label, "type": "percentiles", "field": "value", "params": {"percents": [95]}}


PANEL_SPECS = [
    # ---- Header ----
    (
        markdown_vis(
            "SLO Header",
            markdown=(
                "## Secure MCP Gateway — SLO & Reliability\n\n"
                "Four Golden Signals (Latency · Traffic · Errors · Saturation) for the "
                "control plane (REST API :8001), data plane (MCP gateway :8000), and "
                "underlying resources. Filter by `metric.attributes.server_name`, "
                "`project_name`, or `request_type` to narrow."
            ),
        ),
        "",
        METRICS_DATAVIEW_ID,
        (0, 0, 48, 4),
    ),
    # ============================================================
    # Row 1 — Latency KPI cards (p95)
    # ============================================================
    (markdown_vis("Section: Latency", markdown="### 1. Latency (p95)"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (percentile_vis("Tool Call p95 (s)", percentile=95, custom_label="Tool p95"),
        'name : "enkrypt.tool.duration"', METRICS_DATAVIEW_ID, (0, 6, 12, 6)),
    (percentile_vis("Guardrail p95 (s)", percentile=95, custom_label="Guardrail p95"),
        'name : "enkrypt.guardrail.duration"', METRICS_DATAVIEW_ID, (12, 6, 12, 6)),
    (percentile_vis("Health Check p95 (s)", percentile=95, custom_label="Health p95"),
        'name : "enkrypt.health.duration"', METRICS_DATAVIEW_ID, (24, 6, 12, 6)),
    (percentile_vis("MCP Handshake p95 (s)", percentile=95, custom_label="Handshake p95"),
        'name : "enkrypt.mcp.connection.handshake.duration"', METRICS_DATAVIEW_ID, (36, 6, 12, 6)),
    # Latency time-series
    (multi_series_time_vis("Tool Call Latency (p50/p95/p99)", P95_LATENCY_SERIES, chart_type="line"),
        'name : "enkrypt.tool.duration"', METRICS_DATAVIEW_ID, (0, 12, 24, 12)),
    (multi_series_time_vis("Guardrail Call Latency (p50/p95/p99)", P95_LATENCY_SERIES, chart_type="line"),
        'name : "enkrypt.guardrail.duration"', METRICS_DATAVIEW_ID, (24, 12, 24, 12)),
    # Per-operation latency table (from logs)
    (horizontal_bar_topN_vis(
        "Top Servers by Discovery Duration (p95)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="p95 seconds",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.discovery.per_server.duration"', METRICS_DATAVIEW_ID, (0, 24, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Endpoints by Admin API p95",
        bucket_field="metric.attributes.http@route",
        bucket_label="Endpoint",
        metric_label="p95 seconds",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.api.duration"', METRICS_DATAVIEW_ID, (24, 24, 24, 12)),
    # ============================================================
    # Row 2 — Traffic
    # ============================================================
    (markdown_vis("Section: Traffic", markdown="### 2. Traffic (RPS)"),
        "", METRICS_DATAVIEW_ID, (0, 36, 48, 2)),
    (kpi_metric_vis("Tool Calls (total)", custom_label="Total"),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 38, 8, 6)),
    (kpi_metric_vis("Admin API Requests", custom_label="Total"),
        'name : "enkrypt.api.requests"', METRICS_DATAVIEW_ID, (8, 38, 8, 6)),
    (kpi_metric_vis("MCP HTTP Requests", custom_label="Total"),
        'name : "enkrypt.mcp.http.requests"', METRICS_DATAVIEW_ID, (16, 38, 8, 6)),
    (kpi_metric_vis("Discovery Calls", custom_label="Total"),
        'name : "enkrypt.discovery.list_servers"', METRICS_DATAVIEW_ID, (24, 38, 8, 6)),
    (kpi_metric_vis("Guardrail Checks", custom_label="Total"),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (32, 38, 16, 6)),
    (time_series_vis("Tool Calls/sec", "Tool Calls", chart_type="histogram"),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (0, 44, 24, 12)),
    (area_vis(
        "Tool Calls by Server (stacked)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        size=10,
    ),
        'name : "enkrypt.tool.success"', METRICS_DATAVIEW_ID, (24, 44, 24, 12)),
    (area_vis(
        "Guardrail Checks by Direction",
        bucket_field="metric.attributes.direction",
        bucket_label="Direction",
        size=4,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (0, 56, 24, 12)),
    (area_vis(
        "Admin API by HTTP Method",
        bucket_field="metric.attributes.http@method",
        bucket_label="Method",
        size=8,
    ),
        'name : "enkrypt.api.requests"', METRICS_DATAVIEW_ID, (24, 56, 24, 12)),
    # ============================================================
    # Row 3 — Errors
    # ============================================================
    (markdown_vis("Section: Errors", markdown="### 3. Errors"),
        "", METRICS_DATAVIEW_ID, (0, 68, 48, 2)),
    (kpi_metric_vis("Tool Errors", custom_label="Errors"),
        'name : "enkrypt.tool.failures"', METRICS_DATAVIEW_ID, (0, 70, 8, 6)),
    (kpi_metric_vis("Tool Blocked", custom_label="Blocked"),
        'name : "enkrypt.tool.blocked"', METRICS_DATAVIEW_ID, (8, 70, 8, 6)),
    (kpi_metric_vis("Auth Failures", custom_label="Auth Fail"),
        'name : "enkrypt.auth.failure"', METRICS_DATAVIEW_ID, (16, 70, 8, 6)),
    (kpi_metric_vis("Fail-Open Activations", custom_label="Fail-Open"),
        'name : "enkrypt.degradation.fail_open"', METRICS_DATAVIEW_ID, (24, 70, 8, 6)),
    (kpi_metric_vis("Fail-Closed Activations", custom_label="Fail-Closed"),
        'name : "enkrypt.degradation.fail_closed"', METRICS_DATAVIEW_ID, (32, 70, 8, 6)),
    (kpi_metric_vis("MCP Protocol Errors", custom_label="MCP Err"),
        'name : "enkrypt.mcp.protocol.errors"', METRICS_DATAVIEW_ID, (40, 70, 8, 6)),
    (time_series_vis("Tool Error Rate", "Errors", chart_type="histogram"),
        'name : "enkrypt.tool.failures"', METRICS_DATAVIEW_ID, (0, 76, 24, 12)),
    (area_vis(
        "Errors by Code (top 10)",
        bucket_field="metric.attributes.error_code",
        bucket_label="Error Code",
        size=10,
    ),
        'name : "enkrypt.errors.by_code"', METRICS_DATAVIEW_ID, (24, 76, 24, 12)),
    (pie_vis(
        "Auth Failures by Reason",
        bucket_field="metric.attributes.failure_reason",
        bucket_label="Reason",
        size=10,
    ),
        'name : "enkrypt.auth.failure"', METRICS_DATAVIEW_ID, (0, 88, 24, 12)),
    (area_vis(
        "Admin API 5xx by Endpoint",
        bucket_field="metric.attributes.http@route",
        bucket_label="Endpoint",
        size=10,
    ),
        'name : "enkrypt.api.server_errors"', METRICS_DATAVIEW_ID, (24, 88, 24, 12)),
    # ============================================================
    # Row 4 — Saturation
    # ============================================================
    (markdown_vis("Section: Saturation", markdown="### 4. Saturation & Resources"),
        "", METRICS_DATAVIEW_ID, (0, 100, 48, 2)),
    (kpi_metric_vis("Active Timeout Ops", aggregation="max", custom_label="In-flight"),
        'name : "enkrypt.timeout.active"', METRICS_DATAVIEW_ID, (0, 102, 8, 6)),
    (kpi_metric_vis("Concurrent Admin Reqs", aggregation="max", custom_label="In-flight"),
        'name : "enkrypt.api.requests_in_flight"', METRICS_DATAVIEW_ID, (8, 102, 8, 6)),
    (kpi_metric_vis("Concurrent MCP Reqs", aggregation="max", custom_label="In-flight"),
        'name : "enkrypt.mcp.http.requests_in_flight"', METRICS_DATAVIEW_ID, (16, 102, 8, 6)),
    (kpi_metric_vis("Active Sessions (pool)", aggregation="max", custom_label="Pool"),
        'name : "enkrypt.session.pool.active"', METRICS_DATAVIEW_ID, (24, 102, 8, 6)),
    (kpi_metric_vis("Process Memory RSS (max)", aggregation="max", custom_label="Bytes"),
        'name : "process.runtime.memory.rss"', METRICS_DATAVIEW_ID, (32, 102, 8, 6)),
    (kpi_metric_vis("Open FDs (max)", aggregation="max", custom_label="FDs"),
        'name : "process.open_fds"', METRICS_DATAVIEW_ID, (40, 102, 8, 6)),
    (time_series_vis("Process CPU Utilization", "CPU%", chart_type="line", aggregation="avg"),
        'name : "process.runtime.cpu.utilization"', METRICS_DATAVIEW_ID, (0, 108, 24, 12)),
    (time_series_vis("Process Memory RSS Trend", "Bytes", chart_type="line", aggregation="max"),
        'name : "process.runtime.memory.rss"', METRICS_DATAVIEW_ID, (24, 108, 24, 12)),
    (multi_series_time_vis(
        "Event Loop Lag (p50/p95/p99 ms)",
        P95_LATENCY_SERIES,
        chart_type="line",
    ),
        'name : "enkrypt.asyncio.event_loop.lag"', METRICS_DATAVIEW_ID, (0, 120, 24, 12)),
    (area_vis(
        "Session Pool Queue Depth by Server",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.session.pool.queue_depth"', METRICS_DATAVIEW_ID, (24, 120, 24, 12)),
    (gauge_vis(
        "SLO: % Tool Calls under 5s",
        aggregation="avg",
        custom_label="Success ratio",
        ranges=[{"from": 0, "to": 95}, {"from": 95, "to": 99}, {"from": 99, "to": 100}],
    ),
        'name : "enkrypt.tool.duration" and value < 5', METRICS_DATAVIEW_ID, (0, 132, 24, 12)),
    (area_vis(
        "Timeout Escalations by Level",
        bucket_field="metric.attributes.escalation_level",
        bucket_label="Level",
        size=8,
    ),
        'name : ("enkrypt.timeout.escalation.warn" or "enkrypt.timeout.escalation.timeout" or "enkrypt.timeout.escalation.fail")',
        METRICS_DATAVIEW_ID, (24, 132, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - SLO & Reliability",
        description=(
            "Four Golden Signals + RED method coverage for the MCP gateway. "
            "Latency (p50/p95/p99 for tool/guardrail/health/handshake), "
            "Traffic (RPS by endpoint/server/direction), "
            "Errors (tool/guardrail/auth/MCP protocol/degradation), "
            "Saturation (in-flight, pool, CPU/RSS/FDs, event-loop lag, timeout escalations)."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="slo:",
    )


if __name__ == "__main__":
    main()
