"""Regenerate ``gateway-cache-performance-dashboard.ndjson``.

"Cache & Performance" dashboard — platform/SRE view. Surfaces caching,
session pooling, and per-request latency breakdown.
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

OUT = DASHBOARDS_DIR / "gateway-cache-performance-dashboard.ndjson"

LATENCY_P_SERIES = [
    {"label": "p50", "type": "percentiles", "field": "value", "params": {"percents": [50]}},
    {"label": "p95", "type": "percentiles", "field": "value", "params": {"percents": [95]}},
    {"label": "p99", "type": "percentiles", "field": "value", "params": {"percents": [99]}},
]

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Cache & Performance\n\n"
            "Local + Redis cache health, session pool stats, sandbox runtime "
            "availability, per-request latency breakdown (preprocess / execute / "
            "postprocess). Filter by `server_name` or `mcp_config_id` for "
            "per-server views."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Cache hit ratio
    # ============================================================
    (markdown_vis("Section: Cache", markdown="### 1. Cache Hit/Miss"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Cache Hits", custom_label="Hits"),
        'name : "enkrypt.cache.hits"', METRICS_DATAVIEW_ID, (0, 6, 12, 6)),
    (kpi_metric_vis("Cache Misses", custom_label="Misses"),
        'name : "enkrypt.cache.misses"', METRICS_DATAVIEW_ID, (12, 6, 12, 6)),
    (gauge_vis(
        "Cache Hit Ratio %",
        aggregation="avg",
        custom_label="Hit %",
        ranges=[
            {"from": 0, "to": 50},
            {"from": 50, "to": 80},
            {"from": 80, "to": 100},
        ],
    ),
        'name : "enkrypt.cache.hits"', METRICS_DATAVIEW_ID, (24, 6, 12, 6)),
    (kpi_metric_vis("Local Cache Entries", aggregation="max", custom_label="Entries"),
        'name : "enkrypt.cache.local.entries"', METRICS_DATAVIEW_ID, (36, 6, 12, 6)),
    (time_series_vis("Cache Hits Over Time", "Hits", chart_type="histogram"),
        'name : "enkrypt.cache.hits"', METRICS_DATAVIEW_ID, (0, 12, 24, 12)),
    (time_series_vis("Cache Misses Over Time", "Misses", chart_type="histogram"),
        'name : "enkrypt.cache.misses"', METRICS_DATAVIEW_ID, (24, 12, 24, 12)),
    (pie_vis(
        "Cache Backend Distribution",
        bucket_field="metric.attributes.cache_backend",
        bucket_label="Backend",
        size=4,
    ),
        'name : "enkrypt.cache.backend"', METRICS_DATAVIEW_ID, (0, 24, 16, 12)),
    (horizontal_bar_topN_vis(
        "Cache Activity by Type",
        bucket_field="metric.attributes.cache_type",
        bucket_label="Cache Type",
        metric_label="Entries",
        size=6,
        aggregation="max",
    ),
        'name : "enkrypt.cache.local.entries"', METRICS_DATAVIEW_ID, (16, 24, 16, 12)),
    (kpi_metric_vis("Cache Lookup Latency (logs avg ms)", aggregation="avg",
                     field="log.attributes.cache_lookup_duration_ms",
                     custom_label="Avg ms"),
        'log.attributes.cache_lookup_duration_ms : *', LOGS_DATAVIEW_ID, (32, 24, 16, 12)),
    # ============================================================
    # Redis stats
    # ============================================================
    (markdown_vis("Section: Redis", markdown="### 2. Redis (External Cache)"),
        "", METRICS_DATAVIEW_ID, (0, 36, 48, 2)),
    (kpi_metric_vis("Redis Connection State", aggregation="max",
                     custom_label="State (1=up)"),
        'name : "enkrypt.redis.connection.state"', METRICS_DATAVIEW_ID, (0, 38, 16, 6)),
    (pie_vis(
        "Redis Operations by Kind",
        bucket_field="metric.attributes.redis_operation",
        bucket_label="Op",
        size=6,
    ),
        'name : "enkrypt.redis.operations"', METRICS_DATAVIEW_ID, (16, 38, 16, 12)),
    (area_vis(
        "Redis Operations Over Time",
        bucket_field="metric.attributes.redis_operation",
        bucket_label="Op",
        size=6,
    ),
        'name : "enkrypt.redis.operations"', METRICS_DATAVIEW_ID, (32, 38, 16, 12)),
    # ============================================================
    # Session pool
    # ============================================================
    (markdown_vis("Section: Session Pool", markdown="### 3. MCP Session Pool"),
        "", METRICS_DATAVIEW_ID, (0, 50, 48, 2)),
    (kpi_metric_vis("Active Sessions", aggregation="max", custom_label="Active"),
        'name : "enkrypt.session.pool.active"', METRICS_DATAVIEW_ID, (0, 52, 12, 6)),
    (kpi_metric_vis("Acquire Events", custom_label="Acquires"),
        'name : "enkrypt.session.pool.acquire"', METRICS_DATAVIEW_ID, (12, 52, 12, 6)),
    (gauge_vis(
        "Session Reuse %",
        aggregation="avg",
        custom_label="Reuse %",
        ranges=[
            {"from": 0, "to": 50},
            {"from": 50, "to": 80},
            {"from": 80, "to": 100},
        ],
    ),
        'name : "enkrypt.session.pool.acquire" and metric.attributes.session_reused : true',
        METRICS_DATAVIEW_ID, (24, 52, 12, 6)),
    (kpi_metric_vis("Worker Crashes", custom_label="Crashes"),
        'name : "enkrypt.session.pool.worker_crashes"', METRICS_DATAVIEW_ID, (36, 52, 12, 6)),
    (area_vis(
        "Session Pool Queue Depth by Server",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        size=10,
        aggregation="max",
    ),
        'name : "enkrypt.session.pool.queue_depth"', METRICS_DATAVIEW_ID, (0, 58, 24, 12)),
    (pie_vis(
        "Session Evictions by Reason",
        bucket_field="metric.attributes.eviction_reason",
        bucket_label="Reason",
        size=8,
    ),
        'name : "enkrypt.session.pool.evictions"', METRICS_DATAVIEW_ID, (24, 58, 24, 12)),
    # ============================================================
    # Sandbox
    # ============================================================
    (markdown_vis("Section: Sandbox", markdown="### 4. Sandbox Runtime"),
        "", METRICS_DATAVIEW_ID, (0, 70, 48, 2)),
    (kpi_metric_vis("Sandbox Wraps", custom_label="Wraps"),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (0, 72, 12, 6)),
    (kpi_metric_vis("Sandbox Wrap Failures", custom_label="Failures"),
        'name : "enkrypt.sandbox.wrap.invocations" and metric.attributes.outcome : "error"',
        METRICS_DATAVIEW_ID, (12, 72, 12, 6)),
    (pie_vis(
        "Sandbox Scope (global vs per-server)",
        bucket_field="metric.attributes.sandbox_scope",
        bucket_label="Scope",
        size=4,
    ),
        'name : "enkrypt.sandbox.wrap.invocations"', METRICS_DATAVIEW_ID, (24, 72, 12, 6)),
    (pie_vis(
        "Sandbox Runtime Availability",
        bucket_field="metric.attributes.sandbox_runtime",
        bucket_label="Runtime",
        size=6,
    ),
        'name : "enkrypt.sandbox.availability"', METRICS_DATAVIEW_ID, (36, 72, 12, 6)),
    # ============================================================
    # Per-request latency breakdown (from logs)
    # ============================================================
    (markdown_vis("Section: Latency Breakdown", markdown="### 5. Per-Request Latency Breakdown (logs)"),
        "", LOGS_DATAVIEW_ID, (0, 78, 48, 2)),
    (kpi_metric_vis("Preprocess Avg (ms)", aggregation="avg",
                     field="log.attributes.preprocess_duration_ms",
                     custom_label="ms"),
        'log.attributes.preprocess_duration_ms : *', LOGS_DATAVIEW_ID, (0, 80, 12, 6)),
    (kpi_metric_vis("Execute Avg (ms)", aggregation="avg",
                     field="log.attributes.execution_duration_ms",
                     custom_label="ms"),
        'log.attributes.execution_duration_ms : *', LOGS_DATAVIEW_ID, (12, 80, 12, 6)),
    (kpi_metric_vis("Postprocess Avg (ms)", aggregation="avg",
                     field="log.attributes.postprocess_duration_ms",
                     custom_label="ms"),
        'log.attributes.postprocess_duration_ms : *', LOGS_DATAVIEW_ID, (24, 80, 12, 6)),
    (kpi_metric_vis("Total Request Avg (ms)", aggregation="avg",
                     field="log.attributes.total_request_duration_ms",
                     custom_label="ms"),
        'log.attributes.total_request_duration_ms : *', LOGS_DATAVIEW_ID, (36, 80, 12, 6)),
    (time_series_vis("Total Request Duration (avg ms)", "ms",
                      chart_type="line", aggregation="avg",
                      field="log.attributes.total_request_duration_ms"),
        'log.attributes.total_request_duration_ms : *', LOGS_DATAVIEW_ID, (0, 86, 24, 12)),
    (time_series_vis("Tool Call Duration (avg ms)", "ms",
                      chart_type="line", aggregation="avg",
                      field="log.attributes.tool_call_duration_ms"),
        'log.attributes.tool_call_duration_ms : *', LOGS_DATAVIEW_ID, (24, 86, 24, 12)),
    (time_series_vis("Cache Lookup Duration (avg ms)", "ms",
                      chart_type="line", aggregation="avg",
                      field="log.attributes.cache_lookup_duration_ms"),
        'log.attributes.cache_lookup_duration_ms : *', LOGS_DATAVIEW_ID, (0, 98, 24, 12)),
    (time_series_vis("Guardrail Duration (avg ms)", "ms",
                      chart_type="line", aggregation="avg",
                      field="log.attributes.guardrail_duration_ms"),
        'log.attributes.guardrail_duration_ms : *', LOGS_DATAVIEW_ID, (24, 98, 24, 12)),
    (multi_series_time_vis(
        "MCP Handshake Latency (p50/p95/p99 s)",
        LATENCY_P_SERIES,
        chart_type="line",
    ),
        'name : "enkrypt.mcp.connection.handshake.duration"',
        METRICS_DATAVIEW_ID, (0, 110, 48, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Cache & Performance",
        description=(
            "Platform/SRE view of caching, session pooling, sandbox runtime, and "
            "per-request latency breakdown. Local cache hits/misses + hit ratio, "
            "Redis op rate + connection state, session pool stats (active/reuse %/"
            "evictions/queue depth/worker crashes), sandbox runtime availability + "
            "wrap failures, per-phase latency (preprocess/execute/postprocess + "
            "total) from logs, MCP handshake p50/p95/p99."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="cachePerf:",
    )


if __name__ == "__main__":
    main()
