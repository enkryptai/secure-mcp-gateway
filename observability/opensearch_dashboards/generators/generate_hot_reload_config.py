"""Regenerate ``gateway-hot-reload-config-dashboard.ndjson``.

"Hot Reload & Config" dashboard — platform/ops view. Tracks the config
hot-reload pipeline + config inventory.
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

OUT = DASHBOARDS_DIR / "gateway-hot-reload-config-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Hot Reload & Config\n\n"
            "Config hot-reload pipeline health (frequency, duration, partial "
            "failures), config inventory (size, entries by entity), validation "
            "errors, watcher reliability, plugin reload health, telemetry "
            "provider status."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Reload KPIs
    # ============================================================
    (markdown_vis("Section: KPIs", markdown="### 1. Reload Pipeline KPIs"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Total Reloads (24h)", custom_label="Reloads"),
        'name : "enkrypt.config.reload.total"', METRICS_DATAVIEW_ID, (0, 6, 12, 6)),
    (kpi_metric_vis("Successful Reloads", custom_label="OK"),
        'name : "enkrypt.config.reload.total" and metric.attributes.outcome : "ok"',
        METRICS_DATAVIEW_ID, (12, 6, 12, 6)),
    (kpi_metric_vis("Reload Failures", custom_label="Failed"),
        'name : "enkrypt.config.reload.total" and metric.attributes.outcome : ("partial" or "failed")',
        METRICS_DATAVIEW_ID, (24, 6, 12, 6)),
    (kpi_metric_vis("Seconds Since Last Reload", aggregation="max", custom_label="Stale (s)"),
        'name : "enkrypt.config.reload.seconds_since_last"',
        METRICS_DATAVIEW_ID, (36, 6, 12, 6)),
    # ============================================================
    # Triggers + durations
    # ============================================================
    (markdown_vis("Section: Triggers", markdown="### 2. Triggers & Duration"),
        "", METRICS_DATAVIEW_ID, (0, 12, 48, 2)),
    (pie_vis(
        "Reload Triggers (watcher / api / gateway)",
        bucket_field="metric.attributes.trigger",
        bucket_label="Trigger",
        size=5,
    ),
        'name : "enkrypt.config.reload.total"', METRICS_DATAVIEW_ID, (0, 14, 16, 12)),
    (percentile_vis("Reload Duration p95 (s)", percentile=95, custom_label="p95"),
        'name : "enkrypt.config.reload.duration"', METRICS_DATAVIEW_ID, (16, 14, 16, 12)),
    (percentile_vis("Reload Duration p99 (s)", percentile=99, custom_label="p99"),
        'name : "enkrypt.config.reload.duration"', METRICS_DATAVIEW_ID, (32, 14, 16, 12)),
    (time_series_vis("Reload Duration Trend (avg)", "ms",
                      chart_type="line", aggregation="avg"),
        'name : "enkrypt.config.reload.duration"', METRICS_DATAVIEW_ID, (0, 26, 24, 12)),
    (area_vis(
        "Reloads Over Time by Trigger",
        bucket_field="metric.attributes.trigger",
        bucket_label="Trigger",
        size=5,
    ),
        'name : "enkrypt.config.reload.total"', METRICS_DATAVIEW_ID, (24, 26, 24, 12)),
    # ============================================================
    # Component failures
    # ============================================================
    (markdown_vis("Section: Components", markdown="### 3. Component-Level Reload Failures"),
        "", METRICS_DATAVIEW_ID, (0, 38, 48, 2)),
    (horizontal_bar_topN_vis(
        "Reload Failures by Component",
        bucket_field="metric.attributes.component",
        bucket_label="Component",
        metric_label="Failures",
        size=10,
    ),
        'name : "enkrypt.config.reload.component_failures"', METRICS_DATAVIEW_ID, (0, 40, 24, 12)),
    (horizontal_bar_topN_vis(
        "Component Failure Error Codes",
        bucket_field="metric.attributes.error_code",
        bucket_label="Error Code",
        metric_label="Failures",
        size=10,
    ),
        'name : "enkrypt.config.reload.component_failures"', METRICS_DATAVIEW_ID, (24, 40, 24, 12)),
    # ============================================================
    # Config inventory
    # ============================================================
    (markdown_vis("Section: Inventory", markdown="### 4. Config Inventory"),
        "", METRICS_DATAVIEW_ID, (0, 52, 48, 2)),
    (kpi_metric_vis("Config Size (bytes)", aggregation="max", custom_label="Size"),
        'name : "enkrypt.config.size_bytes"', METRICS_DATAVIEW_ID, (0, 54, 12, 6)),
    (kpi_metric_vis("Total mcp_configs", aggregation="max", custom_label="Configs"),
        'name : "enkrypt.config.entries" and metric.attributes.entity : "mcp_configs"',
        METRICS_DATAVIEW_ID, (12, 54, 12, 6)),
    (kpi_metric_vis("Total Projects", aggregation="max", custom_label="Projects"),
        'name : "enkrypt.config.entries" and metric.attributes.entity : "projects"',
        METRICS_DATAVIEW_ID, (24, 54, 12, 6)),
    (kpi_metric_vis("Total Users", aggregation="max", custom_label="Users"),
        'name : "enkrypt.config.entries" and metric.attributes.entity : "users"',
        METRICS_DATAVIEW_ID, (36, 54, 12, 6)),
    (kpi_metric_vis("Total API Keys", aggregation="max", custom_label="Keys"),
        'name : "enkrypt.config.entries" and metric.attributes.entity : "apikeys"',
        METRICS_DATAVIEW_ID, (0, 60, 12, 6)),
    (kpi_metric_vis("Total Servers (across configs)", aggregation="max", custom_label="Servers"),
        'name : "enkrypt.config.entries" and metric.attributes.entity : "servers_total"',
        METRICS_DATAVIEW_ID, (12, 60, 12, 6)),
    (kpi_metric_vis("Plugin Load Failures", custom_label="Plugin Fails"),
        'name : "enkrypt.config.provider_load_failures"',
        METRICS_DATAVIEW_ID, (24, 60, 12, 6)),
    (kpi_metric_vis("Config Watcher Errors", custom_label="Watcher Err"),
        'name : "enkrypt.config_watcher.triggers" and metric.attributes.outcome : "failure"',
        METRICS_DATAVIEW_ID, (36, 60, 12, 6)),
    # ============================================================
    # Validation errors
    # ============================================================
    (markdown_vis("Section: Validation", markdown="### 5. Config Validation"),
        "", METRICS_DATAVIEW_ID, (0, 66, 48, 2)),
    (kpi_metric_vis("Validation Errors", custom_label="Errors"),
        'name : "enkrypt.config.validation.errors"', METRICS_DATAVIEW_ID, (0, 68, 16, 8)),
    (horizontal_bar_topN_vis(
        "Validation Errors by Code",
        bucket_field="metric.attributes.error_code",
        bucket_label="Error Code",
        metric_label="Errors",
        size=10,
    ),
        'name : "enkrypt.config.validation.errors"', METRICS_DATAVIEW_ID, (16, 68, 32, 8)),
    # ============================================================
    # Plugin lifecycle
    # ============================================================
    (markdown_vis("Section: Plugins", markdown="### 6. Plugin Lifecycle"),
        "", METRICS_DATAVIEW_ID, (0, 76, 48, 2)),
    (data_table_vis(
        "Plugin Reloads (recent)",
        bucket_fields=[
            ("metric.attributes.plugin_type", "Plugin Type"),
            ("metric.attributes.plugin_name", "Plugin Name"),
            ("metric.attributes.outcome", "Outcome"),
        ],
        size=25,
        metric_label="Reloads",
    ),
        'name : "enkrypt.plugin.reload"', METRICS_DATAVIEW_ID, (0, 78, 24, 12)),
    (pie_vis(
        "Telemetry Provider Enabled",
        bucket_field="metric.attributes.provider",
        bucket_label="Provider",
        size=5,
    ),
        'name : "enkrypt.telemetry.enabled"', METRICS_DATAVIEW_ID, (24, 78, 12, 12)),
    (kpi_metric_vis("Telemetry Export Failures", custom_label="Export Failures"),
        'name : "enkrypt.telemetry.export.failures"', METRICS_DATAVIEW_ID, (36, 78, 12, 12)),
    # ============================================================
    # Hot-reload log details
    # ============================================================
    (markdown_vis("Section: Logs", markdown="### 7. Recent Reload Log Detail"),
        "", LOGS_DATAVIEW_ID, (0, 90, 48, 2)),
    (data_table_vis(
        "Last 25 Reload Events",
        bucket_fields=[
            ("log.attributes.trigger", "Trigger"),
            ("log.attributes.auth_reloaded", "Auth?"),
            ("log.attributes.guardrails_reloaded", "Guardrails?"),
            ("log.attributes.telemetry_reloaded", "Telemetry?"),
            ("log.attributes.include_tool_cache", "Tool Cache?"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.trigger : * and (log.attributes.auth_reloaded : * or log.attributes.guardrails_reloaded : *)',
        LOGS_DATAVIEW_ID, (0, 92, 48, 16)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Hot Reload & Config",
        description=(
            "Platform/ops view of the config hot-reload pipeline + config inventory. "
            "Reload frequency by trigger (watcher/api/gateway), duration p95/p99, "
            "partial-failure breakdown by component (auth/guardrails/telemetry/"
            "session_pool/cache), config inventory by entity (mcp_configs/projects/"
            "users/apikeys/servers), validation errors, watcher reliability, plugin "
            "reload health, telemetry provider status."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="hotReload:",
    )


if __name__ == "__main__":
    main()
