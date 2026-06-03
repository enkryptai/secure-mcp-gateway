"""Regenerate ``gateway-audit-trail-dashboard.ndjson``.

"Audit Trail" dashboard — compliance / security-audit view. Surfaces every
mutation made to the gateway control plane (config, projects, users, api
keys, cache, system) with actor attribution.
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
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-audit-trail-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Audit Trail\n\n"
            "Compliance/audit view. Every gateway mutation (config CRUD, project/user "
            "lifecycle, API key rotations, cache flushes, system reset, settings "
            "changes) with actor attribution. Designed for SOC2 / ISO 27001 review."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # KPIs
    # ============================================================
    (markdown_vis("Section: KPIs", markdown="### Audit KPIs"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Admin Actions (total)", custom_label="Actions"),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (0, 6, 8, 6)),
    (kpi_metric_vis("Privileged Operations", custom_label="Privileged"),
        'name : "enkrypt.privileged.operations"', METRICS_DATAVIEW_ID, (8, 6, 8, 6)),
    (kpi_metric_vis("Cache Flushes", custom_label="Flushes"),
        'name : "enkrypt.admin.cache_flush"', METRICS_DATAVIEW_ID, (16, 6, 8, 6)),
    (kpi_metric_vis("System Resets", custom_label="Resets"),
        'name : "enkrypt.system.reset"', METRICS_DATAVIEW_ID, (24, 6, 8, 6)),
    (kpi_metric_vis("API Key Rotations", custom_label="Rotations"),
        'name : "enkrypt.apikey.rotations"', METRICS_DATAVIEW_ID, (32, 6, 8, 6)),
    (kpi_metric_vis("Unauthorized HTTP", custom_label="401/403"),
        'name : "enkrypt.auth.unauthorized_http"', METRICS_DATAVIEW_ID, (40, 6, 8, 6)),
    # ============================================================
    # Top actors
    # ============================================================
    (markdown_vis("Section: Actors", markdown="### 1. Top Actors & Actions"),
        "", METRICS_DATAVIEW_ID, (0, 12, 48, 2)),
    (horizontal_bar_topN_vis(
        "Top 10 Actors by Admin Action Count",
        bucket_field="metric.attributes.actor",
        bucket_label="Actor",
        metric_label="Actions",
        size=10,
    ),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (0, 14, 24, 12)),
    (pie_vis(
        "Actions by Type",
        bucket_field="metric.attributes.action",
        bucket_label="Action",
        size=15,
    ),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (24, 14, 24, 12)),
    (horizontal_bar_topN_vis(
        "Actions by Resource Type",
        bucket_field="metric.attributes.resource_type",
        bucket_label="Resource Type",
        metric_label="Actions",
        size=10,
    ),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (0, 26, 24, 12)),
    (pie_vis(
        "Actions by Source (CLI vs REST)",
        # ``surface`` is what the audit helpers emit (cli | rest_api |
        # mcp_gateway); the original ``source`` name was the pre-
        # implementation design.  Renamed to match the live emission
        # contract so the panel actually populates.
        bucket_field="metric.attributes.surface",
        bucket_label="Source",
        size=4,
    ),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (24, 26, 24, 12)),
    (area_vis(
        "Admin Actions Over Time (by action)",
        bucket_field="metric.attributes.action",
        bucket_label="Action",
        size=15,
    ),
        'name : "enkrypt.admin.actions"', METRICS_DATAVIEW_ID, (0, 38, 48, 12)),
    # ============================================================
    # Privileged operations
    # ============================================================
    (markdown_vis("Section: Privileged", markdown="### 2. Privileged Operations"),
        "", METRICS_DATAVIEW_ID, (0, 50, 48, 2)),
    (pie_vis(
        "Privileged Operations by Type",
        # ``action`` is what the audit helpers emit (cache_flush,
        # apikey_rotated, system_reset, ...).  Renamed from the
        # pre-implementation ``operation``.
        bucket_field="metric.attributes.action",
        bucket_label="Operation",
        size=10,
    ),
        'name : "enkrypt.privileged.operations"', METRICS_DATAVIEW_ID, (0, 52, 16, 12)),
    (pie_vis(
        "Operations by Surface (gateway:8000 vs api:8001)",
        bucket_field="metric.attributes.surface",
        bucket_label="Surface",
        size=4,
    ),
        'name : "enkrypt.privileged.operations"', METRICS_DATAVIEW_ID, (16, 52, 16, 12)),
    (horizontal_bar_topN_vis(
        "Cache Flush Authorization Paths",
        # ``authorization_path`` is the emission contract from
        # record_cache_flush -- matches the existing
        # auth_policy.authorize_apikey_for_cache_flush result["via"]
        # values: admin_apikey | org_match | unauthorized.
        bucket_field="metric.attributes.authorization_path",
        bucket_label="Auth Via",
        metric_label="Flushes",
        size=5,
    ),
        'name : "enkrypt.admin.cache_flush"', METRICS_DATAVIEW_ID, (32, 52, 16, 12)),
    (data_table_vis(
        "Cache Flush Audit (last 25)",
        bucket_fields=[
            # Aligned with the emission contract of
            # ``record_cache_flush`` -- actor / authorization_path /
            # scope / success.  ``include_tool_cache`` was the legacy
            # name for what we now call ``scope`` (and outcome is now
            # the canonical ``success`` boolean attribute).
            ("metric.attributes.actor", "Actor"),
            ("metric.attributes.authorization_path", "Auth Via"),
            ("metric.attributes.scope", "Scope"),
            ("metric.attributes.success", "Success"),
        ],
        size=25,
        metric_label="Flushes",
    ),
        'name : "enkrypt.admin.cache_flush"', METRICS_DATAVIEW_ID, (0, 64, 48, 16)),
    # ============================================================
    # Lifecycle events (api keys, projects, users)
    # ============================================================
    (markdown_vis(
        "Section: Lifecycle",
        markdown=(
            "### 3. API Key / Project / User Lifecycle"
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 80, 48, 2)),
    (kpi_metric_vis("API Keys Created", custom_label="Created"),
        'name : "enkrypt.audit.apikey.created"', METRICS_DATAVIEW_ID, (0, 82, 8, 6)),
    (kpi_metric_vis("API Keys Rotated", custom_label="Rotated"),
        'name : "enkrypt.audit.apikey.rotated"', METRICS_DATAVIEW_ID, (8, 82, 8, 6)),
    (kpi_metric_vis("API Keys Disabled", custom_label="Disabled"),
        'name : "enkrypt.audit.apikey.disabled"', METRICS_DATAVIEW_ID, (16, 82, 8, 6)),
    (kpi_metric_vis("API Keys Deleted", custom_label="Deleted"),
        'name : "enkrypt.audit.apikey.deleted"', METRICS_DATAVIEW_ID, (24, 82, 8, 6)),
    (kpi_metric_vis("Projects Created", custom_label="Projects+"),
        'name : "enkrypt.audit.user.created" or name : "enkrypt.projects.created"',
        METRICS_DATAVIEW_ID, (32, 82, 8, 6)),
    (kpi_metric_vis("Users Created/Deleted", custom_label="User Δ"),
        'name : "enkrypt.audit.user.created" or name : "enkrypt.audit.user.deleted"',
        METRICS_DATAVIEW_ID, (40, 82, 8, 6)),
    (area_vis(
        "Lifecycle Events Over Time",
        bucket_field="name",
        bucket_label="Metric",
        size=20,
    ),
        'name : ("enkrypt.audit.apikey.created" or "enkrypt.audit.apikey.rotated" or "enkrypt.audit.apikey.disabled" or "enkrypt.audit.apikey.deleted" or "enkrypt.audit.user.created" or "enkrypt.audit.user.deleted" or "enkrypt.audit.config.modified")',
        METRICS_DATAVIEW_ID, (0, 88, 48, 12)),
    # ============================================================
    # System ops
    # ============================================================
    (markdown_vis("Section: System Ops", markdown="### 4. System Operations"),
        "", METRICS_DATAVIEW_ID, (0, 100, 48, 2)),
    (kpi_metric_vis("Backups Run", custom_label="Backups"),
        'name : "enkrypt.system.backup.completed"', METRICS_DATAVIEW_ID, (0, 102, 12, 6)),
    (kpi_metric_vis("Restores Run", custom_label="Restores"),
        'name : "enkrypt.system.restore"', METRICS_DATAVIEW_ID, (12, 102, 12, 6)),
    (kpi_metric_vis("Telemetry Config Changes", custom_label="Changes"),
        'name : "enkrypt.audit.settings.telemetry_changed"',
        METRICS_DATAVIEW_ID, (24, 102, 12, 6)),
    (kpi_metric_vis("Enkrypt API Key Updates", custom_label="Key Updates"),
        'name : "enkrypt.audit.settings.enkrypt_api_key_set"',
        METRICS_DATAVIEW_ID, (36, 102, 12, 6)),
    # ============================================================
    # Recent audit log (from logs index)
    # ============================================================
    (markdown_vis(
        "Section: Recent Log",
        markdown=(
            "### 5. Recent Admin Log Entries\n\n"
            "Direct view into `log.attributes.admin_action` / `audit_action` from "
            "the logs index — for incident investigation drill-down."
        ),
    ), "", LOGS_DATAVIEW_ID, (0, 108, 48, 4)),
    (data_table_vis(
        "Recent Admin Actions (last 25)",
        bucket_fields=[
            # Field names aligned with the audit module's emission contract
            # in log_audit() -- ``actor`` (the human display, typically an
            # email) and ``target_id`` (the resource being acted on).
            # The earlier draft used ``actor_email``/``resource_id`` which
            # the audit module never emits, so the data_table aggregation
            # could not group and the panel rendered as 'No results found'.
            ("log.attributes.admin_action", "Admin Action"),
            ("log.attributes.actor", "Actor"),
            ("log.attributes.resource_type", "Resource Type"),
            ("log.attributes.target_id", "Target ID"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.admin_action : *', LOGS_DATAVIEW_ID, (0, 112, 24, 16)),
    (data_table_vis(
        "Recent Audit Events (changed_fields)",
        bucket_fields=[
            ("log.attributes.audit_action", "Audit Action"),
            ("log.attributes.actor", "Actor"),
            ("log.attributes.changed_fields", "Changed Fields"),
        ],
        size=25,
        metric_label="Count",
        aggregation="count",
        field="",
    ),
        'log.attributes.audit_action : *', LOGS_DATAVIEW_ID, (24, 112, 24, 16)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Audit Trail",
        description=(
            "Compliance/security-audit view. Every gateway control-plane mutation "
            "with actor attribution — admin actions by actor/type/resource/source, "
            "privileged operations (cache flush authorization, system reset), "
            "API key / project / user lifecycle events, system ops (backup/restore/"
            "settings changes), recent admin log drill-down. Designed for SOC2/"
            "ISO 27001 audit walkthroughs."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="audit:",
    )


if __name__ == "__main__":
    main()
