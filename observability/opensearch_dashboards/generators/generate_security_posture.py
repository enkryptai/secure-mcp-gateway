"""Regenerate ``gateway-security-dashboard.ndjson``.

"Security Posture" dashboard — security ops / CISO view. Surfaces every
threat-relevant signal across the gateway.

Sections:

1. **Top-level KPIs** — total blocks, distinct attackers, compliance hits
2. **Block analysis** — by violation_type, project, user, time
3. **Compliance** — OWASP / MITRE / NIST / EU AI Act framework hits
4. **Auth & privileged ops** — admin auth, unauthorized cache flushes,
   privileged endpoint hits
5. **Server-side defense** — registration blocks, deny-list, server
   description blocks
6. **Repeat offenders** — sliding-window high-frequency abuse detection
"""

from __future__ import annotations

from pathlib import Path

from _common import (
    
    DASHBOARDS_DIR,LOGS_DATAVIEW_ID,
    METRICS_DATAVIEW_ID,
    area_vis,
    build_dashboard_ndjson,
    data_table_vis,
    heatmap_vis,
    horizontal_bar_topN_vis,
    kpi_metric_vis,
    markdown_vis,
    pie_vis,
    time_series_vis,
)

OUT = DASHBOARDS_DIR / "gateway-security-dashboard.ndjson"

PANEL_SPECS = [
    (markdown_vis(
        "Security Header",
        markdown=(
            "## Secure MCP Gateway — Security Posture\n\n"
            "Live security signals: guardrail blocks, compliance framework hits, "
            "auth failures, privileged operations, registration defense, abuse detection. "
            "Filter by `metric.attributes.org_id` / `project_name` to scope per-tenant."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Top-level KPI row
    # ============================================================
    (markdown_vis("KPI", markdown="### Top-Line Security KPIs"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (kpi_metric_vis("Total Blocks", custom_label="Blocks"),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 6, 8, 6)),
    (kpi_metric_vis("Input Blocks", custom_label="Input"),
        'name : "enkrypt.guardrail.input_blocks"', METRICS_DATAVIEW_ID, (8, 6, 8, 6)),
    (kpi_metric_vis("Output Blocks", custom_label="Output"),
        'name : "enkrypt.guardrail.output_blocks"', METRICS_DATAVIEW_ID, (16, 6, 8, 6)),
    (kpi_metric_vis("Compliance Hits", custom_label="Compliance"),
        'name : "enkrypt.guardrail.compliance_hit"', METRICS_DATAVIEW_ID, (24, 6, 8, 6)),
    (kpi_metric_vis("Auth Failures", custom_label="Auth Fail"),
        'name : "enkrypt.auth.failure"', METRICS_DATAVIEW_ID, (32, 6, 8, 6)),
    (kpi_metric_vis("Unauthorized HTTP", custom_label="401/403"),
        'name : "enkrypt.auth.unauthorized_http"', METRICS_DATAVIEW_ID, (40, 6, 8, 6)),
    # ============================================================
    # Section: Block analysis
    # ============================================================
    (markdown_vis("Section: Blocks", markdown="### 1. Block Analysis"),
        "", METRICS_DATAVIEW_ID, (0, 12, 48, 2)),
    (pie_vis(
        "Blocks by Violation Type",
        bucket_field="metric.attributes.violation_type",
        bucket_label="Violation",
        size=15,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 14, 16, 12)),
    (pie_vis(
        "Blocks by Direction",
        bucket_field="metric.attributes.direction",
        bucket_label="Direction",
        size=4,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (16, 14, 16, 12)),
    (pie_vis(
        "Blocks by Source Event",
        bucket_field="metric.attributes.source_event",
        bucket_label="Source Event",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (32, 14, 16, 12)),
    (area_vis(
        "Blocks Over Time by Violation Type (stacked)",
        bucket_field="metric.attributes.violation_type",
        bucket_label="Violation",
        size=12,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 26, 48, 12)),
    (horizontal_bar_topN_vis(
        "Top Projects by Blocks",
        bucket_field="metric.attributes.project_name",
        bucket_label="Project",
        metric_label="Blocks",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 38, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Users by Blocks",
        bucket_field="metric.attributes.user_id",
        bucket_label="User ID",
        metric_label="Blocks",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (24, 38, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Servers by Blocks",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Blocks",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 50, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Tools by Blocks",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
        metric_label="Blocks",
        size=10,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (24, 50, 24, 12)),
    # ============================================================
    # Section: Compliance
    # ============================================================
    (markdown_vis("Section: Compliance", markdown="### 2. Compliance Framework Hits"),
        "", METRICS_DATAVIEW_ID, (0, 62, 48, 2)),
    (pie_vis(
        "Hits by Framework",
        bucket_field="metric.attributes.compliance_framework",
        bucket_label="Framework",
        size=8,
    ),
        'name : "enkrypt.guardrail.compliance_hit"', METRICS_DATAVIEW_ID, (0, 64, 16, 12)),
    (horizontal_bar_topN_vis(
        "OWASP LLM Top 10 Hits",
        bucket_field="metric.attributes.compliance_label",
        bucket_label="OWASP Label",
        metric_label="Hits",
        size=10,
    ),
        'name : "enkrypt.guardrail.compliance_hit" and metric.attributes.compliance_framework : "owasp_llm_2025"',
        METRICS_DATAVIEW_ID, (16, 64, 16, 12)),
    (horizontal_bar_topN_vis(
        "MITRE ATLAS Hits",
        bucket_field="metric.attributes.compliance_label",
        bucket_label="MITRE Label",
        metric_label="Hits",
        size=10,
    ),
        'name : "enkrypt.guardrail.compliance_hit" and metric.attributes.compliance_framework : "mitre_atlas"',
        METRICS_DATAVIEW_ID, (32, 64, 16, 12)),
    (heatmap_vis(
        "Compliance Framework × Project (heatmap)",
        x_field="metric.attributes.project_name",
        y_field="metric.attributes.compliance_framework",
        x_size=10,
        y_size=5,
    ),
        'name : "enkrypt.guardrail.compliance_hit"', METRICS_DATAVIEW_ID, (0, 76, 48, 14)),
    # ============================================================
    # Section: Auth & privileged ops
    # ============================================================
    (markdown_vis("Section: Auth", markdown="### 3. Authentication & Privileged Ops"),
        "", METRICS_DATAVIEW_ID, (0, 90, 48, 2)),
    (pie_vis(
        "Auth Failures by Reason",
        bucket_field="metric.attributes.failure_reason",
        bucket_label="Reason",
        size=10,
    ),
        'name : "enkrypt.auth.failure"', METRICS_DATAVIEW_ID, (0, 92, 16, 12)),
    (pie_vis(
        "Auth by Provider",
        bucket_field="metric.attributes.provider",
        bucket_label="Provider",
        size=5,
    ),
        'name : ("enkrypt.auth.success" or "enkrypt.auth.failure")',
        METRICS_DATAVIEW_ID, (16, 92, 16, 12)),
    (horizontal_bar_topN_vis(
        "Unauthorized HTTP by Surface",
        bucket_field="metric.attributes.surface",
        bucket_label="Surface",
        metric_label="Unauthorized",
        size=10,
    ),
        'name : "enkrypt.auth.unauthorized_http"', METRICS_DATAVIEW_ID, (32, 92, 16, 12)),
    (area_vis(
        "Privileged Operations Over Time",
        bucket_field="metric.attributes.operation",
        bucket_label="Operation",
        size=10,
    ),
        'name : "enkrypt.privileged.operations"', METRICS_DATAVIEW_ID, (0, 104, 24, 12)),
    (horizontal_bar_topN_vis(
        "Cache Flush Authorization Paths",
        bucket_field="metric.attributes.authorized_via",
        bucket_label="Authorized Via",
        metric_label="Flushes",
        size=5,
    ),
        'name : "enkrypt.admin.cache_flush"', METRICS_DATAVIEW_ID, (24, 104, 24, 12)),
    # ============================================================
    # Section: Server-side defense
    # ============================================================
    (markdown_vis("Section: Server Defense", markdown="### 4. Server-Side Defense"),
        "", METRICS_DATAVIEW_ID, (0, 116, 48, 2)),
    (kpi_metric_vis("Tools Blocked at Registration", custom_label="Reg Blocks"),
        'name : "enkrypt.discovery.tools_blocked_registration"',
        METRICS_DATAVIEW_ID, (0, 118, 12, 6)),
    (kpi_metric_vis("Deny-List Blocks", custom_label="Deny-List"),
        'name : "enkrypt.tool.deny_list.blocks"', METRICS_DATAVIEW_ID, (12, 118, 12, 6)),
    (kpi_metric_vis("Permission Denied", custom_label="403s"),
        'name : "enkrypt.tool.permission_denied"', METRICS_DATAVIEW_ID, (24, 118, 12, 6)),
    (kpi_metric_vis("Bypass Keyword Hits", custom_label="Bypass"),
        'name : "enkrypt.security.bypass_keyword_hits"',
        METRICS_DATAVIEW_ID, (36, 118, 12, 6)),
    (horizontal_bar_topN_vis(
        "Deny-List Activations by Server",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Blocks",
        size=10,
    ),
        'name : "enkrypt.tool.deny_list.blocks"', METRICS_DATAVIEW_ID, (0, 124, 24, 12)),
    (horizontal_bar_topN_vis(
        "Bypass Patterns Detected (hashed)",
        bucket_field="metric.attributes.pattern_hash",
        bucket_label="Pattern Hash",
        metric_label="Hits",
        size=10,
    ),
        'name : "enkrypt.security.bypass_keyword_hits"',
        METRICS_DATAVIEW_ID, (24, 124, 24, 12)),
    # ============================================================
    # Section: Repeat offenders
    # ============================================================
    (markdown_vis(
        "Section: Repeat Offenders",
        markdown=(
            "### 5. Repeat Offenders & Internal Traffic\n\n"
            "Heavy block clusters indicate either abuse, misconfiguration, or an "
            "attacker probing the gateway. Cross-reference with `is_internal_req` "
            "to exclude Enkrypt staff traffic."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 136, 48, 4)),
    (data_table_vis(
        "Repeat Offender Leaderboard (>10 blocks in window)",
        bucket_fields=[
            ("metric.attributes.user_id", "User ID"),
            ("metric.attributes.window_minutes", "Window (min)"),
            ("metric.attributes.project_name", "Project"),
        ],
        size=25,
        metric_label="Offenses",
    ),
        'name : "enkrypt.security.repeat_offender"', METRICS_DATAVIEW_ID, (0, 140, 48, 16)),
    (pie_vis(
        "Internal vs External Traffic (blocks)",
        bucket_field="metric.attributes.is_internal_req",
        bucket_label="Internal?",
        size=4,
    ),
        'name : "enkrypt.guardrail.blocks"', METRICS_DATAVIEW_ID, (0, 156, 24, 12)),
    (time_series_vis(
        "Repeat-Offender Trend",
        "Offenses",
        chart_type="histogram",
    ),
        'name : "enkrypt.security.repeat_offender"', METRICS_DATAVIEW_ID, (24, 156, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Security Posture",
        description=(
            "Security-ops/CISO view. Top-line block KPIs, violation-type breakdowns, "
            "OWASP/MITRE/NIST compliance hits, auth failure analysis, privileged-op "
            "tracking (cache flush, system reset, settings changes), server-side "
            "registration defense (deny-list, server description blocks), repeat-"
            "offender leaderboard. Filter by org_id / project_name / direction for "
            "tenant-scoped views."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="security:",
    )


if __name__ == "__main__":
    main()
