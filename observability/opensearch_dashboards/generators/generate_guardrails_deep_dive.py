"""Regenerate ``gateway-guardrails-deep-dive-dashboard.ndjson``.

"Guardrails Deep Dive" dashboard — security analyst view. Mirrors the apiaas
guardrails-product dashboard widget set (Top Statuses, Playground Requests,
Top Users, per-detector Count/Enabled%/Time Series).

For each of the 11 detectors (nsfw, toxicity, pii, injection_attack,
keyword_detector, policy_violation, bias, sponge_attack, copyright_ip,
system_prompt, topic_detector), the dashboard surfaces:

- **Count** — total blocked events
- **Enabled %** — what fraction of checks had this detector enabled
- **Time Series** — block rate over time
- **Breakdown table** — by direction / project / server

Plus top-level cross-cutting widgets (Top Statuses, Top Users, etc.).
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

OUT = DASHBOARDS_DIR / "gateway-guardrails-deep-dive-dashboard.ndjson"

# 11 detectors, in the order they appear in the apiaas-style screenshot
DETECTORS = [
    ("topic_detector",   "Off Topic"),
    ("nsfw",             "NSFW"),
    ("toxicity",         "Toxicity"),
    ("pii",              "PII"),
    ("injection_attack", "Injection Attack"),
    ("keyword_detector", "Keyword Detected"),
    ("policy_violation", "Policy Violation"),
    ("bias",             "Bias"),
    ("copyright_ip",     "Copyright IP"),
    ("system_prompt",    "System Prompt"),
    ("sponge_attack",    "Sponge Attack"),
]


def _detector_row(y_start: int, det_key: str, det_label: str) -> list[tuple]:
    """One row of 4 widgets per detector (Count / Enabled% / Time Series / Breakdown)."""
    return [
        (markdown_vis(
            f"Section: {det_label}",
            markdown=f"#### {det_label} (`detector:{det_key}`)",
        ), "", METRICS_DATAVIEW_ID, (0, y_start, 48, 2)),
        # Count
        (kpi_metric_vis(f"{det_label} Count", custom_label="Blocks"),
            f'name : "enkrypt.guardrail.{det_key}_blocks"',
            METRICS_DATAVIEW_ID, (0, y_start + 2, 8, 8)),
        # Enabled % (uses enkrypt.guardrail.detection with detector_enabled=true vs all)
        (kpi_metric_vis(
            f"{det_label} Checks (Enabled)",
            custom_label="Enabled checks",
        ),
            f'name : "enkrypt.guardrail.detection" and metric.attributes.detector : "{det_key}" and metric.attributes.detector_enabled : true',
            METRICS_DATAVIEW_ID, (8, y_start + 2, 8, 8)),
        # Time series
        (time_series_vis(f"{det_label} Blocks Over Time", "Blocks", chart_type="histogram"),
            f'name : "enkrypt.guardrail.{det_key}_blocks"',
            METRICS_DATAVIEW_ID, (16, y_start + 2, 16, 8)),
        # Breakdown
        (data_table_vis(
            f"{det_label} Breakdown",
            bucket_fields=[
                ("metric.attributes.direction", "Direction"),
                ("metric.attributes.project_name", "Project"),
                ("metric.attributes.server_name", "Server"),
            ],
            size=10,
            metric_label="Blocks",
        ),
            f'name : "enkrypt.guardrail.{det_key}_blocks"',
            METRICS_DATAVIEW_ID, (32, y_start + 2, 16, 8)),
    ]


PANEL_SPECS: list[tuple] = [
    # ============================================================
    # Header
    # ============================================================
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway — Guardrails Deep Dive\n\n"
            "Per-detector activity for the 11 Enkrypt guardrail detectors. Each row "
            "shows: total blocks, enabled-check count, blocks over time, and a "
            "breakdown by direction × project × server. Top-level widgets cross-cut "
            "all detectors. Powered by `enkrypt.guardrail.{detector}_blocks` (per-"
            "detector counters) and `enkrypt.guardrail.detection` (unified counter "
            "for enabled%/disabled% queries)."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),
    # ============================================================
    # Top-level cross-cutting row
    # ============================================================
    (markdown_vis("Section: Cross-cut", markdown="### Cross-Cutting Top-N"),
        "", METRICS_DATAVIEW_ID, (0, 4, 48, 2)),
    (horizontal_bar_topN_vis(
        "Top Statuses (guardrail HTTP)",
        bucket_field="metric.attributes.status_code",
        bucket_label="HTTP Status",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (0, 6, 12, 12)),
    (kpi_metric_vis("Playground Requests", custom_label="Playground"),
        'name : "enkrypt.guardrail.checks" and (metric.attributes.request_type : "playground_inline" or metric.attributes.request_type : "playground_registry")',
        METRICS_DATAVIEW_ID, (12, 6, 12, 12)),
    (horizontal_bar_topN_vis(
        "Top Users (guardrail activity)",
        bucket_field="metric.attributes.user_id",
        bucket_label="User ID",
        metric_label="Checks",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (24, 6, 12, 12)),
    (kpi_metric_vis("Count - All Requests", custom_label="Total"),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (36, 6, 12, 12)),
    (horizontal_bar_topN_vis(
        "Top Source Events",
        bucket_field="metric.attributes.source_event",
        bucket_label="Source Event",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (0, 18, 16, 12)),
    (horizontal_bar_topN_vis(
        "Top Source Names",
        bucket_field="metric.attributes.source_name",
        bucket_label="Source Name",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (16, 18, 16, 12)),
    (percentile_vis("Guardrail Latency (p95)", percentile=95, custom_label="p95 seconds"),
        'name : "enkrypt.guardrail.duration"', METRICS_DATAVIEW_ID, (32, 18, 16, 12)),
    # ============================================================
    # PII entity breakdown (special — uses enkrypt.guardrail.pii_entity)
    # ============================================================
    (markdown_vis("Section: PII", markdown="### PII Entities (per-entity breakdown)"),
        "", METRICS_DATAVIEW_ID, (0, 30, 48, 2)),
    (pie_vis(
        "PII Entities by Category",
        bucket_field="metric.attributes.pii_category",
        bucket_label="Category",
        size=8,
    ),
        'name : "enkrypt.guardrail.pii_entity"', METRICS_DATAVIEW_ID, (0, 32, 16, 12)),
    (horizontal_bar_topN_vis(
        "Top PII Entity Types",
        bucket_field="metric.attributes.pii_entity_type",
        bucket_label="Entity Type",
        metric_label="Entities Found",
        size=15,
    ),
        'name : "enkrypt.guardrail.pii_entity"', METRICS_DATAVIEW_ID, (16, 32, 16, 12)),
    (kpi_metric_vis("Total PII Redactions", custom_label="Redactions"),
        'name : "enkrypt.pii.redactions"', METRICS_DATAVIEW_ID, (32, 32, 16, 12)),
    # ============================================================
    # Toxicity subtypes (toxicity has 6 subtypes: toxicity,
    # severe_toxicity, obscene, threat, insult, identity_hate)
    # ============================================================
    (markdown_vis("Section: Toxicity Subtypes", markdown="### Toxicity Subtype Distribution"),
        "", METRICS_DATAVIEW_ID, (0, 44, 48, 2)),
    (pie_vis(
        "Toxicity Subtypes",
        bucket_field="metric.attributes.detector_subtype",
        bucket_label="Subtype",
        size=8,
    ),
        'name : "enkrypt.guardrail.detector_score" and metric.attributes.detector : "toxicity"',
        METRICS_DATAVIEW_ID, (0, 46, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Toxicity Subtypes by Avg Score",
        bucket_field="metric.attributes.detector_subtype",
        bucket_label="Subtype",
        metric_label="Avg Confidence",
        size=10,
        aggregation="avg",
    ),
        'name : "enkrypt.guardrail.detector_score" and metric.attributes.detector : "toxicity"',
        METRICS_DATAVIEW_ID, (24, 46, 24, 12)),
]

# ============================================================
# Per-detector rows (11 detectors × 4 widgets each)
# Y starts at 58 and each row consumes 10 y units (2 header + 8 widget).
# ============================================================

_y = 58
for det_key, det_label in DETECTORS:
    PANEL_SPECS.extend(_detector_row(_y, det_key, det_label))
    _y += 10


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Guardrails Deep Dive",
        description=(
            "Security-analyst view mirroring the apiaas-style per-detector dashboard. "
            "11 detectors × (Count / Enabled-check Count / Time Series / Breakdown). "
            "Cross-cutting: Top Statuses, Playground Requests, Top Users, Source Events/"
            "Names, p95 latency. PII entity-type distribution. Toxicity subtype "
            "breakdown. Powered by `enkrypt.guardrail.{detector}_blocks` (per-detector) "
            "and `enkrypt.guardrail.detection` (unified) instruments."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="guardrails:",
    )


if __name__ == "__main__":
    main()
