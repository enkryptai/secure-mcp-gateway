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
    """One row of 4 widgets per detector (Count / Total checks / Time Series / Breakdown).

    Data shape: the gateway emits ONE metric `enkrypt.guardrail.blocks` with the
    detector identity stored in `metric.attributes.violation_type` ("nsfw",
    "injection_attack", "policy_violation", ...). Per-detector widgets therefore
    filter the unified counter by violation_type rather than reading separate
    per-detector metrics.

    The "Total checks" widget shows the unified `enkrypt.guardrail.checks`
    counter (which doesn't carry a violation_type attribute -- it counts the
    whole guardrail-call envelope, not per detector). So it's identical across
    detector rows. Kept as a calibration baseline against blocks: the ratio
    of {detector}_blocks / total_checks is the per-detector hit rate.
    """
    # Filter clause that selects this detector's blocks from the unified counter.
    blocks_filter = (
        f'name : "enkrypt.guardrail.blocks" '
        f'and metric.attributes.violation_type : "{det_key}"'
    )
    return [
        (markdown_vis(
            f"Section: {det_label}",
            markdown=f"#### {det_label} (`violation_type:{det_key}`)",
        ), "", METRICS_DATAVIEW_ID, (0, y_start, 48, 2)),
        # Count -- per-detector block count via violation_type filter
        (kpi_metric_vis(f"{det_label} Count", custom_label="Blocks"),
            blocks_filter,
            METRICS_DATAVIEW_ID, (0, y_start + 2, 8, 8)),
        # Total guardrail checks (envelope-level, same across detectors).
        # Useful as a calibration baseline -- (this row's Blocks) / (Total checks)
        # = the per-detector trigger rate for the current time window.
        (kpi_metric_vis(
            f"{det_label} Checks (Total)",
            custom_label="Total checks",
        ),
            'name : "enkrypt.guardrail.checks"',
            METRICS_DATAVIEW_ID, (8, y_start + 2, 8, 8)),
        # Time series -- same per-detector filter
        (time_series_vis(f"{det_label} Blocks Over Time", "Blocks", chart_type="histogram"),
            blocks_filter,
            METRICS_DATAVIEW_ID, (16, y_start + 2, 16, 8)),
        # Breakdown -- per-detector blocks split by direction / project / server
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
            blocks_filter,
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
            "Per-detector activity for the 11 Enkrypt guardrail detectors. Each "
            "row shows: total blocks, total guardrail-checks (baseline for "
            "trigger rate = blocks/checks), blocks over time, and a breakdown "
            "by direction × project × server. Top-level widgets cross-cut all "
            "detectors. Powered by the unified `enkrypt.guardrail.blocks` "
            "counter filtered by `metric.attributes.violation_type` (one of: "
            "nsfw, toxicity, pii, injection_attack, keyword_detector, "
            "policy_violation, bias, sponge_attack, copyright_ip, "
            "system_prompt, topic_detector) and the envelope-level "
            "`enkrypt.guardrail.checks` counter for total-checks calibration."
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
    # Gateway doesn't emit `source_event` / `source_name`. Repurpose to two
    # attributes that DO exist on enkrypt.guardrail.checks and are useful for
    # the demo: direction (input vs output) and target server.
    (horizontal_bar_topN_vis(
        "Checks by Direction (input/output)",
        bucket_field="metric.attributes.direction",
        bucket_label="Direction",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (0, 18, 16, 12)),
    (horizontal_bar_topN_vis(
        "Top Servers (guardrail activity)",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
        metric_label="Calls",
        size=10,
    ),
        'name : "enkrypt.guardrail.checks"', METRICS_DATAVIEW_ID, (16, 18, 16, 12)),
    # enkrypt.guardrail.duration is an OTel HISTOGRAM metric.  SS4O stores
    # the per-export-interval sum/count as top-level scalar fields (`sum`,
    # `count`); the `buckets[]` array is the histogram bins themselves.
    # OSD's percentile aggregation needs a per-document numeric field --
    # `value` doesn't exist on histograms, so the p95 widget could never
    # render anything.  Show average per-window latency instead, which
    # approximates per-call latency cleanly when concurrent calls within
    # an export interval are rare (the common case for guardrail traffic).
    (kpi_metric_vis(
        "Guardrail Latency (avg)",
        aggregation="avg",
        field="sum",
        custom_label="Avg duration (s)",
    ),
        'name : "enkrypt.guardrail.duration"', METRICS_DATAVIEW_ID, (32, 18, 16, 12)),
    # ============================================================
    # PII entity breakdown -- backed by enkrypt.guardrail.pii_entity.
    # Each violation of type "pii" expands into one increment per
    # detected entity, with metric.attributes.entity_type carrying the
    # entity label (EMAIL, PHONE, SSN, CREDIT_CARD, ...).  The
    # gateway never emits a pii_category attribute, so the original
    # "PII Entities by Category" panel was always empty -- replaced
    # with a per-direction (input vs output) breakdown that uses
    # signal we actually emit.
    # ============================================================
    (markdown_vis("Section: PII", markdown="### PII Entities (per-entity breakdown)"),
        "", METRICS_DATAVIEW_ID, (0, 30, 48, 2)),
    (pie_vis(
        "PII Entities by Direction",
        bucket_field="metric.attributes.direction",
        bucket_label="Direction",
        size=4,
    ),
        'name : "enkrypt.guardrail.pii_entity"', METRICS_DATAVIEW_ID, (0, 32, 16, 12)),
    (horizontal_bar_topN_vis(
        "Top PII Entity Types",
        bucket_field="metric.attributes.entity_type",
        bucket_label="Entity Type",
        metric_label="Entities Found",
        size=15,
    ),
        'name : "enkrypt.guardrail.pii_entity"', METRICS_DATAVIEW_ID, (16, 32, 16, 12)),
    (kpi_metric_vis("Total PII Redactions", custom_label="Redactions"),
        'name : "enkrypt.pii.redactions"', METRICS_DATAVIEW_ID, (32, 32, 16, 12)),
    # ============================================================
    # Toxicity subtypes -- backed by enkrypt.guardrail.toxicity_subtype.
    # The Enkrypt toxicity detector returns per-subtype scores in its
    # details payload (toxicity, severe_toxicity, obscene, threat,
    # insult, identity_hate); we threshold-gate at 0.5 and emit one
    # increment per subtype that crossed.  metric.attributes carries
    # ``subtype`` (the subtype name) and ``score_bucket`` (low|medium|
    # high coarsened from the raw 0..1 score).
    # ============================================================
    (markdown_vis("Section: Toxicity Subtypes", markdown="### Toxicity Subtype Distribution"),
        "", METRICS_DATAVIEW_ID, (0, 44, 48, 2)),
    (pie_vis(
        "Toxicity Subtypes",
        bucket_field="metric.attributes.subtype",
        bucket_label="Subtype",
        size=8,
    ),
        'name : "enkrypt.guardrail.toxicity_subtype"',
        METRICS_DATAVIEW_ID, (0, 46, 24, 12)),
    (horizontal_bar_topN_vis(
        "Top Toxicity Subtypes by Score Bucket",
        bucket_field="metric.attributes.subtype",
        bucket_label="Subtype",
        metric_label="High-Bucket Hits",
        size=10,
        # Filter to score_bucket="high" inside the KQL below so the bar
        # length is the count of subtypes that fired at high confidence.
        # Sum aggregation (default) on `value` matches the SS4O counter
        # convention used everywhere else in this dashboard.
    ),
        'name : "enkrypt.guardrail.toxicity_subtype" and metric.attributes.score_bucket : "high"',
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
            "11 detectors × (Count / Total checks / Time Series / Breakdown). "
            "Cross-cutting: Top Statuses, Playground Requests, Top Users, Checks-by-"
            "Direction, Top Servers, p95 latency. PII entity-type distribution. "
            "Toxicity subtype breakdown. Powered by the unified `enkrypt.guardrail.blocks` "
            "counter filtered by `metric.attributes.violation_type` and the envelope-level "
            "`enkrypt.guardrail.checks` counter."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="guardrails:",
    )


if __name__ == "__main__":
    main()
