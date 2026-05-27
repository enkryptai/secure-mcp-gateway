"""Regenerate ``gateway-overview-dashboard.ndjson`` (next to this script).

Builds the "Secure MCP Gateway - Overview" dashboard:

- 5 KPI cards (single big numbers, inspired by the apiaas Guardrails
  dashboard + the gateway Figma analytics row)
- 2 time-series (Tool Calls / Tools Blocked)
- 2 direction time-series (Input / Output guardrail blocks)
- 2 top-N user breakdowns (Active users / Users by violations)
- 2 top-N entity breakdowns (Servers / Tools)
- 1 pie (Violation type distribution)

Total: 14 visualizations + 1 dashboard.

All viz reference the ``gateway-metrics`` index pattern (already created in
OSD on first ingest by the SS4O metrics data stream).

Usage::

    python observability/opensearch_dashboards/generate_overview.py

To add a new panel, append one entry to ``PANELS`` and one matching
``(x, y, w, h)`` tuple to ``layout`` in :func:`main`. The script regenerates
the NDJSON with stable UUIDs (so re-import overwrites in place rather than
creating duplicates).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------------
# Stable IDs so re-runs don't churn (deterministic UUIDs from seeded strings)
# -------------------------------------------------------------------------

NAMESPACE = uuid.UUID("9b2c7c6c-3c4a-4c4e-8e4a-1c4e8e4a1c4e")


def stable_id(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))


# Existing data view from gateway-dashboards.ndjson (gateway-metrics index pattern)
METRICS_DATAVIEW_ID = "gateway-metrics"


# -------------------------------------------------------------------------
# Vis-state generators
# -------------------------------------------------------------------------

def kpi_metric_vis(
    title: str,
    metric_name_query: str,
    aggregation: str = "sum",
    field: str = "value",
    custom_label: str | None = None,
) -> dict[str, Any]:
    """Single-number metric card."""
    return {
        "title": title,
        "type": "metric",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": aggregation,
                "params": {
                    "field": field,
                    "customLabel": custom_label or title,
                },
                "schema": "metric",
            }
        ],
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": "",
                    "fontSize": 60,
                },
            },
        },
    }


def time_series_vis(
    title: str,
    metric_name_query: str,
    series_label: str,
    color: str = "#54B399",  # green default
    chart_type: str = "histogram",  # histogram | line
) -> dict[str, Any]:
    """Bar (histogram) or line chart over time."""
    return {
        "title": title,
        "type": chart_type,
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "sum",
                "params": {
                    "field": "value",
                    "customLabel": series_label,
                },
                "schema": "metric",
            },
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "params": {
                    "field": "time",
                    "useNormalizedOpenSearchInterval": True,
                    "scaleMetricValues": False,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {},
                },
                "schema": "segment",
            },
        ],
        "params": {
            "type": chart_type,
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "filter": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": series_label},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": chart_type,
                    "mode": "normal" if chart_type == "histogram" else "normal",
                    "data": {"label": series_label, "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": chart_type == "line",
                    "lineWidth": 2,
                    "interpolate": "linear",
                    "showCircles": False,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "top",
            "times": [],
            "addTimeMarker": False,
        },
    }


def horizontal_bar_topN_vis(
    title: str,
    bucket_field: str,
    bucket_label: str,
    metric_label: str,
    size: int = 5,
) -> dict[str, Any]:
    """Top-N horizontal bar (terms agg)."""
    return {
        "title": title,
        "type": "horizontal_bar",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "sum",
                "params": {
                    "field": "value",
                    "customLabel": metric_label,
                },
                "schema": "metric",
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": bucket_field,
                    "orderBy": "1",
                    "order": "desc",
                    "size": size,
                    "otherBucket": False,
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                    "customLabel": bucket_label,
                },
                "schema": "segment",
            },
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "filter": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "BottomAxis-1",
                    "type": "value",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 75, "filter": False, "truncate": 100},
                    "title": {"text": metric_label},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "normal",
                    "data": {"label": metric_label, "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": False,
                    "lineWidth": 2,
                    "interpolate": "linear",
                    "showCircles": False,
                }
            ],
            "addTooltip": True,
            "addLegend": False,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
    }


def pie_vis(title: str, bucket_field: str, bucket_label: str, size: int = 10) -> dict[str, Any]:
    return {
        "title": title,
        "type": "pie",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "sum",
                "params": {"field": "value", "customLabel": "Count"},
                "schema": "metric",
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": bucket_field,
                    "orderBy": "1",
                    "order": "desc",
                    "size": size,
                    "otherBucket": True,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "customLabel": bucket_label,
                },
                "schema": "segment",
            },
        ],
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {
                "show": True,
                "values": True,
                "last_level": True,
                "truncate": 100,
            },
        },
    }


# -------------------------------------------------------------------------
# Wrap visState into a saved-object NDJSON record + name-filter (KQL)
# -------------------------------------------------------------------------

def make_viz(
    title: str,
    visState: dict[str, Any],
    kql: str,
    description: str = "",
) -> dict[str, Any]:
    """Wrap a visState dict into a full visualization saved-object."""
    obj_id = stable_id(f"viz:{title}")
    search_source = {
        "query": {"query": kql, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    return {
        "id": obj_id,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(visState, separators=(",", ":")),
            "uiStateJSON": "{}",
            "description": description,
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source, separators=(",", ":")),
            },
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": METRICS_DATAVIEW_ID,
            }
        ],
    }


# -------------------------------------------------------------------------
# Panel layout (grid: 48 cols wide; each row's panels share a y-row)
# -------------------------------------------------------------------------

GRID_COLS = 48


def panel(viz_id: str, x: int, y: int, w: int, h: int, idx: int) -> dict[str, Any]:
    return {
        "version": "7.10.0",
        "gridData": {"h": h, "i": str(idx), "w": w, "x": x, "y": y},
        "panelIndex": str(idx),
        "embeddableConfig": {},
        "panelRefName": f"panel_{idx}",
    }


# -------------------------------------------------------------------------
# Panel specs
# -------------------------------------------------------------------------

PANELS: list[tuple[dict, str]] = [
    # Row 1: 5 KPI cards
    (kpi_metric_vis("Total Tool Calls", "enkrypt.tool.calls", custom_label="Tool Calls"),
     'name : "enkrypt.tool.calls"'),
    (kpi_metric_vis("Total Tool Failures", "enkrypt.tool.errors", custom_label="Failures"),
     'name : "enkrypt.tool.errors"'),
    (kpi_metric_vis("Total Blocked", "enkrypt.tool.blocked", custom_label="Blocked"),
     'name : "enkrypt.tool.blocked"'),
    (kpi_metric_vis("Total Guardrail Blocks", "enkrypt.guardrail.blocks", custom_label="Blocks"),
     'name : "enkrypt.guardrail.blocks"'),
    (kpi_metric_vis("Total PII Redactions", "enkrypt.pii.redactions", custom_label="Redactions"),
     'name : "enkrypt.pii.redactions"'),

    # Row 2: tool calls + blocked over time
    (time_series_vis("Total Tool Calls Over Time", "enkrypt.tool.calls", "Tool Calls", chart_type="histogram"),
     'name : "enkrypt.tool.calls"'),
    (time_series_vis("Tools Blocked Over Time", "enkrypt.tool.blocked", "Blocked", chart_type="histogram"),
     'name : "enkrypt.tool.blocked"'),

    # Row 3: input/output direction split (use directional counters directly --
    # they have no `direction` attr to filter; the split is baked into the
    # metric name).
    (time_series_vis("Input Guardrail Violations Over Time", "enkrypt.guardrail.input_blocks", "Input Violations", chart_type="histogram"),
     'name : "enkrypt.guardrail.input_blocks"'),
    (time_series_vis("Output Guardrail Violations Over Time", "enkrypt.guardrail.output_blocks", "Output Violations", chart_type="histogram"),
     'name : "enkrypt.guardrail.output_blocks"'),

    # Row 4: top users
    (horizontal_bar_topN_vis("Top 5 Active Users (by tool calls)", "metric.attributes.user_email", "User Email", "Tool Calls", size=5),
     'name : "enkrypt.tool.calls"'),
    (horizontal_bar_topN_vis("Top 5 Users by Violations", "metric.attributes.user_email", "User Email", "Violations", size=5),
     'name : "enkrypt.guardrail.blocks"'),

    # Row 5: top servers / tools / block reasons
    (horizontal_bar_topN_vis("Top Servers (by tool calls)", "metric.attributes.server_name", "Server", "Tool Calls", size=10),
     'name : "enkrypt.tool.calls"'),
    (horizontal_bar_topN_vis("Top Tools (by tool calls)", "metric.attributes.tool_name", "Tool", "Tool Calls", size=10),
     'name : "enkrypt.tool.success"'),
    (pie_vis("Violation Types Distribution", "metric.attributes.violation_type", "Violation", size=10),
     'name : "enkrypt.guardrail.blocks"'),
]


# -------------------------------------------------------------------------
# Build dashboard
# -------------------------------------------------------------------------

def main() -> None:
    # Always write next to this script so the path works regardless of cwd.
    out_path = Path(__file__).resolve().parent / "gateway-overview-dashboard.ndjson"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    viz_objects: list[dict] = []
    panel_objects: list[dict] = []
    references: list[dict] = []

    # Layout: 5 cards row (each w=9 or 12, h=8) + ts rows (w=24 each, h=12)
    layout = [
        # idx -> (x, y, w, h)
        (0,  0, 9, 8),  (9,  0, 9, 8), (18, 0, 9, 8), (27, 0, 9, 8), (36, 0, 12, 8),     # 5 KPI cards
        (0,  8, 24, 12),(24, 8, 24, 12),                                                  # 2 ts
        (0, 20, 24, 12),(24, 20, 24, 12),                                                 # 2 direction ts
        (0, 32, 24, 12),(24, 32, 24, 12),                                                 # 2 user bars
        (0, 44, 16, 12),(16, 44, 16, 12),(32, 44, 16, 12),                                # server / tool / violations
    ]
    assert len(layout) == len(PANELS), f"layout has {len(layout)} but PANELS has {len(PANELS)}"

    for idx, ((vis_state, kql), (x, y, w, h)) in enumerate(zip(PANELS, layout), start=1):
        title = vis_state["title"]
        viz_obj = make_viz(title, vis_state, kql)
        viz_objects.append(viz_obj)

        panel_objects.append({
            "version": "1",
            "gridData": {"h": h, "i": str(idx), "w": w, "x": x, "y": y},
            "panelIndex": str(idx),
            "embeddableConfig": {},
            "panelRefName": f"panel_{idx}",
        })
        references.append({
            "name": f"panel_{idx}",
            "type": "visualization",
            "id": viz_obj["id"],
        })

    dashboard_id = stable_id("dashboard:Secure MCP Gateway - Overview")
    dashboard_obj = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": "Secure MCP Gateway - Overview",
            "description": (
                "High-signal KPIs + breakdowns for the gateway. Built on the "
                "snake_case identity convention; pivots include user_email, "
                "server_name, tool_name, violation_type."
            ),
            "panelsJSON": json.dumps(panel_objects, separators=(",", ":")),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []}),
            },
        },
        "references": references,
    }

    with out_path.open("w", encoding="utf-8") as f:
        for obj in viz_objects:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
        f.write(json.dumps(dashboard_obj, separators=(",", ":")) + "\n")

    print(f"wrote {out_path} ({len(viz_objects)} visualizations + 1 dashboard)")
    print(f"file size: {out_path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
