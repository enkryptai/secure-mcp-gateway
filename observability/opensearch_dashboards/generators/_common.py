"""Shared helpers for OpenSearch Dashboards generator scripts.

All ``generate_*.py`` dashboard generators in this folder use the same set of
visualization builders + saved-object wrapping + grid layout helpers exposed
here. Keeping them in one module guarantees consistent shape across every
dashboard NDJSON we ship.

Conventions
-----------
- **Stable IDs** — Every saved object id is generated via ``stable_id(name)``
  with a fixed namespace UUID so re-imports overwrite in place rather than
  proliferating duplicates.
- **Index patterns** — Three pre-existing dataviews from
  ``saved-objects.ndjson``: ``gateway-metrics`` (time field ``time``),
  ``gateway-logs`` (time field ``time``), ``gateway-traces``
  (time field ``startTime``).
- **OSD compat** — Targets OSD 2.19 (apiaas dev). Saved objects deliberately
  omit ``migrationVersion`` because OSD 2.19 rejects newer migration versions.
- **Grid** — Layout uses a 48-column grid; each panel takes ``(x, y, w, h)``.

Public surface
--------------
``stable_id`` · ``METRICS_DATAVIEW_ID`` · ``LOGS_DATAVIEW_ID`` ·
``TRACES_DATAVIEW_ID`` · ``GRID_COLS``

Visualization builders (all return a ``visState`` dict, which
``make_viz`` then wraps into a saved-object record):

- ``kpi_metric_vis`` — single big-number metric card
- ``gauge_vis`` — single-value gauge with color ranges
- ``time_series_vis`` — line/histogram over time
- ``multi_series_time_vis`` — multiple series in one time chart (e.g. p50/p95/p99)
- ``area_vis`` — stacked area chart (e.g. blocks-by-violation-type over time)
- ``horizontal_bar_topN_vis`` — top-N horizontal bar
- ``vertical_bar_topN_vis`` — top-N vertical bar
- ``pie_vis`` — donut breakdown
- ``heatmap_vis`` — two-dim aggregation as a colored matrix
- ``data_table_vis`` — tabular top-N with multiple columns
- ``percentile_vis`` — single-number percentile (e.g. p95 of `value`)
- ``markdown_vis`` — text panel for section headers / notes

Saved-object wrappers
---------------------
- ``make_viz(title, visState, kql, *, dataview_id, description)`` — wrap
  any visState into a visualization saved object (NDJSON record).
- ``make_dashboard(title, panels, references, *, description, time_restore)``
  — build the dashboard record from a list of panels + references.

Panel layout
------------
- ``panel(idx, x, y, w, h)`` — one panel entry (gridData + ref).
- ``write_ndjson(out_path, viz_objects, dashboard_obj)`` — write the final
  NDJSON file.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Stable IDs (deterministic UUIDs from seeded strings)
# ---------------------------------------------------------------------------

_NAMESPACE = uuid.UUID("9b2c7c6c-3c4a-4c4e-8e4a-1c4e8e4a1c4e")


def stable_id(name: str) -> str:
    """Return a deterministic UUID string for the given seed name."""
    return str(uuid.uuid5(_NAMESPACE, name))


# Index pattern saved-object IDs (must match saved-objects.ndjson)
METRICS_DATAVIEW_ID = "gateway-metrics"
LOGS_DATAVIEW_ID = "gateway-logs"
TRACES_DATAVIEW_ID = "gateway-traces"

GRID_COLS = 48

# Generators live in ``observability/opensearch_dashboards/generators/`` but
# the produced NDJSON artifacts (`saved-objects.ndjson` and the per-dashboard
# files) ship in the parent ``observability/opensearch_dashboards/`` so they
# can be imported into OSD directly without anyone touching the generator
# Python. Every generator writes to this folder via:
#     out_path = DASHBOARDS_DIR / "gateway-foo-dashboard.ndjson"
DASHBOARDS_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Visualization builders — all return visState dicts
# ---------------------------------------------------------------------------


def kpi_metric_vis(
    title: str,
    *,
    aggregation: str = "sum",
    field: str = "value",
    custom_label: str | None = None,
    font_size: int = 60,
) -> dict[str, Any]:
    """Single-number metric card.

    Defaults to ``sum(value)`` which is correct for OTel counters/histograms
    (``value`` is the SS4O data-point value field). Pair with a KQL filter on
    ``name:"enkrypt.foo.bar"`` to scope to one metric instrument.
    """
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
                    "fontSize": font_size,
                },
            },
        },
    }


def percentile_vis(
    title: str,
    *,
    percentile: float = 95.0,
    field: str = "value",
    custom_label: str | None = None,
) -> dict[str, Any]:
    """Single-number percentile metric (e.g. p95 latency).

    For OTel histograms exposed as SS4O documents, the ``value`` field carries
    each data point. Percentile aggregations across many data points give a
    reasonable approximation of the underlying distribution.
    """
    return {
        "title": title,
        "type": "metric",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "percentiles",
                "params": {
                    "field": field,
                    "percents": [percentile],
                    "customLabel": custom_label or f"p{int(percentile)}",
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


def gauge_vis(
    title: str,
    *,
    aggregation: str = "sum",
    field: str = "value",
    custom_label: str | None = None,
    ranges: list[dict[str, float]] | None = None,
) -> dict[str, Any]:
    """Single-value gauge with colored ranges (good for percentages / ratios)."""
    if ranges is None:
        ranges = [
            {"from": 0, "to": 50},
            {"from": 50, "to": 80},
            {"from": 80, "to": 100},
        ]
    return {
        "title": title,
        "type": "gauge",
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
            "type": "gauge",
            "addTooltip": True,
            "addLegend": True,
            "isDisplayWarning": False,
            "gauge": {
                "alignment": "automatic",
                "extendRange": True,
                "percentageMode": False,
                "gaugeType": "Arc",
                "gaugeStyle": "Full",
                "backStyle": "Full",
                "orientation": "vertical",
                "colorSchema": "Green to Red",
                "gaugeColorMode": "Labels",
                "colorsRange": ranges,
                "invertColors": False,
                "labels": {"show": True, "color": "black"},
                "scale": {"show": True, "labels": False, "color": "#333"},
                "type": "meter",
                "style": {"bgWidth": 0.9, "width": 0.9, "mask": False, "bgMask": False, "maskBars": 50, "bgFill": "#eee", "subText": ""},
            },
        },
    }


def time_series_vis(
    title: str,
    series_label: str,
    *,
    chart_type: str = "histogram",
    aggregation: str = "sum",
    field: str = "value",
    time_field: str = "time",
) -> dict[str, Any]:
    """Bar (histogram) or line chart over time, single series."""
    return {
        "title": title,
        "type": chart_type,
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": aggregation,
                "params": {"field": field, "customLabel": series_label},
                "schema": "metric",
            },
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "params": {
                    "field": time_field,
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
        "params": _ts_params(chart_type, series_label),
    }


def multi_series_time_vis(
    title: str,
    series: list[dict[str, Any]],
    *,
    chart_type: str = "line",
    time_field: str = "time",
) -> dict[str, Any]:
    """Multi-line time chart for things like p50/p95/p99 overlays.

    Each ``series`` entry: ``{"label": "p95", "type": "percentiles", "field":
    "value", "params": {"percents": [95]}}`` OR ``{"label": "Errors", "type":
    "sum", "field": "value"}``.
    """
    aggs: list[dict[str, Any]] = []
    series_params: list[dict[str, Any]] = []
    for i, s in enumerate(series, start=1):
        agg: dict[str, Any] = {
            "id": str(i),
            "enabled": True,
            "type": s["type"],
            "params": {
                "field": s.get("field", "value"),
                "customLabel": s["label"],
                **s.get("params", {}),
            },
            "schema": "metric",
        }
        aggs.append(agg)
        series_params.append(
            {
                "show": True,
                "type": chart_type,
                "mode": "normal",
                "data": {"label": s["label"], "id": str(i)},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": chart_type == "line",
                "lineWidth": 2,
                "interpolate": "linear",
                "showCircles": chart_type == "line",
            }
        )
    aggs.append(
        {
            "id": str(len(series) + 1),
            "enabled": True,
            "type": "date_histogram",
            "params": {
                "field": time_field,
                "useNormalizedOpenSearchInterval": True,
                "scaleMetricValues": False,
                "interval": "auto",
                "drop_partials": False,
                "min_doc_count": 1,
                "extended_bounds": {},
            },
            "schema": "segment",
        }
    )
    params = _ts_params(chart_type, title)
    params["seriesParams"] = series_params
    return {"title": title, "type": chart_type, "aggs": aggs, "params": params}


def area_vis(
    title: str,
    *,
    bucket_field: str,
    bucket_label: str = "",
    chart_type: str = "area",
    size: int = 10,
    aggregation: str = "sum",
    field: str = "value",
    time_field: str = "time",
    mode: str = "stacked",
) -> dict[str, Any]:
    """Stacked area chart over time, split by a categorical (e.g. violation_type)."""
    aggs = [
        {
            "id": "1",
            "enabled": True,
            "type": aggregation,
            "params": {"field": field, "customLabel": title},
            "schema": "metric",
        },
        {
            "id": "2",
            "enabled": True,
            "type": "date_histogram",
            "params": {
                "field": time_field,
                "useNormalizedOpenSearchInterval": True,
                "scaleMetricValues": False,
                "interval": "auto",
                "drop_partials": False,
                "min_doc_count": 1,
                "extended_bounds": {},
            },
            "schema": "segment",
        },
        {
            "id": "3",
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
                "customLabel": bucket_label or bucket_field,
            },
            "schema": "group",
        },
    ]
    params = _ts_params(chart_type, title)
    params["seriesParams"] = [
        {
            "show": True,
            "type": chart_type,
            "mode": mode,
            "data": {"label": title, "id": "1"},
            "valueAxis": "ValueAxis-1",
            "drawLinesBetweenPoints": True,
            "lineWidth": 2,
            "interpolate": "linear",
            "showCircles": False,
        }
    ]
    return {"title": title, "type": chart_type, "aggs": aggs, "params": params}


def horizontal_bar_topN_vis(
    title: str,
    *,
    bucket_field: str,
    bucket_label: str,
    metric_label: str,
    size: int = 10,
    aggregation: str = "sum",
    field: str = "value",
) -> dict[str, Any]:
    """Top-N horizontal bar."""
    return {
        "title": title,
        "type": "horizontal_bar",
        "aggs": _topn_aggs(bucket_field, bucket_label, metric_label, size, aggregation, field),
        "params": _bar_params(metric_label, "horizontal"),
    }


def vertical_bar_topN_vis(
    title: str,
    *,
    bucket_field: str,
    bucket_label: str,
    metric_label: str,
    size: int = 10,
    aggregation: str = "sum",
    field: str = "value",
) -> dict[str, Any]:
    """Top-N vertical bar."""
    return {
        "title": title,
        "type": "histogram",
        "aggs": _topn_aggs(bucket_field, bucket_label, metric_label, size, aggregation, field),
        "params": _bar_params(metric_label, "vertical"),
    }


def pie_vis(
    title: str,
    *,
    bucket_field: str,
    bucket_label: str,
    size: int = 10,
    is_donut: bool = True,
    aggregation: str = "sum",
    field: str = "value",
) -> dict[str, Any]:
    """Donut/pie breakdown by a categorical field."""
    return {
        "title": title,
        "type": "pie",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": aggregation,
                "params": {"field": field, "customLabel": "Count"},
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
            "isDonut": is_donut,
            "labels": {
                "show": True,
                "values": True,
                "last_level": True,
                "truncate": 100,
            },
        },
    }


def heatmap_vis(
    title: str,
    *,
    x_field: str,
    y_field: str,
    x_size: int = 10,
    y_size: int = 10,
    aggregation: str = "sum",
    field: str = "value",
) -> dict[str, Any]:
    """Two-dimensional aggregation as a heatmap matrix."""
    return {
        "title": title,
        "type": "heatmap",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": aggregation,
                "params": {"field": field, "customLabel": "Count"},
                "schema": "metric",
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": x_field,
                    "orderBy": "1",
                    "order": "desc",
                    "size": x_size,
                    "otherBucket": False,
                    "missingBucket": False,
                },
                "schema": "segment",
            },
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": y_field,
                    "orderBy": "1",
                    "order": "desc",
                    "size": y_size,
                    "otherBucket": False,
                    "missingBucket": False,
                },
                "schema": "group",
            },
        ],
        "params": {
            "type": "heatmap",
            "addTooltip": True,
            "addLegend": True,
            "enableHover": True,
            "legendPosition": "right",
            "times": [],
            "colorsNumber": 4,
            "colorSchema": "Greens",
            "setColorRange": False,
            "colorsRange": [],
            "invertColors": False,
            "percentageMode": False,
            "valueAxes": [
                {
                    "show": False,
                    "id": "ValueAxis-1",
                    "type": "value",
                    "scale": {"type": "linear", "defaultYExtents": False},
                    "labels": {"show": False, "rotate": 0, "overwriteColor": False, "color": "black"},
                }
            ],
        },
    }


def data_table_vis(
    title: str,
    *,
    bucket_fields: list[tuple[str, str]],  # [(field, label), ...]
    size: int = 25,
    aggregation: str = "sum",
    field: str = "value",
    metric_label: str = "Count",
) -> dict[str, Any]:
    """Multi-column terms-aggregation table."""
    aggs: list[dict[str, Any]] = [
        {
            "id": "1",
            "enabled": True,
            "type": aggregation,
            "params": {"field": field, "customLabel": metric_label},
            "schema": "metric",
        }
    ]
    for i, (bf, bl) in enumerate(bucket_fields, start=2):
        aggs.append(
            {
                "id": str(i),
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": bf,
                    "orderBy": "1",
                    "order": "desc",
                    "size": size,
                    "otherBucket": False,
                    "missingBucket": False,
                    "customLabel": bl,
                },
                "schema": "bucket",
            }
        )
    return {
        "title": title,
        "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum",
        },
    }


def markdown_vis(title: str, *, markdown: str, font_size: int = 14) -> dict[str, Any]:
    """Static markdown panel — for section headers + dashboard notes."""
    return {
        "title": title,
        "type": "markdown",
        "params": {"fontSize": font_size, "openLinksInNewTab": True, "markdown": markdown},
        "aggs": [],
    }


# ---------------------------------------------------------------------------
# Shared internals
# ---------------------------------------------------------------------------


def _topn_aggs(
    bucket_field: str,
    bucket_label: str,
    metric_label: str,
    size: int,
    aggregation: str,
    field: str,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "1",
            "enabled": True,
            "type": aggregation,
            "params": {"field": field, "customLabel": metric_label},
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
    ]


def _bar_params(metric_label: str, orientation: str) -> dict[str, Any]:
    if orientation == "horizontal":
        cat_pos, val_pos, rotate = "left", "bottom", 75
    else:
        cat_pos, val_pos, rotate = "bottom", "left", 0
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": cat_pos,
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
                "name": f"{val_pos.title()}Axis-1",
                "type": "value",
                "position": val_pos,
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": rotate, "filter": False, "truncate": 100},
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
    }


def _ts_params(chart_type: str, label: str) -> dict[str, Any]:
    return {
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
                "title": {"text": label},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": chart_type,
                "mode": "normal",
                "data": {"label": label, "id": "1"},
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
    }


# ---------------------------------------------------------------------------
# Saved-object wrappers
# ---------------------------------------------------------------------------


def make_viz(
    title: str,
    visState: dict[str, Any],
    kql: str,
    *,
    dataview_id: str = METRICS_DATAVIEW_ID,
    description: str = "",
    id_prefix: str = "",
) -> dict[str, Any]:
    """Wrap a visState dict into a full visualization saved object."""
    obj_id = stable_id(f"viz:{id_prefix}{title}")
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
                "id": dataview_id,
            }
        ],
    }


def panel_entry(idx: int, x: int, y: int, w: int, h: int) -> dict[str, Any]:
    """Build a dashboard ``panelsJSON`` entry."""
    return {
        "version": "1",
        "gridData": {"h": h, "i": str(idx), "w": w, "x": x, "y": y},
        "panelIndex": str(idx),
        "embeddableConfig": {},
        "panelRefName": f"panel_{idx}",
    }


def make_dashboard(
    title: str,
    panels: list[dict[str, Any]],
    references: list[dict[str, Any]],
    *,
    description: str = "",
    time_restore: bool = False,
) -> dict[str, Any]:
    """Assemble the dashboard saved object."""
    return {
        "id": stable_id(f"dashboard:{title}"),
        "type": "dashboard",
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": json.dumps(panels, separators=(",", ":")),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            "timeRestore": time_restore,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                ),
            },
        },
        "references": references,
    }


def write_ndjson(
    out_path: Path,
    viz_objects: list[dict[str, Any]],
    dashboard_obj: dict[str, Any],
) -> None:
    """Write a dashboard NDJSON file (viz objects first, dashboard last)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for obj in viz_objects:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
        f.write(json.dumps(dashboard_obj, separators=(",", ":")) + "\n")


def build_dashboard_ndjson(
    *,
    out_path: Path,
    title: str,
    description: str,
    panel_specs: list[tuple[dict[str, Any], str, str, tuple[int, int, int, int]]],
    id_prefix: str = "",
) -> None:
    """High-level helper: take ``[(visState, kql, dataview_id, (x,y,w,h))]``
    and emit a complete NDJSON dashboard.

    Generators that don't need fine control over the build loop call this and
    are done in one line per dashboard.
    """
    viz_objects: list[dict[str, Any]] = []
    panel_objects: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    for idx, (vs, kql, dv, (x, y, w, h)) in enumerate(panel_specs, start=1):
        # include `idx` in the id_prefix so two panels with the same title
        # (e.g. several "Section: Errors" markdown headers, or "{detector}
        # Count" KPI cards repeated per detector) get distinct stable IDs.
        per_panel_prefix = f"{id_prefix}{idx:03d}:"
        viz_obj = make_viz(vs["title"], vs, kql, dataview_id=dv, id_prefix=per_panel_prefix)
        viz_objects.append(viz_obj)
        panel_objects.append(panel_entry(idx, x, y, w, h))
        references.append({"name": f"panel_{idx}", "type": "visualization", "id": viz_obj["id"]})
    dashboard_obj = make_dashboard(title, panel_objects, references, description=description)
    write_ndjson(out_path, viz_objects, dashboard_obj)
    print(f"wrote {out_path} ({len(viz_objects)} visualizations + 1 dashboard, {out_path.stat().st_size} bytes)")
