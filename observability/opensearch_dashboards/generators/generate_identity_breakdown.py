"""Regenerate ``gateway-identity-breakdown-dashboard.ndjson``.

"Identity Breakdown" dashboard -- compact 6-up grid that slices the same
metric (``enkrypt.tool.success``) by every identity dimension the gateway
emits as a label.  Useful for the question "which {gateway, org, project,
user, server, tool} is doing the most work / generating the most blocks?"
without having to apply a separate filter.

History
-------
Replaces an early-prototype dashboard (created 2026-05-25, deleted
2026-06-03) that hard-coded the now-defunct
``metric.attributes.enkrypt@gateway@name`` field-name convention.  The
SS4O schema migration moved those attributes to ``metric.attributes.<x>``
in snake_case form (``gateway_name``, ``org_id``, ``project_name``,
``user_email``, ``server_name``, ``tool_name``).  This file regenerates
the dashboard against the current schema, programmatically so it stays
in lockstep with future template changes.

Identity dimensions
-------------------
Every panel groups ``enkrypt.tool.success`` (the reliable per-invocation
counter -- see also ``generate_overview.py`` for the same rationale) by
one of six dimensions:

  1. ``metric.attributes.gateway_name`` -- which gateway deployment is
     handling traffic (multi-gateway tenants will show >1 bar here).
  2. ``metric.attributes.org_id`` -- top-of-hierarchy isolation unit.
  3. ``metric.attributes.project_name`` -- friendly project label.
  4. ``metric.attributes.user_email`` -- principal that authenticated.
     ``user_email`` is intentionally preferred over ``user_id`` for
     display (more legible in a bar chart); user_id is still available
     for filter pinning via the OSD filter bar.
  5. ``metric.attributes.server_name`` -- downstream MCP server.
  6. ``metric.attributes.tool_name`` -- the specific tool that ran.

To zoom into one slice (e.g. one project), pin the filter bar at the
top of the dashboard; the panels honor it via standard OSD filter
propagation.
"""

from __future__ import annotations

from _common import (
    DASHBOARDS_DIR,
    METRICS_DATAVIEW_ID,
    build_dashboard_ndjson,
    horizontal_bar_topN_vis,
    markdown_vis,
)

OUT = DASHBOARDS_DIR / "gateway-identity-breakdown-dashboard.ndjson"


# Single counter, six identity pivots.  All panels share the same KQL
# filter so the OSD time picker and any pinned filter apply uniformly.
_METRIC = "enkrypt.tool.success"
_KQL = f'name : "{_METRIC}"'


def _id_panel(title: str, bucket_field: str, bucket_label: str) -> dict:
    """Build a Top-10 horizontal-bar visualization for one identity
    pivot.  Centralised so all six panels stay in sync."""
    return horizontal_bar_topN_vis(
        title,
        bucket_field=bucket_field,
        bucket_label=bucket_label,
        metric_label="Tool Calls",
        size=10,
    )


# 6 panels in a 3x2 grid.  Each cell: width 24 (half-row), height 12.
PANEL_SPECS = [
    (markdown_vis(
        "Header",
        markdown=(
            "## Secure MCP Gateway -- Identity Breakdown\n\n"
            "Top-10 successful tool calls grouped by each identity dimension. "
            f"All six panels query `{_METRIC}` and apply the dashboard's "
            "filter bar uniformly -- pin "
            "`metric.attributes.project_name : \"X\"` (or any other identity "
            "attribute) to drill into a single slice."
        ),
    ), "", METRICS_DATAVIEW_ID, (0, 0, 48, 4)),

    # Row 1: Gateway / Org
    (_id_panel(
        "Tool Calls by Gateway",
        bucket_field="metric.attributes.gateway_name",
        bucket_label="Gateway",
    ), _KQL, METRICS_DATAVIEW_ID, (0, 4, 24, 12)),
    (_id_panel(
        "Tool Calls by Org",
        bucket_field="metric.attributes.org_id",
        bucket_label="Org ID",
    ), _KQL, METRICS_DATAVIEW_ID, (24, 4, 24, 12)),

    # Row 2: Project / User
    (_id_panel(
        "Tool Calls by Project",
        bucket_field="metric.attributes.project_name",
        bucket_label="Project",
    ), _KQL, METRICS_DATAVIEW_ID, (0, 16, 24, 12)),
    (_id_panel(
        "Tool Calls by User",
        bucket_field="metric.attributes.user_email",
        bucket_label="User Email",
    ), _KQL, METRICS_DATAVIEW_ID, (24, 16, 24, 12)),

    # Row 3: Server / Tool
    (_id_panel(
        "Tool Calls by Server",
        bucket_field="metric.attributes.server_name",
        bucket_label="Server",
    ), _KQL, METRICS_DATAVIEW_ID, (0, 28, 24, 12)),
    (_id_panel(
        "Tool Calls by Tool",
        bucket_field="metric.attributes.tool_name",
        bucket_label="Tool",
    ), _KQL, METRICS_DATAVIEW_ID, (24, 28, 24, 12)),
]


def main() -> None:
    build_dashboard_ndjson(
        out_path=OUT,
        title="Secure MCP Gateway - Identity Breakdown",
        description=(
            "Per-identity tool-call breakdowns across the 6 dimensions the "
            "gateway labels every enkrypt.tool.success event with: "
            "gateway_name, org_id, project_name, user_email, server_name, "
            "tool_name. Apply a KQL filter at the dashboard level (e.g. "
            "metric.attributes.project_name : \"X\") to scope all panels to "
            "one identity slice. Replaces a 2026-05-25 prototype that used "
            "the obsolete metric.attributes.enkrypt@gateway@name field-name "
            "convention; the SS4O migration moved those to snake_case."
        ),
        panel_specs=PANEL_SPECS,
        id_prefix="identity:",
    )


if __name__ == "__main__":
    main()
