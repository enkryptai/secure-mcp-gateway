"""Regenerate ``saved-objects.ndjson`` with full field lists for every gateway
index pattern.

OpenSearch Dashboards builds the dropdown of available fields per index
pattern from OS's ``_field_caps`` API, which only returns fields **present in
at least one document**. So with ``dynamic: false`` templates, a field that is
*declared* in the template but never *emitted* by the gateway shows up as
``"Could not locate that index-pattern-field"`` in every widget that
references it.

This script reads each of the three gateway templates and bakes the full,
declared field list into the saved index-pattern's ``attributes.fields``
JSON string. After re-importing ``saved-objects.ndjson`` into OSD, every
declared field is searchable/aggregatable in the OSD UI immediately --
widgets render without the "field not found" error even before any
matching document exists.

Notes:

- Re-run this any time you change a template (then ``local-test.ps1``
  imports the updated file).
- The shipping field list is deterministic (sorted by name) so re-imports
  overwrite cleanly.
"""

from __future__ import annotations

import json
from pathlib import Path
from _common import DASHBOARDS_DIR
from typing import Any

REPO = Path(__file__).resolve().parents[3]
TEMPLATES_DIR = REPO / "observability" / "opensearch" / "templates"
OUT_PATH = DASHBOARDS_DIR / "saved-objects.ndjson"

# Mapping from OS `type` -> OSD field `type`
_OS_TO_OSD_TYPE = {
    "keyword":     "string",
    "text":        "string",
    "long":        "number",
    "integer":     "number",
    "short":       "number",
    "byte":        "number",
    "double":      "number",
    "float":       "number",
    "half_float":  "number",
    "scaled_float": "number",
    "boolean":     "boolean",
    "date":        "date",
    "date_nanos":  "date",
    "ip":          "ip",
    "geo_point":   "geo_point",
    "geo_shape":   "geo_shape",
    "nested":      "nested",
    "object":      "object",
}

# Three patterns declared in the legacy saved-objects.ndjson.
INDEX_PATTERNS = [
    {
        "id":           "gateway-metrics",
        "title":        "gateway-metrics",
        "time_field":   "time",
        "template":     "gateway-metrics-elastic-template.json",
    },
    {
        "id":           "gateway-logs",
        "title":        "gateway-logs",
        "time_field":   "time",
        "template":     "gateway-logs-elastic-template.json",
    },
    {
        "id":           "gateway-traces",
        "title":        "gateway-traces",
        "time_field":   "startTime",
        "template":     "gateway-traces-elastic-template.json",
    },
]

# Extra patterns we want to keep in saved-objects.ndjson but don't need
# template-based field lists for (OSD falls back to _field_caps for these).
EXTRA_PATTERNS = [
    {
        "id":         "ss4o_traces-gateway-pattern",
        "title":      "ss4o_traces-gateway*",
        "time_field": "startTime",
    },
    {
        "id":         "otel-v1-apm-service-map",
        "title":      "otel-v1-apm-service-map*",
        "time_field": None,
    },
]


def _walk_properties(
    properties: dict[str, Any],
    prefix: str = "",
    out: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Walk a template's ``properties`` block recursively into a flat field list."""
    if out is None:
        out = []
    for name, spec in properties.items():
        full = f"{prefix}{name}" if not prefix else f"{prefix}.{name}"
        os_type = spec.get("type")
        if os_type == "nested":
            # Nested fields: OSD lists them with their own type and recurses
            # into the nested properties as separate entries `parent.child`.
            out.append(_field_entry(full, "nested"))
            for sub_name, sub_spec in spec.get("properties", {}).items():
                _walk_properties({sub_name: sub_spec}, prefix=full, out=out)
            continue
        if os_type is None:
            # Could be a `properties`-only object (no explicit `type`). Recurse.
            sub_props = spec.get("properties")
            if isinstance(sub_props, dict):
                _walk_properties(sub_props, prefix=full, out=out)
            continue
        osd_type = _OS_TO_OSD_TYPE.get(os_type, "string")
        out.append(_field_entry(full, osd_type, es_type=os_type))
        # Sub-keyword fields on `text` (e.g. `body.keyword`)
        for sub_name, sub_spec in (spec.get("fields") or {}).items():
            sub_os_type = sub_spec.get("type", "keyword")
            sub_osd_type = _OS_TO_OSD_TYPE.get(sub_os_type, "string")
            out.append(_field_entry(f"{full}.{sub_name}", sub_osd_type, es_type=sub_os_type))
    return out


def _field_entry(name: str, osd_type: str, *, es_type: str | None = None) -> dict[str, Any]:
    """OSD index-pattern field record. Mirrors what OSD writes itself."""
    entry: dict[str, Any] = {
        "name": name,
        "type": osd_type,
        "searchable": True,
        "aggregatable": osd_type not in {"object"} and osd_type != "text",
        "readFromDocValues": osd_type not in {"text", "nested", "object"},
        "count": 0,
    }
    if es_type:
        entry["esTypes"] = [es_type]
    return entry


def _meta_fields() -> list[dict[str, Any]]:
    """Standard OS/Lucene metadata fields OSD always wants present."""
    return [
        _field_entry("_id", "string"),
        _field_entry("_index", "string"),
        _field_entry("_score", "number"),
        _field_entry("_source", "_source"),
        _field_entry("_type", "string"),
    ]


def build_pattern_object(*, id: str, title: str, time_field: str | None, fields_json: str | None) -> dict[str, Any]:
    """Build one index-pattern saved object record."""
    attributes: dict[str, Any] = {"title": title}
    if time_field:
        attributes["timeFieldName"] = time_field
    if fields_json:
        attributes["fields"] = fields_json
    return {
        "type": "index-pattern",
        "id": id,
        "attributes": attributes,
        "references": [],
        "migrationVersion": {"index-pattern": "7.6.0"},
    }


def extract_fields_for_template(template_name: str) -> list[dict[str, Any]]:
    path = TEMPLATES_DIR / template_name
    template = json.loads(path.read_text(encoding="utf-8"))
    properties = (
        template.get("template", {})
                .get("mappings", {})
                .get("properties", {})
    )
    fields = _walk_properties(properties)
    fields.extend(_meta_fields())
    # OSD likes the list sorted by name for stable rendering.
    fields.sort(key=lambda f: f["name"])
    # Dedupe (in case template lists same field twice).
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for f in fields:
        if f["name"] in seen:
            continue
        seen.add(f["name"])
        deduped.append(f)
    return deduped


def main() -> None:
    lines: list[str] = []

    for pat in INDEX_PATTERNS:
        fields = extract_fields_for_template(pat["template"])
        fields_json = json.dumps(fields, separators=(",", ":"))
        obj = build_pattern_object(
            id=pat["id"],
            title=pat["title"],
            time_field=pat["time_field"],
            fields_json=fields_json,
        )
        lines.append(json.dumps(obj, separators=(",", ":")))
        print(f"  {pat['id']:<35} {len(fields):>4} fields baked in ({pat['template']})")

    for pat in EXTRA_PATTERNS:
        obj = build_pattern_object(
            id=pat["id"],
            title=pat["title"],
            time_field=pat["time_field"],
            fields_json=None,
        )
        lines.append(json.dumps(obj, separators=(",", ":")))
        print(f"  {pat['id']:<35}   (no template; OSD will discover fields from _field_caps)")

    # Default-index config record (same as the existing saved-objects.ndjson).
    lines.append(json.dumps(
        {
            "type": "config",
            "id": "2.19.1",
            "attributes": {"buildNum": 8312, "defaultIndex": "gateway-metrics"},
            "migrationVersion": {"config": "7.9.0"},
        },
        separators=(",", ":"),
    ))

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {OUT_PATH}  ({len(lines)} saved objects, {OUT_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
