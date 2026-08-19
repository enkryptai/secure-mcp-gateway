"""One-off audit: report dashboard widgets that reference a field not declared
in the index template they target.

Run::

    python observability/opensearch_dashboards/_audit_fields.py

Exits non-zero if any mismatch is found.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TPL = REPO / "observability" / "opensearch" / "templates"
GEN_DIR = Path(__file__).resolve().parent


def load_fields(path: Path) -> set[str]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return set(obj["template"]["mappings"]["properties"].keys())


METRICS = load_fields(TPL / "gateway-metrics-elastic-template.json")
LOGS = load_fields(TPL / "gateway-logs-elastic-template.json")
TRACES = load_fields(TPL / "gateway-traces-elastic-template.json")

DV = {
    "METRICS_DATAVIEW_ID": METRICS,
    "LOGS_DATAVIEW_ID": LOGS,
    "TRACES_DATAVIEW_ID": TRACES,
}

PANEL_LINE_RE = re.compile(r",\s*(METRICS_DATAVIEW_ID|LOGS_DATAVIEW_ID|TRACES_DATAVIEW_ID)\s*,")
FIELD_KWARG_RE = re.compile(
    r'(?:bucket_field|field|x_field|y_field)\s*=\s*"((?:metric|log|span)\.attributes\.[\w@.]+)"'
)


def audit() -> int:
    mismatches: list[tuple[str, str, str]] = []
    for gen_path in sorted(GEN_DIR.glob("generate_*.py")):
        name = gen_path.name
        if name in {"generate_all.py", "generate_index_patterns.py", "generate_overview.py"}:
            continue
        text = gen_path.read_text(encoding="utf-8")
        # Walk panel-spec block: each panel is (visState, kql, DATAVIEW_ID, (x,y,w,h)).
        # The visState construction sits on its own line(s); the dataview ID lives on
        # the same line as the `(x, y, w, h)` tuple — we walk lines forwards and
        # remember the *next* dataview ID for the most recent field reference.
        lines = text.splitlines()
        pending_fields: list[str] = []
        for line in lines:
            for m in FIELD_KWARG_RE.finditer(line):
                pending_fields.append(m.group(1))
            dv_match = PANEL_LINE_RE.search(line)
            if dv_match and pending_fields:
                dv_id = dv_match.group(1)
                expected = DV[dv_id]
                for field in pending_fields:
                    # strip "metric.attributes." / "log.attributes." / "span.attributes." prefix
                    bare = field.split(".attributes.", 1)[1]
                    candidate = f"{field.split('.', 1)[0]}.attributes.{bare}"
                    if candidate not in expected:
                        mismatches.append((name, dv_id, candidate))
                pending_fields = []
    if not mismatches:
        print("OK: every field reference matches its template.")
        return 0
    print(f"FOUND {len(mismatches)} field/dataview mismatches:\n")
    for name, dv, field in mismatches:
        short = name.replace("generate_", "").replace(".py", "")
        print(f"  {short:<28} {dv:<25} {field}")
    return 1


if __name__ == "__main__":
    sys.exit(audit())
