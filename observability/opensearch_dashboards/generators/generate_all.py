"""Generate every Secure MCP Gateway dashboard NDJSON in one shot.

Usage::

    python observability/opensearch_dashboards/generate_all.py

This runs each individual ``generate_*.py`` script's ``main()`` in sequence
and produces 13 ``gateway-*-dashboard.ndjson`` files next to this script.

The order is fixed so dashboard cross-references (none today, but planned)
resolve deterministically.
"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path
from _common import DASHBOARDS_DIR

GENERATORS = [
    "generate_index_patterns",          # saved-objects.ndjson with field lists baked from templates
    "generate_overview",                # existing — Executive Overview
    "generate_slo",                     # SLO & Reliability
    "generate_security_posture",        # Security Posture
    "generate_guardrails_deep_dive",    # Per-detector deep dive
    "generate_tools_and_servers",       # Tools & MCP Servers
    "generate_per_tenant",              # Per-Tenant
    "generate_identity_breakdown",      # Identity Breakdown (6-up by gateway/org/project/user/server/tool)
    "generate_cloud_cost",              # Cloud Cost & API Usage
    "generate_cache_performance",       # Cache & Performance
    "generate_hot_reload_config",       # Hot Reload & Config
    "generate_audit_trail",             # Audit Trail
    "generate_sandbox_mcp_protocol",    # Sandbox & MCP Protocol
    "generate_error_forensics",         # Error Forensics
]


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    failed: list[tuple[str, Exception]] = []
    start = time.monotonic()
    for mod_name in GENERATORS:
        try:
            print(f"\n=== {mod_name} ===")
            mod = importlib.import_module(mod_name)
            mod.main()
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"FAILED: {mod_name} -- {exc}", file=sys.stderr)
            failed.append((mod_name, exc))
    elapsed = time.monotonic() - start
    print(f"\n=== Done: {len(GENERATORS) - len(failed)}/{len(GENERATORS)} OK in {elapsed:.1f}s ===")
    if failed:
        print("Failures:", file=sys.stderr)
        for mod, exc in failed:
            print(f"  - {mod}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
