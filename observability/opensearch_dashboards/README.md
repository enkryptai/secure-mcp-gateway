# Secure MCP Gateway — OpenSearch Dashboards

Twelve admin-grade dashboards covering every operational concern, generated
programmatically from Python so re-import overwrites in place rather than
proliferating duplicates.

## Dashboard catalog

| # | Dashboard | Generator | Audience | Index patterns |
|---|---|---|---|---|
| 1 | Executive Overview | `generate_overview.py` | Leadership | metrics |
| 2 | SLO & Reliability (Four Golden Signals) | `generate_slo.py` | SRE / On-call | metrics + logs |
| 3 | Security Posture | `generate_security_posture.py` | Security ops / CISO | metrics |
| 4 | Guardrails Deep Dive (per-detector) | `generate_guardrails_deep_dive.py` | Security analysts | metrics |
| 5 | Tools & MCP Servers | `generate_tools_and_servers.py` | Platform / Integration | metrics |
| 6 | Per-Tenant | `generate_per_tenant.py` | Customer success / Account mgmt | metrics + logs |
| 7 | Cloud Cost & API Usage | `generate_cloud_cost.py` | FinOps / Eng mgmt | metrics |
| 8 | Cache & Performance | `generate_cache_performance.py` | Platform / SRE | metrics + logs |
| 9 | Hot Reload & Config | `generate_hot_reload_config.py` | Platform / Ops | metrics + logs |
| 10 | Audit Trail | `generate_audit_trail.py` | Compliance / Audit | metrics + logs |
| 11 | Sandbox & MCP Protocol | `generate_sandbox_mcp_protocol.py` | Platform / Security | metrics |
| 12 | Error Forensics (correlation_id drill-down) | `generate_error_forensics.py` | Engineering / Support | logs + traces |

## File layout

```
observability/opensearch_dashboards/
├── README.md                                       # this file
├── saved-objects.ndjson                            # index patterns (with field lists baked from templates)
├── gateway-dashboards.ndjson                       # legacy bundle (kept for back-compat)
│
├── gateway-overview-dashboard.ndjson               # 12 ready-to-import dashboards
├── gateway-slo-dashboard.ndjson
├── gateway-security-dashboard.ndjson
├── gateway-guardrails-deep-dive-dashboard.ndjson
├── gateway-tools-servers-dashboard.ndjson
├── gateway-per-tenant-dashboard.ndjson
├── gateway-cloud-cost-dashboard.ndjson
├── gateway-cache-performance-dashboard.ndjson
├── gateway-hot-reload-config-dashboard.ndjson
├── gateway-audit-trail-dashboard.ndjson
├── gateway-sandbox-mcp-protocol-dashboard.ndjson
├── gateway-error-forensics-dashboard.ndjson
│
└── generators/                                     # source-of-truth Python (only needed to edit dashboards)
    ├── _common.py                                  # shared visualization helpers
    ├── _audit_fields.py                            # validate widget fields vs templates
    ├── local-test.ps1                              # one-shot local OSD test (Windows)
    ├── generate_all.py                             # orchestrator — runs all 13 generators
    ├── generate_index_patterns.py                  # writes ../saved-objects.ndjson
    ├── generate_overview.py                        # 1. Executive Overview
    ├── generate_slo.py                             # 2. SLO & Reliability
    ├── generate_security_posture.py                # 3. Security Posture
    ├── generate_guardrails_deep_dive.py            # 4. Guardrails Deep Dive
    ├── generate_tools_and_servers.py               # 5. Tools & MCP Servers
    ├── generate_per_tenant.py                      # 6. Per-Tenant
    ├── generate_cloud_cost.py                      # 7. Cloud Cost
    ├── generate_cache_performance.py               # 8. Cache & Performance
    ├── generate_hot_reload_config.py               # 9. Hot Reload & Config
    ├── generate_audit_trail.py                     # 10. Audit Trail
    ├── generate_sandbox_mcp_protocol.py            # 11. Sandbox & MCP Protocol
    └── generate_error_forensics.py                 # 12. Error Forensics
```

**Operators** only ever need the top-level NDJSON files (import them into OSD).
**Dashboard authors** edit Python in `generators/` and re-run `generate_all.py` to refresh the NDJSON artifacts.

## Regenerate

```bash
# regenerate all 13 NDJSONs (saved-objects + 12 dashboards)
python observability/opensearch_dashboards/generators/generate_all.py

# or regenerate one
python observability/opensearch_dashboards/generators/generate_slo.py
```

Each generator writes its NDJSON to `..` (i.e. the parent
`observability/opensearch_dashboards/` directory) with stable IDs derived
from `stable_id("dashboard:Secure MCP Gateway - ...")` so re-import overwrites
in place rather than creating duplicates.

## Import to OpenSearch Dashboards

Two ways:

### A) Via OSD UI

1. *Stack Management → Saved Objects → Import*
2. Upload one NDJSON at a time
3. Choose *"Automatically overwrite all conflicts"*

### B) Via API (bulk, idempotent)

```bash
OSD_URL="https://<osd-host>:5601"
AUTH="admin:<admin-pwd>"

# Pre-req: index patterns must exist (one-time)
curl -u "$AUTH" -k -X POST "$OSD_URL/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  --form file=@observability/opensearch_dashboards/saved-objects.ndjson

# Then import each dashboard
for f in observability/opensearch_dashboards/gateway-*-dashboard.ndjson; do
  echo "Importing $f"
  curl -u "$AUTH" -k -X POST "$OSD_URL/api/saved_objects/_import?overwrite=true" \
    -H "osd-xsrf: true" \
    --form file=@"$f"
done
```

For dev environments using `apiaas` install scripts, the bootstrap script at
`enkryptai-apiaas/scripts/install/opensearch/gateway/bootstrap.sh` typically
includes the import step.

## Index patterns

Three index patterns (data views) defined in `saved-objects.ndjson`:

| ID | Title pattern | Time field |
|---|---|---|
| `gateway-metrics` | `gateway-metrics` (alias of `ss4o_metrics-gateway*`) | `time` |
| `gateway-logs` | `gateway-logs` (alias of `ss4o_logs-gateway*`) | `time` |
| `gateway-traces` | `gateway-traces` (alias of `ss4o_traces-gateway*`) | `startTime` |

## Naming conventions

- **Identity attrs** are snake_case across logs/metrics/traces. Pivots:
  `user_id`, `user_email`, `project_id`, `project_name`, `project_registry`,
  `org_id`, `gateway_name`, `gateway_version`, `server_name`, `tool_name`.
- **Operational span attrs** are snake_case after the templates migration
  (`enkrypt_auth_base_url` instead of `enkrypt.auth.base_url`). Only
  unavoidable `@` remain (OTel-emitted `service@name`, `host@name`, code
  context).
- **Latency** lives in `*_duration_ms` log/span attrs OR as histogram metric
  instrument NAMES (`enkrypt.tool.duration`, `enkrypt.guardrail.duration`,
  etc.) with values in the standard OTel `value`/`sum`/`count`/`bucketCounts`
  fields.
- **Per-detector blocks** use dedicated metric instruments like
  `enkrypt.guardrail.nsfw_blocks`, `enkrypt.guardrail.toxicity_blocks`, etc.
  Filterable via `detector` + `detector_enabled` + `detector_blocked`
  attributes on the unified `enkrypt.guardrail.detection` counter.

## Authoring a new dashboard

1. Copy any `generators/generate_*.py` as a template
2. Update the `OUT` path (use `DASHBOARDS_DIR / "gateway-X-dashboard.ndjson"`)
3. Define `PANEL_SPECS` as a list of `(visState, kql, dataview_id, (x, y, w, h))`
4. Use helpers from `generators/_common.py`:
   - `kpi_metric_vis`, `percentile_vis`, `gauge_vis`
   - `time_series_vis`, `multi_series_time_vis`, `area_vis`
   - `horizontal_bar_topN_vis`, `vertical_bar_topN_vis`, `pie_vis`
   - `heatmap_vis`, `data_table_vis`, `markdown_vis`
5. Call `build_dashboard_ndjson(out_path=..., title=..., description=..., panel_specs=...)`
6. Add the new module name to `GENERATORS` in `generators/generate_all.py`
7. Run `python generators/_audit_fields.py` to validate field references
8. Run `python generators/generate_all.py` to refresh NDJSON
9. Add the dashboard to the catalog table above

## Layout grid

48 columns wide, each panel `(x, y, w, h)`. Conventions used:

| Element | Width | Height |
|---|---|---|
| Section header (markdown) | 48 | 2 |
| Full-width descriptive markdown | 48 | 4 |
| KPI big-number card | 8–12 | 6 |
| Time-series (single) | 24 | 12 |
| Time-series (full-width stacked) | 48 | 12 |
| Pie / donut | 16 | 12 |
| Horizontal bar (top-N) | 24 | 12 |
| Heatmap | 48 | 14 |
| Data table | 24–48 | 14–16 |

`y` is incremented manually between rows. Be mindful that rows of different
heights need their `y` start values bumped to match.

## Field reference

Every widget queries fields declared in:

- `observability/opensearch/templates/gateway-metrics-elastic-template.json`
- `observability/opensearch/templates/gateway-logs-elastic-template.json`
- `observability/opensearch/templates/gateway-traces-elastic-template.json`

Templates are `dynamic: false`, so any field referenced must be either
mapped explicitly or visible via OTel-auto-emitted resource attrs. See
those templates' `_meta.description` for the full catalog of expected
metric instrument names and attribute fields.

## Stats

```
12 dashboards
~456 visualizations
~890 KB total NDJSON (incl. saved-objects with baked field lists)
0 external Python dependencies (stdlib only)
```

Regenerate in <1 second with `python generators/generate_all.py`.

## Local end-to-end test (Windows)

```powershell
# brings stack up, applies templates, regens NDJSONs, imports to OSD
pwsh observability/opensearch_dashboards/generators/local-test.ps1

# stack already up — skip docker compose
pwsh observability/opensearch_dashboards/generators/local-test.ps1 -SkipUp
```

The script runs `_audit_fields.py` → `generate_all.py` → deletes cached index patterns → re-imports patterns + all 12 dashboards. Idempotent — safe to re-run after any edit.
