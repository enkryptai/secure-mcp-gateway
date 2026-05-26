# Observability stack -- OpenSearch backend (primary)

Self-contained local stack that ships every gateway signal -- logs, metrics,
traces -- into a single-node OpenSearch cluster, with the Alerting plugin
firing the 9 canonical MCP-Gateway alerts to Slack.

OpenSearch is the **primary** backend. It claims the OTel default ports
**4317 (gRPC) / 4318 (HTTP)**, so the gateway's default telemetry endpoint
(`http://localhost:4317`) lands here with **no gateway config change**.

The legacy Grafana/Prometheus/Loki/Jaeger stack
([docker-compose.grafana.yml](docker-compose.grafana.yml)) is still available as an
alternative -- it moved to **4327/4328**. You run **one** backend at a
time (the gateway emits to a single collector); the two stacks use
non-overlapping host ports so they *can* run together if you ever want
to compare, but that's not required.

```text
                       ┌──────────────────────────────────┐
secure-mcp-gateway     │  OTel Collector                  │
(unchanged on :8000)──▶│  (otel-collector-config.opensearch.yaml)
   OTLP on :4317 (gRPC)│   --> Data Prepper                │
   OTLP on :4318 (HTTP)│       --> OpenSearch              │
                       └──────────────────────────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
            ss4o_metrics-gateway    ss4o_traces-gateway      ss4o_logs-gateway
            (alias: gateway-metrics) (alias: gateway-traces)  (alias: gateway-logs)
                                          │
                                          ▼
                              otel-v1-apm-service-map (Trace Analytics)
```

## What you get out of the box

| Component               | Endpoint                       | Auto-provisioned content                                    |
| ----------------------- | ------------------------------ | ----------------------------------------------------------- |
| OpenSearch              | https://localhost:9200         | 1 ISM policy + 3 SS4O data streams + 1 internal alias each + 1 least-privilege writer user |
| OpenSearch Dashboards   | http://localhost:5601          | 5 index patterns + default config (gateway-metrics)         |
| Data Prepper (internal) | data-prepper:21890/91/92, :4900 | 4 pipelines (traces, service-map, metrics, logs); writes as `mcp_gateway_telemetry_plugin`, not admin |
| OTel Collector          | :4317 gRPC / :4318 HTTP        | OTLP receiver + Data Prepper exporters                      |
| Alerting (Slack)        | via :9200/_plugins/_alerting   | 1 Slack channel + 9 monitors (matches Grafana rules.yaml)   |

## Quick start

Prerequisites: Docker Desktop or Docker Engine + compose plugin.

```bash
cd observability

# 1. Copy and edit the env file
cp .env.opensearch.example .env.opensearch
# Edit:
#   OPENSEARCH_INITIAL_ADMIN_PASSWORD   -- must be 8+ chars, upper/lower/digit/symbol
#   MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD   -- same rules; gets auto-provisioned
#                                          as the data-prepper writer creds
#   SLACK_WEBHOOK_URL                   -- real webhook so monitor actions actually post

# 2. Bring up the stack
docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch up -d

# 3. Wait ~60-90s for OpenSearch first-boot, then visit:
#    http://localhost:5601    (Dashboards; admin / your password)
```

The gateway's default `plugins.telemetry.config.url` is already
`http://localhost:4317`, which is exactly where this stack's OTel
collector listens -- so no gateway config change is needed. (If your
gateway was previously pointed at `http://localhost:4327` for the Grafana
stack, change it back to `http://localhost:4317` and restart. Endpoint
changes require a restart -- see [CLAUDE.md](../CLAUDE.md) "Settings
still requiring restart".)

## What's provisioned (the as-code templates)

Everything below is plain JSON/YAML in this directory. Edit the file,
restart the relevant bootstrap container (or `docker compose down && up`),
and the change ships.

### Data stream templates -- [`opensearch/templates/`](opensearch/templates/)

| File                                    | Index pattern              | Data Prepper sink writes to | Timestamp field |
| --------------------------------------- | -------------------------- | --------------------------- | --------------- |
| `gateway-metrics-elastic-template.json` | `ss4o_metrics-gateway*`    | `ss4o_metrics-gateway`      | `time`          |
| `gateway-traces-elastic-template.json`  | `ss4o_traces-gateway*`     | `ss4o_traces-gateway`       | `startTime`     |
| `gateway-logs-elastic-template.json`    | `ss4o_logs-gateway*`       | `ss4o_logs-gateway`         | `time`          |

All three:
- have `data_stream: {}` with an explicit `timestamp_field` override (Data
  Prepper emits SS4O field names that don't match OpenSearch's default
  `@timestamp` requirement);
- attach the `gateway_telemetry_policy` ISM policy at backing-index
  creation time;
- declare an inline `aliases` block so each backing index automatically
  gets the friendly alias (`gateway-metrics`, etc.) at creation;
- use `dynamic_templates` with `path_match: "metric.attributes.*"` /
  `"span.attributes.*"` / `"log.attributes.*"` so the per-signal attribute
  namespaces land as keyword (cheap aggregation) by default;
- cap mappings at 5000 fields (vs the Kong templates' 2000) because OTel
  attribute spaces are open-ended.

### Identity attribute field names

The gateway currently emits identity attributes in **snake_case only**
(`metric.attributes.server_name`, `log.attributes.user_email`,
`span.attributes.org_id`, ...). Use those names in monitor aggregations,
PPL queries, and dashboards.

Background -- and how to re-enable the dotted form -- in
[`docs/metric_attributes_key_mismatch.md`](../docs/metric_attributes_key_mismatch.md).
Briefly: the OpenTelemetry-canonical dotted form
(``enkrypt.server.name``, etc.) is commented out in
``src/secure_mcp_gateway/log.py:CANONICAL_ATTR_KEYS`` and
``src/secure_mcp_gateway/plugins/telemetry/conventions.py:SpanAttributes``.
Swap each commented/uncommented pair to restore dual emission; when the
dotted form is active, Data Prepper flattens it with literal dots in the
field prefix and substitutes ``@`` for sub-key dots (OTel attr
``enkrypt.server.name`` -> field ``metric.attributes.enkrypt@server@name``).

### ISM policy -- [`opensearch/policies/gateway_telemetry_policy.json`](opensearch/policies/gateway_telemetry_policy.json)

| Phase | Duration | Action                                  |
| ----- | -------- | --------------------------------------- |
| hot   | 0--7d    | rollover at 1d age or 25 GB primary     |
| delete| 7d+      | drop the backing index                  |

Priority 1000 (higher than the existing `rollover_policy` priority 999)
so this policy wins on overlap. Pattern: `ss4o_{metrics,traces,logs}-gateway*`.

### Slack notification channel -- [`opensearch/notification_channels/slack-mcpgw-alerts.json`](opensearch/notification_channels/slack-mcpgw-alerts.json)

Deterministic `config_id: slack-mcpgw-alerts`. `${SLACK_WEBHOOK_URL}`
substituted at bootstrap time. Re-runs upsert in place (PUT to
`/configs/<id>`).

### Alert monitors -- [`opensearch/monitors/`](opensearch/monitors/)

All 9 are `bucket_level_monitor` -- composite agg by attributes, threshold
condition, Slack action targeting the channel above. Mirrors
[`grafana/provisioning/alerting/rules.yaml`](grafana/provisioning/alerting/rules.yaml).

| #  | Monitor                            | Severity | Trigger                                                |
| -- | ---------------------------------- | -------- | ------------------------------------------------------ |
| 01 | Policy Violation Burst             | 1 (crit) | > 5 `violation_type=policy_violation` per (server,tool) in 5m |
| 02 | Injection Attack Burst             | 1 (crit) | > 3 `violation_type=injection_attack` per (server,tool) in 5m |
| 03 | PII Redaction Detected             | 1 (crit) | any `enkrypt.pii.redactions` event in 5m               |
| 04 | Toxicity / NSFW Surge              | 3 (warn) | > 5 toxicity OR nsfw blocks per (server,tool) in 5m    |
| 05 | Output Quality Failure             | 3 (warn) | > 3 relevancy/adherence/hallucination per (server,tool) in 5m |
| 06 | Tool Deny-List Burst               | 3 (warn) | > 5 `enkrypt.tool.blocked` per (server,tool) in 5m     |
| 07 | User Targeting -- Guardrails       | 1 (crit) | > 10 guardrail blocks per single `user_id` in 5m       |
| 08 | Guardrail API Latency              | 3 (warn) | max(`enkrypt.guardrail.duration`) > 2s in 5m (proxy for p95) |
| 09 | Auth Failure Burst                 | 1 (crit) | > 10 `enkrypt.auth.failure` per `failure_reason` in 5m |

Severities map to OpenSearch Alerting's 1-5 scale: 1 = critical, 3 = warn.
Each monitor's schedule is 1 minute; the search window is 5 minutes.

#### Monitor #8 caveat -- p95 approximation

True p95 over histogram buckets requires a `percentile_bucket` pipeline
aggregation. As a tractable proxy this monitor takes `max(max)` of the
histogram per server, which catches any export window where a guardrail
call exceeded 2s. Over-fires vs. the Grafana p95 rule but is correct in
spirit. The `_meta` note in the JSON documents this.

### Dashboards saved-objects

Two NDJSONs ship under [`opensearch_dashboards/`](opensearch_dashboards/), both
imported via `_import?overwrite=true`:

- [`saved-objects.ndjson`](opensearch_dashboards/saved-objects.ndjson) -- 5
  index patterns (`gateway-metrics`, `gateway-traces`, `gateway-logs`,
  `ss4o_traces-gateway*`, `otel-v1-apm-service-map*`) + 1 config saved-object
  setting `defaultIndex=gateway-metrics`.
- [`gateway-dashboards.ndjson`](opensearch_dashboards/gateway-dashboards.ndjson)
  -- 13 visualizations + 3 dashboards ("Secure MCP Gateway - Metrics /
  Traces / Logs"). Ports the existing Grafana `gateway-metrics.json` panels
  to SS4O field names: `sum(value)` with `metric.name` filters for the rate
  charts; `sum(sum)` + `sum(count)` separately for histogram metrics (true
  averages require Lens formula, deferred). Traces and logs panels are new
  -- the Grafana stack didn't have equivalents.

`bootstrap.sh` (and the docker-compose `opensearch-dashboards-bootstrap`
service) read every `*.ndjson` in the dashboards directory, concatenate
them into one tempfile, and submit a single `_import` call. Adding more
NDJSONs requires no script change.

Concatenation matters: OpenSearch Dashboards 2.19.1's `_import` DOES
enforce reference resolution at import time. If we imported each file
separately, `gateway-dashboards.ndjson` (visualizations referencing
`gateway-metrics`/`gateway-traces`/`gateway-logs` index-patterns) would
be rejected with `missing_references` on a fresh cluster because the
patterns are defined in `saved-objects.ndjson` and `gateway-` sorts
before `saved-` lexically. Inside a single payload OSD processes
saved-objects by type, so index-patterns land first and the
visualizations resolve cleanly regardless of file order on disk.

### Verifying dashboards with synthetic data -- [`emit_dummy_telemetry.py`](emit_dummy_telemetry.py)

Drives the OTel collector at `localhost:4317` (gRPC) with realistic
gateway-shaped telemetry: counters + histograms with DELTA temporality
(matching [`opentelemetry_provider.py`](../src/secure_mcp_gateway/plugins/telemetry/opentelemetry_provider.py)),
canonical metric names from [`conventions.py`](../src/secure_mcp_gateway/plugins/telemetry/conventions.py),
`enkrypt.server.name`/`enkrypt.tool.name` attribute keys, plus spans and
INFO/WARN/ERROR/DEBUG logs. Useful for end-to-end verification when the
real gateway isn't running, or when changing dashboards / monitors and
needing fresh data to validate against.

```bash
# requires the same OTel SDK the gateway already pins (pyproject.toml)
python observability/emit_dummy_telemetry.py
```

Defaults to ~10-15 tool calls per 2s round across 3 dummy servers; Ctrl-C
to stop. All 12 dashboard panels populate within a couple of rounds.

## Gateway-side prerequisite -- DELTA temporality

The 9 alert monitors use `sum(value) > threshold` against the SS4O metric
documents. This semantics is correct **only when** the gateway emits
metrics with DELTA aggregation temporality (each export window's value is
the count of events in that window, not the cumulative running total).

The gateway's [`opentelemetry_provider.py`](../src/secure_mcp_gateway/plugins/telemetry/opentelemetry_provider.py)
sets this explicitly via `preferred_temporality` on the `OTLPMetricExporter`.
Counters, Histograms, and ObservableCounters are DELTA; UpDownCounter and
Gauge stay CUMULATIVE (they represent current state, not events).

The OTel Collector's prometheus exporter automatically accumulates DELTA
into CUMULATIVE at scrape time, so the legacy Grafana/Prometheus stack
keeps working with PromQL `increase()`/`rate()` unchanged if you choose
to run it instead.

## Choosing a backend (you run one, not both)

The gateway emits to a **single** OTel collector. Pick the backend by
which stack you bring up; the gateway's endpoint defaults to
`http://localhost:4317`, which is the OpenSearch stack.

| Service                 | OpenSearch stack (primary) | Grafana stack (legacy) |
| ----------------------- | -------------------------- | ---------------------- |
| OTel Collector gRPC     | :4317  (gateway default)   | :4327                  |
| OTel Collector HTTP     | :4318                      | :4328                  |
| UI                      | OS Dashboards :5601        | Grafana :3001          |
| Underlying storage      | OpenSearch :9200           | Prometheus/Loki/Jaeger |

```bash
# OpenSearch (default -- no gateway config change needed)
docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch up -d

# OR the legacy Grafana stack (then point the gateway at :4327)
docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d
```

The two stacks bind non-overlapping host ports, so they *can* run
simultaneously if you ever want to compare side-by-side -- but that's
optional and not the normal path. Switching which collector the gateway
targets requires a gateway process restart (per
[CLAUDE.md](../CLAUDE.md) -- the OTLP TracerProvider/MeterProvider is set
once per process).

## Verification (end-to-end smoke test)

```bash
PW='<your OPENSEARCH_INITIAL_ADMIN_PASSWORD>'

# 1. OpenSearch reachable + cluster green
curl -fksu admin:$PW https://localhost:9200/_cluster/health?wait_for_status=yellow

# 2. Templates + ISM policy applied (expect 3 templates, 1 policy)
curl -fksu admin:$PW https://localhost:9200/_index_template/gateway-* \
  | jq '.index_templates | length'                         # -> 3
curl -fksu admin:$PW https://localhost:9200/_plugins/_ism/policies/gateway_telemetry_policy \
  | jq '._id'                                              # -> "gateway_telemetry_policy"

# 3. Data Prepper pipelines healthy (expect 4)
docker exec secure-mcp-gateway-observability-opensearch-data-prepper-1 \
  curl -fs http://localhost:4900/list \
  | jq '.pipelines | length'                               # -> 4

# 4. Notifications channel + monitors (expect 9 + 1)
curl -fksu admin:$PW https://localhost:9200/_plugins/_notifications/configs/slack-mcpgw-alerts \
  | jq '.config_id'                                        # -> "slack-mcpgw-alerts"
curl -fksu admin:$PW -X POST https://localhost:9200/_plugins/_alerting/monitors/_search \
  -H 'Content-Type: application/json' -d '{"size":0,"query":{"match_all":{}}}' \
  | jq '.hits.total.value'                                 # -> 9

# 5. Dashboards index patterns (expect 5)
curl -fsu admin:$PW -H 'osd-xsrf: true' \
  'http://localhost:5601/api/saved_objects/_find?type=index-pattern' \
  | jq '.total'                                            # -> 5

# 6. Trigger a tool call against the gateway. After ~10s:
curl -fksu admin:$PW 'https://localhost:9200/gateway-metrics/_count' \
  | jq '.count'                                            # -> >= 1
```

## Switching from the legacy Grafana stack

If a gateway is currently pointed at the Grafana stack (now on
`http://localhost:4327`), cutover to OpenSearch is:

1. Bring down the Grafana stack: `docker compose -f docker-compose.grafana.yml --env-file .env.grafana down`.
2. Bring up the OpenSearch stack:
   `docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch up -d`.
3. Set the gateway's `plugins.telemetry.config.url` back to the default
   `http://localhost:4317` (or just remove the override) and restart the
   gateway. Verify metrics/traces/logs land in
   `gateway-metrics`/`gateway-traces`/`gateway-logs`.

Rollback to Grafana: bring the Grafana stack back up, set the gateway's
`plugins.telemetry.config.url` to `http://localhost:4327`, and restart.
OpenSearch indices stay intact either way.

## Customising

### Adjust an alert threshold

Edit the relevant file in [`opensearch/monitors/`](opensearch/monitors/),
then re-run the bootstrap container:

```bash
docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch \
  up -d --force-recreate opensearch-bootstrap
```

The script's "Monitor: ... exists; updating..." path will PUT the new
JSON over the existing one. The `_id` stays stable (name-based lookup).

### Add a new monitor

1. Drop a new `NN-<slug>.json` file into [`opensearch/monitors/`](opensearch/monitors/).
2. Use `${SLACK_CHANNEL_ID}` as a placeholder for the action's
   destination -- bootstrap substitutes it at runtime.
3. Re-run the opensearch-bootstrap container.

### Swap Slack for a different destination

Edit [`opensearch/notification_channels/slack-mcpgw-alerts.json`](opensearch/notification_channels/slack-mcpgw-alerts.json)
to a different `config_type` (e.g. `webhook`, `email`, `sns`,
`microsoft_teams`, `chime`). Adjust the `config` shape per the
Notifications plugin docs. Re-run the bootstrap container.

### Tighten Slack delivery rate

Each monitor has `throttle_enabled: false`. Set it to `true` and add a
`throttle: { value: N, unit: MINUTES }` block on the action to batch
repeat fires.

### Apply only templates + ISM (skip alerting setup)

```bash
SKIP_MONITORS=1 docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch up -d
```

Useful for a staging cluster where you don't want pager noise yet.

## Troubleshooting

### `Bind for 0.0.0.0:9200 failed: port is already allocated`

You have another OpenSearch (or Elasticsearch) running on 9200. Override
in `.env.opensearch`:

```
OS_HTTP_HOST_PORT=19200
```

### `OpenSearch refuses to start, exits immediately`

OpenSearch 2.12+ requires `OPENSEARCH_INITIAL_ADMIN_PASSWORD` to be set
**and** to satisfy: 8+ chars, mixed case, digit, symbol. Check
`.env.opensearch`. Weak passwords are silently rejected at first boot.

### Dashboards container marked "unhealthy" but `/` works

Older versions of this stack used the `/api/status` healthcheck, which
requires auth and returned 401 anonymously. The current compose uses `/`
(returns 302 to login) which satisfies `curl -f`. If you still see this,
recreate the dashboards container:

```bash
docker compose -f docker-compose.opensearch.yml up -d --force-recreate opensearch-dashboards
```

### Data Prepper "Document failed to write" warnings

Most common causes:

* **Field type mismatch** -- a Data Prepper schema change emits a field
  shape that doesn't match the template. Check the template in
  [`opensearch/templates/`](opensearch/templates/), drop the affected
  data stream (`curl -X DELETE /_data_stream/<name>`), and re-ingest
  (the new backing index uses the corrected template).
* **Missing `@timestamp`** -- if you've removed the
  `data_stream.timestamp_field` block from a template, OpenSearch
  defaults to requiring `@timestamp`. Data Prepper emits `time` /
  `startTime` per SS4O, not `@timestamp`. Restore the
  `timestamp_field.name` override.

### Monitor never fires despite breaching data

Two likeliest culprits:

1. **CUMULATIVE temporality slipped back in.** The gateway must emit
   DELTA. Check
   [`opentelemetry_provider.py`](../src/secure_mcp_gateway/plugins/telemetry/opentelemetry_provider.py)
   has the `preferred_temporality=_PREFERRED_TEMPORALITY` argument on
   the `OTLPMetricExporter`. Test:
   ```
   curl -ksu admin:$PW 'https://localhost:9200/gateway-metrics/_search?size=1' \
     | jq '.hits.hits[0]._source.aggregationTemporality'
   ```
   Expect `"AGGREGATION_TEMPORALITY_DELTA"`. If you see `CUMULATIVE`, the
   monitor's `sum(value)` will compound.
2. **Time field mismatch.** Monitors filter on `time` (which is what
   metrics + logs use). The traces field is `startTime`. If you copy a
   monitor across signals, update both the index in `inputs.search.indices`
   AND the `range.<field>` block.

### "no such index [ss4o_metrics-gateway]" on first start

Data streams are created on the first ingest, not at template-apply time.
Data Prepper will retry until the OTel Collector forwards the first
record. Send a synthetic OTLP doc (see the verification section) and the
stream will appear within a second.

### `${OPENSEARCH_HOSTS}` literal in Data Prepper logs

Data Prepper 2.11 does **not** natively substitute `${VAR}` env-var
placeholders in `pipelines.yaml`. The stack renders the file at boot via
the `data-prepper-render` one-shot service, which runs
[`data_prepper/render_pipelines.py`](data_prepper/render_pipelines.py)
against the template and writes the result to a shared named volume that
the `data-prepper` container then reads. If you bypass the render
service (e.g. by removing the `depends_on` chain), the file stays in its
unrendered state and Data Prepper crashes on the first `${...}` token.

The Python renderer replaced an earlier `sed`-based shim that broke if a
password contained `|`, `&`, or `\\` (sed's substitution language).
`render_pipelines.py` is pure Python with no third-party deps and has its
own unit tests under
[`data_prepper/test_render_pipelines.py`](data_prepper/test_render_pipelines.py).

### Saved-object import returns `Document has property "..." which belongs to a more recent version`

Your NDJSON's `migrationVersion` for a saved-object type is newer than
the running Dashboards build supports. For 2.19.1: `index-pattern: 7.6.0`,
`config: 7.9.0`.

## Where to look for what

| I want to see…                              | Go to                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------- |
| Raw metric / trace / log docs                | Dashboards → Discover → pick `gateway-*` index pattern                |
| End-to-end span / service map               | Dashboards → Observability → Trace Analytics                          |
| Live alert state / monitor history          | Dashboards → Alerting → Monitors                                       |
| Slack delivery debugging                    | `docker logs ... opensearch-1` | grep alerting                          |
| Raw OpenSearch index/health                 | `https://localhost:9200/_cat/indices?v`                                |
| Data Prepper pipeline status                | `curl http://localhost:4900/list` (in-container) or compose exec       |
| Bootstrap script logs                       | `docker logs secure-mcp-gateway-observability-opensearch-opensearch-bootstrap-1` |

## Related files

* [`docker-compose.opensearch.yml`](docker-compose.opensearch.yml) -- the orchestration
* [`.env.opensearch.example`](.env.opensearch.example) -- env var template
* [`opensearch/bootstrap.sh`](opensearch/bootstrap.sh) -- idempotent installer
* [`data_prepper/pipelines.yaml`](data_prepper/pipelines.yaml) -- 4 pipelines (traces / service-map / metrics / logs)
* [`otel_collector/otel-collector-config.opensearch.yaml`](otel_collector/otel-collector-config.opensearch.yaml) -- collector config
* [`README.md`](README.md) -- the Grafana/Prometheus stack (mode B)
* [`../CLAUDE.md`](../CLAUDE.md) -- gateway architecture overview
* [`../src/secure_mcp_gateway/plugins/telemetry/conventions.py`](../src/secure_mcp_gateway/plugins/telemetry/conventions.py) -- canonical metric / span / attribute names
