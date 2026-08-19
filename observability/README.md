# Observability stack — Secure MCP Gateway (legacy Grafana backend)

Self-contained, fully-provisioned **logs / metrics / traces / alerts** stack
for the Secure MCP Gateway. Everything is templated as code: clone, copy
the env file, run one `docker compose -f docker-compose.grafana.yml`, get
a working dashboard with Slack alerts.

> **Note:** OpenSearch is now the **primary** backend and owns the OTel
> default ports `4317`/`4318` (see
> [README.opensearch.md](README.opensearch.md)). This legacy Grafana
> stack moved to **`4327`/`4328`**, so to use it you must point the
> gateway's telemetry endpoint at `http://localhost:4327`. You run one
> backend at a time.

```text
┌─────────────────────┐   logs (OTLP)         ┌────────────┐    LogQL    ┌─────────┐
│ secure-mcp-gateway  │──────────────────────▶│            │────────────▶│         │
│ (host process       │   metrics (OTLP)      │   OTel     │             │ Grafana │
│  on :8000)          │──────────────────────▶│ Collector  │   PromQL    │ (:3030) │
│                     │   traces  (OTLP)      │ (:4327)    │────────────▶│         │
└─────────────────────┘                       └────────────┘             └─────────┘
                                              │     │     │                  ▲
                                              ▼     ▼     ▼                  │
                                          ┌──────┐ ┌────┐ ┌────────┐         │
                                          │ Loki │ │Prom│ │ Jaeger │─────────┘
                                          └──────┘ └────┘ └────────┘     dashboards
                                                          (:16686)        & alerts
```

## What you get out-of-the-box

| Component                | Endpoint              | Provisioned content                                                    |
| ------------------------ | --------------------- | ---------------------------------------------------------------------- |
| **Grafana**              | `http://localhost:3030` (default 3001) | 3 dashboards · 9 alert rules · Slack contact point · 2 datasources |
| **Prometheus**           | `http://localhost:9090` | Scrapes OTel Collector at `:8889` every 15s                           |
| **Loki**                 | `http://localhost:3100` | Receives logs from OTel Collector via OTLP                            |
| **Jaeger UI**            | `http://localhost:16686` | Traces from OTel Collector                                            |
| **OTel Collector OTLP**  | `:4327` (gRPC), `:4328` (HTTP) | Gateway points its OTLP exporter here (moved off the 4317/4318 defaults, which OpenSearch now owns) |
| **OTel Collector metrics**| `http://localhost:8889/metrics` | Prometheus-format scrape target                                  |

Anonymous-admin auth is enabled for Grafana (no login screen). To set a
real admin password, see *Customising* below.

## Quick start

Prerequisites: Docker Desktop (Windows/macOS) or Docker Engine + compose
plugin (Linux).

This stack is invoked exactly like the OpenSearch stack -- explicit
`-f` and `--env-file` flags (no auto-loaded `docker-compose.yml`/`.env`),
so the two backends never collide:

```bash
cd observability

# 1. Copy the env template and edit the Slack webhook URL
cp .env.grafana.example .env.grafana
# (edit observability/.env.grafana and replace SLACK_WEBHOOK_URL with
#  your real https://hooks.slack.com/services/... URL)

# 2. Bring up the full stack
docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d

# 3. Open Grafana (default 3030, or whatever GRAFANA_HOST_PORT you set)
#    -> http://localhost:3030
#    -> Dashboards -> "OpenTelemetry Gateway Metrics"
#    -> Alerting -> Alert rules (you should see 9 rules under "MCP Gateway Alerts")
```

To send the gateway's telemetry to this stack, set
`plugins.telemetry.config.url` to `http://localhost:4327` (this stack's
gRPC port — the default `4317` now goes to the OpenSearch stack) and
restart the gateway. Trigger any tool call against it and watch the
dashboard update.

## What's provisioned (the as-code templates)

Everything below is plain YAML/JSON in this directory. Edit the file,
restart Grafana, and the change ships — no clicking around the UI.

### Datasources — `grafana/provisioning/datasources/datasources.yaml`

| UID          | Type       | Backing service                  |
| ------------ | ---------- | -------------------------------- |
| `prometheus` | prometheus | `http://prometheus:9090`         |
| `loki`       | loki       | `http://loki:3100`               |
| (default)    | jaeger     | `http://jaeger:16686`            |

### Alert rules — `grafana/provisioning/alerting/rules.yaml`

All 9 rules are PromQL-backed against the metrics emitted by the gateway
helpers in `src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py`.

| UID                                | Severity   | Trigger (5–10 min window)                                             |
| ---------------------------------- | ---------- | --------------------------------------------------------------------- |
| `mcpgw-policy-violation-burst`     | critical   | > 5 `policy_violation` blocks                                         |
| `mcpgw-injection-attack-burst`     | critical   | > 3 `injection_attack` input blocks                                   |
| `mcpgw-pii-found`                  | critical   | any PII redaction event                                               |
| `mcpgw-toxicity-nsfw-surge`        | warning    | > 5 `toxicity` or `nsfw` blocks                                       |
| `mcpgw-output-quality-failure`     | warning    | > 3 relevancy + adherence + hallucination blocks                      |
| `mcpgw-tool-deny-list-burst`       | warning    | > 5 deny-list-block tool calls                                        |
| `mcpgw-user-targeting-guardrails`  | critical   | single `user_id` triggers > 10 guardrail blocks                       |
| `mcpgw-guardrail-api-latency`      | warning    | p95 guardrail HTTP > 2s                                               |
| `mcpgw-auth-failure-burst`         | critical   | > 10 auth failures                                                    |

Burst rules use `sum by (server_name, tool_name)` (or `user_id`,
`failure_reason`) so each distinct offender gets its own Slack message
rather than one aggregated alert. See `docs/metric_reference.md` for the
underlying metric series.

### Contact points — `grafana/provisioning/alerting/contact-points.yaml`

One Slack contact point named `slack-grafana-alerts`. The webhook URL
comes from `SLACK_WEBHOOK_URL` in `.env.grafana`; the message template
conditionally renders metadata lines (Server / Tool / User / Direction /
Failure reason / Provider / Check kind) — labels not present on a given
alert are omitted entirely instead of rendering as `n/a`.

### Notification policies — `grafana/provisioning/alerting/notification-policies.yaml`

Routes everything to Slack with two grouping behaviours:

* `severity=critical` → 0s group wait (fire immediately)
* `severity=warning` → 5m group wait (batch)

`group_by` includes `alertname, severity, server_name, tool_name,
failure_reason, check_kind, direction, user_id` so distinct instances
produce distinct Slack messages.

### Dashboards — `grafana/provisioning/dashboards/`

* `OpenTelemetry Gateway Metrics.json` — the canonical operator dashboard
  (traffic, latency, guardrail violations, cache, per-tool stats).
  Variables let you scope to a project / user / config / mcp_config.
* `otel-grafana-complete.json` — same data, alternative layout (titled
  "OpenTelemetry Gateway Metrics (Complete)").
* `gateway-metrics.json` — minimal "first-look" view.

All three are auto-loaded by the file provider configured in
`dashboards/dashboards.yaml`.

## Customising

### Change an alert threshold

Open `grafana/provisioning/alerting/rules.yaml`, find the rule (e.g.
`mcpgw-policy-violation-burst`), tweak the `[5m]` window or the `> 5`
threshold in the `expr:` block, then:

```bash
docker compose restart grafana
```

The rule reloads from disk on every start; the in-database copy is
overwritten by the file. If you also want to allow ad-hoc edits in the UI
that survive reloads, switch the dashboard provider to
`disableDeletion: false; allowUiUpdates: true` (already the default in
`dashboards.yaml`) and pin the rule via the UI's "edit" button.

### Add a new alert rule

1. Add a rule block to `grafana/provisioning/alerting/rules.yaml`. Copy
   the structure of an existing rule (UID, condition, labels, data).
2. If it consumes a metric that's not yet wired, see
   `docs/metric_reference.md` → "Adding a new metric" for the helper
   pattern.
3. Restart Grafana.

### Disable Slack and use a different channel

Replace the receiver block in
`grafana/provisioning/alerting/contact-points.yaml` with the channel of
your choice (PagerDuty, Opsgenie, generic webhook, email, …). All Grafana
contact-point types are supported. Then restart Grafana.

### Switch off anonymous Grafana auth

Edit `docker-compose.grafana.yml`, in the `grafana:` service, remove
these two env vars and add a real password:

```yaml
environment:
  # - GF_AUTH_ANONYMOUS_ENABLED=true        ← remove
  # - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin      ← remove
  - GF_SECURITY_ADMIN_USER=admin
  - GF_SECURITY_ADMIN_PASSWORD=<your-password>
```

Then `docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d --force-recreate grafana`.

## Verifying it works (end-to-end smoke test)

```bash
# 1. Stack up
cd observability && docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d

# 2. Confirm provisioning succeeded (no errors / no "title is not unique" warnings)
docker compose -f docker-compose.grafana.yml logs grafana | grep -E 'provisioning|error' | tail -20

# 3. Confirm alert rules loaded (expect 9 rules under group "MCP Gateway Alerts")
curl -s http://localhost:${GRAFANA_HOST_PORT:-3001}/api/v1/provisioning/alert-rules \
  | jq 'length'    # -> 9

# 4. Confirm Prometheus is scraping the gateway's metrics
#    (after the gateway has handled at least one tool call)
curl -s 'http://localhost:9090/api/v1/query?query=otel_enkrypt_tool_calls_total' \
  | jq '.data.result | length'   # -> >= 1

# 5. Trigger an injection violation against echo_server / echo and watch
#    the "Injection Attack Burst" rule transition to "firing" in
#    Grafana > Alerting > Alert rules within ~30s.  Slack message should
#    arrive within 0-5s of the firing transition (critical rules use
#    group_wait: 0s).
```

## Troubleshooting

### `Bind for 0.0.0.0:3001 failed: port is already allocated`

Native Grafana service or Docker WSL relay holds the port. Fix:

```bash
# In observability/.env.grafana
GRAFANA_HOST_PORT=3030
```

`docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d --force-recreate grafana` will pick it up.

### `token must be specified when using the Slack chat API`

Means `recipient:` was added to the Slack contact-point config — that
flips Grafana to the `chat.postMessage` API which requires a bot token.
Remove the `recipient:` field. Incoming-webhook mode (which we use) gets
the channel from the URL itself.

### Slack POSTs succeed but the message says `Server: n/a`

The metric isn't carrying the expected label. Check the helper call site
in `secure_tool_execution_service.py` — it should pass
`auth_context=auth_context` (which carries `user_id`, `project_id`) and
include `server_name`/`tool_name` directly. The Slack template only
renders a label line when the label exists.

### Dashboard panels show "No data"

Two common causes — check both:

**(a) Metric-name mismatch.** The dashboard query references a series
that doesn't exist. Cross-reference `docs/metric_reference.md` (source
of truth for OTel names → Prometheus series). The bundled dashboards
have been aligned to that table; if you wrote a new dashboard, list the
actually-emitted names with:

```bash
curl -s 'http://localhost:9090/api/v1/label/__name__/values' \
  | jq -r '.data[]' | grep enkrypt
```

**(b) Exact-match label filter against a multi-value "All" variable.**
If your panel filters with `metric{user_id="$user_id"}` (note the `=`,
not `=~`) and the variable is set to "All", Grafana substitutes
`$__all` -> empty string, so the query becomes `metric{user_id=""}`
which matches no series. The fix is `metric{user_id=~"$user_id"}` —
with `=~`, "All" expands to the regex `.*` and matches every series.
Cross-reference: open the panel's Query Inspector → Query, and look for
`=""` literals in the resolved query. This bit the bundled dashboard
once; see the matching CHANGELOG entry.

**(c) Panel queries a "wrapper" metric that doesn't exist.** Some
guardrail panels (Output / Relevancy / Adherence / Hallucination
Violations) historically queried per-check `*_blocks_total` series
(e.g. `otel_enkrypt_guardrail_relevancy_blocks_total`) that the gateway
never actually emits. The gateway emits a single
`otel_enkrypt_guardrail_blocks_total` with `direction` /
`violation_type` labels, so the correct query is
`rate(otel_enkrypt_guardrail_blocks_total{violation_type="relevancy"}[5m])`,
not a separate metric name. The bundled dashboards have been rewritten
this way; if you copy from an older snapshot, mind the rename.

### `dashboard title is not unique in folder` warning at startup

Two dashboard JSON files have the same root-level `"title"` field. Grafana
silently drops one of them. Set distinct titles or move conflicting files
to a sub-folder (and update `dashboards.yaml`'s `path:`).

### Grafana doesn't pick up `.env.grafana` changes

`docker compose restart grafana` re-runs the same container with its
existing env block. To re-read `.env.grafana`, force-recreate:

```bash
docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d --force-recreate grafana
```

## Where to look for what

| I want to see…                                   | Go to                                                                  |
| ------------------------------------------------ | ---------------------------------------------------------------------- |
| Live tool-call rate, latency, blocks             | Grafana → "OpenTelemetry Gateway Metrics" dashboard                    |
| Why a specific request was blocked               | Grafana → Explore → Loki → `{service_name="secure-mcp-gateway"}`       |
| End-to-end span for a single tool call           | Grafana → Explore → Jaeger, or `:16686` directly                       |
| Raw metric series                                | `http://localhost:9090/graph` (Prometheus UI)                          |
| Alert state / rule history                       | Grafana → Alerting → Alert rules / History                             |
| Slack delivery debug                             | `docker logs ... grafana` — search for `ngalert.notifier`              |
| Metric naming convention reference               | `../docs/metric_reference.md`                                          |

## Related docs

* `../docs/metric_reference.md` — every helper → OTel name → Prometheus
  series, with consuming alert rules.
* `../CHANGELOG.md` (Unreleased section) — recent telemetry & alerting
  changes.
* `../src/secure_mcp_gateway/plugins/telemetry/conventions.py` — the
  canonical list of metric / span / attribute names.
