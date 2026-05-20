# OpenSearch query guide — gateway telemetry

Frontend / dashboard reference for querying Secure MCP Gateway telemetry
in OpenSearch. The gateway emits OTLP to an OTel collector → Data Prepper
→ three SS4O data streams; this guide gives you the exact field names,
time fields, and copy-pasteable queries for each.

- **Backend**: OpenSearch 2.19.1 with the Alerting plugin
- **Ingest**: Data Prepper 2.11 (Linux container)
- **Convention**: SS4O (Simple Schema for Observability) data streams,
  with friendly aliases attached at template creation
- **Auth**: Basic auth for now (local: `admin:<OPENSEARCH_INITIAL_ADMIN_PASSWORD>`;
  prod: a least-privilege read role — talk to your operator)

---

## Table of contents

1. [The three indices](#1-the-three-indices)
2. [Field name map (identity attributes)](#2-field-name-map-identity-attributes)
3. [Why field names differ across signals](#3-why-field-names-differ-across-signals)
4. [Querying traces](#4-querying-traces)
5. [Querying metrics](#5-querying-metrics)
6. [Querying logs](#6-querying-logs)
7. [Practical tips](#7-practical-tips)
8. [The registry-name gotcha](#8-the-registry-name-gotcha)
9. [SQL plugin alternative](#9-sql-plugin-alternative)
10. [Related](#10-related)

---

## 1. The three indices

The gateway emits three telemetry signals. Always use the **friendly
aliases** in queries — they survive index rollovers automatically and
spare you the SS4O internals.

| Signal | Friendly alias | Underlying data stream | Time field |
| ------ | -------------- | ---------------------- | ---------- |
| Traces | `gateway-traces` | `ss4o_traces-gateway` | `startTime` |
| Metrics | `gateway-metrics` | `ss4o_metrics-gateway` | `time` |
| Logs | `gateway-logs` | `ss4o_logs-gateway` | `time` |

All three start ingesting on first OTLP record. Aliases are attached
inline via each template's `aliases` block, so they exist from the very
first backing index.

---

## 2. Field name map (identity attributes)

Six identity attributes flow through every signal, sourced from the
cloud's `get-gateway-config` response (the `request_context` block):

```json
"request_context": {
  "user_id": "1388b711-f2c5-45b2-930b-3c91eb26e26d",
  "gateway_saved_name": "demo_mcp_gateway",
  "gateway_version": "v1",
  "org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
  "registry_name": "default",
  "project_name": "mcp-demo"
}
```

`/mcp-playground/*` traffic has two additional identity sources, both
also from the Enkrypt cloud:

- **Registry-header mode** — `GET /mcp-registry/get-server` populates
  `saved_name` / `server_version` / `registry_id` / `registry_name` /
  `project_name` (also exposed on the response's `registry` block).
- **Inline-body mode on enkrypt-provider gateways** — `GET /consumer-info`
  populates `user_id` / `org_id` / `project_name` / `email` /
  `is_internal_req` (also exposed on the response's `consumer` block).

Both paths set the same identity SpanAttributes (`enkrypt.user.id`,
`enkrypt.org.id`, `enkrypt.project.name`, etc.), so existing
identity-filtered dashboards pick up playground traffic automatically.

Here is where to find each one per signal:

| Identity | Traces | Metrics | Logs |
| -------- | ------ | ------- | ---- |
| `user_id` | `span.attributes.enkrypt@user@id` | `metric.attributes.user_id` | `log.attributes.user_id` |
| `gateway_saved_name` | `span.attributes.enkrypt@gateway@name` | `metric.attributes.gateway_name` | `log.attributes.gateway_name` |
| `gateway_version` | `span.attributes.enkrypt@gateway@version` | `metric.attributes.gateway_version` | `log.attributes.gateway_version` |
| `org_id` | `span.attributes.enkrypt@org@id` | `metric.attributes.org_id` | `log.attributes.org_id` |
| `registry_name` | `span.attributes.enkrypt@project@registry` | `metric.attributes.project_registry` | `log.attributes.registry_name` |
| `project_name` | `span.attributes.enkrypt@project@name` | `metric.attributes.project_name` | `log.attributes.project_name` |

Also useful, available on the same signals where applicable:

| Field | Traces | Metrics | Logs |
| ----- | ------ | ------- | ---- |
| `project_id` | `span.attributes.enkrypt@project@id` | `metric.attributes.project_id` | `log.attributes.project_id` |
| `email` | `span.attributes.enkrypt@user@email` | `metric.attributes.user_email` ² | `log.attributes.email` |
| `mcp_config_id` | `span.attributes.enkrypt@config@id` | — | `log.attributes.mcp_config_id` |
| `gateway_key` (masked) | `span.attributes.enkrypt@gateway@key` | — | — |
| `server_name` | `span.attributes.enkrypt@server@name` | `metric.attributes.server_name` (where relevant) | `log.attributes.server_name` |
| `tool_name` | — | `metric.attributes.tool_name` | — |
| `is_internal_req` ¹ | `span.attributes.enkrypt@user@is_internal_req` | `metric.attributes.is_internal_req` | `log.attributes.is_internal_req` |
| `auth_provider` ¹ | — | — | `log.attributes.auth_provider` |
| `playground_mode` ¹ | — | — | `log.attributes.playground_mode` |
| `transport` ¹ | — | — | `log.attributes.transport` |

¹ Only populated for `/mcp-playground/*` requests. `is_internal_req`
specifically only flows when the gateway runs `plugins.auth.provider =
"enkrypt"` and the playground is called in inline-body mode (the
`/consumer-info` path); it's `true` for dashboard / next-js / staff
keys, useful for splitting internal traffic from customer traffic in
dashboards. On metrics it's stringified `"true"`/`"false"` to keep
label cardinality bounded.

² `metric.attributes.user_email` is emitted on the tool-call lifecycle
(`enkrypt.tool.*`), guardrail violation (`enkrypt.guardrail.*`), and PII
redaction (`enkrypt.pii.redactions`) counters when the cloud auth
provider promotes `request_context.forwarded_user_email` from the
`GET /mcp-gateway/get-gateway-config` response. Local-apikey gateways
and cloud gateways called without a forwarded end-user identity leave
the field absent (stripped by `_safe_attrs`) — filter with
`exists` rather than expecting a sentinel.

---

## 3. Why field names differ across signals

If you noticed the asymmetry in the table — yes, **spans namespace
identity under `enkrypt.*`, but metrics and logs use bare snake_case**.

The "why":

- **Spans** are set with the gateway's typed `SpanAttributes`
  constants (see [`conventions.py`](../src/secure_mcp_gateway/plugins/telemetry/conventions.py)).
  Every attribute is dotted: `enkrypt.user.id`,
  `enkrypt.gateway.name`, etc. Data Prepper's `otel_traces` processor
  flattens those dots into `@`-separators so OpenSearch sees them as
  flat keyword fields — hence `span.attributes.enkrypt@user@id`.
- **Metrics** are tagged in `metrics_helpers.py` using OTel attribute
  dicts with bare keys (`{"user_id": ..., "org_id": ...}`). No dots,
  no flattening — they land as `metric.attributes.user_id`.
- **Logs** flow through Python's `logging` module: `build_log_extra`
  returns a dict with bare keys (`{"user_id": ..., "org_id": ...}`)
  which the OTel `LoggingHandler` attaches as log record attributes.
  Result: `log.attributes.user_id`.

Quote field names containing `@` in JSON queries — they're valid JSON
identifiers but easy to misread. URL-encode them in query strings
(`%40`).

---

## 4. Querying traces

### Find a user's recent spans in a given gateway version

```http
POST gateway-traces/_search
Content-Type: application/json

{
  "size": 50,
  "sort": [{ "startTime": "desc" }],
  "query": {
    "bool": {
      "filter": [
        { "term":  { "span.attributes.enkrypt@user@id": "1388b711-f2c5-45b2-930b-3c91eb26e26d" } },
        { "term":  { "span.attributes.enkrypt@gateway@version": "v1" } },
        { "range": { "startTime": { "gte": "now-1h" } } }
      ]
    }
  }
}
```

### Error spans grouped by org + gateway version

```http
POST gateway-traces/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "status.code": 2 } },
        { "range": { "startTime": { "gte": "now-24h" } } }
      ]
    }
  },
  "aggs": {
    "by_tenant": {
      "composite": {
        "size": 100,
        "sources": [
          { "org":     { "terms": { "field": "span.attributes.enkrypt@org@id" } } },
          { "gateway": { "terms": { "field": "span.attributes.enkrypt@gateway@name" } } },
          { "version": { "terms": { "field": "span.attributes.enkrypt@gateway@version" } } }
        ]
      }
    }
  }
}
```

### Trace duration distribution per tool

Span duration is `durationInNanos`. To get latency percentiles per
tool name:

```http
POST gateway-traces/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [{ "range": { "startTime": { "gte": "now-1h" } } }]
    }
  },
  "aggs": {
    "by_tool": {
      "terms": { "field": "span.attributes.enkrypt@tool@name", "size": 20 },
      "aggs":  {
        "latency_pct": {
          "percentiles": {
            "field": "durationInNanos",
            "percents": [50, 95, 99]
          }
        }
      }
    }
  }
}
```

### Full-text search inside span attributes

For OpenSearch Dashboards' Observability plugin (Trace Analytics) the
same fields appear in the right-hand attribute panel under their dotted
OTel names — copy a `user_id` from there straight into your query.

---

## 5. Querying metrics

Metric names live at the **top-level `name` field** (NOT under
`metric.attributes`). The value lives at `value`. Metric attributes
(`user_id`, `org_id`, `server_name`, etc.) live at `metric.attributes.*`.

The gateway emits metrics with **DELTA** aggregation temporality, so
you almost always want `sum(value)` over a window. **Always** filter
by `aggregationTemporality: AGGREGATION_TEMPORALITY_DELTA` to be safe
— the index can contain cumulative copies from older collectors.

### Tool calls per registry + project (last hour)

```http
POST gateway-metrics/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "name": "enkrypt.tool.calls" } },
        { "term":  { "aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA" } },
        { "range": { "time": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_registry_project": {
      "composite": {
        "size": 50,
        "sources": [
          { "registry": { "terms": { "field": "metric.attributes.project_registry" } } },
          { "project":  { "terms": { "field": "metric.attributes.project_name" } } }
        ]
      },
      "aggs": {
        "calls": { "sum": { "field": "value" } }
      }
    }
  }
}
```

### Per-user guardrail blocks (last 24h)

Same shape used by the alerting plugin's monitor #7
("User Targeting — Guardrails"):

```http
POST gateway-metrics/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "name": "enkrypt.guardrail.blocks" } },
        { "term":  { "aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA" } },
        { "range": { "time": { "gte": "now-24h" } } }
      ]
    }
  },
  "aggs": {
    "by_user": {
      "terms": { "field": "metric.attributes.user_id", "size": 20 },
      "aggs":  { "blocks": { "sum": { "field": "value" } } }
    }
  }
}
```

Swap the terms field to `metric.attributes.user_email` to bucket by end
user instead of internal UUID — useful when reading the result without
a side trip through the cloud's user-lookup. Only populated for traffic
where the calling app forwarded an end-user identity (see footnote ²).

### Histogram average (e.g. tool duration)

For histogram metrics like `enkrypt.tool.duration`, sum the `sum` and
`count` fields, then divide in the FE:

```http
POST gateway-metrics/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "name": "enkrypt.tool.duration" } },
        { "term":  { "kind": "HISTOGRAM" } },
        { "range": { "time": { "gte": "now-15m" } } }
      ]
    }
  },
  "aggs": {
    "sum_of_sum":   { "sum": { "field": "sum" } },
    "sum_of_count": { "sum": { "field": "count" } }
  }
}
```

Then: `avg_seconds = aggs.sum_of_sum.value / aggs.sum_of_count.value`.

### Canonical metric names

A few that the gateway emits today (full list in
[`conventions.py:MetricNames`](../src/secure_mcp_gateway/plugins/telemetry/conventions.py)):

| Name | Kind | What it counts |
| ---- | ---- | -------------- |
| `enkrypt.tool.calls` | counter | every tool invocation |
| `enkrypt.tool.duration` | histogram | tool execution latency (seconds) |
| `enkrypt.tool.blocked` | counter | tool calls blocked by guardrails/deny-list |
| `enkrypt.guardrail.checks` | counter | guardrail API calls (input + output) |
| `enkrypt.guardrail.blocks` | counter | guardrail violations resulting in a block |
| `enkrypt.guardrail.duration` | histogram | guardrail API latency (seconds) |
| `enkrypt.cache.hits` / `.misses` | counter | session/tool cache outcome |
| `enkrypt.discovery.list_servers` | counter | server-listing invocations |
| `enkrypt.discovery.servers_found` | counter | total servers discovered per request |
| `enkrypt.auth.failure` | counter | failed authentications |
| `enkrypt.pii.redactions` | counter | PII redaction operations |
| `enkrypt.playground.registry_lookup.duration` | histogram | `GET /mcp-registry/get-server` latency (**ms**) emitted per call from the playground in registry-header mode. Labelled `outcome` (`success`/`auth_error`/`not_found`/`upstream_error`/`timeout`), `cache` (`hit`/`miss`), `status_code`, plus `saved_name` / `server_version` / `registry_name` / `project_name`. |
| `enkrypt.playground.consumer_info_lookup.duration` | histogram | `GET /consumer-info` latency (**ms**) emitted per call from the playground in inline-body + provider=enkrypt mode. Labelled `outcome` (`success`/`auth_error`/`upstream_error`/`timeout`), `cache` (`hit`/`miss`), `status_code`, plus `user_id` / `org_id` / `project_name` / `is_internal_req`. 5-minute in-process cache, so `cache=hit` rows have `value ≈ 0`. |

> **Unit gotcha**: most gateway histograms (`enkrypt.tool.duration`,
> `enkrypt.guardrail.duration`) emit **seconds**. The two
> `enkrypt.playground.*_lookup.duration` histograms emit **milliseconds**
> — Grafana panels and OpenSearch monitors should divide by 1000 if
> normalising onto the same axis as the other gateway latencies.

---

## 6. Querying logs

Log records have `severityText` (`INFO|WARN|ERROR|DEBUG`), `body`
(both `text` for search and `body.keyword` for aggregation), and
`log.attributes.*` for the structured fields from `build_log_extra`.

### Recent ERROR/WARN for one gateway

```http
POST gateway-logs/_search
{
  "size": 100,
  "sort": [{ "time": "desc" }],
  "query": {
    "bool": {
      "filter": [
        { "terms": { "severityText": ["ERROR", "WARN"] } },
        { "term":  { "log.attributes.gateway_name":    "demo_mcp_gateway" } },
        { "term":  { "log.attributes.gateway_version": "v1" } },
        { "range": { "time": { "gte": "now-1h" } } }
      ]
    }
  },
  "_source": [
    "time", "severityText", "body",
    "log.attributes.user_id", "log.attributes.org_id",
    "log.attributes.project_name", "log.attributes.registry_name"
  ]
}
```

### Free-text body search scoped to an org

```http
POST gateway-logs/_search
{
  "size": 20,
  "query": {
    "bool": {
      "must":   [{ "match": { "body": "guardrail blocked" } }],
      "filter": [
        { "term":  { "log.attributes.org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab" } },
        { "range": { "time": { "gte": "now-24h" } } }
      ]
    }
  }
}
```

---

## 7. Practical tips

1. **Always pin `aggregationTemporality: AGGREGATION_TEMPORALITY_DELTA`**
   when summing metric `value` — without it your sums double-count any
   cumulative series in the index.

2. **Use the friendly aliases** (`gateway-metrics`/`gateway-traces`/
   `gateway-logs`), not the SS4O index names. They follow rollovers
   automatically.

3. **Missing-field semantics**: cloud-side `null` becomes either
   absent (spans) or the literal `"not_provided"` (logs and most
   metric attrs — `build_log_extra` and `_safe_attrs` write
   `"not_provided"` so dashboards always see a stable token). Defensive
   filter:

   ```json
   {
     "bool": {
       "should": [
         { "term":  { "metric.attributes.org_id": "not_provided" } },
         { "bool": { "must_not": [{ "exists": { "field": "metric.attributes.org_id" } }] } }
       ],
       "minimum_should_match": 1
     }
   }
   ```

4. **JSON quoting of `@`**: no escaping needed in JSON bodies (HTTP
   client like `fetch`/axios). For URL-encoded query strings,
   `@` → `%40`.

5. **OpenSearch Dashboards Discover** uses the exact same field names.
   For ad-hoc validation: `http://<host>:5601` → Discover → pick the
   `gateway-metrics`/`gateway-traces`/`gateway-logs` index pattern →
   KQL: `span.attributes.enkrypt@user@id : "<uuid>"`.

6. **Cardinality awareness**: `user_id`, `org_id`, `mcp_config_id`
   are high-cardinality. For top-N alerts/aggregations, use `terms`
   aggs with a `size` cap rather than unbounded composite paging.

7. **Auth headers**: standard HTTP basic auth.

   ```http
   GET gateway-metrics/_count
   Authorization: Basic <base64(user:pass)>
   ```

   Don't burn the `admin` password in FE code — get a read-only role
   from the operator and use that instead. The role only needs
   `crud + indices_monitor` on `ss4o_*-gateway*`.

---

## 8. The registry-name gotcha

This is the **only** field whose name differs across all three signals
(pre-existing inconsistency, not a recent change):

- Traces: `span.attributes.enkrypt@project@registry`
- Metrics: `metric.attributes.project_registry`
- Logs: `log.attributes.registry_name`

If you build a shared "identity filter" component on the FE, parametrize
by signal kind and dispatch to the right field name. Don't assume one
canonical name works everywhere.

---

## 9. SQL plugin alternative

If you prefer SQL over DSL, the OS SQL plugin works on the same fields.
Watch the escaping: `@` in identifiers needs double-quoting.

```http
POST _plugins/_sql
Content-Type: application/json

{
  "query": "SELECT span.attributes.\"enkrypt@user@id\" AS user_id, COUNT(*) AS spans FROM \"gateway-traces\" WHERE startTime > now() - INTERVAL 1 HOUR GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
}
```

PPL (Piped Processing Language, the OpenSearch native alternative)
also works:

```http
POST _plugins/_ppl
{
  "query": "source=gateway-traces | where startTime > now() - 1h | stats count() by span.attributes.enkrypt@user@id | head 10"
}
```

---

## 10. Related

- [`observability/README.opensearch.md`](../observability/README.opensearch.md)
  — the OpenSearch stack as a whole (bootstrap, ISM policy, alerting)
- [`src/secure_mcp_gateway/plugins/telemetry/conventions.py`](../src/secure_mcp_gateway/plugins/telemetry/conventions.py)
  — canonical `SpanAttributes`, `SpanNames`, `MetricNames`
- [`src/secure_mcp_gateway/utils.py`](../src/secure_mcp_gateway/utils.py)
  (`build_log_extra`) — the function that produces `log.attributes.*`
- [`src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py`](../src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py)
  — the `record_*` helpers that set `metric.attributes.*`
- [`observability/opensearch/monitors/`](../observability/opensearch/monitors/)
  — concrete alerting queries the gateway provisions out of the box;
  good worked examples of the DSL shape
