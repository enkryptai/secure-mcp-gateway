# Dev OTel Collector — `logs/gateway` filter patch

Companion to `dev_otelcol_metrics_gateway_filter.md` (or whichever doc captured
the equivalent `metrics/gateway` patch). Applies the same noise-filter pattern
to the `ss4o_logs-gateway` data stream.

## Problem

The dev cluster's agent-side OTel Collector
(`opentelemetry/otel-collector-opentelemetry-collector-agent`) ran a single
`logs` pipeline that merged two receivers:

```
receivers: [otlp, filelog]   # gateway OTLP + every k8s pod's stdout/stderr
exporters: [otlp_http/loki, otlp/data_prepper_logs]
```

That sent **every** container log to Data Prepper, which writes the gateway's
SS4O `ss4o_logs-gateway` data stream. Result: ~32.8M docs in the data stream,
of which only ~4k per 24h are actually gateway logs. ~2000:1 noise-to-signal.

OpenSearch Dashboards' "Add filter → Value" suggestions endpoint runs a `terms`
aggregation with a hardcoded `terminate_after: 100000`. With 99.95% of recent
docs lacking `log.attributes.enkrypt@user@email` /
`log.attributes.user_email` (because they are container stdout, not gateway
OTLP), the scan terminates before finding enough non-empty values to populate
the dropdown. The user sees "There aren't any options available" even though
the data is in OpenSearch — KQL filters like `log.attributes.user_email :
"akhil@enkryptai.com"` still work, only the autocomplete dropdown is starved.

## Fix

Mirror what we already did for metrics:

1. Add `processors.filter/only_gateway_logs` that keeps only logs whose
   resource attribute `service.name == secure-mcp-gateway`.
2. Drop `otlp/data_prepper_logs` from the existing `logs` pipeline (it keeps
   exporting everything to Loki, which has no such suggestion-budget problem).
3. Add a new `logs/gateway` pipeline that takes only the `otlp` receiver,
   runs the new filter, and exports to Data Prepper.

## Patch (apply to `enkryptai-apiaas/code/infra/kubernetes/platform/opentelemetry-collector/config.yaml`)

### Add to `processors:` (next to the existing `filter/only_gateway`)

```yaml
filter/only_gateway_logs:
  logs:
    include:
      match_type: strict
      resource_attributes:
        - key: service.name
          value: secure-mcp-gateway
```

### Replace the existing `logs` pipeline and add `logs/gateway`

```yaml
logs:
  receivers:
    - otlp
    - filelog
  processors:
    - k8sattributes
    - memory_limiter
    - batch
  exporters:
    - otlp_http/loki                   # was: [otlp_http/loki, otlp/data_prepper_logs]

logs/gateway:
  receivers:
    - otlp
  processors:
    - k8sattributes
    - memory_limiter
    - filter/only_gateway_logs
    - batch
  exporters:
    - otlp/data_prepper_logs
```

## After ArgoCD syncs

1. Rolling restart the DaemonSet:

   ```bash
   kubectl -n opentelemetry rollout restart daemonset/otel-collector-opentelemetry-collector-agent
   kubectl -n opentelemetry rollout status   daemonset/otel-collector-opentelemetry-collector-agent --timeout=180s
   ```

2. Roll over the data stream so noise from before the rollout ages out of any
   "Last 15m / Last 1h" window:

   ```bash
   curl -sk -u "admin:$OS_ADMIN_PASS" -X POST \
     "https://opensearch.dev.enkryptai.com/ss4o_logs-gateway/_rollover"
   ```

   (A second rollover ~1 minute later evicts the brief noise blip that lands
   during the rolling restart, when some nodes still ran the old config while
   others ran the new — same behaviour we saw on the metrics rollout.)

3. Refresh the `gateway-*` index pattern in OSD (Stack Management → Index
   Patterns → refresh icon) so OSD picks up any newly-mapped fields.

## Verification

The "Add filter → Value" dropdown should populate for any of the
identity fields:

- `log.attributes.user_email`
- `log.attributes.user_id`
- `log.attributes.project_name`
- `log.attributes.org_id`
- `log.attributes.server_name`
- `log.attributes.tool_name`
- `log.attributes.gateway_name`
- `log.attributes.gateway_version`
- `log.attributes.project_registry`
- `log.attributes.project_id`

(All snake_case as of the 2026-05-26 single-form mode -- see
[`metric_attributes_key_mismatch.md`](metric_attributes_key_mismatch.md)
for how to re-enable the `enkrypt@*` dotted form alongside.)

Direct check via OS REST:

```bash
curl -sk -u "admin:$OS_ADMIN_PASS" \
  "https://opensearch.dev.enkryptai.com/ss4o_logs-gateway/_search" \
  -H 'content-type: application/json' \
  -d '{
    "size": 0,
    "query": {"range": {"time": {"gte": "now-15m"}}},
    "aggs": {"by_email": {"terms": {"field": "log.attributes.user_email", "size": 5}}}
  }' | jq '.aggregations.by_email.buckets'
```

Expected: one bucket per distinct authenticated user, with non-zero
`doc_count`.
