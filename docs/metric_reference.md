# Metric Reference - secure-mcp-gateway

This document describes the Prometheus / OpenTelemetry metrics emitted by the
gateway, where they are wired in code, and which alert rules consume them.

It is the developer-facing companion to the operator-facing alert pack at
`observability/grafana/provisioning/alerting/rules.yaml`.

## Naming convention

The gateway uses OpenTelemetry instrument names of the form
`enkrypt.<area>.<metric>`. The OTel Collector exporter
(`observability/otel_collector/otel-collector-config.yaml`) is configured with:

```yaml
exporters:
  prometheus:
    namespace: "otel"
    const_labels:
      service_name: "secure-mcp-gateway"
```

so a counter `enkrypt.guardrail.blocks` becomes the Prometheus series

```
otel_enkrypt_guardrail_blocks_total{service_name="secure-mcp-gateway", ...}
```

Histograms get the unit suffix appended (`enkrypt.guardrail.duration` with
`unit="s"` becomes `otel_enkrypt_guardrail_duration_seconds_{bucket,sum,count}`).

## Helper module

All non-trivial metric writes go through
`src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py`. The helpers:

* never raise (return early if telemetry is uninitialised);
* drop `None` attribute values (OTel SDK rejects them);
* attach a consistent label set per metric family.

Use them rather than calling `.add()` / `.record()` directly, so attribute
naming stays uniform across call sites.

## Metric catalog

### Tool-call lifecycle

| Helper attribute              | OTel name                | Prometheus series                          | Wired in                                                                                            |
| ----------------------------- | ------------------------ | ------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `tool_call_counter`           | `enkrypt.tool.calls`     | `otel_enkrypt_tool_calls_total`            | `services/discovery/discovery_service.py` (pre-existing)                                            |
| `tool_call_duration`          | `enkrypt.tool.duration`  | `otel_enkrypt_tool_duration_seconds_*`     | `services/discovery/discovery_service.py` (pre-existing)                                            |
| `tool_call_success_counter`   | `enkrypt.tool.success`   | `otel_enkrypt_tool_success_total`          | `services/execution/secure_tool_execution_service.py::_build_successful_result`                     |
| `tool_call_failure_counter`   | `enkrypt.tool.failures`  | `otel_enkrypt_tool_failures_total`         | reserved (currently unused)                                                                         |
| `tool_call_error_counter`     | `enkrypt.tool.errors`    | `otel_enkrypt_tool_errors_total`           | `secure_tool_execution_service.py` exception handler around `_execute_single_tool`                  |
| `tool_call_blocked_counter`   | `enkrypt.tool.blocked`   | `otel_enkrypt_tool_blocked_total`          | `_build_blocked_result` (input/output violations) and the deny-list block path in `_execute_single_tool` |

Labels: `server_name`, `tool_name`, `outcome`, plus `block_reason` when
`outcome="blocked"`, plus optional `user_id` / `project_id` (see
"Per-principal labels" below). `block_reason` values are:
`input_violation`, `output_violation`, `deny_list`.

### Guardrail violations

| Helper attribute                       | OTel name                                  | Prometheus series                                       |
| -------------------------------------- | ------------------------------------------ | ------------------------------------------------------- |
| `guardrail_violation_counter`          | `enkrypt.guardrail.blocks`                 | `otel_enkrypt_guardrail_blocks_total`                   |
| `input_guardrail_violation_counter`    | `enkrypt.guardrail.input_blocks`           | `otel_enkrypt_guardrail_input_blocks_total`             |
| `output_guardrail_violation_counter`   | `enkrypt.guardrail.output_blocks`          | `otel_enkrypt_guardrail_output_blocks_total`            |
| `relevancy_violation_counter`          | `enkrypt.guardrail.relevancy_blocks`       | `otel_enkrypt_guardrail_relevancy_blocks_total`         |
| `adherence_violation_counter`          | `enkrypt.guardrail.adherence_blocks`       | `otel_enkrypt_guardrail_adherence_blocks_total`         |
| `hallucination_violation_counter`      | `enkrypt.guardrail.hallucination_blocks`   | `otel_enkrypt_guardrail_hallucination_blocks_total`     |

Wired through `record_guardrail_violations(direction, violation_types, ...)` in
`secure_tool_execution_service.py` at three call sites:

* `_execute_with_input_guardrails` when `guardrail_response.is_safe == False`
* `_process_sync_output_guardrails` when `has_blocking == True`
* `_process_async_output_guardrails` when `has_blocking == True`

Labels: `direction` (`input` or `output`), `violation_type`, `server_name`,
`tool_name`, optional `policy_name`, optional `user_id`, optional
`project_id`. The per-check counters (`relevancy_violation_counter`,
`adherence_violation_counter`, `hallucination_violation_counter`) are only
incremented when the `violation_type` value matches their kind, so they
remain a true subset of the overall counter.

`user_id` and `project_id` are threaded in from
`secure_tool_execution_service::_execute_tools_with_guardrails` via an
`auth_context` dict so each metric increment carries the authenticated
principal — see the "Per-principal labels" note below.

### Guardrail provider HTTP calls

| Helper attribute                  | OTel name                    | Prometheus series                                |
| --------------------------------- | ---------------------------- | ------------------------------------------------ |
| `guardrail_api_request_counter`   | `enkrypt.guardrail.checks`   | `otel_enkrypt_guardrail_checks_total`            |
| `guardrail_api_request_duration`  | `enkrypt.guardrail.duration` | `otel_enkrypt_guardrail_duration_seconds_*`      |

Wired through `_post_with_metrics()` in
`plugins/guardrails/enkrypt_provider.py`, used by:

* `EnkryptInputGuardrail.validate` (`check_kind="policy"`, `direction="input"`)
* `EnkryptOutputGuardrail._check_policy` (`output`, `policy`)
* `EnkryptOutputGuardrail._check_relevancy` (`output`, `relevancy`)
* `EnkryptOutputGuardrail._check_adherence` (`output`, `adherence`)
* `EnkryptOutputGuardrail._check_hallucination` (`output`, `hallucination`)
* `EnkryptPIIHandler.detect_pii` (`input`, `pii_detect`)
* `EnkryptPIIHandler.redact_pii` (`input`, `pii_redact`)
* `EnkryptPIIHandler.restore_pii` (`output`, `pii_restore`)

Labels: `direction`, `check_kind`, `provider` (=`enkrypt`), `status_code`
(string; `"0"` is used for client-side / network failures so failed external
calls still appear in the latency histogram).

### PII

| Helper attribute          | OTel name                | Prometheus series                       |
| ------------------------- | ------------------------ | --------------------------------------- |
| `pii_redactions_counter`  | `enkrypt.pii.redactions` | `otel_enkrypt_pii_redactions_total`     |

Wired in `plugins/guardrails/enkrypt_provider.py`:

* `redact_pii` increments with `direction="input"` only when the redaction
  endpoint actually rewrote the text.
* `restore_pii` increments with `direction="output"` only when the response
  endpoint actually rewrote the text.

This means the metric reflects *real* PII events, not the baseline rate of
PII checks.

### Auth

| Helper attribute        | OTel name              | Prometheus series                  |
| ----------------------- | ---------------------- | ---------------------------------- |
| `auth_success_counter`  | `enkrypt.auth.success` | `otel_enkrypt_auth_success_total`  |
| `auth_failure_counter`  | `enkrypt.auth.failure` | `otel_enkrypt_auth_failure_total`  |

Wired around the public `authenticate()` method of:

* `plugins/auth/local_apikey_provider.py::LocalApiKeyProvider`
* `plugins/auth/enkrypt_provider.py::EnkryptAuthProvider`

The implementation funnels through `_authenticate_impl` so the counter fires
once per top-level call regardless of which return path is taken (including
the broad `except Exception` path).

Labels: `provider` (provider name as returned by `get_name()`), `outcome`,
plus `failure_reason` on failure. `failure_reason` defaults to
`AuthResult.error` and falls back to `AuthResult.status.value`.

### Per-principal labels (`user_id`, `project_id`)

`record_tool_call_outcome`, `record_guardrail_violations` and
`record_pii_redaction` accept optional `user_id` and `project_id` keyword
arguments. They are threaded through `secure_tool_execution_service`:

```
_execute_tools_with_guardrails  (auth_context = {user_id, project_id} from gateway_config)
   └─ _execute_single_tool(... auth_context=auth_context)
        ├─ _execute_with_input_guardrails(... auth_context=...)
        ├─ _process_sync_output_guardrails(... auth_context=...)
        ├─ _process_async_output_guardrails(... auth_context=...)
        ├─ _build_blocked_result(... auth_context=...)
        └─ _build_successful_result(... auth_context=...)
```

`_safe_attrs` strips the labels when they are `None` or empty strings, so
unauthenticated paths (e.g. a 401 before the principal is resolved) don't
inflate label cardinality with empty values. This is what powers the
per-user `mcpgw-user-targeting-guardrails` alert via PromQL
`sum by (user_id) (increase(otel_enkrypt_guardrail_blocks_total{user_id!=""}[10m]))`.

## Alert rules backed by these metrics

`observability/grafana/provisioning/alerting/rules.yaml` consumes these
metrics through the rules below. All rules are scoped to
`service_name="secure-mcp-gateway"`.

| Rule UID                          | Severity  | Backing query (summary)                                                       |
| --------------------------------- | --------- | ----------------------------------------------------------------------------- |
| `mcpgw-policy-violation-burst`    | critical  | `increase(otel_enkrypt_guardrail_blocks_total{violation_type="policy_violation"}[5m]) > 5` |
| `mcpgw-injection-attack-burst`    | critical  | `increase(otel_enkrypt_guardrail_input_blocks_total{violation_type="injection_attack"}[5m]) > 3` |
| `mcpgw-pii-found`                 | critical  | `increase(otel_enkrypt_pii_redactions_total[1m]) > 0`                          |
| `mcpgw-toxicity-nsfw-surge`       | warning   | `increase(otel_enkrypt_guardrail_blocks_total{violation_type=~"toxicity|nsfw"}[10m]) > 5` |
| `mcpgw-output-quality-failure`    | warning   | sum of relevancy + adherence + hallucination per-check counters > 3 / 10m     |
| `mcpgw-tool-deny-list-burst`      | warning   | `increase(otel_enkrypt_tool_blocked_total{block_reason="deny_list"}[5m]) > 5` |
| `mcpgw-user-targeting-guardrails` | critical  | `sum by (user_id) (increase(otel_enkrypt_guardrail_blocks_total{user_id!=""}[10m])) > 10` |
| `mcpgw-guardrail-api-latency`     | warning   | `histogram_quantile(0.95, ...) > 2s`                                           |
| `mcpgw-auth-failure-burst`        | critical  | `increase(otel_enkrypt_auth_failure_total[5m]) > 10`                           |

## Open gaps

* **Failure / cancellation paths.** `tool_call_failure_counter` is declared
  but never incremented yet - we do not have a clear "tool returned an
  application-level failure but did not raise" path in the current
  execution service. If a future change distinguishes failure from error
  on the tool-execution result, wire it in `_build_blocked_result` /
  `_build_successful_result` consistently.

* **Example providers.** The example auth providers in
  `plugins/auth/example_providers.py` (4 separate `authenticate()` methods)
  are not wired. They are demo classes; if they ever back a real
  deployment they should adopt the same `_authenticate_impl` pattern.

* **`/metrics` end-to-end smoke test.** The current automated tests cover
  the helper routing logic. A live test that turns telemetry on, exercises
  the gateway against a fake MCP server, and asserts series appear in
  Prometheus would close the loop. Pending an integration-test harness.

## Adding a new metric

1. Add the OTel name to `plugins/telemetry/conventions.py::MetricNames`
   plus a description in `METRIC_DESCRIPTIONS`.
2. Create the instrument inside both
   `OpenTelemetryProvider._create_metrics` (active path) and
   `OpenTelemetryProvider._setup_disabled_telemetry` (no-op path).
3. Add a property accessor on `TelemetryConfigManager` if external code
   needs to read it without going through a helper.
4. Add (or extend) a helper in
   `plugins/telemetry/metrics_helpers.py` that takes domain arguments and
   never raises.
5. Wire the helper at the relevant decision point in the application
   layer. Do not call `.add()` / `.record()` directly from execution
   services or providers - go through the helper so attribute naming is
   uniform.
6. Add a unit test alongside the existing ones in
   `tests/test_metrics_helpers.py` that asserts the helper routes to the
   correct instrument.
7. If the new metric is alert-worthy, add a rule to
   `observability/grafana/provisioning/alerting/rules.yaml` and document
   it under "Alert rules" above.
