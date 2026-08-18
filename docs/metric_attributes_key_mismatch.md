# Identity Attribute Naming — Issue & Fix (logs / metrics / traces)

> **2026-05-26 update — single-form (snake_case-only) mode**
>
> The gateway used to emit identity attributes in **both** forms (canonical
> `enkrypt.*` dotted + snake_case alias). As of commit `4bdcb20` it emits
> the **snake_case form only**. Use these field names everywhere
> (monitors, dashboards, PPL queries, Slack alert templates):
>
> ```text
> log.attributes.user_email          metric.attributes.user_email          span.attributes.user_email
> log.attributes.user_id             metric.attributes.user_id             span.attributes.user_id
> log.attributes.project_id          metric.attributes.project_id          span.attributes.project_id
> log.attributes.project_name        metric.attributes.project_name        span.attributes.project_name
> log.attributes.project_registry    metric.attributes.project_registry    span.attributes.project_registry
> log.attributes.org_id              metric.attributes.org_id              span.attributes.org_id
> log.attributes.gateway_name        metric.attributes.gateway_name        span.attributes.gateway_name
> log.attributes.gateway_version     metric.attributes.gateway_version     span.attributes.gateway_version
> log.attributes.server_name         metric.attributes.server_name         span.attributes.server_name
> log.attributes.tool_name           metric.attributes.tool_name           span.attributes.tool_name
> ```
>
> The dotted/`enkrypt@*` form is **not emitted on new docs**; old
> backing indices still carry it until ISM ages them out.
>
> To restore the dual-emission behaviour described in the rest of this
> document, swap the commented-out lines in:
> - `src/secure_mcp_gateway/log.py` -- `CANONICAL_ATTR_KEYS`
> - `src/secure_mcp_gateway/plugins/telemetry/conventions.py` -- `SpanAttributes` identity constants
>
> Every helper (`set_span_attr_with_legacy`, `add_legacy_filter_aliases`,
> `_canonicalize_event_dict`, `_identity_attrs_from_context`) is
> direction-agnostic and works either way.
>
> The rest of this doc describes the original snake_case-only ->
> dual-form migration that landed earlier on this branch, kept here for
> historical context and so the original Option-B design is documented
> if the dual form is ever turned back on.

---

## Issue (in plain words)

The gateway used to emit **metrics** and **logs** with identity attribute
keys in flat `snake_case` (`server_name`, `project_id`, `user_id`, ...),
but every dashboard / alert / index-template `_meta` example expected the
dotted **`enkrypt.*`** convention (`enkrypt.server.name`,
`enkrypt.project.id`, `enkrypt.user.id`, ...).

In OpenSearch the business attributes were therefore landing at
`metric.attributes.server_name` and `log.attributes.server_name` instead
of the dotted `*.attributes.enkrypt@*` form, and any dashboard pivoting
on `enkrypt@*` saw nothing. The trace pipeline was already fine —
`SpanAttributes` constants were used consistently — only the metric and
log pipelines had drifted.

A second, separate bug surfaced during verification: the
`EnkryptAuthProvider` was substituting the literal sentinel
`"enkrypt_principal"` for `user_id` whenever the cloud's `request_context`
didn't surface a real user, polluting dashboards with a value that
didn't exist in the customer's user table.

## Why it happened

- `plugins/telemetry/conventions.py` defines canonical dotted keys
  (e.g. `SpanAttributes.SERVER_NAME = "enkrypt.server.name"`).
- ~24 call sites used those constants via `span.set_attribute(...)`.
- **Zero call sites used them for metrics or log records.** Metric sites
  passed `attributes=build_log_extra(ctx, ...)` and log sites passed
  `extra=build_log_extra(ctx, ...)`.
- `utils.build_log_extra()` returned a flat snake_case dict
  (`{"server_name": ..., "project_id": ..., ...}`).
- `metrics_helpers._safe_attrs()` was a no-op pass-through — no key
  rewriting.

Result: metric and log docs in OpenSearch carried
`metric.attributes.server_name` / `log.attributes.server_name`, while the
`enkrypt@*` namespace existed only on trace docs.

## Fix (Option B — single-source canonicalizer)

Both `build_log_extra` and `metrics_helpers._safe_attrs` now route through
a shared `canonicalize_attr_keys()` helper in `utils.py`. Identity keys
are rewritten to the dotted `enkrypt.*` convention; categorical /
diagnostic keys (`outcome`, `direction`, `provider`, `check_kind`,
`status_code`, `violation_type`, `failure_reason`, `block_reason`,
`cache`, ad-hoc `**kwargs`) pass through unchanged.

| OpenSearch field today | Source signal |
|---|---|
| `*.attributes.enkrypt@server@name` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@project@id` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@user@id` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@user@email` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@gateway@name` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@gateway@version` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@org@id` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@project@name` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@project@registry` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@config@id` | logs ✓ metrics ✓ |
| `*.attributes.enkrypt@custom@id` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@tool@name` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@guardrail@name` | logs ✓ traces ✓ metrics ✓ |
| `*.attributes.enkrypt@error@message` | logs ✓ metrics ✓ |
| `*.attributes.outcome` | metrics (categorical, unchanged) |
| `*.attributes.direction` | metrics (categorical, unchanged) |
| `*.attributes.provider` | metrics (categorical, unchanged) |

## Files changed

### Naming-convention fix (logs + metrics + traces)

- `src/secure_mcp_gateway/log.py` (foundation module — single source of truth)
  - Added `CANONICAL_ATTR_KEYS` (snake_case → dotted map).
  - Added `canonicalize_attr_keys(attrs)` public helper.
  - Added `_canonicalize_event_dict` structlog processor wired into both
    `shared_processors` (for native structlog calls) and the stdlib
    `ProcessorFormatter`'s `foreign_pre_chain` (for stdlib
    `logger.info(..., extra={...})` calls). Catches **every** log site,
    including the inline `extra={...}` dicts in `services/...py` that
    bypass `build_log_extra`. No per-site sweep needed.
- `src/secure_mcp_gateway/utils.py`
  - Re-exports `CANONICAL_ATTR_KEYS` and `canonicalize_attr_keys` from
    `log.py` so existing imports keep working.
  - Rewired `build_log_extra` to emit dotted keys for fixed identity
    params and to canonicalize known kwargs (`tool_name`, `request_id`,
    `num_tool_calls`, `tool_arguments`, `guardrail_name`).
- `src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py`
  - `_safe_attrs` now calls `canonicalize_attr_keys` so every helper
    (`record_tool_call_outcome`, `record_guardrail_violations`,
    `record_pii_redaction`, `record_auth_outcome`, `record_guardrail_api`,
    `record_registry_lookup`, `record_consumer_info_lookup`) emits dotted
    identity keys without touching its call sites.
- `tests/test_metrics_helpers.py`
  - All 23 tests updated to assert on the new dotted identity keys; both
    snake_case and dotted forms are now checked in the
    "omitted-when-None / -empty" tests so a regression that re-introduces
    either form fails loudly.

### `user_id` data-correctness fix

- `src/secure_mcp_gateway/plugins/auth/enkrypt_provider.py`
  - Removed the `or "enkrypt_principal"` fallback at the
    `request_context.get("user_id")` lookup. When the cloud doesn't
    surface a user, `user_id` now stays `None` and `_safe_attrs` /
    `build_log_extra` strip the field entirely (matching the existing
    `org_id` / `registry_name` pattern). No more synthetic
    `enkrypt_principal` value in dashboards.
  - `composite_id` (cache / session key) now falls back to `gateway_id`
    when `user_id` is `None` so the key stays stable per apikey.
- `tests/test_enkrypt_auth_provider.py`
  - Updated `test_map_response_handles_missing_request_context` to
    assert `user_id is None` (matches the new behaviour).

## What was NOT changed (intentional)

- The `enkrypt_mcp_config.json` schema — local config fields stay
  `project_id` / `user_id` / `mcp_config_id` etc. so existing CLI / REST
  clients keep working.
- Span attributes — `plugins/...py` already used `SpanAttributes.*` (the
  dotted names) for `span.set_attribute(...)`, so traces were already
  correct.
- Categorical metric attrs (`outcome`, `direction`, `provider`,
  `check_kind`, `status_code`, `violation_type`, `block_reason`,
  `failure_reason`, `cache`, `is_internal_req`) — there are no canonical
  dotted equivalents in `conventions.py` and dashboards already query
  these snake_case names, so they pass through unchanged.

## Verification

- `python -m pytest tests/test_metrics_helpers.py` → **23 passed**.
- `python -m pytest tests/ --ignore=…sandbox/cli/integration` →
  **313 passed**.
- Live gateway terminal log after restart shows the new dotted keys, e.g.:

  ```text
  extra={'enkrypt.custom.id': 'daaabfa6-...',
         'enkrypt.server.name': 'test-deepwiki-hosted-public',
         'enkrypt.gateway.name': 'demo_mcp_gateway',
         'enkrypt.user.id': '',  # cloud didn't surface, _safe_attrs strips
         ...}
  ```

- OpenSearch Discover on `gateway-metrics` shows 12 new
  `metric.attributes.enkrypt@*` fields (`@server@name`, `@user@id`,
  `@user@email`, `@project@id`, `@project@name`, `@project@registry`,
  `@org@id`, `@gateway@name`, `@gateway@version`, `@config@id`,
  `@custom@id`, `@error@message`).

### After the fixes above, also verify in OpenSearch Dashboards

> Note: the field-list panel in OpenSearch Discover **caches** which
> fields exist on documents in the index. After restarting the gateway
> with new code that emits previously-absent keys, click the **refresh
> field list** button on the index pattern (Stack Management → Index
> patterns → `gateway-logs` / `gateway-traces` → top-right refresh icon)
> or the new attributes won't appear in the sidebar even though they're
> on every new document. This is the most common reason "Not the other
> two" is reported after the metric side is already working.

1. **`gateway-logs`**: filter the field-name search box for `enkrypt`.
   Expect the same 12 dotted fields under `log.attributes.enkrypt@*`.
2. **`gateway-traces`**: filter for `enkrypt`. Expect dotted fields
   under `span.attributes.enkrypt@*` (was already correct pre-fix; if
   missing, click refresh field list — the trace-side code never wrote
   snake_case keys).
3. **`user_id` correctness**: pivot a chart on
   `metric.attributes.enkrypt@user@id`. The `enkrypt_principal` value
   should no longer appear; instead, when the cloud surfaces a real
   user, you'll see real Enkrypt user IDs, and when it doesn't, the
   field is simply absent from the metric series.
