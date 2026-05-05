# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

## [Unreleased]

### Enkrypt cloud auth provider (rewrite)

- **`plugins.auth.enkrypt_provider.EnkryptAuthProvider` now fetches gateway
  config from the cloud** (`GET {base_url}/mcp-gateway/get-gateway-config`)
  instead of the legacy local-file fallback. The provider was effectively
  unused before; setting `plugins.auth.provider: "enkrypt"` previously
  resolved to `LocalApiKeyProvider` via the plugin loader's class mapping.
  That mapping is fixed in `plugins/plugin_loader.py` so `enkrypt` now
  resolves to the new class. The default fallback (no `provider` key) still
  uses `LocalApiKeyProvider` for backwards compatibility.
- **New `auth.config` shape** (hard rename — old keys raise at boot):

  ```json
  {
    "provider": "enkrypt",
    "config": {
      "apikey": "<fallback enkrypt apikey>",
      "gateway_name": "<saved_name from /mcp-gateway/add-gateway>",
      "gateway_version": "v1",
      "project_name": "default",
      "base_url": "https://api.enkryptai.com",
      "cache_ttl_seconds": 600
    }
  }
  ```

  Removed keys: `api_key`, `use_remote_config`, `timeout`. Operators get
  a clear `ValueError` at boot pointing them at the new keys.
- **Per-request multi-tenancy.** Every MCP client passes its own apikey via
  the `apikey` header; `AuthConfigManager.extract_credentials()` already
  forwards it as `credentials.gateway_key`. The new provider uses that
  per-request key to call the cloud, so a single gateway process can serve
  many tenants. The boot-time `apikey` from `auth.config` is only a
  fallback for clients that don't supply one.
- **`request_context` mapping.** Wires the cloud's new `request_context`
  block into our identity / metric labels:
  `forwarded_user_id` wins over `user_id` for the metric `user_id` label
  so alerts attribute to the actual end-user, not the gateway-owner;
  `forwarded_user_email` populates the dashboard `var-email` filter; until
  the cloud surfaces a stable `project_id` UUID, `project_name` is mirrored
  into the `project_id` slot. Unmapped fields (`org_id`, `actioner`,
  `registry_name`) are stashed under `_request_context_extra` and surfaced
  via `AuthResult.metadata` for log enrichment without exploding metric
  cardinality.
- **`gateway_overrides` honoured.** When
  `expanded_servers[].gateway_overrides.<policy>` is set in the cloud
  response, that policy replaces the corresponding `mcp_config.<policy>`
  field in the merged server entry. Whole-policy replacement (matches
  cloud-side semantics).
- **Local-only fields layered on top.** `sandbox`, `denied_tools` and
  (legacy) `oauth_config` are not yet part of the cloud spec but are
  first-class in the gateway. A new top-level `local_server_overrides`
  block in the local config file (keyed by server `saved_name`) lets
  operators layer those fields onto cloud-fetched servers. Cloud values
  win for any field present on both sides — local entries only fill gaps.
- **Hard-fail on cloud errors.** Network / 5xx / non-JSON responses
  surface as `AuthStatus.ERROR` with the upstream message attached. No
  local-file fallback, no stale-cache serving. Operationally clearer than
  silently downgrading to a stale config.
- **In-process cache, 10-minute TTL.** Cloud responses are cached per
  apikey (SHA-256 hashed key, never plain text in memory) for
  `ENKRYPT_REMOTE_CONFIG_TTL_SECONDS = 600` (overridable via
  `auth.config.cache_ttl_seconds`). Cache cleared via
  `provider.invalidate_cache()`.
- **Null safety in `request_context`.** Cloud confirmed `org_id`,
  `actioner`, `project_name`, `project_id` and the `forwarded_*` fields
  may arrive as `null`. The mapper now filters `None` values out of
  `_request_context_extra` before they reach `AuthResult.metadata`, so
  they don't fan out as `None`-valued OTel attributes (which the SDK
  rejects with `Invalid type NoneType for attribute` warnings) and don't
  pollute Grafana metric labels. Promoted fields with a fallback chain
  (`project_name` → top-level → auth.config → `"default"`) skip past
  null values cleanly.
- 26 unit tests in `tests/test_enkrypt_auth_provider.py` cover
  constructor validation, `request_context` mapping, `gateway_overrides`
  precedence, local-overlay rules, cache hit/miss/expiry, and
  hard-fail-on-cloud-error semantics. All passing.
- Example config (`example_enkrypt_mcp_config.json`) gained two
  documentation keys (`_doc_local_server_overrides`,
  `_doc_auth_enkrypt_cloud`) and a `local_server_overrides` demo block
  showing how to layer sandbox + deny-list rules onto a cloud-fetched
  server.

### Provider-aware `secure-mcp-gateway install` (cloud-auth `mcp.json` shape)

Closes the migration gap that surfaced when a Cursor session hit `HTTP
401` against `https://api.dev.enkryptai.com/mcp-gateway/get-gateway-config`
even though the gateway-side cloud config was correct. Root cause was
the client `mcp.json` still using the local-mode header triple
(`ENKRYPT_GATEWAY_KEY` + `project_id` + `user_id`) under a
cloud-configured gateway — the legacy `ENKRYPT_GATEWAY_KEY` won the
priority chain in `extract_credentials` and got forwarded to the cloud
as the apikey, producing 401s on every request.

- **`install` is now provider-aware.** It reads
  `plugins.auth.provider` from the local config and emits the matching
  credential shape:

  | Provider | stdio install env vars | http install headers |
  | --- | --- | --- |
  | `enkrypt` | `ENKRYPT_APIKEY` (only) | `apikey` (only) |
  | `local_apikey` | `ENKRYPT_GATEWAY_KEY` + `ENKRYPT_PROJECT_ID` + `ENKRYPT_USER_ID` (legacy triple, unchanged) | `ENKRYPT_GATEWAY_KEY` + `project_id` + `user_id` (legacy triple, unchanged) |

  All three install targets (`claude-desktop`, `cursor`, `claude-code`)
  pick up the new shape automatically; no flags needed for local-mode
  installs.

- **New CLI flags on `install`:**
  - `--apikey <KEY>` — Enkrypt cloud apikey to embed. Only used when
    `auth.provider == "enkrypt"`. Falls back to `auth.config.apikey`
    when omitted. Local-mode installs ignore it.
  - `--transport {stdio,http}` — `stdio` (default) generates a
    `command + args + env` subprocess entry. `http` generates a `url +
    headers` streamable-HTTP entry — supported for `claude-desktop`
    and `cursor`. (`claude-code` users should run `claude mcp add
    --transport http` directly.)
  - `--url <URL>` — Gateway URL when `--transport=http`. Defaults to
    `http://localhost:8000/mcp/`.

- **New helper: `cli.get_install_credentials(config_path,
  override_apikey)`.** Single source of truth for credential extraction
  during install. Detects the provider, pulls the right values from the
  right places (CLI flag > `auth.config.apikey` > `apikeys` block),
  raises a clear `ValueError` if cloud mode has no apikey anywhere.

- **New env-var fallback in `AuthConfigManager.extract_credentials`:**
  the gateway now reads `ENKRYPT_APIKEY` (the cloud-mode env var the
  new install path emits) into both `credentials.api_key` and
  `credentials.gateway_key`. `ENKRYPT_APIKEY` takes priority over the
  legacy `ENKRYPT_GATEWAY_KEY` env var so a leftover legacy var in a
  shared shell doesn't override a fresh cloud install. Local-mode
  installs that set only the legacy var continue to work unchanged.

- **Diagnostic output on every install.** The CLI now prints a single
  masked summary line so operators can verify the right provider was
  detected before restarting their MCP client:

  ```
  INFO: Installing with auth.provider='enkrypt' transport='http' credentials={'ENKRYPT_APIKEY': '****05yg'}
  ```

- **Tests:** `tests/test_cli_install.py` (9 tests) covers cloud-mode
  CLI flag wins, cloud-mode config-file fallback, missing-apikey error
  message, local-mode unchanged behaviour, the silently-ignored
  `--apikey` in local mode, default-provider handling, and all three
  branches of the `extract_credentials` env-var fallback chain.

- **Docs:** `docs/auth-providers.md` gains a "Migrating MCP client
  config" section with the per-provider header contract, a table of
  generated `mcp.json` shapes for every (provider × transport)
  combination, and the diagnostic log line to grep for when 401s show
  up.

### Package init no longer double-executes `gateway.py`

- **Removed wildcard imports from `secure_mcp_gateway/__init__.py`.** The
  package init had::

      from secure_mcp_gateway.client import *
      from secure_mcp_gateway.gateway import *
      from secure_mcp_gateway.utils import *

  When the user ran ``python -m secure_mcp_gateway.gateway``, Python first
  imported the parent package — which registered ``gateway`` under
  ``sys.modules`` as a side effect — and then ``runpy`` re-executed the
  module body as ``__main__``. The result: every top-level statement in
  ``gateway.py`` ran twice. Concrete observed effect: the cache service
  singleton's "Cache service initialized" line printed twice on every
  gateway start, alongside ``RuntimeWarning: 'secure_mcp_gateway.gateway'
  found in sys.modules after import of package 'secure_mcp_gateway' …``.
  A repo-wide grep confirmed nothing relied on the package re-exports
  (every consumer uses the qualified ``secure_mcp_gateway.<submodule>``
  form), so they were removed. The init now only contains a docstring
  explaining the historical context. Confirmed with a clean restart:
  ``Cache service initialized`` count went from **2 → 1** and
  ``RuntimeWarning`` count went from **1 → 0** with no other behavioural
  change.

### Cloud-auth fallout fixes (telemetry hygiene + session-key symmetry)

These two bugs were latent before the cloud-auth rewrite — every code path
relied on `local_apikey` clients sending `project_id` / `user_id` headers,
so the `None` cases were never hit. Cloud auth clients only send `apikey`,
which surfaced both regressions on every gateway tool call.

- **OTel `Invalid type NoneType for attribute 'project_id'` warnings on
  every request.** Multiple service modules used
  `credentials.get("project_id", "not_provided")` as a defensive default,
  but `dict.get(k, default)` only substitutes the default when the key is
  *missing* — a present-but-`None` value still returns `None`. With cloud
  auth, `extract_credentials` packs `{"project_id": None, "user_id": None}`
  into the dict, so `None` was being passed straight to
  `span.set_attribute(...)`, which the OTel SDK rejects loudly. Fixed by
  switching to `credentials.get(k) or "not_provided"` everywhere, which
  collapses both missing-key and `None`-value cases to the placeholder.
  Touches: `services/discovery/discovery_service.py`,
  `services/cache/cache_status_service.py`,
  `services/cache/cache_management_service.py`,
  `services/server/server_info_service.py`,
  `services/server/server_listing_service.py`.
- **`Session ..._None_None_... not found` `ValueError` on every cached
  tool call after the null-fix.** Auth's store side built session keys via
  `f"{gateway_key}_{project_id}_{user_id}_{mcp_id}"` with raw `None`
  components — the literal string `"None"` ended up in the key. Service
  layers' lookup side now coerces `None` → `"not_provided"` (per the
  null-fix above), so the lookup key no longer matches the stored key and
  every cached-session lookup raised. Fixed by canonicalizing inside
  `AuthConfigManager.create_session_key()` so any caller (including the
  inline f-string call sites) ends up with the same string. Service-layer
  call sites that were building session keys via raw `credentials.get(...)`
  are now rewired to call `auth_manager.create_session_key(...)` instead,
  funnelling all session-key generation through the single canonical
  helper. New regression tests in `tests/test_enkrypt_auth_provider.py`
  pin the store/lookup symmetry.

### Telemetry Wiring

- **Wired up 15 previously-dead Prometheus counters / histograms.** The OTel
  provider declared instruments for guardrail violations (overall + input /
  output / per-check), guardrail-API request count and duration, PII
  redactions, tool-call lifecycle (success / failure / error / blocked) and
  auth success / failure, but only the basic `tool_call_counter` was
  actually incremented in code. Production deployments that scraped
  Prometheus were therefore missing all guardrail / PII / auth signal.
- Added `src/secure_mcp_gateway/plugins/telemetry/metrics_helpers.py`: a
  central, no-throw helper module that wraps every metric with a consistent
  attribute set and degrades to a silent no-op when telemetry is not
  initialised.
- Wired the helpers into:
  - `services/execution/secure_tool_execution_service.py`: tool-call
    lifecycle counters (incl. `block_reason="deny_list" | "input_violation"
    | "output_violation"`), input/output guardrail violation counters with
    per-check breakdown.
  - `plugins/guardrails/enkrypt_provider.py`: shared
    `_post_with_metrics()` wrapper around every external HTTP call records
    `guardrail_api_request_counter` + `guardrail_api_request_duration` for
    `policy`, `relevancy`, `adherence`, `hallucination`, `pii_detect`,
    `pii_redact`, `pii_restore` check kinds.
  - `plugins/auth/local_apikey_provider.py` and `plugins/auth/enkrypt_provider.py`:
    every public `authenticate()` outcome (success or failure) is now
    recorded, including `failure_reason`.
- Added 16 unit tests in `tests/test_metrics_helpers.py` covering routing,
  attribute hygiene, no-telemetry safety and SDK-failure resilience.
- Added developer-facing reference at `docs/metric_reference.md` mapping
  every helper -> OTel name -> Prometheus series, the call-site that
  drives it, and the alert rule that consumes it.

### Observability dashboards & docs

- **Fixed dashboard `No data` panels.** The 3 provisioned Grafana
  dashboards (`OpenTelemetry Gateway Metrics.json`,
  `otel-grafana-complete.json`, `gateway-metrics.json`) referenced an
  older metric naming scheme (`otel_enkrypt_guardrail_violations_total`,
  `otel_enkrypt_tool_call_duration_seconds_*`, `tool` label) that no
  longer matches what the gateway emits. Renamed all queries to the
  current series:
  - `otel_enkrypt_tool_call_duration_seconds_*` -> `otel_enkrypt_tool_duration_seconds_*`
  - `otel_enkrypt_tool_call_success_total`      -> `otel_enkrypt_tool_success_total`
  - `otel_enkrypt_tool_call_failure_total`      -> `otel_enkrypt_tool_failures_total`
  - `otel_enkrypt_tool_call_errors_total`       -> `otel_enkrypt_tool_errors_total`
  - `otel_enkrypt_*_violations_total`           -> `otel_enkrypt_guardrail_*_blocks_total`
  - `tool` label                                -> `tool_name` label
- Resolved a Grafana provisioning warning where two dashboards shared the
  title `OpenTelemetry Gateway Metrics`, causing one to be silently
  dropped. The "complete" variant is now titled
  `OpenTelemetry Gateway Metrics (Complete)`.
- **Fixed `No data` panels caused by exact-match label filters with
  multi-value variables.** 18 queries on the main dashboard used `=` for
  `project_id`, `mcp_config_id`, `user_id`, `project_name` against
  template variables that have `includeAll: true, multi: true`. When
  "All" was selected, Grafana substituted `$__all` -> empty string for
  exact-match operators, producing `project_id=""` which matched no
  series. Switched all four label filters to `=~` so "All" expands to
  the regex `.*` and matches every series.
- Added `observability/README.md` (operator-facing setup guide) and
  `observability/.env.example` (committed env template). The README
  covers quick-start, what's auto-provisioned, customisation,
  end-to-end smoke test, troubleshooting, and a "where to look for what"
  index. `.env.example` documents `SLACK_WEBHOOK_URL` and
  `GRAFANA_HOST_PORT` overrides.
- **Repointed 7 dashboard panels at metrics that actually exist.** The
  shipped dashboards still queried four legacy "wrapper" metric names
  (`otel_enkrypt_guardrail_output_blocks_total`,
  `otel_enkrypt_guardrail_relevancy_blocks_total`,
  `otel_enkrypt_guardrail_adherence_blocks_total`,
  `otel_enkrypt_guardrail_hallucination_blocks_total`) plus two
  discovery counters that never made it past prototype
  (`otel_enkrypt_list_all_servers_calls_total`,
  `otel_enkrypt_servers_discovered`). The gateway in fact emits a single
  `otel_enkrypt_guardrail_blocks_total` with `direction` /
  `violation_type` labels, and discovery counts are
  `otel_enkrypt_discovery_list_servers_total` /
  `otel_enkrypt_discovery_servers_found_total`. Rewrote the four
  guardrail-subtype panels to filter the unified metric (e.g.
  `rate(otel_enkrypt_guardrail_blocks_total{direction="output"}[5m])`,
  `{violation_type="adherence|hallucination|relevancy"}`) and pointed
  the discovery panels at the real counters. After the change, **Server
  Discovery Activity** lights up on every `enkrypt_discover_all_tools`
  call; the four guardrail-subtype panels now stay correctly empty
  *until* an output / hallucination / adherence / relevancy block
  actually fires (rather than being permanently dead due to a typo).

### Grafana Alerting

- Provisioned 9 alert rules at
  `observability/grafana/provisioning/alerting/rules.yaml` covering policy
  violation bursts, injection attacks, PII detection, toxicity / NSFW,
  output quality (hallucination / adherence / relevancy), deny-list bursts,
  per-user red-team patterns, guardrail-API p95 latency, and auth-failure
  bursts. **All 9 are now PromQL-backed** — the previously LogQL-backed
  per-user rule (`mcpgw-user-targeting-guardrails`) was migrated once
  `user_id` / `project_id` were added as metric attributes (see "Per-principal
  labels" below).
- **Per-(server, tool) and per-principal alert routing.** The 6 burst rules
  (policy violation, injection, PII, toxicity/NSFW, output quality,
  deny-list) and the auth-failure rule now `sum by (server_name, tool_name)`
  / `sum by (failure_reason, provider)` / `sum by (user_id)` so each
  distinct offender produces its own Slack message instead of a single
  aggregated alert. The Slack template renders these labels conditionally
  — labels that aren't present on a particular series are omitted entirely
  rather than displayed as "n/a".
- **`user_id` / `project_id` on metric attributes.**
  `record_tool_call_outcome`, `record_guardrail_violations` and
  `record_pii_redaction` now accept optional `user_id` / `project_id`
  kwargs. They are threaded through the secure execution service from
  `_execute_tools_with_guardrails` (which has access to `gateway_config`)
  via an `auth_context` dict. `_safe_attrs` strips the labels when
  `None`/empty so unauthenticated paths don't pollute label cardinality.
- Provisioned Slack contact point and notification policy (critical -> 0s
  group wait, warning -> 5m). The webhook URL is read from
  `observability/.env`'s `SLACK_WEBHOOK_URL` (gitignored), passed through
  to the Grafana container by `docker-compose.yml`.
- Bumped published Grafana port to `${GRAFANA_HOST_PORT:-3001}` (defaults
  to 3030 in the example `.env`) to avoid colliding with native Windows
  Grafana service installs.

## [2.1.7] - 2026-02-13

### Updates in v2.1.7

#### Bug Fixes

- **Fixed AUTH_001 "Already authenticated (session)" error** -- `AuthResult` objects in `config_manager.py` used raw strings (`"success"`, `"error"`) instead of `AuthStatus` enum values, causing `is_success` to always return `False` on cached/session auth results. Every request after the first one failed with AUTH_001. Replaced all 6 occurrences with proper enum values.
- **Fixed tools being blocked during discovery even when guardrails were disabled** -- `EnkryptServerRegistrationGuardrail` had hardcoded `SERVER_DETECTORS` and `TOOL_DETECTORS` that always ran all detectors (injection_attack, nsfw, toxicity, etc.) regardless of per-server configuration. Tools like Notion were incorrectly flagged.

#### Configurable Tool Guardrails Policy

- Added `tool_guardrails_policy` per-server config field, replacing the boolean `enable_tool_guardrails`
- The `block` list in the policy controls which detectors run during tool/server registration validation at discovery time
- Detectors not in the `block` list are disabled -- no more hardcoded always-on detectors
- `policy_name` field is used for the policy violation detector's policy text
- Added `_build_detectors()` method to `EnkryptServerRegistrationGuardrail` for dynamic detector construction from policy config
- Removed `DEFAULT_SERVER_DETECTORS` and `DEFAULT_TOOL_DETECTORS` hardcoded fallbacks -- detectors are now **only** driven by `tool_guardrails_policy.block`

#### Breaking Changes

- **`enable_tool_guardrails` is no longer supported.** The boolean field has been fully replaced by the `tool_guardrails_policy` object. Existing configs using `enable_tool_guardrails: true/false` will be silently ignored (guardrails will default to disabled). **You must regenerate your config** with `secure-mcp-gateway generate-config --overwrite` or manually add the `tool_guardrails_policy` field to each server entry.
- **Hardcoded default detectors removed.** Previously, when no policy was provided, all detectors ran with hardcoded defaults. Now, detectors only run when explicitly listed in the `block` array of `tool_guardrails_policy`. If `block` is empty or missing, no tools/servers are blocked — the gateway logs a monitor-only message and allows everything through.

#### CLI Enhancements

- Added `--docker` flag to auto-wrap any CLI command in a `docker run` invocation (no more verbose Docker commands)
- Added `--docker-image` flag to specify a custom Docker image when using `--docker`
- Added `install --client claude-code` support for direct Claude Code integration via `claude mcp add`
- Fixed Windows `.cmd` executable resolution using `shutil.which()` for Claude Code install
- Suppressed duplicate initialization output when delegating to Docker with `--docker`
- `config add-server` now generates `tool_guardrails_policy` with full block list (disabled by default)

#### Auth Error Messages

- Enhanced AUTH_001 error messages across all service layers to include detailed `AuthResult` message and error context instead of generic "Not authenticated."

#### Documentation

- Revamped CLI Quick Start Guide (Section 8) with narrative walkthrough and three guided paths (A/B/C)
- Added Steps for setting Enkrypt API key and configuring telemetry
- Added telemetry stack startup instructions (`docker compose up` from `infra/`)
- Fixed bash line-continuation backslashes and markdown rendering issues across README

## [2.1.6] - 2025-12-23

### Updates in v2.1.6

- Auto-detect Docker environment and skip dependency installation by default
- Added `config set-enkrypt-api-key` command for guardrails configuration
- Added `config configure-telemetry` command for OpenTelemetry settings
- Fixed Cursor config path for macOS (`~/.cursor`)

## [2.1.5] - 2025-11-10

### Updates in v2.1.5

- Minor bug fixes and improvements

## [2.1.4] - 2025-11-05

### Updates in v2.1.4

#### Security & Authentication

- Added `admin_apikey` (256-character secure key) for administrative REST API operations
- Separated admin API key from regular user API keys for enhanced security
- Updated API server authentication to use `admin_apikey` for administrative endpoints

#### API & Configuration

- Improved OpenAPI schema handling with static `openapi.json` file
- Added `openapi.json` to package data and MANIFEST.in
- Updated API server to load OpenAPI schema from static file
- Added `admin_apikey` to example configuration and documentation

#### Command Structure & Dependencies

- Simplified command structure from `uv run --with mcp[cli] mcp` to `mcp`
- Added `email-validator` dependency for pydantic EmailStr validation
- Updated dependencies.py with FastAPI and REST API requirements
- Removed automatic package installation in gateway.py

#### Documentation

- Updated README.md with admin API key details and usage
- Added REST API authentication section
- Updated Claude Desktop and Cursor configuration examples

#### Bug Fixes

- Minor code cleanup and improvements

## [2.1.3] - 2025-11-03

### Updates in v2.1.3

- Minor bug fixes and improvements
- Tests for the Gateway with OAuth enabled

## [2.1.2] - 2025-10-16

### Updates in v2.1.2

- OAuth Authorization Code Grant support
- Bug fixes and improvements

## [2.1.1] - 2025-10-10

### Updates in v2.1.1

- Updated telemetry plugin to use the new telemetry conf

- Tool guardrails

- OAuth 2.0, 2.1 client credentials support

- Standardized logging and error handling

- Added request timeout settings

- Added support for parallel processing

- Standardized sync async usage

- Bug fixes and improvements

## [2.1.0] - 2025-10-07

### New Features in v2.1.0

- Added API support for all `cli` commands

- Added API documentation

- Added support for async output guardrails

- Added concept of `plugins` to the gateway
  - Added support for `guardrails plugin` in the gateway
  - Added support for `telemetry plugin` in the gateway
  - Added support for `local apikey plugin` in the gateway

### Updates in v2.1.0

- Refactored the codebase to make it more modular and easier to maintain

- Updated the `enkrypt_mcp_config.json` schema to include `plugins` section and other changes

- Fixed external cache server issues

- Using single detect call for PII redaction on input side instead of 2 like before

- Pre-commit hooks for linting, formatting, security checks and type checking

- Minor bug fixes and improvements

## [2.0.3] - 2025-09-05

- Fixed no-op issue when telemetry is disabled

## [2.0.2] - 2025-09-04

### Updates in v2.0.2

- Updated gateway according to latest `FastMCP` version

- Locked dependencies to fix the version mismatch issues

## [2.0.1] - 2025-07-24

### New Features in v2.0.1

- Added Grafana dashboard and some more metrics

## [2.0.0] - 2025-07-18

### New Features in v2.0.0

- Updated `enkrypt_mcp_config.json` structure to include projects, users and apikeys **(Breaking Change)**
  - Please update your existing `enkrypt_mcp_config.json` or delete and regenerate using `secure-mcp-gateway generate-config`

- Introduced the concept of Projects, Users and MCP Configs
  - MCP Config is an array of MCP servers like `mcp_server_1`, `mcp_server_2`, `mcp_server_3` etc.
    - Each config has a unique ID
  - User is a user of the gateway with unique email and ID
  - A project is a collection of users that share an MCP Config
    - Project has a name and unique ID
    - The MCP Config can be updated or can be pointed to a different config by the Admin
    - Users can be added to multiple projects
  - An API Key is created for a user and project combination
    - A user can have different API Keys for different projects
    - This API Key is used to authenticate the user and identify the right project and MCP Config

- Added new `cli` commands to manage `mcp_configs`, `projects`, `users`, `apikeys` and `guardrails`
  - We can list, add, get, update, remove resources based on the config file
  - See `CLI-Commands-Reference.md` for more details

- Enhanced the metrics, logs and traces with labels like `project_id`, `project_name`, `user_id`, `email`, `mcp_config_id` for better filtering and analysis

## [1.0.5] - 2025-07-09

### New Features in v1.0.5

- `opentelemetry` support for tracing

- `prometheus`, `jaeger` and `grafana loki` setup for tracing

## [1.0.4] - 2025-07-07

### New Features in v1.0.4

- `streamable-http` transport support for remote installation

- `gateway_key` is now fetched from the request context in addition to the environment variable

- Auto disovering all tools of all servers in list and discover calls

- Using `fastmcp.tools` instead of `@mcp.tool()` decorator for centralized tool definitions

- Minor bug fixes and improvements

## [1.0.3] - 2025-06-17

### New Features in v1.0.3

- Local `Docker` installation support

## [1.0.1, 1.0.2] - 2025-06-15

### New Features in v1.0.1, v1.0.2

- `pip` support for installation

- `cli` commands to `generate-config` and `install` the gateway for `claude-desktop` and `cursor`

- Automatic installation of dependencies

- Simplified Readme

## [1.0.0] - 2025-06-04

### Initial Release

- Initial release of Enkrypt Secure MCP Gateway

- Core gateway functionality with authentication and authorization

- Dynamic tool discovery and management

- Tool invocation restriction capabilities

- Comprehensive caching system with local and external cache support

- Guardrails integration for input and output protection

- Logging system for request/response monitoring

- CLI interface for easy installation and setup

- Cross-platform support with Windows and Unix installation scripts

### Features

- **Authentication**
  - Unique gateway key authentication
  - Enkrypt API key integration for guardrails
  - Gateway configuration management

- **Tool Management**
  - Dynamic tool discovery from MCP servers
  - Tool restriction capabilities
  - Secure tool invocation
  - Server configuration management

- **Caching**
  - Local in-memory cache
  - External Redis cache support
  - Configurable cache expiration
  - Cache invalidation mechanisms

- **Guardrails**
  - Input Protection:
    - Topic detection
    - NSFW filtering
    - Toxicity detection
    - Injection attack prevention
    - Keyword detection
    - Policy violation detection
    - Bias detection
    - PII redaction
  - Output Protection:
    - All input protections
    - Adherence checking
    - Relevancy validation
    - Auto unredaction of responses

- **Logging**
  - Local request/response logging

### Dependencies

- flask>=2.0.0

- flask-cors>=3.0.0

- redis>=4.0.0

- requests>=2.26.0

- aiohttp>=3.8.0

- python-json-logger>=2.0.0

- python-dateutil>=2.8.2

- cryptography>=3.4.0

- pyjwt>=2.0.0

- asyncio>=3.4.3

- mcp[cli]

### System Requirements

- Python >= 3.8

- MCP CLI installed

- Redis (optional, for external caching)
