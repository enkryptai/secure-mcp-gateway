# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

## [v2.2.3]

Clears every finding from the Semgrep scan. No default behaviour changes, but
the container now runs as a non-root user — see the first entry before you
deploy.

### Security

- **The container no longer runs as root.**  The image now drops to UID 1000
  (`ubuntu`) after the build.  Nothing the gateway writes at runtime lives on
  the root filesystem, but a **host directory or Kubernetes volume mounted at
  `/app/.enkrypt` must now be readable — and, if you run the CLI or the REST
  management API in the container, writable — by UID 1000.**  Either `chown -R
  1000:1000` the mount (the example K8s manifest's init container now does
  this) or pass `docker run --user <uid>:<gid>` to match your host account.
  `secure-mcp-gateway --docker` and the compose stack are unaffected.  The CLI
  also no longer aborts a config write when it cannot `chmod` a mount it does
  not own; it warns and keeps the host's permissions.

- **The OAuth callback page escaped nothing.**  `/oauth2callback` interpolated
  the identity provider's `error` and `error_description`, and the server name,
  straight into its HTML response, so an attacker who could steer a victim's
  browser to a crafted callback URL could execute script in the gateway's
  origin.  All interpolated values are now HTML-escaped.

- **CORS origins and the listen address are configurable.**  The REST API
  hardcoded `Access-Control-Allow-Origin: *` alongside
  `allow_credentials=True`, and the gateway always bound `0.0.0.0`.  Both
  defaults are unchanged, but `ENKRYPT_API_CORS_ORIGINS` (comma-separated) and
  `ENKRYPT_GATEWAY_HOST` now let a deployment narrow them.

- **CI actions are pinned to commit SHAs**, and the release workflows no longer
  interpolate `github.*` context directly into `run:` shell, closing a
  supply-chain vector and a shell-injection vector in the build pipeline.

### Changed

- Internal hardening with no behaviour change: static imports in the dashboard
  generator, a validated module path ahead of the plugin loader's dynamic
  import, `requests` instead of `urllib` for connectivity probes so a malformed
  endpoint cannot become a `file://` read, argv lists instead of `shell=True`,
  and `stat.S_IRWXU` in place of a bare octal mode.

## [v2.2.2]

### Fixed

- **`X-Enkrypt-MCP-Gateway-Version` is now honored on the request.**  Enkrypt
  cloud looks a gateway up by `(gateway_saved_name, gateway_version)`, but the
  gateway only read the name from the client and always sent the version from
  `plugins.auth.config.gateway_version` (default `"v1"`).  Gateways registered
  under any other version were unreachable from a header-routed deployment —
  `get-gateway-config` returned `404 MCP gateway not found` on every request.

  The version now resolves like the name: pinned `auth.config` value wins,
  otherwise the request header, otherwise `"v1"`.  Configs that set it are
  unaffected; configs that omit it gain per-request routing.

- **Tool discovery used the wrong apikey for guardrail checks.**  Guardrails
  resolve per apikey/project, and the nine detect/PII calls already forwarded
  the caller's key — but the registration and tool-batch checks that gate
  discovery used the gateway's boot-time key instead. In a multi-tenant
  deployment those checks looked the guardrail up in the wrong account and
  returned `404 Guardrail not found`, so discovery failed closed and every
  server came back with no tools. The batch route now forwards the caller's
  apikey like the rest, and discovery publishes it the way tool execution
  already did.

- **A missing guardrail now says so.**  When a server's configured guardrail
  doesn't exist for the gateway's apikey, tool discovery failed closed with a
  raw upstream `404 Guardrail not found`, which read like the tools had been
  blocked by a policy. It now raises `GUARD_010` naming the guardrail and
  noting that the name is matched exactly, including case — the usual cause.
  Behaviour is unchanged — still fail-closed.

- **Inline guardrail detectors were posted to the wrong route.**  The
  saved-guardrail route (`/guardrails/guardrail/batch/detect`) rejects a
  `detectors` body with `400 Unexpected key`; inline detectors belong on
  `/guardrails/batch/detect`. The batch client now picks the route by mode.
  No behaviour change for saved-guardrail checks, which is every configured
  path today.

### Security

- **Remote server credentials were returned to MCP clients in cleartext.**
  `enkrypt_list_all_servers` / `enkrypt_get_server_info` masked `config.env`
  but not `config.headers`, so a `url`-based server's `Authorization` header
  (e.g. a GitHub PAT) was echoed verbatim to any client that listed servers.
  Headers are now masked the same way. Rotate any credential configured this
  way on a gateway running an earlier build.

- **Replaced the pip wheel that `python3 -m venv` bootstraps from.**  Ubuntu
  stages a pip wheel in `/usr/share/python-wheels` for `ensurepip`, and on 24.04
  that is pip 24.0, carrying vendored copies of urllib3 1.26.17 and requests
  2.31.0.  Those vendored copies, not pip itself, are the subjects of the three
  mediums left after `v2.2.1-2`: CVE-2025-66471 and CVE-2025-66418 (urllib3,
  fixed in 2.6.0) and CVE-2024-35195 (requests, fixed in 2.32.0).  The build now
  stages current pip instead, which vendors urllib3 2.7.0 and requests 2.34.2, so
  no copy of the vulnerable code remains anywhere in the image and new virtualenvs
  bootstrap a current pip rather than a two-year-old one.

  Inspector reads dpkg metadata rather than file contents, so it will keep
  reporting all three against `python3-pip-whl 24.0`.  This closes the
  vulnerability, not the finding; only Ubuntu Pro (ESM) closes the finding.

  Two approaches were rejected first.  Removing the package breaks apt outright,
  because `python3.12-venv` depends on it and `dpkg --force-depends` leaves
  unmet dependencies that make any later `apt-get install` fail, with apt's own
  suggested `--fix-broken` restoring the vulnerable wheel.  An earlier note in the
  `v2.2.1-2` entry claimed `ensurepip` hardcodes the bundled pip version and that
  a drop-in wheel could not work; that was wrong.  `ensurepip._find_packages`
  resolves the directory by scanning it, so the version in the filename is picked
  up automatically.  The original failure was the purge taking `python3.12-venv`,
  and with it `ensurepip`, along with the package.

  A `python3 -m venv` probe now runs in the same build step and fails the build if
  a future pip layout stops satisfying `ensurepip`, rather than shipping an image
  where MCP servers cannot create virtualenvs.

## [v2.2.1-2] - container security rebuild

Image-only release.  No application code changed, so the Python package stays at
`2.2.1`; the `-2` suffix is the container build number, continuing from the
`v2.2.1-1` image.  Amazon Inspector reported 10 criticals, 331 highs and 621
mediums against `v2.2.1-1`; every one of those had a published fix.

### Security

- **`apt-get upgrade` added to the image build.**  The `ubuntu:24.04` tag is
  refreshed on Canonical's release cadence rather than Ubuntu's security cadence,
  so the build inherited the unpatched snapshot of every OS package.  This single
  change accounts for the bulk of the findings, across `linux-libc-dev`
  (kernel headers, 3C/288H/558M on their own), `curl` / `libcurl4t64` /
  `libcurl3t64-gnutls` (4C each), `openssl` / `libssl3t64`, `glibc` / `libc6`,
  `openssh-client`, `python3.12`, `libheif`, `krb5`, `libnss3`, `python3-httplib2`,
  `wget`, `sqlite3`, `systemd`, `tar`, `gzip`, `nghttp2`, `libxpm`, `libxml2`
  and `pam`.  A second upgrade runs after the `COPY` steps so that source
  changes, not just base-image moves, pull in newly published patches.
- **Dependency ceilings raised where `~=` was pinning the vulnerable minor.**
  The compatible-release operator caps the minor version, so these fixes were
  unreachable without editing the pin: `aiohttp` 3.13.5 -> 3.14.3 (11H/3M),
  `cryptography` 46.0.7 -> 50.0.0 (3H/1M, incl. CVE-2026-69249),
  `pyjwt` 2.12.1 -> 2.13.0 (1H/3M, CVE-2026-48526), `mcp[cli]` 1.27.0 -> 1.28.1
  (CVE-2026-59950).  Applied to `requirements.txt`, `pyproject.toml` and
  `dependencies.py` together, per the sync note in those files.
- **`uv` pinned to 0.12.5.**  It was installed unpinned, and because that layer
  only rebuilds when the line changes, the image kept shipping the version the
  first build resolved - old enough for Inspector to flag the Rust crates
  statically linked into the binary (`quick-xml` RUSTSEC-2026-0195, `quinn-proto`
  CVE-2026-25800).
- Rebuilding also refreshed transitive packages that had fixes waiting and no
  pin blocking them: `starlette` 1.2.1 -> 1.6.0 (1H/1M),
  `pydantic-settings` 2.14.1 -> 2.15.0, `setuptools` 82.0.1 -> 84.0.0.

- **apt `python3-pip` and `python3-wheel` purged** (1H, 3M).  Their fixes ship
  only in Ubuntu Pro (ESM), and nothing used them: the pip installs in this
  Dockerfile put newer copies in `/usr/local`.  Verified after purging that
  `pip3`, `python3 -m pip`, `python3 -m wheel`, `python3 -m venv` + pip
  bootstrap, `pipx install`, `uv venv`, `uv pip install`, sdist builds and `npx`
  all still work.

### Known remaining

Down to 0 criticals, 0 highs, 5 mediums, none of which have a fix available:

- `python3-pip-whl` (3M) is deliberately kept.  It is not a duplicate of the
  purged packages - it supplies the wheels `python3 -m venv` uses to bootstrap
  pip, which MCP servers rely on, and `python3.12-venv` depends on it.  Fix is
  ESM-only.  See the entry above for how the underlying vulnerable code was
  since removed without touching the package.
- `rsa` (2M, RUSTSEC-2023-0071, a Marvin-attack timing sidechannel) is vendored
  into the `uv` binary and has no upstream fix.  Not reachable from the gateway:
  it is in a build tool, not the request path.
- `linux-libc-dev` will re-accumulate kernel CVEs between rebuilds.  It is pulled
  in by `build-essential` -> `libc6-dev`, which the image keeps deliberately so
  MCP servers can compile native dependencies at runtime.  Dropping the
  toolchain would remove that finding class permanently, at the cost of that
  capability.

## [v2.2.1]

Consolidated release bundling everything that shipped to dev as patch-image
overlays since v2.2.0.  Single image, no overlay tool required.

### Added (telemetry instrumentation)

- **Tier-1 metrics** (7 new counters): `enkrypt.errors.by_code` auto-emitted
  from every `MCPGatewayError`, plus `enkrypt.guardrail.compliance_hit`,
  `enkrypt.tool.permission_denied`, `enkrypt.degradation.fail_open` /
  `.fail_closed`, `enkrypt.transport.errors`,
  `enkrypt.discovery.server_failures`.
- **Audit / compliance** (18 new counters): full coverage of admin REST
  mutations via `audit.py` + `audit_middleware.py`.  Powers the new
  "Audit Trail" dashboard.
- **Guardrail per-detector detail**: `enkrypt.guardrail.pii_entity` +
  `enkrypt.guardrail.toxicity_subtype` extracted from
  `violation.metadata.details` at the 3 STES violation sites; powers the
  Guardrails Deep Dive "PII Entities" and "Toxicity Subtypes" panels.
- **Per-request phase timing** (8 log fields) on every blocked/successful
  tool call: `preprocess_duration_ms`, `execution_duration_ms`,
  `postprocess_duration_ms`, `guardrail_duration_ms`,
  `tool_call_duration_ms`, `total_request_duration_ms`,
  `cache_lookup_duration_ms`, `mcp_handshake_duration_ms`.  Powers the
  Cache & Performance "Latency Breakdown" section.
- **Session pool gauge**: `enkrypt.session.active` wired in pool
  acquire/evict/close_all/_reap so "Active Sessions" populates.
- **Identity labels** on `record_tool_call_outcome` /
  `record_guardrail_violations` / `record_pii_redaction`:
  `user_email`, `project_name`, `project_registry`, `org_id`,
  `gateway_name`, `gateway_version` (all optional kwargs).

### Added (gateway features)

- **Playground routes mounted on FastMCP** (port 8000): new
  `gateway_playground_routes.py` exposes `/mcp-playground/test-server` (POST),
  `/mcp-playground/get-tools` (GET), `/mcp-playground/call-tool` (POST) via
  `FastMCP.custom_route`.  No separate `api_server.py` process needed for
  the playground UI to work in production.
- **Playground registry-mode** + **consumer-info** metrics:
  `record_registry_lookup`, `record_consumer_info_lookup` helpers.

### Fixed

- **Session-pool hang protection** (PR #40): `asyncio.wait_for` guards
  around `acquire()` and the `_worker` connect path so a dead upstream
  MCP server cannot indefinitely stall the gateway.
- **OSD dashboard query corrections** across Overview / Per-Tenant /
  Sandbox & MCP Protocol / SLO / Tools & MCP Servers / Audit Trail /
  Guardrails Deep Dive / Cache & Performance: repointed panels to the
  metric names + log fields the gateway actually emits.
- **OpenSearch index templates**: declared all new attribute /
  log-field shapes (`metric.attributes.{entity_type, subtype,
  score_bucket, authorization_path, ...}` + `log.attributes.{actor,
  target_id, surface, success, authorization_path, *_duration_ms,
  pii_entity_types, toxicity_subtypes, ...}`) so `dynamic: false`
  doesn't silently drop them at index time.

### Operational tools

- `tools/guardrail_coverage_smoke.py` (22-prompt detector probe)
- `tools/guardrail_detail_smoke.py` (PII + toxicity smoke)
- `tools/osd_force_field_declare.py` (workaround OSD missing-field-cache
  banner when emission preconditions aren't met yet)
- `tools/local_benign_smoke.py` (3 benign tool calls)

The patch-image overlay tooling (`tools/build_tier1_overlay.py`,
`tools/verify_patch_tier1.py`, `Dockerfile.patch-tier1metrics`) is no
longer needed for v2.2.1 builds but remains in the repo so future
emergency patches can reuse the pattern without re-inventing it.

## [v2.2.0]

### New Features in v2.2.0

#### Enkrypt Cloud Auth Provider

- New `enkrypt` auth provider that fetches gateway config from the Enkrypt cloud (`/mcp-gateway/get-gateway-config`) instead of the local config file
- Per-request multi-tenancy — each MCP client passes its own apikey via the `apikey` header, so a single gateway process can serve many tenants
- `request_context` from the cloud is mapped onto identity / metric labels (`user_id`, `user_email`, `project_name`) for accurate attribution in dashboards and alerts
- `gateway_overrides` from the cloud replace per-server input/output guardrail policies on the merged config
- New top-level `local_server_overrides` block lets operators layer local-only fields (`sandbox`, `denied_tools`, `oauth_config`) onto cloud-fetched servers; cloud values always win on conflict
- In-process cache keyed on a SHA-256 hash of the apikey, with a 10-minute TTL (`cache_ttl_seconds` configurable)
- Cloud's `is_active: false` flag now drops servers from discovery / execution / cache before the per-server merge

#### Provider-Aware Install

- `secure-mcp-gateway install` now reads `plugins.auth.provider` from the local config and emits the matching credential shape in the generated `mcp.json` (avoids `HTTP 401`s when a cloud-configured gateway received a local-mode header triple)
- New `--apikey`, `--transport {stdio,http}`, and `--url` flags on `install`
- HTTP transport supported for `claude-desktop` and `cursor`
- Diagnostic summary line printed on every install so operators can verify the detected provider and masked credentials before restarting their MCP client

#### Grafana Alerting

- Provisioned 9 alert rules covering policy-violation bursts, injection attacks, PII detection, toxicity/NSFW, output-quality (hallucination/adherence/relevancy), deny-list bursts, per-user red-team patterns, guardrail-API p95 latency, and auth-failure bursts
- Alerts route per-`(server, tool)` and per-principal (`user_id`, `failure_reason`, `provider`) so each distinct offender produces its own Slack message
- Provisioned Slack contact point and notification policy (critical → 0s group wait, warning → 5m); webhook URL read from `observability/.env`

### Updates in v2.2.0

#### Telemetry Wiring

- Wired up 15 previously-dead Prometheus counters and histograms — guardrail violations (overall + input/output + per-check), guardrail-API request count and duration, PII redactions, tool-call lifecycle (success/failure/error/blocked), and auth success/failure are now actually emitted
- Added a central, no-throw metrics helper module that degrades to a silent no-op when telemetry is not initialised
- Added developer-facing reference at `docs/metric_reference.md` mapping every helper to its OTel name, Prometheus series, call-site, and alert rule

#### Observability Dashboards & Docs

- Renamed all dashboard queries to match the current metric naming scheme (the 3 provisioned dashboards were querying older series and showing `No data`)
- Switched 18 dashboard label filters from `=` to `=~` so the `All` template-variable selection now matches every series
- Repointed 7 dashboard panels at metrics that actually exist (legacy "wrapper" guardrail names and prototype discovery counters)
- Resolved a Grafana provisioning warning where two dashboards shared the same title (the "complete" variant is now suffixed `(Complete)`)
- Bumped published Grafana port to `${GRAFANA_HOST_PORT:-3001}` to avoid colliding with native Windows Grafana service installs
- Added `observability/README.md` operator setup guide and `observability/.env.example` template

#### Bug Fixes

- Fixed `OTel Invalid type NoneType for attribute 'project_id'` warnings on every request — service modules now coerce missing/`None` credentials to a placeholder before emitting span attributes (cloud-auth clients only send `apikey`, surfacing the `None` case that local-apikey clients never hit)
- Fixed `Session ..._None_None_... not found` `ValueError` on every cached tool call after the null-fix — session-key generation is now funnelled through a single canonical helper so the store and lookup sides always agree
- Fixed `gateway.py` running twice on startup — removed wildcard re-exports from `secure_mcp_gateway/__init__.py` that caused `python -m secure_mcp_gateway.gateway` to re-execute the module body as `__main__`

#### Breaking Changes

- **`auth.config` shape renamed for the `enkrypt` provider.** Removed keys: `api_key`, `use_remote_config`, `timeout`. New keys: `apikey`, `gateway_name`, `gateway_version`, `project_name`, `base_url`, `cache_ttl_seconds`. Operators see a clear `ValueError` at boot pointing at the new keys.
- **Plugin loader mapping fixed.** Setting `plugins.auth.provider: "enkrypt"` previously resolved to `LocalApiKeyProvider`; it now resolves to the new cloud provider. The default fallback (no `provider` key) still uses `LocalApiKeyProvider` for backwards compatibility.
- **Cloud auth hard-fails on errors.** Network / 5xx / non-JSON responses surface as auth errors with the upstream message attached — no local-file fallback, no stale-cache serving.

## [2.1.7] - 2026-02-13

### Updates in v2.1.7

#### Bug Fixes

- **Fixed AUTH_001 "Already authenticated (session)" error** -- `AuthResult` objects in `config_manager.py` used raw strings (`"success"`, `"error"`) instead of `AuthStatus` enum values, causing `is_success` to always return `False` on cached/session auth results. Every request after the first one failed with AUTH_001. Replaced all 6 occurrences with proper enum values.
- **Fixed tools being blocked during discovery even when guardrails were disabled** -- `EnkryptServerRegistrationGuardrail` had hardcoded `SERVER_DETECTORS` and `TOOL_DETECTORS` that always ran all detectors (injection_attack, nsfw, toxicity, etc.) regardless of per-server configuration. Tools like Notion were incorrectly flagged.

#### Configurable Tool Guardrails Policy

- Added `tool_guardrails_config` per-server config field, replacing the boolean `enable_tool_guardrails`
- The `block` list in the policy controls which detectors run during tool/server registration validation at discovery time
- Detectors not in the `block` list are disabled -- no more hardcoded always-on detectors
- `guardrail_name` field is used for the policy violation detector's policy text
- Added `_build_detectors()` method to `EnkryptServerRegistrationGuardrail` for dynamic detector construction from policy config
- Removed `DEFAULT_SERVER_DETECTORS` and `DEFAULT_TOOL_DETECTORS` hardcoded fallbacks -- detectors are now **only** driven by `tool_guardrails_config.block`

#### Breaking Changes

- **`enable_tool_guardrails` is no longer supported.** The boolean field has been fully replaced by the `tool_guardrails_config` object. Existing configs using `enable_tool_guardrails: true/false` will be silently ignored (guardrails will default to disabled). **You must regenerate your config** with `secure-mcp-gateway generate-config --overwrite` or manually add the `tool_guardrails_config` field to each server entry.
- **Hardcoded default detectors removed.** Previously, when no policy was provided, all detectors ran with hardcoded defaults. Now, detectors only run when explicitly listed in the `block` array of `tool_guardrails_config`. If `block` is empty or missing, no tools/servers are blocked — the gateway logs a monitor-only message and allows everything through.

#### CLI Enhancements

- Added `--docker` flag to auto-wrap any CLI command in a `docker run` invocation (no more verbose Docker commands)
- Added `--docker-image` flag to specify a custom Docker image when using `--docker`
- Added `install --client claude-code` support for direct Claude Code integration via `claude mcp add`
- Fixed Windows `.cmd` executable resolution using `shutil.which()` for Claude Code install
- Suppressed duplicate initialization output when delegating to Docker with `--docker`
- `config add-server` now generates `tool_guardrails_config` with full block list (disabled by default)

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
