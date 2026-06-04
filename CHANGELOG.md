# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

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
