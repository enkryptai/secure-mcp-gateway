# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

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
- Backward compatible: existing configs with `enable_tool_guardrails: true` continue to work
- Added `_build_detectors()` method to `EnkryptServerRegistrationGuardrail` for dynamic detector construction from policy config

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
