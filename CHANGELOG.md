# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

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
