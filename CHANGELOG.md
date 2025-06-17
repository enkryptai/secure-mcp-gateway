# Changelog

All notable changes to the Enkrypt Secure MCP Gateway project will be documented in this file.

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
