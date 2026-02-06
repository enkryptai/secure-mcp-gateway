# Secure MCP Gateway - Complete Project Analysis

**Version**: 2.1.2
**Last Updated**: 2025-10-15
**Project Type**: Python Security Middleware for Model Context Protocol (MCP)

---

## 📋 Project Overview

**Secure MCP Gateway** is an Enkrypt AI-developed security middleware that sits between MCP clients (like Claude Desktop, Cursor) and MCP servers. It acts as both an MCP server (to clients) and an MCP client (to actual servers), providing:

- **Authentication & Authorization**
- **OAuth 2.0/2.1 Support** (Client credentials, mTLS, token management)
- **Dynamic Tool Discovery**
- **Guardrails** (Input/Output protection)
- **Caching** (Local & External Redis/KeyDB)
- **Observability** (OpenTelemetry, Prometheus, Grafana)
- **RESTful API** for management

---

## 🏗️ Project Structure

```

secure-mcp-gateway/
├── src/secure_mcp_gateway/
│   ├── __init__.py                    # Package initialization
│   ├── version.py                     # Version: "2.1.2"
│   ├── consts.py                      # Constants and defaults
│   ├── utils.py                       # Utilities, lazy logger, masking
│   ├── dependencies.py                # Package dependencies list
│   │
│   ├── gateway.py                     # ⭐ Main MCP server (FastMCP)
│   ├── client.py                      # ⭐ MCP client to actual servers
│   ├── cli.py                         # ⭐ CLI interface (huge file)
│   ├── api_server.py                  # FastAPI REST API server
│   ├── api_routes.py                  # Additional API routes
│   │
│   ├── error_handling.py              # Standardized error handling
│   ├── exceptions.py                  # Custom exception classes
│   │
│   ├── plugins/                       # 🔌 Plugin system
│   │   ├── plugin_loader.py           # Dynamic plugin discovery
│   │   ├── provider_loader.py         # Provider loading utilities
│   │   │
│   │   ├── auth/                      # Authentication plugins
│   │   │   ├── base.py                # AuthProvider abstract class
│   │   │   ├── config_manager.py      # Auth plugin manager
│   │   │   ├── enkrypt_provider.py    # Enkrypt remote auth
│   │   │   └── example_providers.py   # Local API key provider
│   │   │
│   │   ├── guardrails/                # Guardrail plugins
│   │   │   ├── base.py                # GuardrailProvider abstract class
│   │   │   ├── config_manager.py      # Guardrail plugin manager
│   │   │   ├── enkrypt_provider.py    # Enkrypt guardrail API
│   │   │   └── example_providers.py   # OpenAI, Custom keyword providers
│   │   │
│   │   └── telemetry/                 # Telemetry plugins
│   │       ├── base.py                # TelemetryProvider abstract class
│   │       ├── config_manager.py      # Telemetry plugin manager
│   │       ├── opentelemetry_provider.py  # OpenTelemetry OTLP
│   │       └── example_providers.py   # Stdout provider
│   │
│   ├── services/                      # 🎯 Service layer
│   │   ├── cache/
│   │   │   ├── cache_service.py       # Core cache operations
│   │   │   ├── cache_management_service.py  # Clear cache
│   │   │   └── cache_status_service.py      # Cache statistics
│   │   │
│   │   ├── discovery/
│   │   │   └── discovery_service.py   # Tool discovery service
│   │   │
│   │   ├── execution/
│   │   │   ├── secure_tool_execution_service.py  # With guardrails
│   │   │   ├── tool_execution_service.py         # Basic execution
│   │   │   └── execution_utils.py                # Utilities
│   │   │
│   │   ├── oauth/                     # 🔐 OAuth 2.0/2.1 service
│   │   │   ├── oauth_service.py       # Core OAuth implementation
│   │   │   ├── token_manager.py       # Token caching & refresh
│   │   │   ├── integration.py         # Client integration
│   │   │   ├── models.py              # OAuth data models
│   │   │   ├── validation.py          # Scope & token validation
│   │   │   └── metrics.py             # OAuth metrics tracking
│   │   │
│   │   ├── server/
│   │   │   ├── server_listing_service.py  # List all servers
│   │   │   └── server_info_service.py     # Server details
│   │   │
│   │   └── timeout/
│   │       └── timeout_manager.py     # Timeout management
│   │
│   ├── bad_mcps/                      # 🧪 Test MCP servers (security testing)
│   │   ├── echo_mcp.py                # Simple echo server
│   │   ├── echo_oauth_mcp.py          # OAuth header testing server
│   │   ├── bad_mcp.py                 # Multiple attack vectors
│   │   ├── bad_output_mcp.py          # Malicious output testing
│   │   ├── command_injection_mcp.py   # Command injection scenarios
│   │   ├── credential_theft_mcp.py    # Credential theft attacks
│   │   ├── mpma_mcp.py                # Multi-parameter manipulation
│   │   ├── path_traversal_mcp.py      # Path traversal attacks
│   │   ├── prompt_injection_mcp.py    # Prompt injection attacks
│   │   ├── rce_mcp.py                 # Remote code execution
│   │   ├── resource_exhaustion_mcp.py # DoS/resource exhaustion
│   │   ├── schema_poisoning_mcp.py    # Schema manipulation
│   │   ├── session_management_mcp.py  # Session attacks
│   │   ├── ssrf_mcp.py                # Server-side request forgery
│   │   ├── tool_poisoning_mcp.py      # Tool definition attacks
│   │   └── unauthenticated_access_mcp.py  # Auth bypass scenarios
│   │
│   └── example_enkrypt_mcp_config.json  # Example configuration
│
├── infra/                             # Infrastructure configs
│   ├── docker-compose.yml             # Full observability stack
│   ├── grafana/                       # Grafana dashboards
│   ├── prometheus/                    # Prometheus config
│   ├── loki/                          # Loki logging config
│   └── otel_collector/                # OpenTelemetry collector
│
├── docs/                              # Documentation
├── pyproject.toml                     # Python project config
├── setup.py                           # Setup script
├── README.md                          # Main documentation
├── CHANGELOG.md                       # Version history
├── CLI-Commands-Reference.md          # CLI documentation
└── API-Reference.md                   # API documentation

```

---

## 🎯 Core Components

### 1. Entry Points

#### **Main Gateway** ([gateway.py:796](gateway.py))

- **Framework**: FastMCP (MCP SDK wrapper)

- **Transport**: Streamable HTTP on `0.0.0.0:8000`

- **Endpoint**: `/mcp/`

- **Purpose**: Acts as MCP server to clients

**Gateway Tools**:

1. `enkrypt_list_all_servers` - List all configured servers

2. `enkrypt_get_server_info` - Get server details

3. `enkrypt_discover_all_tools` - Discover tools from servers

4. `enkrypt_secure_call_tools` - Execute tools with guardrails

5. `enkrypt_get_cache_status` - Cache statistics

6. `enkrypt_clear_cache` - Clear cache entries

7. `enkrypt_get_timeout_metrics` - Timeout metrics

**Initialization Sequence**:

```python

1. Load common config

2. Initialize guardrail system

3. Initialize auth system

4. Initialize telemetry system

5. Initialize timeout manager

6. Create FastMCP instance with tools

7. Run on streamable HTTP

```

#### **CLI Interface** ([cli.py](cli.py))

**Commands** (36,000+ lines):
- **Config Management**: add, list, get, update, remove, copy, rename, search, validate, export, import

- **Server Management**: add, update, remove servers from configs

- **Guardrail Management**: update input/output guardrails

- **Project Management**: create, list, get, remove, assign-config, add-user

- **User Management**: create, list, get, update, delete users

- **API Key Management**: generate, list, rotate, disable, enable, delete

- **System Operations**: backup, restore, reset, health-check, version

#### **REST API Server** ([api_server.py:1049](api_server.py), [api_routes.py:716](api_routes.py))

- **Framework**: FastAPI

- **Port**: `8001`

- **Auth**: Bearer token (API key validation)

- **Docs**: `/docs` (Swagger), `/redoc` (ReDoc)

- **CORS**: Enabled for all origins

**Endpoints**:
- `/api/v1/configs/*` - Configuration management

- `/api/v1/projects/*` - Project management

- `/api/v1/users/*` - User management

- `/api/v1/api-keys/*` - API key management

- `/api/v1/system/*` - System operations

- `/health` - Health check (no auth)

---

### 2. Client Layer ([client.py:900](client.py))

**Purpose**: Acts as MCP client to forward requests to actual MCP servers

**Key Functions**:

```python
async def forward_tool_call(server_name, tool_name, args=None, gateway_config=None):
    """
    Forwards tool calls to MCP servers via stdio transport.
    Returns tool discovery results if tool_name is None.
    """

async def get_server_metadata_only(server_name, gateway_config=None):
    """
    Gets server metadata (name, version, description) without tool discovery.
    Used for config servers with predefined tools.
    """

```

**Cache System**:
- **Local Cache**: In-memory dictionary with threading locks

- **External Cache**: Redis/KeyDB support

- **Cache Keys**: MD5 hashed for security

- **Expiration**: 4 hours (tools), 24 hours (gateway config)

**Cache Functions**:

```python
cache_tools(cache_client, id, server_name, tools)
get_cached_tools(cache_client, id, server_name)
cache_gateway_config(cache_client, id, config)
get_cached_gateway_config(cache_client, id)
cache_key_to_id(cache_client, gateway_key, id)
get_id_from_key(cache_client, gateway_key)

```

---

### 3. Configuration System

#### **Config File Structure**

**Location**:
- macOS/Linux: `~/.enkrypt/enkrypt_mcp_config.json`

- Windows: `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json`

- Docker: `/app/.enkrypt/docker/enkrypt_mcp_config.json`

**Schema**:

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_use_remote_mcp_config": false,
    "enkrypt_mcp_use_external_cache": false,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_async_input_guardrails_enabled": false,
    "enkrypt_async_output_guardrails_enabled": false,
    "timeout_settings": {
      "default_timeout": 30,
      "guardrail_timeout": 15,
      "auth_timeout": 10,
      "tool_execution_timeout": 60,
      "discovery_timeout": 20,
      "cache_timeout": 5,
      "connectivity_timeout": 2,
      "escalation_policies": {
        "warn_threshold": 0.8,
        "timeout_threshold": 1.0,
        "fail_threshold": 1.2
      }
    }
  },
  "plugins": {
    "auth": {
      "provider": "local_apikey",
      "config": {}
    },
    "guardrails": {
      "provider": "enkrypt",
      "config": {
        "api_key": "YOUR_ENKRYPT_API_KEY",
        "base_url": "https://api.enkryptai.com"
      }
    },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "mcp_configs": {
    "UNIQUE_MCP_CONFIG_ID": {
      "mcp_config_name": "default_config",
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Dummy Echo Server",
          "config": {
            "command": "python",
            "args": ["PATH_TO_ECHO_MCP"]
          },
          "tools": {},
          "enable_tool_guardrails": true,
          "input_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": { "pii_redaction": false },
            "block": ["policy_violation", "injection_attack", ...]
          },
          "output_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": {
              "relevancy": false,
              "hallucination": false,
              "adherence": false
            },
            "block": ["policy_violation", ...]
          }
        }
      ]
    }
  },
  "projects": {
    "UNIQUE_PROJECT_ID": {
      "project_name": "default_project",
      "mcp_config_id": "UNIQUE_MCP_CONFIG_ID",
      "users": ["UNIQUE_USER_ID"],
      "created_at": "2025-01-01T00:00:00.000000"
    }
  },
  "users": {
    "UNIQUE_USER_ID": {
      "email": "default@example.com",
      "created_at": "2025-01-01T00:00:00.000000"
    }
  },
  "apikeys": {
    "UNIQUE_GATEWAY_KEY": {
      "project_id": "UNIQUE_PROJECT_ID",
      "user_id": "UNIQUE_USER_ID",
      "created_at": "2025-01-01T00:00:00.000000"
    }
  }
}

```

#### **Config Loading Priority** ([utils.py:241](utils.py))

1. Docker config (if `is_docker()` returns True)

2. User config (`~/.enkrypt/`)

3. Example config (from package)

4. Default config (hardcoded in [consts.py:54](consts.py))

---

### 4. Plugin System

**Architecture**: Provider-based plugin system for extensibility

#### **Auth Plugins** ([plugins/auth/](plugins/auth/))

**Base Class** ([base.py](plugins/auth/base.py)):

```python
class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(self, ctx: Context) -> AuthResult

    @abstractmethod
    def get_gateway_credentials(self, ctx: Context) -> Dict[str, str]

    @abstractmethod
    async def get_local_mcp_config(self, gateway_key, project_id, user_id)

```

**Providers**:
- `local_apikey`: Validates API keys from local config file

- `enkrypt`: Remote authentication via Enkrypt API (future)

**Manager** ([config_manager.py](plugins/auth/config_manager.py)):
- Singleton pattern

- Dynamic provider loading

- Credential extraction from request context

#### **Guardrail Plugins** ([plugins/guardrails/](plugins/guardrails/))

**Base Class** ([base.py](plugins/guardrails/base.py)):

```python
class GuardrailProvider(ABC):
    @abstractmethod
    async def check_input(self, request: str, policy: Dict) -> GuardrailResult

    @abstractmethod
    async def check_output(self, request: str, response: str, policy: Dict) -> GuardrailResult

```

**Providers**:
- `enkrypt`: Production Enkrypt guardrail API

- `openai`: OpenAI moderation API

- `custom_keyword`: Simple keyword blocking

**Features**:
- **Input Guardrails**: PII detection, toxicity, NSFW, injection attacks, policy violations, bias, keyword detection

- **Output Guardrails**: All input checks + relevancy, adherence, hallucination detection

- **PII Handling**: Redaction on input, de-anonymization on output

#### **Telemetry Plugins** ([plugins/telemetry/](plugins/telemetry/))

**Base Class** ([base.py](plugins/telemetry/base.py)):

```python
class TelemetryProvider(ABC):
    @abstractmethod
    def get_logger(self) -> Any

    @abstractmethod
    def get_tracer(self) -> Any

    @abstractmethod
    def shutdown(self) -> None

```

**Providers**:
- `opentelemetry`: Full OpenTelemetry with OTLP export, Prometheus metrics

- `stdout`: Simple stdout logging

**OpenTelemetry Features** ([opentelemetry_provider.py](plugins/telemetry/opentelemetry_provider.py)):
- Structured logging with `structlog`

- Distributed tracing with context propagation

- Metrics export to Prometheus

- OTLP gRPC export to collector

- Integration with Grafana, Jaeger, Loki

---

### 5. Service Layer

#### **Cache Services** ([services/cache/](services/cache/))

**cache_service.py**:
- Core cache initialization

- Cache client management

- Expiration configuration

**cache_management_service.py**:

```python
class CacheManagementService:
    async def clear_cache(self, ctx, id, server_name, cache_type, logger)
    # Clears: all, gateway_config, server_config

```

**cache_status_service.py**:

```python
class CacheStatusService:
    async def get_cache_status(self, ctx, logger)
    # Returns: total_gateways, total_tool_caches, total_config_caches

```

#### **Discovery Service** ([services/discovery/discovery_service.py](services/discovery/discovery_service.py))

```python
class DiscoveryService:
    async def discover_tools(self, ctx, server_name, tracer_obj, logger_instance,
                           IS_DEBUG_LOG_LEVEL, session_key)
    """
    Discovers tools for a server:
    1. Check cache first
    2. If tools are configured, return them
    3. Otherwise, call forward_tool_call with tool_name=None
    4. Cache discovered tools
    5. Return tools with metadata
    """

```

#### **Execution Services** ([services/execution/](services/execution/))

**secure_tool_execution_service.py**:

```python
class SecureToolExecutionService:
    async def execute_secure_tools(self, ctx, server_name, tool_calls, logger)
    """
    Executes tools with guardrails:
    1. Authenticate and get config
    2. For each tool call:
       a. Run input guardrails (optional)
       b. Execute tool via forward_tool_call
       c. Run output guardrails (optional)
    3. Handle PII redaction/de-anonymization
    4. Return results
    """

```

**tool_execution_service.py**:
- Basic tool execution without guardrails

- Used internally by secure service

#### **Server Services** ([services/server/](services/server/))

**server_listing_service.py**:

```python
class ServerListingService:
    async def list_servers(self, ctx, discover_tools, tracer, logger,
                          IS_DEBUG_LOG_LEVEL, cache_client)
    """
    Lists all servers with their tools.
    Returns: available_servers, servers_needing_discovery
    """

```

**server_info_service.py**:

```python
class ServerInfoService:
    async def get_server_info(self, ctx, server_name, tracer, logger, cache_client)
    """
    Gets detailed server information including tools.
    """

```

#### **Timeout Service** ([services/timeout/timeout_manager.py](services/timeout/timeout_manager.py))

```python
class TimeoutManager:
    def get_timeout(self, operation_type: str) -> float
    def track_operation(self, operation_id: str, operation_type: str,
                       start_time: float) -> None
    def complete_operation(self, operation_id: str, success: bool) -> None
    def get_metrics(self) -> Dict
    def get_active_operations(self) -> List[Dict]

```

**Timeout Types**:
- `default_timeout`: 30s

- `guardrail_timeout`: 15s

- `auth_timeout`: 10s

- `tool_execution_timeout`: 60s

- `discovery_timeout`: 20s

- `cache_timeout`: 5s

- `connectivity_timeout`: 2s

#### **OAuth Services** ([services/oauth/](services/oauth/))

**Purpose**: Complete OAuth 2.0/2.1 implementation for authenticating with remote MCP servers

**oauth_service.py** - Core OAuth Service:

```python
class OAuthService:
    async def get_access_token(self, server_name, oauth_config, config_id)
    """
    Acquires OAuth access token with:
    - Client credentials grant
    - Mutual TLS (mTLS) support (RFC 8705)
    - Automatic caching & refresh
    - Exponential backoff retry (3 attempts)
    - Request correlation IDs
    """

    async def revoke_token(self, server_name, token, oauth_config, token_type_hint)
    """
    Revokes OAuth token (RFC 7009)
    """
```

**token_manager.py** - Token Caching & Lifecycle:

```python
class TokenManager:
    def cache_token(self, server_name, config_id, token_response)
    def get_cached_token(self, server_name, config_id)
    def is_token_expired(self, token_info, buffer_seconds=300)
    def invalidate_token(self, server_name, config_id)
    """
    Token management with:
    - In-memory token cache
    - Proactive refresh (5 min before expiry)
    - Token expiration tracking
    - Thread-safe operations
    """
```

**integration.py** - Client Integration:

```python
async def inject_oauth_token(server_entry, config_id)
"""
Injects OAuth tokens into MCP server connections:
- Remote servers: HTTP Authorization headers via mcp-remote
- Local servers: Environment variables (ENKRYPT_ACCESS_TOKEN, etc.)
- Automatic token acquisition if missing
"""

async def refresh_server_oauth_token(server_name, server_entry, config_id)
"""Force refresh OAuth token for a server"""

async def invalidate_server_oauth_token(server_name, config_id)
"""Invalidate cached token"""
```

**models.py** - OAuth Data Models:

```python
@dataclass
class OAuthConfig:
    enabled: bool
    version: str  # "2.0" or "2.1"
    grant_type: str  # "client_credentials"
    client_id: str
    client_secret: str
    token_url: str
    audience: Optional[str]
    scope: Optional[str]
    # ... (full OAuth config model)

@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str]
    # ... (token response model)
```

**validation.py** - Scope & Security Validation:

```python
def validate_oauth_config(config: Dict) -> Tuple[bool, Optional[str]]
"""Validates OAuth configuration for OAuth 2.0/2.1 compliance"""

def validate_token_scopes(requested_scopes, received_scopes) -> bool
"""Validates token has requested scopes"""

def enforce_https(token_url: str, version: str) -> Tuple[bool, Optional[str]]
"""Enforces HTTPS for OAuth 2.1"""
```

**metrics.py** - OAuth Metrics:

```python
class OAuthMetrics:
    def get_metrics(self) -> Dict
    """
    Returns OAuth metrics:
    - token_acquisitions_total
    - token_acquisitions_success/failure
    - token_cache_hits/misses
    - token_refreshes
    - cache_hit_ratio
    - success_rate
    - avg/max/min_latency_ms
    - active_tokens
    """
```

**OAuth Features**:
- **OAuth 2.0 & 2.1 Compliance**: Full spec support with security best practices

- **Client Credentials Grant**: Server-to-server authentication

- **Mutual TLS (mTLS)**: Optional client certificate authentication (RFC 8705)

- **Token Caching**: Automatic caching with expiration tracking

- **Proactive Refresh**: Tokens refreshed 5 minutes before expiry

- **Token Revocation**: RFC 7009 compliant token revocation

- **Scope Validation**: Verifies returned token has requested scopes

- **Retry Logic**: Exponential backoff (2s, 4s, 8s) for transient failures

- **Security**: HTTPS enforcement, scope validation, mTLS support

- **Metrics**: Comprehensive tracking of token operations

- **Correlation IDs**: Request tracing for debugging

---

### 6. Utilities & Constants

#### **Utils** ([utils.py:725](utils.py))

**Lazy Logger** ([utils.py:63](utils.py)):

```python
class LazyLogger:
    """Defers telemetry initialization to avoid circular imports"""
    def __getattr__(self, name):
        logger = get_logger()
        return getattr(logger, name) if logger else lambda *a, **k: None

logger = LazyLogger()  # Global logger

```

**Key Functions**:

```python
def get_common_config(print_debug=False) -> Dict
def is_telemetry_enabled() -> bool
def generate_custom_id() -> str  # 34 random chars + timestamp
def mask_sensitive_data(data: Dict) -> Dict
def mask_sensitive_headers(headers: Dict) -> Dict
def mask_sensitive_env_vars(env_vars: Dict) -> Dict
def build_log_extra(ctx, custom_id, server_name, error, **kwargs) -> Dict

```

#### **Constants** ([consts.py:55](consts.py))

```python
CONFIG_NAME = "enkrypt_mcp_config.json"
DOCKER_CONFIG_PATH = "/app/.enkrypt/docker/enkrypt_mcp_config.json"
CONFIG_PATH = "~/.enkrypt/enkrypt_mcp_config.json"

DEFAULT_COMMON_CONFIG = {
    "enkrypt_log_level": "INFO",
    "enkrypt_use_remote_mcp_config": False,
    "enkrypt_mcp_use_external_cache": False,
    # ... (full default config)
}

```

---

## 🔄 Request Flow

### **Complete Flow Diagram**:

```

┌─────────────┐
│ MCP Client  │ (Claude Desktop, Cursor)
│ (e.g. stdio)│
└──────┬──────┘
       │ 1. Connect with API key in request context
       ▼
┌──────────────────────────────────────────────────────────┐
│ Gateway Server (gateway.py:796)                          │
│ FastMCP on 0.0.0.0:8000/mcp/                            │
├──────────────────────────────────────────────────────────┤
│ 2. Extract gateway_key from ctx.request_context         │
│    via get_gateway_credentials()                         │
└──────┬───────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Auth Plugin (plugins/auth/config_manager.py)             │
├──────────────────────────────────────────────────────────┤
│ 3. Validate API key                                      │
│ 4. Get project_id, user_id, mcp_config_id               │
│ 5. Retrieve gateway config (cached or fresh)            │
└──────┬───────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Request Router                                            │
└──┬───────────────────────────────────┬──────────────────┬┘
   │ Tool Discovery                    │ Tool Execution   │
   ▼                                   ▼                  │
┌─────────────────────────────┐  ┌────────────────────┐  │
│ Discovery Service           │  │ Secure Execution   │  │
│ (discovery_service.py)      │  │ Service            │  │
├─────────────────────────────┤  ├────────────────────┤  │
│ 6a. Check cache             │  │ 6b. Input          │  │
│ 6b. If miss:                │  │     Guardrails     │  │
│     └─> Gateway Client      │  │     (optional)     │  │
│ 6c. Cache results           │  └────────┬───────────┘  │
└─────────────────────────────┘           ▼              │
                                  ┌────────────────────┐  │
                                  │ Gateway Client     │◄─┘
                                  │ (client.py:900)    │
                                  ├────────────────────┤
                                  │ 7. stdio_client()  │
                                  │    StdioServer     │
                                  │    Parameters      │
                                  └────────┬───────────┘
                                           │
                                           ▼
                                  ┌────────────────────┐
                                  │ Actual MCP Server  │
                                  │ (e.g. GitHub MCP)  │
                                  └────────┬───────────┘
                                           │
                                           ▼
                                  ┌────────────────────┐
                                  │ 8. Response        │
                                  └────────┬───────────┘
                                           │
                                           ▼
                                  ┌────────────────────┐
                                  │ Output Guardrails  │
                                  │ (optional)         │
                                  ├────────────────────┤
                                  │ 9. PII de-anon     │
                                  │ 10. Relevancy      │
                                  │ 11. Adherence      │
                                  └────────┬───────────┘
                                           │
                                           ▼
                                  ┌────────────────────┐
                                  │ 12. Return to      │
                                  │     MCP Client     │
                                  └────────────────────┘
                                           ▲
                                           │
                                  ┌────────┴───────────┐
                                  │ Telemetry Plugin   │
                                  │ (logs/traces/      │
                                  │  metrics)          │
                                  └────────────────────┘

```

---

## 🔒 Security Features

### **1. Authentication**

- API key-based with project/user context

- Extracted from `ctx.request_context.request.headers`

- Validated against local config or remote Enkrypt API

### **2. Sensitive Data Masking**

**Environment Variables** ([utils.py:458](utils.py)):

```python
sensitive_keys = ["token", "key", "secret", "password", "auth", ...]

# Masks: "abcd1234efgh" -> "abcd****efgh"

```

**HTTP Headers** ([utils.py:546](utils.py)):

```python
sensitive_patterns = ["authorization", "bearer", "cookie", "session", ...]

# Masks: "Bearer abc123def456" -> "Be***56"

```

**API Keys in Logs**:

```python
def mask_key(key):
    return "****" + key[-4:] if len(key) >= 4 else "****"

```

### **3. Guardrails**

**Input Protection**:
- Topic detection (block off-topic requests)

- NSFW filtering

- Toxicity detection

- Injection attack prevention (prompt injection, SQL injection)

- Keyword detection (custom blocklist)

- Policy violation detection

- Bias detection

- PII redaction (auto-detect and redact before sending to server)

**Output Protection**:
- All input protections

- Relevancy validation (is response relevant to input?)

- Adherence checking (does response follow instructions?)

- Hallucination detection

- PII de-anonymization (restore redacted PII in response)

### **4. Cache Key Hashing**

```python
def hash_key(key):
    return hashlib.md5(key.encode()).hexdigest()

```

- All cache keys are MD5 hashed

- Prevents exposure of sensitive identifiers

---

## 📊 Monitoring & Observability

### **1. Logging** (Structured with context)

**Log Levels**: DEBUG, INFO, WARNING, ERROR

**Structured Context** ([utils.py:352](utils.py)):

```python
extra = {
    "custom_id": "...",
    "server_name": "github_server",
    "project_id": "abc-123",
    "project_name": "MyProject",
    "user_id": "user-456",
    "email": "user@example.com",
    "mcp_config_id": "config-789",
    "error": "...",
    **kwargs
}
logger.info("Tool executed", extra=extra)

```

### **2. Distributed Tracing** (OpenTelemetry)

**Tracer Usage**:

```python
with tracer.start_as_current_span("operation_name") as span:
    span.set_attribute("server_name", server_name)
    span.set_attribute("tool_name", tool_name)
    # ... operation

```

**Trace Export**: OTLP gRPC to `http://localhost:4317`

### **3. Metrics** (Prometheus)

**Metrics Exported**:
- Request counts

- Error rates

- Latencies

- Cache hit/miss rates

- Guardrail block counts

- Timeout escalations

**Endpoint**: Metrics served on Prometheus-compatible endpoint

### **4. Infrastructure** ([infra/](infra/))

**Docker Compose Stack**:
- **Gateway**: Main service

- **OpenTelemetry Collector**: Receives OTLP, exports to backends

- **Prometheus**: Metrics storage

- **Grafana**: Dashboards

- **Jaeger**: Trace visualization

- **Loki**: Log aggregation

- **Redis/KeyDB**: External cache

**Grafana Dashboards**:
- Gateway metrics (request rate, errors, latency)

- OpenTelemetry metrics

- Server-specific metrics

---

## 📦 Dependencies

**Core** ([dependencies.py:22](dependencies.py)):

```python
__dependencies__ = [
    "mcp[cli]>=1.10.1",              # MCP SDK
    "flask>=2.0.0",                  # REST API (legacy)
    "flask-cors>=3.0.0",
    "redis>=4.0.0",                  # External cache
    "requests>=2.26.0",
    "aiohttp>=3.8.0",                # Async HTTP
    "python-json-logger>=2.0.0",     # JSON logging
    "python-dateutil>=2.8.2",
    "cryptography>=3.4.0",           # Security
    "pyjwt>=2.0.0",
    "asyncio>=3.4.3",
    "opentelemetry-sdk>=1.34.1",     # Telemetry
    "opentelemetry-exporter-otlp>=1.34.1",
    "opentelemetry-exporter-prometheus>=0.55b1",
    "opentelemetry-instrumentation>=0.55b1",
    "opentelemetry-instrumentation-requests>=0.55b1",
    "structlog>=25.4.0",             # Structured logging
]

```

**System Requirements**:
- Python >= 3.8

- Git 2.43+

- pip 25.0.1+

- uv 0.7.9+

---

## 🚀 Deployment Patterns

### **1. Local Installation (pip)**

```bash
python -m venv .secure-mcp-gateway-venv
source .secure-mcp-gateway-venv/bin/activate  # or Windows: .\..\Scripts\activate
pip install secure-mcp-gateway
secure-mcp-gateway generate-config
secure-mcp-gateway install claude-desktop

```

### **2. Docker Installation**

```bash
docker-compose up -d

# Gateway runs on 0.0.0.0:8000

# API runs on 0.0.0.0:8001

# Grafana on 0.0.0.0:3000

```

### **3. Remote Deployment**

- Uses streamable HTTP transport

- Can be hosted on cloud platforms

- Clients connect via HTTP instead of stdio

---

## 🎯 Key Design Patterns

### **1. Plugin Architecture**

- Abstract base classes for providers

- Dynamic plugin discovery via `example_providers.py`

- Config-based provider selection

- Singleton pattern for managers

### **2. Service Layer**

- Clear separation of concerns

- Each service handles one domain (cache, discovery, execution, etc.)

- Dependency injection via function parameters

### **3. Lazy Loading**

- Telemetry initialized lazily to avoid circular imports

- Logger wraps actual logger to defer initialization

- Configs loaded on first access with `@lru_cache`

### **4. Caching Strategy**

- Multi-level: Local in-memory + External Redis

- Hash-based keys for security

- Expiration-based invalidation

- Registry tracking for cleanup

### **5. Context Propagation**

- Request context flows through all layers

- Auth credentials extracted from context

- Logging context built from request data

- Tracing spans carry context

### **6. Error Handling**

- Custom exception hierarchy ([exceptions.py](exceptions.py))

- Standardized error responses ([error_handling.py](error_handling.py))

- Error codes and severities

- Context tracking for debugging

---

## 🧩 Important Code Locations

### **Configuration**

- Default config: [consts.py:23](consts.py)

- Config loading: [utils.py:190](utils.py)

- Example config: [example_enkrypt_mcp_config.json](example_enkrypt_mcp_config.json)

### **Authentication**

- Gateway key extraction: [gateway.py:251](gateway.py)

- Auth manager: [plugins/auth/config_manager.py](plugins/auth/config_manager.py)

- Local API key provider: [plugins/auth/example_providers.py](plugins/auth/example_providers.py)

### **Guardrails**

- Guardrail manager: [plugins/guardrails/config_manager.py](plugins/guardrails/config_manager.py)

- Enkrypt provider: [plugins/guardrails/enkrypt_provider.py](plugins/guardrails/enkrypt_provider.py)

- Input/output checks: [services/execution/secure_tool_execution_service.py](services/execution/secure_tool_execution_service.py)

### **Caching**

- Cache initialization: [client.py:53](client.py)

- Cache functions: [client.py:387](client.py)

- Cache service: [services/cache/cache_service.py](services/cache/cache_service.py)

### **Tool Discovery**

- Discovery service: [services/discovery/discovery_service.py](services/discovery/discovery_service.py)

- Forward tool call: [client.py:263](client.py)

### **Telemetry**

- Telemetry manager: [plugins/telemetry/config_manager.py](plugins/telemetry/config_manager.py)

- OpenTelemetry provider: [plugins/telemetry/opentelemetry_provider.py](plugins/telemetry/opentelemetry_provider.py)

- Lazy logger: [utils.py:37](utils.py)

### **OAuth**

- OAuth service: [services/oauth/oauth_service.py](services/oauth/oauth_service.py)

- Token manager: [services/oauth/token_manager.py](services/oauth/token_manager.py)

- Client integration: [services/oauth/integration.py](services/oauth/integration.py)

- OAuth models: [services/oauth/models.py](services/oauth/models.py)

- Validation: [services/oauth/validation.py](services/oauth/validation.py)

- Metrics: [services/oauth/metrics.py](services/oauth/metrics.py)

### **Test Servers**

- Echo server (basic): [bad_mcps/echo_mcp.py](bad_mcps/echo_mcp.py)

- Echo OAuth server: [bad_mcps/echo_oauth_mcp.py](bad_mcps/echo_oauth_mcp.py)

- Security test servers: [bad_mcps/](bad_mcps/) (14 attack scenario servers)

---

## 📝 Common Tasks

### **Add a New Server to Config**

```bash
secure-mcp-gateway config add-server --config-name "<config_name>" \
  --server-name "github" \
  --server-command "npx" \
  --args="-y,@modelcontextprotocol/server-github" \
  --description "GitHub MCP Server"
```

### **Enable Guardrails for a Server**

```bash
secure-mcp-gateway config update-server-guardrails <config_id> github \
  --input-policy '{"enabled": true, "policy_name": "Sample Airline Guardrail", "block": ["policy_violation"]}'

```

### **View Cache Status**

- Via CLI: `secure-mcp-gateway cache status`

- Via API: `GET /api/v1/cache/status` (coming soon)

- Via MCP tool: `enkrypt_get_cache_status()`

### **Clear Cache**

```bash

# Clear all
secure-mcp-gateway cache clear

# Clear specific server
secure-mcp-gateway cache clear --server-name github

# Clear gateway config
secure-mcp-gateway cache clear --cache-type gateway_config

```

### **Rotate API Key**

```bash
secure-mcp-gateway apikey rotate <old_api_key>

```

---

## 🔧 Troubleshooting

### **Common Issues**

1. **Gateway key not found**
   - Ensure API key exists in `apikeys` section of config
   - Check that key is passed in request context

2. **Cache not working**
   - Verify `enkrypt_mcp_use_external_cache` is set correctly
   - Check Redis/KeyDB connection if using external cache
   - Review cache expiration settings

3. **Guardrails not triggering**
   - Confirm `enabled: true` in guardrails policy
   - Verify Enkrypt API key is valid
   - Check that policy name exists in Enkrypt dashboard

4. **Telemetry not working**
   - Ensure OpenTelemetry Collector is running on configured port
   - Check `enkrypt_telemetry.enabled` in config
   - Verify connectivity to OTLP endpoint

### **Debug Mode**

Set `enkrypt_log_level: "DEBUG"` in config for verbose logging.

---

## 🏆 Best Practices

1. **Always use API keys**: Don't bypass authentication

2. **Cache externally for production**: Use Redis/KeyDB for multi-instance deployments

3. **Enable guardrails selectively**: Only on sensitive servers

4. **Monitor timeout metrics**: Track slow operations

5. **Use structured logging**: Include context in all logs

6. **Mask sensitive data**: Always mask in logs and responses

7. **Rotate API keys regularly**: Use built-in rotation feature

8. **Backup configs**: Use `system backup` command

9. **Test guardrails**: Use example servers to test policies

10. **Review metrics**: Use Grafana dashboards for insights

---

## 📚 Additional Resources

- **Documentation**: [README.md](README.md)

- **CLI Reference**: [CLI-Commands-Reference.md](CLI-Commands-Reference.md)

- **API Reference**: [API-Reference.md](API-Reference.md)

- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

- **PyPI**: https://pypi.org/project/secure-mcp-gateway/

- **Docker Hub**: https://hub.docker.com/r/enkryptai/secure-mcp-gateway

- **MCP Protocol**: https://modelcontextprotocol.io/

---

## 🎓 Learning Path

1. **Start with README**: Understand basic concepts

2. **Run example**: Use echo_mcp server to test

3. **Explore CLI**: Use `--help` on each command

4. **Add a real server**: GitHub MCP server

5. **Enable guardrails**: Test with sample policy

6. **Set up observability**: Run Docker Compose stack

7. **Use REST API**: Programmatic management

8. **Create custom plugin**: Extend functionality

---

**End of Documentation**

*This document serves as a comprehensive memory reference for understanding the entire secure-mcp-gateway project architecture, components, and usage.*
