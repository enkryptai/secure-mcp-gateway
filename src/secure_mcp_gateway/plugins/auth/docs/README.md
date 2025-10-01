# Authentication Plugin System

A flexible, extensible authentication system for the Enkrypt MCP Gateway following SOLID principles.

## 🎯 Overview

The Authentication Plugin System allows you to use multiple authentication providers (Enkrypt, OAuth, JWT, custom) in your MCP Gateway, with each provider implementing a common interface for easy extensibility.

### Key Features

✅ **Multiple Providers** - Enkrypt, OAuth 2.0, JWT, API keys, Basic Auth
✅ **SOLID Principles** - Clean, maintainable architecture
✅ **Pluggable** - Easy to add custom providers
✅ **Type-Safe** - Full type hints and protocols
✅ **Session Management** - Built-in session handling
✅ **Backward Compatible** - Existing code works unchanged

---

## 🚀 Quick Start

### Using Existing Enkrypt Authentication

```python
# No changes needed!
# Existing auth_service continues to work
from secure_mcp_gateway.services.auth.auth_service import auth_service

result = auth_service.authenticate(ctx)
```

### Adding Multiple Providers

```json
{
  "common_mcp_gateway_config": {
    "auth_plugins": {
      "enabled": true,
      "default_provider": "enkrypt",
      "providers": [
        {
          "name": "oauth2",
          "type": "oauth",
          "config": {
            "client_id": "your-client-id",
            "client_secret": "your-secret"
          }
        }
      ]
    }
  }
}
```

### Using Different Providers

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager

manager = get_auth_config_manager()

# Authenticate with Enkrypt (default)
result = await manager.authenticate(ctx)

# Authenticate with OAuth
result = await manager.authenticate(ctx, provider_name="oauth2")

# Authenticate with JWT
result = await manager.authenticate(ctx, provider_name="jwt")
```

---

## 🏗️ Architecture

### SOLID Principles

```
┌─────────────────────────────────────┐
│     AuthProvider (Interface)        │
│  • authenticate()                   │
│  • validate_session()               │
│  • refresh_authentication()         │
└──────────────┬──────────────────────┘
               │
    ┌──────────┼──────────┬──────────┐
    │          │          │          │
    ▼          ▼          ▼          ▼
Enkrypt     OAuth       JWT      Custom
Provider   Provider  Provider   Provider
```

### Components

1. **AuthProvider** - Abstract interface all providers implement
2. **AuthCredentials** - Container for authentication credentials
3. **AuthResult** - Standardized authentication result
4. **AuthConfigManager** - Provider registration and management
5. **SessionManager** - Session lifecycle management

---

## 📦 Available Providers

### 1. Enkrypt Provider (Default)

Authenticates using Enkrypt's gateway key system.

```python
from secure_mcp_gateway.plugins.auth import EnkryptAuthProvider

provider = EnkryptAuthProvider(
    api_key="your-enkrypt-api-key",
    base_url="https://api.enkryptai.com",
    use_remote_config=True
)
```

### 2. OAuth 2.0 Provider

Supports OAuth 2.0 flows.

```python
from secure_mcp_gateway.plugins.auth.example_providers import OAuth2Provider

provider = OAuth2Provider(
    client_id="your-client-id",
    client_secret="your-secret",
    authorization_url="https://provider.com/oauth/authorize",
    token_url="https://provider.com/oauth/token",
    user_info_url="https://provider.com/oauth/userinfo"
)
```

### 3. JWT Provider

Validates JWT tokens.

```python
from secure_mcp_gateway.plugins.auth.example_providers import JWTProvider

provider = JWTProvider(
    secret_key="your-secret-key",
    algorithm="HS256",
    verify_exp=True
)
```

### 4. API Key Provider

Simple API key validation.

```python
from secure_mcp_gateway.plugins.auth.example_providers import APIKeyProvider

provider = APIKeyProvider(
    valid_keys={
        "key123": {"user_id": "user1", "project_id": "proj1"},
        "key456": {"user_id": "user2", "project_id": "proj2"}
    }
)
```

### 5. Basic Auth Provider

HTTP Basic authentication.

```python
from secure_mcp_gateway.plugins.auth.example_providers import BasicAuthProvider

provider = BasicAuthProvider(
    users={
        "admin": "hashed_password_here",
        "user": "hashed_password_here"
    }
)
```

---

## 🔧 Creating Custom Providers

### Step 1: Implement AuthProvider

```python
from secure_mcp_gateway.plugins.auth import (
    AuthProvider,
    AuthCredentials,
    AuthResult,
    AuthStatus,
    AuthMethod,
)

class MyCustomProvider(AuthProvider):
    def get_name(self) -> str:
        return "my-custom"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self):
        return [AuthMethod.CUSTOM]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        # Your custom authentication logic
        if self.is_valid(credentials):
            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="Authentication successful",
                user_id="user123"
            )

        return AuthResult(
            status=AuthStatus.INVALID_CREDENTIALS,
            authenticated=False,
            message="Invalid credentials"
        )

    async def validate_session(self, session_id: str) -> bool:
        return True

    async def refresh_authentication(self, session_id: str, credentials: AuthCredentials) -> AuthResult:
        return await self.authenticate(credentials)
```

### Step 2: Register Your Provider

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager

manager = get_auth_config_manager()
manager.register_provider(MyCustomProvider())
```

### Step 3: Use Your Provider

```python
result = await manager.authenticate(ctx, provider_name="my-custom")
```

---

## 📚 API Reference

### AuthCredentials

```python
@dataclass
class AuthCredentials:
    # Primary credentials
    api_key: Optional[str] = None
    gateway_key: Optional[str] = None
    project_id: Optional[str] = None
    user_id: Optional[str] = None

    # OAuth/JWT
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None

    # Basic auth
    username: Optional[str] = None
    password: Optional[str] = None

    # Metadata
    headers: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
```

### AuthResult

```python
@dataclass
class AuthResult:
    status: AuthStatus
    authenticated: bool
    message: str

    # User info
    user_id: Optional[str] = None
    project_id: Optional[str] = None
    session_id: Optional[str] = None

    # Configuration
    gateway_config: Optional[Dict] = None
    mcp_config: Optional[List[Dict]] = None

    # Permissions
    permissions: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
```

### AuthProvider Interface

```python
class AuthProvider(ABC):
    @abstractmethod
    def get_name(self) -> str:
        """Provider name"""

    @abstractmethod
    def get_version(self) -> str:
        """Provider version"""

    @abstractmethod
    def get_supported_methods(self) -> List[AuthMethod]:
        """Supported auth methods"""

    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """Authenticate user"""

    @abstractmethod
    async def validate_session(self, session_id: str) -> bool:
        """Validate session"""

    @abstractmethod
    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """Refresh authentication"""
```

---

## 🔄 Migration from Legacy Auth Service

The plugin system is **100% backward compatible**. Your existing code continues to work unchanged.

### Current Code (Still Works)

```python
from secure_mcp_gateway.services.auth.auth_service import auth_service

# All existing methods work
result = auth_service.authenticate(ctx)
is_authed = auth_service.is_authenticated(ctx)
session = auth_service.get_authenticated_session(ctx)
```

### New Plugin System (Optional)

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager

manager = get_auth_config_manager()

# Use multiple providers
result = await manager.authenticate(ctx, provider_name="oauth2")
```

---

## ⚙️ Configuration

### Minimal Configuration (Enkrypt Only)

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_api_key": "your-key",
    "enkrypt_base_url": "https://api.enkryptai.com"
  }
}
```

### Multi-Provider Configuration

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_api_key": "your-key",

    "auth_plugins": {
      "enabled": true,
      "default_provider": "enkrypt",

      "providers": [
        {
          "name": "oauth2",
          "type": "oauth",
          "config": {
            "client_id": "your-client-id",
            "client_secret": "your-secret",
            "authorization_url": "https://provider.com/oauth/authorize",
            "token_url": "https://provider.com/oauth/token",
            "user_info_url": "https://provider.com/oauth/userinfo"
          }
        },
        {
          "name": "jwt",
          "type": "jwt",
          "config": {
            "secret_key": "your-jwt-secret",
            "algorithm": "HS256",
            "verify_exp": true
          }
        }
      ]
    }
  }
}
```

---

## 🧪 Testing

### Unit Test Your Provider

```python
import pytest
from secure_mcp_gateway.plugins.auth import AuthCredentials

@pytest.mark.asyncio
async def test_custom_provider():
    provider = MyCustomProvider()

    credentials = AuthCredentials(api_key="test-key")
    result = await provider.authenticate(credentials)

    assert result.is_success
    assert result.user_id == "expected-user"
```

### Integration Test

```python
@pytest.mark.asyncio
async def test_provider_registration():
    from secure_mcp_gateway.plugins.auth import (
        get_auth_config_manager,
        initialize_auth_system
    )

    config = {"enkrypt_api_key": "test-key"}
    initialize_auth_system(config)

    manager = get_auth_config_manager()
    manager.register_provider(MyCustomProvider())

    assert "my-custom" in manager.list_providers()
```

---

## 🎯 Use Cases

### Use Case 1: Multiple Auth Methods

Different clients use different authentication:

```python
# Web app uses OAuth
web_result = await manager.authenticate(web_ctx, "oauth2")

# Mobile app uses JWT
mobile_result = await manager.authenticate(mobile_ctx, "jwt")

# Internal tools use Enkrypt
internal_result = await manager.authenticate(internal_ctx, "enkrypt")
```

### Use Case 2: Auth Provider Fallback

Try multiple providers in order:

```python
providers = ["oauth2", "jwt", "enkrypt"]

for provider_name in providers:
    result = await manager.authenticate(ctx, provider_name)
    if result.is_success:
        break
```

### Use Case 3: Custom Business Logic

```python
class BusinessAuthProvider(AuthProvider):
    async def authenticate(self, credentials):
        # Check database
        user = await db.get_user(credentials.api_key)

        # Check permissions
        if not user.has_permission("mcp_access"):
            return AuthResult(
                status=AuthStatus.INSUFFICIENT_PERMISSIONS,
                authenticated=False,
                message="Insufficient permissions"
            )

        # Check rate limits
        if await rate_limiter.is_limited(user.id):
            return AuthResult(
                status=AuthStatus.RATE_LIMITED,
                authenticated=False,
                message="Rate limit exceeded"
            )

        return AuthResult(
            status=AuthStatus.SUCCESS,
            authenticated=True,
            user_id=user.id,
            permissions=user.permissions
        )
```

---

## 📊 Features Comparison

| Feature | Legacy Auth Service | Plugin System |
|---------|---------------------|---------------|
| Enkrypt Auth | ✅ | ✅ |
| Multiple Providers | ❌ | ✅ |
| OAuth Support | ❌ | ✅ |
| JWT Support | ❌ | ✅ |
| Custom Providers | ❌ | ✅ |
| Session Management | ✅ | ✅ |
| Type Safety | ✅ | ✅ |
| Backward Compatible | N/A | ✅ |

---

## 🛠️ Troubleshooting

### Provider Not Found

```python
# Check registered providers
manager = get_auth_config_manager()
print(manager.list_providers())

# Register if missing
manager.register_provider(MyProvider())
```

### Authentication Failing

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check credentials
credentials = manager.extract_credentials(ctx)
print(credentials)  # Sensitive data is masked

# Try authentication
result = await manager.authenticate(ctx)
print(result.error)  # Check error message
```

### Session Issues

```python
# Check session stats
stats = manager.get_session_stats()
print(stats)

# Clean up expired sessions
cleaned = manager.cleanup_expired_sessions(max_age_hours=24)
print(f"Cleaned up {cleaned} expired sessions")
```

---

## 📖 Documentation

- **README.md** (this file) - Overview and quick start
- **COMPLETE_DOCUMENTATION.md** - Comprehensive guide
- **INTEGRATION_GUIDE.md** - Step-by-step integration
- **QUICKSTART.md** - Quick reference
- **example_providers.py** - Example implementations

---

## 🎓 Learn More

### Next Steps

1. Read **COMPLETE_DOCUMENTATION.md** for full details
2. Check **example_providers.py** for implementation examples
3. See **INTEGRATION_GUIDE.md** for custom provider development
4. Review **base.py** for core interfaces

### Resources

- [Enkrypt API Documentation](https://docs.enkryptai.com)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [JWT Introduction](https://jwt.io/introduction)

---

## ✅ Summary

The Authentication Plugin System provides:

✅ **Flexibility** - Use any authentication provider
✅ **Extensibility** - Easy to add custom providers
✅ **Maintainability** - Clean SOLID architecture
✅ **Compatibility** - Works with existing code
✅ **Production-Ready** - Full error handling and logging

**Status:** ✅ Production Ready
**Version:** 1.0.0
**Backward Compatible:** Yes (100%)

---

**Happy authenticating! 🚀**
