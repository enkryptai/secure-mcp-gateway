# Authentication Plugin System - Quick Start

## 🚀 5-Minute Quick Start

### Using Existing Enkrypt Auth (No Changes)

```python
from secure_mcp_gateway.services.auth.auth_service import auth_service

result = auth_service.authenticate(ctx)
# Everything works as before!
```

---

## Adding a Second Provider

### 1. Register Provider

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.auth.example_providers import OAuth2Provider

manager = get_auth_config_manager()

oauth_provider = OAuth2Provider(
    client_id="your-id",
    client_secret="your-secret",
    authorization_url="https://provider.com/oauth/authorize",
    token_url="https://provider.com/oauth/token"
)

manager.register_provider(oauth_provider)
```

### 2. Use Provider

```python
# Authenticate with OAuth
result = await manager.authenticate(ctx, provider_name="oauth2")

if result.is_success:
    print(f"Authenticated user: {result.user_id}")
```

---

## Creating Custom Provider

```python
from secure_mcp_gateway.plugins.auth import (
    AuthProvider, AuthCredentials, AuthResult, AuthStatus
)

class MyProvider(AuthProvider):
    def get_name(self):
        return "my-provider"

    async def authenticate(self, credentials):
        if self.validate(credentials.api_key):
            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                user_id="user123"
            )
        return AuthResult(
            status=AuthStatus.INVALID_CREDENTIALS,
            authenticated=False
        )
```

Register and use:

```python
manager.register_provider(MyProvider())
result = await manager.authenticate(ctx, "my-provider")
```

---

## Configuration

```json
{
  "common_mcp_gateway_config": {
    "auth_plugins": {
      "enabled": true,
      "providers": [
        {
          "name": "oauth2",
          "type": "oauth",
          "config": {"client_id": "...", "client_secret": "..."}
        }
      ]
    }
  }
}
```

---

## API Reference

```python
# Initialize
from secure_mcp_gateway.plugins.auth import initialize_auth_system
initialize_auth_system(config)

# Get manager
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
manager = get_auth_config_manager()

# Register provider
manager.register_provider(provider)

# Authenticate
result = await manager.authenticate(ctx, "provider-name")

# List providers
print(manager.list_providers())
```

---

## Documentation

- **README.md** - Full features and examples
- **COMPLETE_DOCUMENTATION.md** - Everything
- **INTEGRATION_GUIDE.md** - Custom providers
- **example_providers.py** - Code examples

---

**Status:** ✅ Production Ready | **Version:** 1.0.0 | **Backward Compatible:** Yes
