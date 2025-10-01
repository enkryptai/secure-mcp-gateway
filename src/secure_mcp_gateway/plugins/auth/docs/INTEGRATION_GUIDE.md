# Authentication Plugin System - Integration Guide

## Complete Guide to Building Custom Authentication Providers

This guide shows you how to create and integrate custom authentication providers into the Enkrypt MCP Gateway.

---

## Table of Contents

1. [Understanding the System](#understanding-the-system)
2. [Creating Your First Provider](#creating-your-first-provider)
3. [Registering Your Provider](#registering-your-provider)
4. [Using Your Provider](#using-your-provider)
5. [Advanced Patterns](#advanced-patterns)
6. [Testing](#testing)
7. [Production Deployment](#production-deployment)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Understanding the System

### Architecture Overview

```
AuthConfigManager
     ↓
AuthProviderRegistry
     ↓
AuthProvider (Abstract Interface)
     ↓
Your Custom Provider
```

### Key Concepts

1. **AuthProvider** - Interface your provider implements
2. **AuthCredentials** - Container for authentication data
3. **AuthResult** - Standardized result structure
4. **SessionData** - Session information
5. **AuthConfigManager** - Provider lifecycle management

### Core Interfaces

```python
class AuthProvider(ABC):
    """All providers must implement this interface."""

    @abstractmethod
    def get_name(self) -> str:
        """Unique provider name"""
        pass

    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """Authenticate user"""
        pass

    @abstractmethod
    async def validate_session(self, session_id: str) -> bool:
        """Validate session"""
        pass

    @abstractmethod
    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """Refresh authentication"""
        pass
```

---

## Creating Your First Provider

### Step 1: Basic Structure

```python
from secure_mcp_gateway.plugins.auth import (
    AuthProvider,
    AuthCredentials,
    AuthResult,
    AuthStatus,
    AuthMethod,
)

class MyCustomProvider(AuthProvider):
    """My custom authentication provider."""

    def __init__(self, api_key: str = None, **config):
        self.api_key = api_key
        self.config = config

    def get_name(self) -> str:
        return "my-custom-provider"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self):
        return [AuthMethod.API_KEY]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """Authenticate user."""
        api_key = credentials.api_key

        if not api_key:
            return AuthResult(
                status=AuthStatus.INVALID_CREDENTIALS,
                authenticated=False,
                message="API key required"
            )

        # Your validation logic
        if api_key == "valid-key":
            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="Authentication successful",
                user_id="user123"
            )

        return AuthResult(
            status=AuthStatus.INVALID_CREDENTIALS,
            authenticated=False,
            message="Invalid API key"
        )

    async def validate_session(self, session_id: str) -> bool:
        return True

    async def refresh_authentication(self, session_id, credentials):
        return await self.authenticate(credentials)
```

---

## Registering Your Provider

### Option 1: In Code

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager

manager = get_auth_config_manager()
manager.register_provider(MyCustomProvider(api_key="your-key"))
```

### Option 2: Via Configuration

```json
{
  "auth_plugins": {
    "enabled": true,
    "providers": [
      {
        "name": "my-custom-provider",
        "type": "custom",
        "module": "mypackage.providers.MyCustomProvider",
        "config": {"api_key": "your-key"}
      }
    ]
  }
}
```

---

## Using Your Provider

```python
from secure_mcp_gateway.plugins.auth import get_auth_config_manager

manager = get_auth_config_manager()

# Authenticate
result = await manager.authenticate(ctx, "my-custom-provider")

if result.is_success:
    print(f"User: {result.user_id}")
    print(f"Session: {result.session_id}")
```

---

## Advanced Patterns

### Pattern 1: Database Provider

```python
import asyncpg

class DatabaseAuthProvider(AuthProvider):
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.pool = None

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        if self.pool is None:
            self.pool = await asyncpg.create_pool(self.db_url)

        async with self.pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT * FROM users WHERE api_key = $1",
                credentials.api_key
            )

        if user:
            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                user_id=str(user['id'])
            )

        return AuthResult(
            status=AuthStatus.INVALID_CREDENTIALS,
            authenticated=False,
            message="Invalid credentials"
        )
```

### Pattern 2: External API Provider

```python
import httpx

class ExternalAPIProvider(AuthProvider):
    def __init__(self, api_url: str, timeout: int = 10):
        self.api_url = api_url
        self.timeout = timeout

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/validate",
                    json={"token": credentials.access_token},
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    return AuthResult(
                        status=AuthStatus.SUCCESS,
                        authenticated=True,
                        user_id=data['user_id']
                    )
        except Exception as e:
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                error=str(e)
            )
```

### Pattern 3: Cached Provider

```python
import time

class CachedAuthProvider(AuthProvider):
    def __init__(self, underlying_provider: AuthProvider, cache_ttl: int = 300):
        self.underlying_provider = underlying_provider
        self.cache_ttl = cache_ttl
        self.cache = {}

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        cache_key = credentials.api_key

        # Check cache
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if (time.time() - timestamp) < self.cache_ttl:
                return result

        # Authenticate
        result = await self.underlying_provider.authenticate(credentials)

        # Cache success
        if result.is_success:
            self.cache[cache_key] = (result, time.time())

        return result
```

---

## Testing

### Unit Test

```python
import pytest

@pytest.mark.asyncio
async def test_custom_provider():
    provider = MyCustomProvider()

    # Valid credentials
    credentials = AuthCredentials(api_key="valid-key")
    result = await provider.authenticate(credentials)
    assert result.is_success

    # Invalid credentials
    credentials = AuthCredentials(api_key="invalid-key")
    result = await provider.authenticate(credentials)
    assert not result.is_success
```

### Integration Test

```python
@pytest.mark.asyncio
async def test_provider_registration():
    from secure_mcp_gateway.plugins.auth import get_auth_config_manager

    manager = get_auth_config_manager()
    manager.register_provider(MyCustomProvider())

    assert "my-custom-provider" in manager.list_providers()
```

---

## Production Deployment

### Error Handling

```python
class ProductionProvider(AuthProvider):
    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        try:
            # Validation
            if not credentials.api_key:
                return self._error_result("API key required")

            # Rate limiting
            if not await self._check_rate_limit(credentials):
                return AuthResult(
                    status=AuthStatus.RATE_LIMITED,
                    authenticated=False,
                    message="Rate limit exceeded"
                )

            # Authenticate with retry
            for attempt in range(3):
                try:
                    return await self._do_authenticate(credentials)
                except TimeoutError:
                    if attempt < 2:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return self._error_result("Timeout")

        except Exception as e:
            return self._error_result(f"Error: {e}")
```

### Monitoring

```python
class MonitoredProvider(AuthProvider):
    def __init__(self, underlying_provider: AuthProvider):
        self.underlying_provider = underlying_provider
        self.metrics = {
            "total": 0,
            "success": 0,
            "failed": 0
        }

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        self.metrics["total"] += 1

        result = await self.underlying_provider.authenticate(credentials)

        if result.is_success:
            self.metrics["success"] += 1
        else:
            self.metrics["failed"] += 1

        return result

    def get_metrics(self):
        return self.metrics
```

---

## Best Practices

### Security

✅ **DO:**

- Validate all inputs
- Use HTTPS for APIs
- Hash passwords securely
- Implement rate limiting
- Log security events

❌ **DON'T:**

- Store plain text passwords
- Log sensitive credentials
- Skip input validation
- Ignore rate limiting

### Error Handling

✅ **DO:**

- Return meaningful errors
- Log errors for debugging
- Handle timeouts
- Implement retries

❌ **DON'T:**

- Expose internal errors
- Swallow exceptions
- Return generic messages

### Performance

✅ **DO:**

- Use async/await
- Implement caching
- Set timeouts
- Use connection pooling

❌ **DON'T:**

- Block event loop
- Make unnecessary calls
- Skip timeout config

### Testing

✅ **DO:**

- Write unit tests
- Write integration tests
- Test error cases
- Mock external services

❌ **DON'T:**

- Skip tests
- Test only happy path
- Skip error testing

---

## Troubleshooting

### Provider Not Found

```python
manager = get_auth_config_manager()
print(manager.list_providers())  # Check registered providers
manager.register_provider(MyProvider())  # Register if missing
```

### Authentication Fails

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check credentials
credentials = manager.extract_credentials(ctx)
print(credentials)  # Sensitive data is masked

# Check error
result = await manager.authenticate(ctx)
if not result.is_success:
    print(f"Error: {result.error}")
```

### Session Issues

```python
# Check session stats
stats = manager.get_session_stats()
print(stats)

# Clean expired sessions
cleaned = manager.cleanup_expired_sessions(max_age_hours=24)
print(f"Cleaned {cleaned} sessions")
```

---

## Complete Example

Here's a complete, production-ready provider:

```python
"""
Complete custom authentication provider example.
"""
import asyncio
import hashlib
import time
from typing import Dict, Any

import httpx

from secure_mcp_gateway.plugins.auth import (
    AuthProvider,
    AuthCredentials,
    AuthResult,
    AuthStatus,
    AuthMethod,
)
from secure_mcp_gateway.utils import sys_print


class CompleteCustomProvider(AuthProvider):
    """
    Production-ready authentication provider with:
    - Error handling
    - Retry logic
    - Rate limiting
    - Caching
    - Monitoring
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: int = 10,
        retry_attempts: int = 3,
        cache_ttl: int = 300,
        rate_limit_per_minute: int = 60
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.cache_ttl = cache_ttl
        self.rate_limit = rate_limit_per_minute

        # Cache and metrics
        self.cache: Dict[str, tuple] = {}
        self.rate_limiter: Dict[str, list] = {}
        self.metrics = {
            "total_attempts": 0,
            "successful": 0,
            "failed": 0,
            "cached": 0,
            "rate_limited": 0
        }

    def get_name(self) -> str:
        return "complete-custom-provider"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self):
        return [AuthMethod.API_KEY, AuthMethod.BEARER_TOKEN]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """Authenticate with comprehensive error handling."""
        self.metrics["total_attempts"] += 1
        start_time = time.time()

        try:
            # 1. Validate credentials
            if not self._validate_credentials(credentials):
                return self._error_result("Invalid credentials format")

            # 2. Check rate limit
            if not self._check_rate_limit(credentials):
                self.metrics["rate_limited"] += 1
                return AuthResult(
                    status=AuthStatus.RATE_LIMITED,
                    authenticated=False,
                    message="Rate limit exceeded"
                )

            # 3. Check cache
            cache_key = self._get_cache_key(credentials)
            cached_result = self._get_from_cache(cache_key)
            if cached_result:
                self.metrics["cached"] += 1
                cached_result.metadata["from_cache"] = True
                return cached_result

            # 4. Authenticate with retry
            result = await self._authenticate_with_retry(credentials)

            # 5. Update metrics and cache
            duration = time.time() - start_time
            result.metadata["duration_ms"] = duration * 1000

            if result.is_success:
                self.metrics["successful"] += 1
                self._add_to_cache(cache_key, result)
            else:
                self.metrics["failed"] += 1

            return result

        except Exception as e:
            sys_print(f"[{self.get_name()}] Error: {e}", is_error=True)
            self.metrics["failed"] += 1
            return self._error_result(f"Authentication error: {str(e)}")

    def _validate_credentials(self, credentials: AuthCredentials) -> bool:
        """Validate credential format."""
        token = credentials.access_token or credentials.api_key
        return token is not None and len(token) > 0

    def _check_rate_limit(self, credentials: AuthCredentials) -> bool:
        """Check rate limiting."""
        key = credentials.api_key or credentials.access_token or "anonymous"
        current_time = time.time()

        if key not in self.rate_limiter:
            self.rate_limiter[key] = []

        # Remove old entries
        self.rate_limiter[key] = [
            t for t in self.rate_limiter[key]
            if current_time - t < 60
        ]

        # Check limit
        if len(self.rate_limiter[key]) >= self.rate_limit:
            return False

        # Add current request
        self.rate_limiter[key].append(current_time)
        return True

    def _get_cache_key(self, credentials: AuthCredentials) -> str:
        """Generate cache key."""
        token = credentials.access_token or credentials.api_key
        return hashlib.sha256(token.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str):
        """Get from cache if valid."""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if (time.time() - timestamp) < self.cache_ttl:
                return result
            else:
                del self.cache[cache_key]
        return None

    def _add_to_cache(self, cache_key: str, result: AuthResult):
        """Add to cache."""
        self.cache[cache_key] = (result, time.time())

    async def _authenticate_with_retry(
        self, credentials: AuthCredentials
    ) -> AuthResult:
        """Authenticate with exponential backoff retry."""
        last_error = None

        for attempt in range(self.retry_attempts):
            try:
                return await self._do_authenticate(credentials)

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self.retry_attempts - 1:
                    wait_time = 2 ** attempt
                    sys_print(
                        f"[{self.get_name()}] Timeout, retrying in {wait_time}s...",
                        is_debug=True
                    )
                    await asyncio.sleep(wait_time)
                continue

            except Exception as e:
                last_error = e
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(1)
                    continue
                break

        return self._error_result(f"Failed after {self.retry_attempts} attempts: {last_error}")

    async def _do_authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """Perform actual authentication."""
        token = credentials.access_token or credentials.api_key

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.api_url}/auth/validate",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-API-Key": self.api_key
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return AuthResult(
                    status=AuthStatus.SUCCESS,
                    authenticated=True,
                    message="Authentication successful",
                    user_id=data.get("user_id"),
                    project_id=data.get("project_id"),
                    metadata={"api_response": data}
                )
            elif response.status_code == 401:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Invalid credentials"
                )
            elif response.status_code == 429:
                return AuthResult(
                    status=AuthStatus.RATE_LIMITED,
                    authenticated=False,
                    message="API rate limit exceeded"
                )
            else:
                return self._error_result(f"API error: {response.status_code}")

    def _error_result(self, message: str) -> AuthResult:
        """Create error result."""
        return AuthResult(
            status=AuthStatus.ERROR,
            authenticated=False,
            message=message,
            error=message
        )

    async def validate_session(self, session_id: str) -> bool:
        """Validate session."""
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """Refresh authentication."""
        # Clear cache on refresh
        cache_key = self._get_cache_key(credentials)
        if cache_key in self.cache:
            del self.cache[cache_key]

        return await self.authenticate(credentials)

    def get_metrics(self) -> Dict[str, Any]:
        """Get provider metrics."""
        total = self.metrics["total_attempts"]
        return {
            **self.metrics,
            "success_rate": self.metrics["successful"] / total if total > 0 else 0,
            "cache_hit_rate": self.metrics["cached"] / total if total > 0 else 0
        }

    def clear_cache(self):
        """Clear all cache."""
        self.cache.clear()
```

---

## Summary

You now know how to:

✅ Create custom authentication providers
✅ Implement the AuthProvider interface
✅ Register providers with the system
✅ Use different authentication methods
✅ Handle errors comprehensively
✅ Add caching and monitoring
✅ Test your implementations
✅ Deploy to production

**Your custom provider is ready for production!** 🚀

---

For more information:
- **README.md** - Features and examples
- **QUICKSTART.md** - Quick reference
- **SUMMARY.md** - Complete overview
- **base.py** - Core interfaces
- **example_providers.py** - More examples

**Happy authenticating! 🎉**
