# OAuth 2.0/2.1 Configuration Guide

## Overview

Secure MCP Gateway provides comprehensive OAuth 2.0/2.1 support for authenticating with MCP servers that require OAuth tokens. This guide covers all configuration options and use cases.

---

## Supported Features

✅ **OAuth 2.0 and 2.1 Compliance**
✅ **Client Credentials Grant** (for server-to-server authentication)
✅ **Mutual TLS (mTLS)** for enhanced security (RFC 8705)
✅ **Token Caching** with automatic refresh
✅ **Scope Validation**
✅ **Token Revocation** (RFC 7009)
✅ **Exponential Backoff** retry logic
✅ **Request Correlation IDs** for tracing
✅ **Metrics & Monitoring**

---

## Configuration Schema

### Minimal Configuration

```json
{
  "oauth_config": {
    "enabled": true,
    "OAUTH_VERSION": "2.1",
    "OAUTH_GRANT_TYPE": "client_credentials",
    "OAUTH_CLIENT_ID": "your-client-id",
    "OAUTH_CLIENT_SECRET": "your-client-secret",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token"
  }
}

```

### Complete Configuration

```json
{
  "oauth_config": {
    // Required fields
    "enabled": true,
    "OAUTH_VERSION": "2.1",                             // "2.0" or "2.1"
    "OAUTH_GRANT_TYPE": "client_credentials",          // Only client_credentials supported
    "OAUTH_CLIENT_ID": "your-client-id",
    "OAUTH_CLIENT_SECRET": "your-client-secret",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",

    // Optional - Server detection
    "is_remote": true,                                  // Explicit remote server flag

    // Optional - Token scope and resource
    "OAUTH_AUDIENCE": "https://api.example.com",       // Intended audience
    "OAUTH_ORGANIZATION": "org-123",                   // Organization ID
    "OAUTH_SCOPE": "read write delete",                // Space-separated scopes
    "OAUTH_RESOURCE": "https://resource.example.com",  // OAuth 2.1 resource indicator

    // Security settings
    "OAUTH_USE_BASIC_AUTH": true,                      // client_secret_basic (recommended)
    "OAUTH_ENFORCE_HTTPS": true,                       // Required for OAuth 2.1
    "OAUTH_TOKEN_IN_HEADER_ONLY": true,                // Never use query params
    "OAUTH_VALIDATE_SCOPES": true,                     // Validate returned scopes

    // Token management
    "OAUTH_TOKEN_EXPIRY_BUFFER": 300,                  // Refresh 5 min before expiry (seconds)

    // Mutual TLS (mTLS) - RFC 8705
    "OAUTH_USE_MTLS": false,                           // Enable mTLS
    "OAUTH_CLIENT_CERT_PATH": "/path/to/client.pem",   // Client certificate
    "OAUTH_CLIENT_KEY_PATH": "/path/to/client-key.pem",// Client private key
    "OAUTH_CA_BUNDLE_PATH": "/path/to/ca-bundle.pem",  // Optional CA bundle

    // Token revocation - RFC 7009
    "OAUTH_REVOCATION_URL": "https://auth.example.com/oauth/revoke",

    // Advanced
    "OAUTH_ADDITIONAL_PARAMS": {                       // Extra params for token request
      "custom_param": "value"
    },
    "OAUTH_CUSTOM_HEADERS": {                          // Custom HTTP headers
      "X-Custom-Header": "value"
    }
  }
}

```

---

## Configuration Fields Reference

### Core Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | Yes | `false` | Enable OAuth for this server |
| `OAUTH_VERSION` | string | No | `"2.0"` | OAuth version: `"2.0"` or `"2.1"` |
| `OAUTH_GRANT_TYPE` | string | No | `"client_credentials"` | Grant type (only client_credentials supported) |
| `OAUTH_CLIENT_ID` | string | Yes* | - | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | string | Yes* | - | OAuth client secret |
| `OAUTH_TOKEN_URL` | string | Yes | - | Token endpoint URL (must be HTTPS for OAuth 2.1) |

*Required when `enabled: true`

### Server Detection

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `is_remote` | boolean | No | Auto-detect | Explicit flag for remote servers |

**Auto-detection heuristics** (when `is_remote` not set):
- Detects `npx`, `mcp-remote`, `curl` in command

- Detects `http://` or `https://` in args

**Recommendation**: Set `is_remote: true` explicitly for remote servers to avoid false positives/negatives.

### Scope & Resource

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_AUDIENCE` | string | No | - | Intended audience for the token |
| `OAUTH_ORGANIZATION` | string | No | - | Organization identifier |
| `OAUTH_SCOPE` | string | No | - | Space-separated scopes (e.g., `"read write"`) |
| `OAUTH_RESOURCE` | string | No | - | Resource Indicator (OAuth 2.1, RFC 8707) |

### Security Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_USE_BASIC_AUTH` | boolean | No | `true` | Use HTTP Basic Auth (`client_secret_basic`) instead of body params (`client_secret_post`) |
| `OAUTH_ENFORCE_HTTPS` | boolean | No | `true` (2.1), `true` (2.0) | Enforce HTTPS for token URL |
| `OAUTH_TOKEN_IN_HEADER_ONLY` | boolean | No | `true` (2.1), `true` (2.0) | Never use query params for tokens |
| `OAUTH_VALIDATE_SCOPES` | boolean | No | `true` | Validate returned token has requested scopes |

**OAuth 2.1 Compliance**:
- `OAUTH_USE_BASIC_AUTH: true` (recommended over `client_secret_post`)

- `OAUTH_ENFORCE_HTTPS: true` (required)

- `OAUTH_TOKEN_IN_HEADER_ONLY: true` (required)

### Token Management

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_TOKEN_EXPIRY_BUFFER` | integer | No | `300` | Seconds before expiry to refresh token |

**How it works**:
- Tokens are cached after acquisition

- Cache is checked on each request

- Proactive refresh occurs when `expires_at - buffer < now`

- Default: Refresh 5 minutes before expiry

### Mutual TLS (mTLS) - RFC 8705

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_USE_MTLS` | boolean | No | `false` | Enable mutual TLS authentication |
| `OAUTH_CLIENT_CERT_PATH` | string | Yes (if mTLS) | - | Path to client certificate (.pem) |
| `OAUTH_CLIENT_KEY_PATH` | string | Yes (if mTLS) | - | Path to client private key (.pem) |
| `OAUTH_CA_BUNDLE_PATH` | string | No | - | Path to CA bundle for server verification |

**Example**:

```json
{
  "OAUTH_USE_MTLS": true,
  "OAUTH_CLIENT_CERT_PATH": "~/.certs/client.pem",
  "OAUTH_CLIENT_KEY_PATH": "~/.certs/client-key.pem",
  "OAUTH_CA_BUNDLE_PATH": "~/.certs/ca-bundle.pem"
}

```

**Notes**:
- Paths support tilde expansion (`~` → home directory)

- Certificate and key must be in PEM format

- CA bundle is optional (uses system defaults if not provided)

### Token Revocation - RFC 7009

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_REVOCATION_URL` | string | No | - | Token revocation endpoint URL |

**Usage** (programmatic):

```python
from secure_mcp_gateway.services.oauth import get_oauth_service

oauth_service = get_oauth_service()
success, error = await oauth_service.revoke_token(
    server_name="my-server",
    token="access_token_to_revoke",
    oauth_config=config,
    token_type_hint="access_token"
)

```

### Advanced Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `OAUTH_ADDITIONAL_PARAMS` | object | No | `{}` | Extra parameters for token request body |
| `OAUTH_CUSTOM_HEADERS` | object | No | `{}` | Custom HTTP headers for token request |

---

## Use Cases

### 1. Basic OAuth 2.1 with Auth0

```json
{
  "oauth_config": {
    "enabled": true,
    "OAUTH_VERSION": "2.1",
    "OAUTH_GRANT_TYPE": "client_credentials",
    "OAUTH_CLIENT_ID": "your-auth0-client-id",
    "OAUTH_CLIENT_SECRET": "your-auth0-client-secret",
    "OAUTH_TOKEN_URL": "https://yourtenant.auth0.com/oauth/token",
    "OAUTH_AUDIENCE": "https://yourapi.example.com",
    "OAUTH_SCOPE": "read:data write:data"
  }
}

```

### 2. Remote MCP Server with OAuth

```json
{
  "server_name": "remote-mcp-server",
  "config": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "https://mcp.example.com", "--allow-http"]
  },
  "oauth_config": {
    "enabled": true,
    "is_remote": true,
    "OAUTH_CLIENT_ID": "client-123",
    "OAUTH_CLIENT_SECRET": "secret-456",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
    "OAUTH_AUDIENCE": "https://mcp.example.com"
  }
}

```

**How it works**:
- Token is obtained via OAuth flow

- For remote servers: Token injected via `--header "Authorization: Bearer <token>"` arguments

- For local servers: Token available in environment variables

### 3. mTLS with GitHub

```json
{
  "oauth_config": {
    "enabled": true,
    "OAUTH_VERSION": "2.0",
    "OAUTH_CLIENT_ID": "github-app-client-id",
    "OAUTH_CLIENT_SECRET": "github-app-client-secret",
    "OAUTH_TOKEN_URL": "https://github.com/login/oauth/access_token",
    "OAUTH_USE_MTLS": true,
    "OAUTH_CLIENT_CERT_PATH": "~/.ssh/github-app.pem",
    "OAUTH_CLIENT_KEY_PATH": "~/.ssh/github-app-key.pem"
  }
}

```

### 4. Keycloak with Organization

```json
{
  "oauth_config": {
    "enabled": true,
    "OAUTH_VERSION": "2.0",
    "OAUTH_CLIENT_ID": "keycloak-client",
    "OAUTH_CLIENT_SECRET": "keycloak-secret",
    "OAUTH_TOKEN_URL": "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token",
    "OAUTH_AUDIENCE": "account",
    "OAUTH_SCOPE": "openid profile email",
    "OAUTH_ADDITIONAL_PARAMS": {
      "realm": "myrealm"
    }
  }
}

```

### 5. Okta with Token Revocation

```json
{
  "oauth_config": {
    "enabled": true,
    "OAUTH_VERSION": "2.0",
    "OAUTH_CLIENT_ID": "okta-client-id",
    "OAUTH_CLIENT_SECRET": "okta-client-secret",
    "OAUTH_TOKEN_URL": "https://dev-123456.okta.com/oauth2/default/v1/token",
    "OAUTH_REVOCATION_URL": "https://dev-123456.okta.com/oauth2/default/v1/revoke",
    "OAUTH_AUDIENCE": "api://default",
    "OAUTH_SCOPE": "custom.scope"
  }
}

```

---

## Token Injection

### For Remote Servers

Tokens are injected via HTTP headers:

```bash
npx -y mcp-remote https://api.example.com --allow-http \
  --header "Authorization: Bearer <access_token>"

```

### For Local Servers

Tokens are available in environment variables:

```bash
ENKRYPT_ACCESS_TOKEN=<access_token>
AUTHORIZATION=Bearer <access_token>
OAUTH_ACCESS_TOKEN=<access_token>
OAUTH_TOKEN_TYPE=Bearer
HTTP_HEADER_Authorization=Bearer <access_token>
HTTP_HEADER_AUTHORIZATION=Bearer <access_token>

```

---

## Monitoring & Metrics

### Available Metrics

```python
from secure_mcp_gateway.services.oauth import get_oauth_service

oauth_service = get_oauth_service()
metrics = oauth_service.get_metrics()

print(metrics)

# {

#   "token_acquisitions_total": 150,

#   "token_acquisitions_success": 148,

#   "token_acquisitions_failure": 2,

#   "token_cache_hits": 1200,

#   "token_cache_misses": 150,

#   "token_refreshes": 45,

#   "token_invalidations": 3,

#   "cache_hit_ratio": 0.889,

#   "success_rate": 0.987,

#   "avg_latency_ms": 234.5,

#   "max_latency_ms": 1200.3,

#   "min_latency_ms": 120.1,

#   "active_tokens": 12

# }

```

### Logging

OAuth operations are logged with correlation IDs:

```

[OAuthService] Token request correlation_id=f47ac10b-58cc-4372-a567-0e02b2c3d479 for github-server
[OAuthService] Successfully obtained token for github-server, expires in 3600s

```

**Log Levels**:
- `INFO`: Token acquisition success, cache hits

- `WARNING`: Scope validation failures, retries, missing CA bundles

- `ERROR`: Authentication failures, network errors, certificate errors

- `DEBUG`: Detailed request/response info (when `enkrypt_log_level: DEBUG`)

---

## Error Handling

### Common Errors

**1. Invalid Credentials**

```

OAuth token request failed: invalid_client - Client authentication failed

```

**Solution**: Verify `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`

**2. HTTPS Required**

```

OAuth 2.1 requires HTTPS for token_url

```

**Solution**: Use `https://` URL or set `OAUTH_VERSION: "2.0"`

**3. Certificate Not Found**

```

Client certificate not found: /path/to/cert.pem

```

**Solution**: Verify certificate path and file permissions

**4. Scope Validation Failure**

```

Token scopes validation failed. Requested: read write, Received: read

```

**Solution**: Request correct scopes or set `OAUTH_VALIDATE_SCOPES: false`

**5. Network Errors (Retried)**

```

Retrying token acquisition for server-name, attempt 2/3

```

**Info**: Automatic retry with exponential backoff (2s, 4s, 8s)

---

## Security Best Practices

### ✅ Do's

1. **Use OAuth 2.1** when possible for enhanced security

2. **Enable HTTPS enforcement** (`OAUTH_ENFORCE_HTTPS: true`)

3. **Use HTTP Basic Auth** (`OAUTH_USE_BASIC_AUTH: true`)

4. **Validate scopes** (`OAUTH_VALIDATE_SCOPES: true`)

5. **Enable mTLS** for high-security environments

6. **Rotate secrets regularly** using token revocation

7. **Use minimal scopes** (principle of least privilege)

8. **Store certificates securely** with proper file permissions (600)

### ❌ Don'ts

1. **Don't commit secrets** to version control

2. **Don't disable HTTPS** in production

3. **Don't use `client_secret_post`** unless required by server

4. **Don't set long expiry buffers** (keep default 300s)

5. **Don't ignore scope validation failures**

6. **Don't share client certificates** across environments

---

## Troubleshooting

### Enable Debug Logging

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "DEBUG"
  }
}

```

### Check Token Cache

```python
from secure_mcp_gateway.services.oauth import get_token_manager

token_manager = get_token_manager()
token_info = token_manager.get_token_info("server-name", "config-id")
print(token_info)

# {

#   "access_token": "ey...***",

#   "token_type": "Bearer",

#   "expires_in": 3600,

#   "scope": "read write",

#   "created_at": "2025-01-15T10:00:00",

#   "expires_at": "2025-01-15T11:00:00",

#   "is_expired": false,

#   "status": "valid"

# }

```

### Invalidate Token

```python
from secure_mcp_gateway.services.oauth import invalidate_server_oauth_token

await invalidate_server_oauth_token("server-name", "config-id")

```

### Force Refresh

```python
from secure_mcp_gateway.services.oauth import refresh_server_oauth_token

token, error = await refresh_server_oauth_token(
    server_name="server-name",
    server_entry=server_config,
    config_id="config-id"
)

```

---

## FAQ

**Q: Can I use authorization code grant?**
A: Not yet. Only client credentials grant is currently supported.

**Q: How do I know if my server is remote?**
A: Set `is_remote: true` explicitly in `oauth_config`, or the gateway will auto-detect based on command/args.

**Q: Do tokens work with stdio MCP servers?**
A: Yes! Tokens are injected as environment variables for stdio servers.

**Q: How often are tokens refreshed?**
A: Proactively, 5 minutes (300s) before expiry by default. Configurable via `OAUTH_TOKEN_EXPIRY_BUFFER`.

**Q: Can I use OAuth without mTLS?**
A: Yes. mTLS is optional and disabled by default.

**Q: What happens if token acquisition fails?**
A: Automatic retry with exponential backoff (3 attempts: 2s, 4s, 8s). After exhaustion, returns error.

**Q: Are tokens shared across servers?**
A: No. Each server has its own cached token, keyed by `server_name` and `config_id`.

---

## Version History

- **v2.1.2** (2025-10-15): Added mTLS, scope validation, token revocation, retry logic, metrics

- **v2.1.0** (2025-10-10): Initial OAuth 2.0/2.1 client credentials support

---

## References

- [OAuth 2.0 (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)

- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10)

- [OAuth 2.0 Mutual-TLS (RFC 8705)](https://datatracker.ietf.org/doc/html/rfc8705)

- [OAuth 2.0 Token Revocation (RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)

- [OAuth 2.0 Resource Indicators (RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707)
