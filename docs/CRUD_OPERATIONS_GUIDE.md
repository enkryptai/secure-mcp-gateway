# Enkrypt Secure MCP Gateway CRUD Operations Guide

This guide provides comprehensive documentation for managing gateways, MCP servers, and users through CRUD (Create, Read, Update, Delete) operations.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [REST API](#rest-api)
4. [CLI Management](#cli-management)
5. [Data Models](#data-models)
6. [Authentication & Authorization](#authentication--authorization)
7. [Usage Examples](#usage-examples)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

## Overview

The Enkrypt Secure MCP Gateway provides three interfaces for managing resources:

1. **CRUD Module** (`crud.py`) - Core business logic for data operations
2. **REST API** (`api.py`) - HTTP API endpoints with FastAPI
3. **CLI Manager** (`cli_manager.py`) - Command-line interface with Click

### Key Features

- **Comprehensive CRUD Operations** - Full Create, Read, Update, Delete support
- **Role-Based Access Control** - Admin, User, Viewer, Operator roles
- **Data Validation** - Pydantic models with comprehensive validation
- **Audit Trails** - Complete audit logging for all operations
- **Async Operations** - High-performance async/await support
- **Caching** - Redis-based caching for improved performance
- **Encryption** - Sensitive data encryption at rest
- **Pagination** - Efficient pagination for large datasets

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Manager   │    │    REST API     │    │   Web Client    │
│   (cli_manager) │    │     (api.py)    │    │   (Browser)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼───────────────┐
                    │        CRUD Module          │
                    │        (crud.py)            │
                    └─────────────┬───────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────▼───────┐    ┌─────────▼───────┐    ┌─────────▼───────┐
│ Telemetry       │    │ Audit Trails    │    │ Cache Layer     │
│ (telemetry.py)  │    │ (audit.py)      │    │ (Redis)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## REST API

### Base URL
```
http://localhost:8000/api/v1
```

### Authentication
All API endpoints require JWT authentication (except login and health check).

```bash
# Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "password"}'

# Use token in subsequent requests
curl -X GET "http://localhost:8000/api/v1/gateways" \
     -H "Authorization: Bearer <your-jwt-token>"
```

### Gateway Management

#### Create Gateway
```bash
POST /api/v1/gateways
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "Production Gateway",
  "description": "Main production gateway for MCP services",
  "mcp_config": [
    {
      "command": "node",
      "args": ["server.js"],
      "env": {"NODE_ENV": "production"}
    }
  ],
  "settings": {
    "timeout": 30,
    "max_connections": 100
  },
  "metadata": {
    "environment": "production",
    "region": "us-east-1"
  }
}
```

#### List Gateways
```bash
GET /api/v1/gateways?limit=10&offset=0&status=active
Authorization: Bearer <token>
```

#### Get Gateway
```bash
GET /api/v1/gateways/{gateway_id}
Authorization: Bearer <token>
```

#### Update Gateway
```bash
PUT /api/v1/gateways/{gateway_id}
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "Updated Gateway Name",
  "description": "Updated description"
}
```

#### Delete Gateway
```bash
DELETE /api/v1/gateways/{gateway_id}
Authorization: Bearer <token>
```

### MCP Server Management

#### Create MCP Server
```bash
POST /api/v1/servers
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "GitHub Integration Server",
  "description": "MCP server for GitHub API integration",
  "command": "python",
  "args": ["-m", "github_mcp_server"],
  "env": {
    "GITHUB_TOKEN": "ghp_xxxxxxxxxxxx"
  },
  "gateway_id": "gateway-uuid-here",
  "tools": {
    "github_search": {"enabled": true},
    "github_issues": {"enabled": true}
  },
  "guardrails": {
    "rate_limit": {"requests_per_minute": 60},
    "content_filter": {"enabled": true}
  }
}
```

#### List MCP Servers
```bash
GET /api/v1/servers?gateway_id={gateway_id}&status=active
Authorization: Bearer <token>
```

#### Get MCP Server
```bash
GET /api/v1/servers/{server_id}
Authorization: Bearer <token>
```

#### Update MCP Server
```bash
PUT /api/v1/servers/{server_id}
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "Updated Server Name",
  "tools": {
    "github_search": {"enabled": false}
  }
}
```

#### Delete MCP Server
```bash
DELETE /api/v1/servers/{server_id}
Authorization: Bearer <token>
```

### User Management

#### Create User
```bash
POST /api/v1/users
Content-Type: application/json
Authorization: Bearer <token>

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "secure_password123",
  "role": "user",
  "permissions": ["read_gateways", "read_servers"],
  "metadata": {
    "department": "engineering",
    "team": "platform"
  }
}
```

#### List Users
```bash
GET /api/v1/users?role=user&status=active
Authorization: Bearer <token>
```

#### Get User
```bash
GET /api/v1/users/{user_id}
Authorization: Bearer <token>
```

#### Update User
```bash
PUT /api/v1/users/{user_id}
Content-Type: application/json
Authorization: Bearer <token>

{
  "email": "john.doe@example.com",
  "role": "operator"
}
```

#### Delete User
```bash
DELETE /api/v1/users/{user_id}
Authorization: Bearer <token>
```

### Health & Monitoring

#### Health Check
```bash
GET /api/v1/health
```

#### System Metrics (Admin Only)
```bash
GET /api/v1/metrics
Authorization: Bearer <token>
```

## CLI Management

### Installation
```bash
pip install -r requirements.txt
```

### Gateway Commands

#### Create Gateway
```bash
python -m secure_mcp_gateway.cli_manager gateway create \
  --name "My Gateway" \
  --description "Test gateway for development" \
  --config-file ./gateway-config.json \
  --settings '{"timeout": 30}' \
  --metadata '{"env": "dev"}'
```

#### List Gateways
```bash
# Table format (default)
python -m secure_mcp_gateway.cli_manager gateway list

# JSON format
python -m secure_mcp_gateway.cli_manager gateway list --output json

# Filter by status
python -m secure_mcp_gateway.cli_manager gateway list --status active
```

#### Show Gateway Details
```bash
python -m secure_mcp_gateway.cli_manager gateway show <gateway-id>
```

#### Update Gateway
```bash
python -m secure_mcp_gateway.cli_manager gateway update <gateway-id> \
  --name "Updated Name" \
  --description "Updated description"
```

#### Delete Gateway
```bash
python -m secure_mcp_gateway.cli_manager gateway delete <gateway-id>

# Skip confirmation
python -m secure_mcp_gateway.cli_manager gateway delete <gateway-id> --force
```

#### Export Gateway Configuration
```bash
# Export to stdout
python -m secure_mcp_gateway.cli_manager gateway export <gateway-id>

# Export to file
python -m secure_mcp_gateway.cli_manager gateway export <gateway-id> \
  --output-file ./gateway-backup.json
```

### MCP Server Commands

#### Create MCP Server
```bash
python -m secure_mcp_gateway.cli_manager server create \
  --name "GitHub Server" \
  --description "GitHub integration server" \
  --command "python" \
  --args '["--m", "github_server"]' \
  --env '{"GITHUB_TOKEN": "token"}' \
  --gateway-id <gateway-id> \
  --tools '{"search": {"enabled": true}}' \
  --guardrails '{"rate_limit": 60}'
```

#### List MCP Servers
```bash
# All servers
python -m secure_mcp_gateway.cli_manager server list

# Filter by gateway
python -m secure_mcp_gateway.cli_manager server list --gateway-id <gateway-id>

# Filter by status
python -m secure_mcp_gateway.cli_manager server list --status active
```

#### Show MCP Server Details
```bash
python -m secure_mcp_gateway.cli_manager server show <server-id>
```

#### Delete MCP Server
```bash
python -m secure_mcp_gateway.cli_manager server delete <server-id>
```

#### Start API Server
```bash
python -m secure_mcp_gateway.cli_manager server start-api \
  --host 0.0.0.0 \
  --port 8000 \
  --reload
```

### User Commands

#### Create User
```bash
python -m secure_mcp_gateway.cli_manager user create \
  --username admin \
  --email admin@example.com \
  --role admin \
  --permissions '["admin"]'
```

#### List Users
```bash
python -m secure_mcp_gateway.cli_manager user list

# Filter by role
python -m secure_mcp_gateway.cli_manager user list --role admin
```

#### Show User Details
```bash
python -m secure_mcp_gateway.cli_manager user show <user-id>
```

#### Delete User
```bash
python -m secure_mcp_gateway.cli_manager user delete <user-id>
```

#### Reset User Password
```bash
python -m secure_mcp_gateway.cli_manager user reset-password <user-id>
```

### System Commands

#### Show Configuration
```bash
python -m secure_mcp_gateway.cli_manager config show
```

#### Health Check
```bash
python -m secure_mcp_gateway.cli_manager health
```

#### System Metrics
```bash
python -m secure_mcp_gateway.cli_manager metrics
```

## Data Models

### Gateway Model
```python
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "api_key": "string",
  "status": "active|inactive|suspended|deleted",
  "created_at": "datetime",
  "updated_at": "datetime",
  "created_by": "user_id",
  "mcp_config": [
    {
      "command": "string",
      "args": ["string"],
      "env": {"key": "value"}
    }
  ],
  "settings": {
    "timeout": 30,
    "max_connections": 100
  },
  "metadata": {
    "environment": "production",
    "region": "us-east-1"
  }
}
```

### MCP Server Model
```python
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "command": "string",
  "args": ["string"],
  "env": {"key": "value"},
  "status": "active|inactive|suspended|deleted",
  "created_at": "datetime",
  "updated_at": "datetime",
  "created_by": "user_id",
  "gateway_id": "uuid",
  "tools": {
    "tool_name": {
      "enabled": true,
      "config": {}
    }
  },
  "guardrails": {
    "rate_limit": {"requests_per_minute": 60},
    "content_filter": {"enabled": true}
  },
  "metadata": {}
}
```

### User Model
```python
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "role": "admin|user|viewer|operator",
  "status": "active|inactive|suspended|deleted",
  "created_at": "datetime",
  "updated_at": "datetime",
  "last_login": "datetime",
  "permissions": ["string"],
  "metadata": {}
}
```

## Authentication & Authorization

### User Roles

#### Admin
- Full access to all resources
- Can create, read, update, delete all entities
- Can manage users and system configuration

#### Operator
- Can manage gateways and MCP servers
- Cannot manage users (except own profile)
- Can view system metrics

#### User
- Can view own profile and assigned resources
- Limited access to gateway and server information
- Cannot perform administrative actions

#### Viewer
- Read-only access to assigned resources
- Cannot modify any data
- Can view system health and basic metrics

### JWT Token Structure
```json
{
  "user_id": "uuid",
  "username": "string",
  "role": "admin|user|viewer|operator",
  "exp": 1234567890,
  "iat": 1234567890
}
```

### API Key Authentication
Gateways use API keys for authentication:
```bash
curl -X POST "http://localhost:8000/api/v1/gateway/tools" \
     -H "X-API-Key: gw_xxxxxxxxxxxxxxxx" \
     -H "Content-Type: application/json"
```

## Usage Examples

### Complete Workflow Example

#### 1. Create Admin User
```bash
python -m secure_mcp_gateway.cli_manager user create \
  --username admin \
  --email admin@company.com \
  --role admin
```

#### 2. Start API Server
```bash
python -m secure_mcp_gateway.cli_manager server start-api --port 8000
```

#### 3. Login via API
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your-password"}'
```

#### 4. Create Gateway
```bash
curl -X POST "http://localhost:8000/api/v1/gateways" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Production Gateway",
       "description": "Main production gateway"
     }'
```

#### 5. Create MCP Server
```bash
curl -X POST "http://localhost:8000/api/v1/servers" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "GitHub Server",
       "description": "GitHub integration",
       "command": "python",
       "args": ["-m", "github_server"],
       "gateway_id": "<gateway-id>"
     }'
```

### Batch Operations Example

#### Create Multiple Users
```bash
#!/bin/bash
users=("alice:alice@company.com:user" "bob:bob@company.com:operator")

for user_data in "${users[@]}"; do
  IFS=':' read -r username email role <<< "$user_data"
  python -m secure_mcp_gateway.cli_manager user create \
    --username "$username" \
    --email "$email" \
    --role "$role"
done
```

#### Export All Gateway Configurations
```bash
#!/bin/bash
gateways=$(python -m secure_mcp_gateway.cli_manager gateway list --output json | jq -r '.gateways[].id')

for gateway_id in $gateways; do
  python -m secure_mcp_gateway.cli_manager gateway export "$gateway_id" \
    --output-file "./backups/gateway-${gateway_id}.json"
done
```

## Best Practices

### Security
1. **Use Strong Passwords** - Enforce minimum 8 characters with complexity
2. **Rotate API Keys** - Regularly rotate gateway API keys
3. **Limit Permissions** - Follow principle of least privilege
4. **Enable Audit Logging** - Monitor all administrative actions
5. **Use HTTPS** - Always use HTTPS in production

### Performance
1. **Use Pagination** - Always paginate large result sets
2. **Cache Frequently Accessed Data** - Leverage Redis caching
3. **Batch Operations** - Use batch operations for bulk changes
4. **Monitor Resource Usage** - Track API usage and performance metrics

### Data Management
1. **Regular Backups** - Export configurations regularly
2. **Soft Deletes** - Use soft deletes for data recovery
3. **Version Control** - Track configuration changes
4. **Data Validation** - Always validate input data

### Monitoring
1. **Health Checks** - Implement comprehensive health monitoring
2. **Audit Trails** - Enable complete audit logging
3. **Metrics Collection** - Use OpenTelemetry for observability
4. **Alerting** - Set up alerts for critical events

## Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Check token expiration
curl -X GET "http://localhost:8000/api/v1/users/me" \
     -H "Authorization: Bearer <token>"

# Login again if token expired
curl -X POST "http://localhost:8000/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "password"}'
```

#### Permission Denied
```bash
# Check user role and permissions
python -m secure_mcp_gateway.cli_manager user show <user-id>

# Update user role if needed
curl -X PUT "http://localhost:8000/api/v1/users/<user-id>" \
     -H "Authorization: Bearer <admin-token>" \
     -H "Content-Type: application/json" \
     -d '{"role": "admin"}'
```

#### Cache Issues
```bash
# Check Redis connection
redis-cli ping

# Clear cache if needed
redis-cli flushdb
```

#### API Server Issues
```bash
# Check server logs
python -m secure_mcp_gateway.cli_manager server start-api --reload

# Verify health endpoint
curl -X GET "http://localhost:8000/api/v1/health"
```

### Debug Mode
Enable debug mode for detailed logging:
```bash
export ENKRYPT_LOG_LEVEL=debug
python -m secure_mcp_gateway.cli_manager --debug gateway list
```

### Log Analysis
Check audit logs for troubleshooting:
```bash
# View recent audit events
grep "audit_event" /var/log/enkrypt-gateway.log | tail -20

# Filter by user
grep "user_id.*admin" /var/log/enkrypt-gateway.log
```

## Configuration

### Environment Variables
```bash
# JWT Configuration
export ENKRYPT_JWT_SECRET="your-secret-key"
export ENKRYPT_JWT_EXPIRATION_HOURS=24

# Redis Configuration
export ENKRYPT_REDIS_HOST="localhost"
export ENKRYPT_REDIS_PORT=6379
export ENKRYPT_REDIS_PASSWORD=""

# API Configuration
export ENKRYPT_API_HOST="0.0.0.0"
export ENKRYPT_API_PORT=8000

# Logging Configuration
export ENKRYPT_LOG_LEVEL="INFO"
export ENKRYPT_AUDIT_ENABLED=true

# Encryption
export ENKRYPT_CRUD_ENCRYPTION_KEY="your-encryption-key"
```

### Configuration File
Create `config.json`:
```json
{
  "enkrypt_jwt_secret": "your-secret-key",
  "enkrypt_jwt_expiration_hours": 24,
  "enkrypt_redis_host": "localhost",
  "enkrypt_redis_port": 6379,
  "enkrypt_api_host": "0.0.0.0",
  "enkrypt_api_port": 8000,
  "enkrypt_log_level": "INFO",
  "enkrypt_audit_enabled": true
}
```

## Support

For additional support:
1. Check the [main documentation](../README.md)
2. Review [performance optimizations](./PERFORMANCE_OPTIMIZATIONS.md)
3. See [telemetry implementation](./TELEMETRY_AND_AUDIT_IMPLEMENTATION.md)
4. Open an issue on GitHub for bugs or feature requests

---

*This guide covers the comprehensive CRUD operations for the Enkrypt Secure MCP Gateway. For the latest updates and additional features, please refer to the main documentation.*