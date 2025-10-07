# Enkrypt Secure MCP Gateway REST API Reference

This document provides comprehensive documentation for the REST API endpoints that expose all CLI functionality for the Enkrypt Secure MCP Gateway.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
   - [Configuration Management](#configuration-management)
   - [Project Management](#project-management)
   - [User Management](#user-management)
   - [System Operations](#system-operations)
4. [Error Handling](#error-handling)
5. [Examples](#examples)

## Getting Started

### Starting the API Server

You can start the REST API server using the CLI:

```bash
# Start with default settings (host: 0.0.0.0, port: 8001)
secure-mcp-gateway system start-api

# Start with custom host and port
python cli.py system start-api --host 127.0.0.1 --port 9000

# Start with auto-reload for development
python cli.py system start-api --reload
```

### API Documentation

Once the server is running, you can access:

- **Interactive API Documentation**: `http://localhost:8001/docs`
- **ReDoc Documentation**: `http://localhost:8001/redoc`
- **OpenAPI Schema**: `http://localhost:8001/openapi.json`

## Authentication

All API endpoints require authentication using an API key. Include the API key in the `Authorization` header:

```Shell
Authorization: Bearer <your_api_key>
```

### Getting an API Key

1. Create a user: `POST /api/v1/users`
2. Create a project: `POST /api/v1/projects`
3. Add user to project: `POST /api/v1/projects/{project_id}/users`
4. Generate API key: `POST /api/v1/users/{user_id}/api-keys`

## API Endpoints

### Configuration Management

#### List All Configurations

```http
GET /api/v1/configs
```

**Response:**

```json
{
  "message": "Configurations retrieved successfully",
  "data": [
    {
      "mcp_config_id": "uuid",
      "mcp_config_name": "My Config",
      "servers": 2,
      "used_by_projects": [...]
    }
  ]
}
```

#### Create Configuration

```http
POST /api/v1/configs
Content-Type: application/json

{
  "config_name": "My New Config"
}
```

#### Get Configuration

```http
GET /api/v1/configs/{config_identifier}
```

#### Update Configuration Name

```http
PUT /api/v1/configs/{config_identifier}/rename
Content-Type: application/json

{
  "new_name": "Updated Config Name"
}
```

#### Delete Configuration

```http
DELETE /api/v1/configs/{config_identifier}
```

#### Copy Configuration

```http
POST /api/v1/configs/copy
Content-Type: application/json

{
  "source_config": "source_config_name_or_id",
  "target_config": "new_config_name"
}
```

#### List Servers in Configuration

```http
GET /api/v1/configs/{config_identifier}/servers
```

#### Add Server to Configuration

```http
POST /api/v1/configs/{config_identifier}/servers
Content-Type: application/json

{
  "server_name": "my_server",
  "server_command": "python",
  "args": ["/path/to/server.py"],
  "env": {"ENV_VAR": "value"},
  "tools": {},
  "description": "My MCP Server",
  "input_guardrails_policy": {
    "enabled": true,
    "policy_name": "Sample Policy"
  },
  "output_guardrails_policy": {
    "enabled": true,
    "policy_name": "Sample Policy"
  }
}
```

#### Update Server in Configuration

```http
PUT /api/v1/configs/{config_identifier}/servers/{server_name}
Content-Type: application/json

{
  "server_command": "python3",
  "args": ["/new/path/to/server.py"],
  "description": "Updated description"
}
```

#### Remove Server from Configuration

```http
DELETE /api/v1/configs/{config_identifier}/servers/{server_name}
```

#### Remove All Servers from Configuration

```http
DELETE /api/v1/configs/{config_identifier}/servers
```

#### Validate Configuration

```http
POST /api/v1/configs/{config_identifier}/validate
```

#### Export Configuration

```http
POST /api/v1/configs/{config_identifier}/export
Content-Type: application/json

{
  "output_file": "/path/to/export.json"
}
```

#### Import Configuration

```http
POST /api/v1/configs/import
Content-Type: application/json

{
  "input_file": "/path/to/import.json",
  "config_name": "Imported Config"
}
```

#### Search Configurations

```http
POST /api/v1/configs/search
Content-Type: application/json

{
  "search_term": "search_query"
}
```

#### Update Server Input Guardrails

```http
PUT /api/v1/configs/{config_identifier}/servers/{server_name}/input-guardrails
Content-Type: application/json

{
  "policy_file": "/path/to/policy.json",
  "policy": {
    "enabled": true,
    "policy_name": "Input Guardrail Policy",
    "additional_config": {
      "pii_redaction": true
    },
    "block": ["policy_violation", "injection_attack"]
  }
}
```

#### Update Server Output Guardrails

```http
PUT /api/v1/configs/{config_identifier}/servers/{server_name}/output-guardrails
Content-Type: application/json

{
  "policy_file": "/path/to/policy.json",
  "policy": {
    "enabled": true,
    "policy_name": "Output Guardrail Policy",
    "additional_config": {
      "pii_redaction": true
    },
    "block": ["policy_violation", "injection_attack"]
  }
}
```

#### Update Server Guardrails (Both)

```http
PUT /api/v1/configs/{config_identifier}/servers/{server_name}/guardrails
Content-Type: application/json

{
  "input_policy_file": "/path/to/input_policy.json",
  "input_policy": {
    "enabled": true,
    "policy_name": "Input Guardrail Policy"
  },
  "output_policy_file": "/path/to/output_policy.json",
  "output_policy": {
    "enabled": true,
    "policy_name": "Output Guardrail Policy"
  }
}
```

### Project Management

#### List All Projects

```http
GET /api/v1/projects
```

#### Create Project

```http
POST /api/v1/projects
Content-Type: application/json

{
  "project_name": "My Project"
}
```

#### Get Project

```http
GET /api/v1/projects/{project_identifier}
```

#### Delete Project

```http
DELETE /api/v1/projects/{project_identifier}
```

#### Assign Configuration to Project

```http
POST /api/v1/projects/{project_identifier}/assign-config
Content-Type: application/json

{
  "config_name": "config_name_or_id"
}
```

#### Unassign Configuration from Project

```http
POST /api/v1/projects/{project_identifier}/unassign-config
```

#### Get Project Configuration

```http
GET /api/v1/projects/{project_identifier}/config
```

#### List Project Users

```http
GET /api/v1/projects/{project_identifier}/users
```

#### Add User to Project

```http
POST /api/v1/projects/{project_identifier}/users
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Remove User from Project

```http
DELETE /api/v1/projects/{project_identifier}/users/{user_identifier}
```

#### Remove All Users from Project

```http
DELETE /api/v1/projects/{project_identifier}/users
```

#### Export Project

```http
POST /api/v1/projects/{project_identifier}/export
Content-Type: application/json

{
  "output_file": "/path/to/project_export.json"
}
```

#### Search Projects

```http
POST /api/v1/projects/search
Content-Type: application/json

{
  "search_term": "search_query"
}
```

### User Management

#### List All Users

```http
GET /api/v1/users
```

#### Create User

```http
POST /api/v1/users
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Get User

```http
GET /api/v1/users/{user_identifier}
```

#### Update User

```http
PUT /api/v1/users/{user_identifier}
Content-Type: application/json

{
  "new_email": "newemail@example.com"
}
```

#### Delete User

```http
DELETE /api/v1/users/{user_identifier}
Content-Type: application/json

{
  "force": false
}
```

#### List User Projects

```http
GET /api/v1/users/{user_identifier}/projects
```

#### Generate API Key for User

```http
POST /api/v1/users/{user_identifier}/api-keys
Content-Type: application/json

{
  "project_name": "project_name_or_id"
}
```

#### List User API Keys

```http
GET /api/v1/users/{user_identifier}/api-keys?project_identifier=optional_project_id
```

#### Delete All User API Keys

```http
DELETE /api/v1/users/{user_identifier}/api-keys
```

#### List All API Keys

```http
GET /api/v1/api-keys
```

#### Rotate API Key

```http
POST /api/v1/api-keys/rotate
Content-Type: application/json

{
  "api_key": "old_api_key"
}
```

#### Disable API Key

```http
POST /api/v1/api-keys/{api_key}/disable
```

#### Enable API Key

```http
POST /api/v1/api-keys/{api_key}/enable
```

#### Delete API Key

```http
DELETE /api/v1/api-keys/{api_key}
```

#### Search Users

```http
POST /api/v1/users/search
Content-Type: application/json

{
  "search_term": "search_query"
}
```

### System Operations

#### Health Check

```http
GET /api/v1/system/health
```

#### System Backup

```http
POST /api/v1/system/backup
Content-Type: application/json

{
  "output_file": "/path/to/backup.json"
}
```

#### System Restore

```http
POST /api/v1/system/restore
Content-Type: application/json

{
  "input_file": "/path/to/backup.json"
}
```

#### System Reset

```http
POST /api/v1/system/reset
Content-Type: application/json

{
  "confirm": true
}
```

## Error Handling

The API uses standard HTTP status codes and returns error responses in the following format:

```json
{
  "error": "Error type",
  "detail": "Detailed error message",
  "timestamp": "2024-01-01T00:00:00"
}
```

### Common Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Invalid or missing API key
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

## Examples

### Complete Workflow Example

Here's a complete example of creating a configuration, project, user, and API key:

```bash
# 1. Create a user
curl -X POST "http://localhost:8001/api/v1/users" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email": "developer@example.com"}'

# Response: {"message": "User created successfully", "data": {"user_id": "uuid", "email": "developer@example.com"}}

# 2. Create a project
curl -X POST "http://localhost:8001/api/v1/projects" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"project_name": "Development Project"}'

# Response: {"message": "Project created successfully", "data": {"project_id": "uuid", "project_name": "Development Project"}}

# 3. Add user to project
curl -X POST "http://localhost:8001/api/v1/projects/{project_id}/users" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email": "developer@example.com"}'

# 4. Create a configuration
curl -X POST "http://localhost:8001/api/v1/configs" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"config_name": "Development Config"}'

# 5. Add server to configuration
curl -X POST "http://localhost:8001/api/v1/configs/{config_id}/servers" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "github_server",
    "server_command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "description": "GitHub MCP Server"
  }'

# 6. Assign configuration to project
curl -X POST "http://localhost:8001/api/v1/projects/{project_id}/assign-config" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"config_name": "Development Config"}'

# 7. Generate API key for user
curl -X POST "http://localhost:8001/api/v1/users/{user_id}/api-keys" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{"project_name": "Development Project"}'

# Response: {"message": "API key generated successfully", "data": {"api_key": "generated_api_key"}}
```

### Using the Generated API Key

Once you have an API key, you can use it to make authenticated requests:

```bash
# List configurations using the generated API key
curl -X GET "http://localhost:8001/api/v1/configs" \
  -H "Authorization: Bearer <generated_api_key>"

# List projects
curl -X GET "http://localhost:8001/api/v1/projects" \
  -H "Authorization: Bearer <generated_api_key>"
```

## Integration Examples

### Python Client Example

```python
import requests

class EnkryptGatewayAPI:
    def __init__(self, base_url="http://localhost:8001", api_key=None):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def list_configs(self):
        response = requests.get(f"{self.base_url}/api/v1/configs", headers=self.headers)
        return response.json()
    
    def create_config(self, config_name):
        data = {"config_name": config_name}
        response = requests.post(f"{self.base_url}/api/v1/configs", 
                               headers=self.headers, json=data)
        return response.json()
    
    def create_user(self, email):
        data = {"email": email}
        response = requests.post(f"{self.base_url}/api/v1/users", 
                               headers=self.headers, json=data)
        return response.json()

# Usage
api = EnkryptGatewayAPI(api_key="your_api_key")
configs = api.list_configs()
print(configs)
```

### JavaScript/Node.js Client Example

```javascript
class EnkryptGatewayAPI {
    constructor(baseUrl = 'http://localhost:8001', apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        };
    }
    
    async listConfigs() {
        const response = await fetch(`${this.baseUrl}/api/v1/configs`, {
            headers: this.headers
        });
        return response.json();
    }
    
    async createConfig(configName) {
        const response = await fetch(`${this.baseUrl}/api/v1/configs`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({ config_name: configName })
        });
        return response.json();
    }
}

// Usage
const api = new EnkryptGatewayAPI('http://localhost:8001', 'your_api_key');
api.listConfigs().then(configs => console.log(configs));
```

This REST API provides complete programmatic access to all CLI functionality, making it easy to integrate the Enkrypt Secure MCP Gateway into your applications and workflows.
