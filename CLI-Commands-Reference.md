# ENKRYPT SECURE MCP GATEWAY CLI - COMPLETE FEATURES & TESTED COMMANDS REFERENCE

- **Full Feature Set & Test Coverage**

## TABLE OF CONTENTS

1. [SETUP & INSTALLATION](#1-setup--installation)
2. [CONFIGURATION MANAGEMENT](#2-configuration-management)
    - [2.1 Update server input guardrails policy](#21-update-server-input-guardrails-policy)
3. [PROJECT MANAGEMENT](#3-project-management)
4. [USER MANAGEMENT](#4-user-management)
5. [SYSTEM MANAGEMENT](#5-system-management)
6. [SEARCH & DISCOVERY](#6-search--discovery)
7. [IMPORT/EXPORT OPERATIONS](#7-importexport-operations)
8. [VALIDATION & HEALTH CHECKS](#8-validation--health-checks)
9. [BACKUP & RECOVERY](#9-backup--recovery)
10. [WORKFLOW EXAMPLES](#10-workflow-examples)
11. [TROUBLESHOOTING & ERROR SCENARIOS](#11-troubleshooting--error-scenarios)
12. [ADVANCED FEATURES & COVERAGE](#12-advanced-features--coverage)
13. [BEST PRACTICES](#13-best-practices)
14. [USAGE INSTRUCTIONS](#14-usage-instructions)
15. [SUPPORT & HELP](#15-support--help)

## 1. SETUP & INSTALLATION

### Generate Default Configuration

```bash
secure-mcp-gateway generate-config
```

### Install Gateway for Claude Desktop

```bash
secure-mcp-gateway install --client claude-desktop
secure-mcp-gateway install --client claude
```

### Install Gateway for Cursor

```bash
secure-mcp-gateway install --client cursor
```

## 2. CONFIGURATION MANAGEMENT

### BASIC CONFIG OPERATIONS

#### List all MCP configurations

```bash
secure-mcp-gateway config list
```

#### Add new MCP configuration

```bash
secure-mcp-gateway config add --config-name "production-config"
secure-mcp-gateway config add --config-name "development-config"
```

#### Get MCP configuration details

```bash
secure-mcp-gateway config get --config-name "production-config"
secure-mcp-gateway config get --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777"
```

#### Copy MCP configuration

```bash
secure-mcp-gateway config copy --source-config "production-config" --target-config "staging-config"
```

#### Rename MCP configuration

```bash
secure-mcp-gateway config rename --config-name "old-name" --new-name "new-name"
secure-mcp-gateway config rename --config-id "config-id" --new-name "new-name"
```

#### Remove MCP configuration

```bash
secure-mcp-gateway config remove --config-name "production-config"
secure-mcp-gateway config remove --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777"
```

### SERVER MANAGEMENT

#### List servers in configuration

```bash
secure-mcp-gateway config list-servers --config-name "development-config"
secure-mcp-gateway config list-servers --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777"
```

#### Add server to configuration

```bash
secure-mcp-gateway config add-server --config-name "staging-config" --server-name "web-server" --server-command "python" --args "server.py" --description "Web server"
```

#### Add server with environment variables

```bash
secure-mcp-gateway config add-server --config-name "development-config" --server-name "db-server" --server-command "python" --args "db.py" --env '{"DB_HOST": "localhost", "DB_PORT": "5432", "DEBUG": "true"}' --description "Database server with env vars"
```


#### Add server with tools configuration

```bash
secure-mcp-gateway config add-server --config-name "development-config" --server-name "tool-server" --server-command "python" --args "tools.py" --tools '{"search": {"enabled": true}, "calculator": {"enabled": false}, "file_reader": {"enabled": true}}' --description "Tool server with specific tools"
```

#### Add server with guardrails

```bash
secure-mcp-gateway config add-server --config-name "production-config" --server-name "secure-input-server" --server-command "python" --args "secure.py" --input-guardrails-policy '{"enabled": true, "policy_name": "Input Security Policy", "additional_config": {"pii_redaction": true, "content_filtering": true}, "block": ["policy_violation", "injection_attack", "malicious_input"]}' --description "Server with input guardrails"

secure-mcp-gateway config add-server --config-name "production-config" --server-name "secure-output-server" --server-command "python" --args "secure_output.py" --output-guardrails-policy '{"enabled": true, "policy_name": "Output Security Policy", "additional_config": {"relevancy": true, "hallucination": true, "adherence": true, "toxicity_filter": true}, "block": ["policy_violation", "injection_attack", "harmful_content"]}' --description "Server with output guardrails"
```

#### Add server with complex configuration

```bash
secure-mcp-gateway config add-server --config-name "production-config" --server-name "complex-server" --server-command "python" --args "complex.py" --env '{"API_KEY": "secret", "ENVIRONMENT": "production", "LOG_LEVEL": "INFO"}' --tools '{"web_search": {"enabled": true}, "code_interpreter": {"enabled": false}, "file_system": {"enabled": true, "read_only": true}}' --input-guardrails-policy {input-guardrails} --description "Complex server configuration"
```

#### Get server details

```bash
secure-mcp-gateway config get-server --config-name "development-config" --server-name "web-server"
```

#### Update server configuration

```bash
secure-mcp-gateway config update-server --config-name "development-config" --server-name "web-server" --server-command "node" --args "app.js" --description "Updated web server"
secure-mcp-gateway config update-server --config-name "development-config" --server-name "tool-server" --tools '{"search": {"enabled": true}, "calculator": {"enabled": true}, "summarizer": {"enabled": false}}'
secure-mcp-gateway config update-server --config-name "development-config" --server-name "db-server" --env '{"DB_HOST": "remote-db", "DB_PORT": "5433", "DEBUG": "false", "CACHE_ENABLED": "true"}'
```

### 2.1 Update server input guardrails policy

#### Update both input and output guardrails policies

```bash
# Update both guardrails with JSON strings
secure-mcp-gateway config update-server-guardrails --config-name "default_config" --server-name "echo_server" --input-policy "{\"enabled\": true, \"policy_name\": \"Custom Input Policy\", \"additional_config\": {\"pii_redaction\": true}, \"block\": [\"policy_violation\", \"sensitive_data\"]}" --output-policy "{\"enabled\": true, \"policy_name\": \"Custom Output Policy\", \"additional_config\": {\"relevancy\": true, \"hallucination\": true, \"adherence\": true}, \"block\": [\"policy_violation\", \"hallucination\"]}"

# Update both guardrails from JSON files
secure-mcp-gateway config update-server-guardrails --config-name "default_config" --server-name "echo_server" --input-policy-file "input_policy.json" --output-policy-file "output_policy.json"

# Update only input guardrails using combined command
secure-mcp-gateway config update-server-guardrails --config-name "default_config" --server-name "echo_server" --input-policy-file "input_policy.json"

# Update only output guardrails using combined command
secure-mcp-gateway config update-server-guardrails --config-name "default_config" --server-name "echo_server" --output-policy-file "output_policy.json"
```

#### Update server input guardrails policy

```bash
# Update input guardrails with JSON string
secure-mcp-gateway config update-server-input-guardrails --config-name "default_config" --server-name "echo_server" --policy "{\"enabled\": true, \"policy_name\": \"Custom Policy\", \"additional_config\": {\"pii_redaction\": true}, \"block\": [\"policy_violation\", \"sensitive_data\"]}"

# Update input guardrails from JSON file
secure-mcp-gateway config update-server-input-guardrails --config-name "default_config" --server-name "echo_server" --policy-file "input_policy.json"

# Update input guardrails by config ID
secure-mcp-gateway config update-server-input-guardrails --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777" --server-name "echo_server" --policy-file "input_policy.json"
```

#### Update server output guardrails policy

```bash
# Update output guardrails with JSON string
secure-mcp-gateway config update-server-output-guardrails --config-name "default_config" --server-name "echo_server" --policy "{\"enabled\": true, \"policy_name\": \"Custom Output Policy\", \"additional_config\": {\"relevancy\": true, \"hallucination\": true, \"adherence\": true}, \"block\": [\"policy_violation\", \"hallucination\"]}"

# Update output guardrails from JSON file
secure-mcp-gateway config update-server-output-guardrails --config-name "default_config" --server-name "echo_server" --policy-file "output_policy.json"

# Update output guardrails by config ID
secure-mcp-gateway config update-server-output-guardrails --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777" --server-name "echo_server" --policy-file "output_policy.json"
```

#### Remove server from configuration

```bash
secure-mcp-gateway config remove-server --config-name "development-config" --server-name "web-server"
secure-mcp-gateway config remove-server --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777" --server-name "api-server"
```

#### Remove all servers from configuration

```bash
secure-mcp-gateway config remove-all-servers --config-name "development-config"
```

### CONFIGURATION RELATIONSHIPS

#### List projects using a configuration

```bash
secure-mcp-gateway config list-projects --config-name "development-config"
```

### VALIDATION & TESTING

#### Validate configuration structure

```bash
secure-mcp-gateway config validate --config-name "development-config"
```

### IMPORT/EXPORT

#### Export configuration

```bash
secure-mcp-gateway config export --config-name "development-config" --output-file "prod-config.json"
```

#### Import configuration

```bash
secure-mcp-gateway config import --input-file "prod-config.json" --config-name "imported-config"
```

### SEARCH

#### Search configurations by name or server

```bash
secure-mcp-gateway config search --search-term "web"
secure-mcp-gateway config search --search-term "production"
secure-mcp-gateway config search --search-term "secure"
```

## 3. PROJECT MANAGEMENT

### BASIC PROJECT OPERATIONS

#### List all projects

```bash
secure-mcp-gateway project list
```

#### Create new project

```bash
secure-mcp-gateway project create --project-name "My New Project"
secure-mcp-gateway project create --project-name "Development Project"
```

#### Get project details

```bash
secure-mcp-gateway project get --project-name "My New Project"
secure-mcp-gateway project get --project-id "5d1b268b-0e39-447b-aa69-37f3df1596b2"
```

#### Remove project

```bash
secure-mcp-gateway project remove --project-name "My New Project"
secure-mcp-gateway project remove --project-id "5d1b268b-0e39-447b-aa69-37f3df1596b2"
```

### CONFIG ASSIGNMENT

#### Assign MCP configuration to project

```bash
secure-mcp-gateway project assign-config --project-name "My New Project" --config-name "production-config"
secure-mcp-gateway project assign-config --project-id "5d1b268b-0e39-447b-aa69-37f3df1596b2" --config-id "f957f1b2-c77a-4de6-a53a-3d09784be777"
```

#### Unassign configuration from project

```bash
secure-mcp-gateway project unassign-config --project-name "My New Project"
```

#### Get configuration assigned to project

```bash
secure-mcp-gateway project get-config --project-name "My New Project"
```

### USER MANAGEMENT

#### List users in project

```bash
secure-mcp-gateway project list-users --project-name "My New Project"
```

#### Add user to project

```bash
secure-mcp-gateway project add-user --project-name "My New Project" --email "user@example.com"
secure-mcp-gateway project add-user --project-id "5d1b268b-0e39-447b-aa69-37f3df1596b2" --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0"
```

#### Remove user from project

```bash
secure-mcp-gateway project remove-user --project-name "My New Project" --email "user@example.com"
```

#### Remove all users from project

```bash
secure-mcp-gateway project remove-all-users --project-name "My New Project"
```

### IMPORT/EXPORT

#### Export project

```bash
secure-mcp-gateway project export --project-name "My New Project" --output-file "project.json"
```

### SEARCH

#### Search projects by name or user

```bash
secure-mcp-gateway project search --search-term "development"
secure-mcp-gateway project search --search-term "user@example.com"
secure-mcp-gateway project search --search-term "Production"
```

## 4. USER MANAGEMENT

### BASIC USER OPERATIONS

#### List all users

```bash
secure-mcp-gateway user list
```

#### Create new user

```bash
secure-mcp-gateway user create --email "newuser@example.com"
secure-mcp-gateway user create --email "admin@company.com"
```

#### Get user details

```bash
secure-mcp-gateway user get --email "user@example.com"
secure-mcp-gateway user get --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0"
```

#### Update user email

```bash
secure-mcp-gateway user update --email "old@example.com" --new-email "new@example.com"
secure-mcp-gateway user update --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0" --new-email "updated@example.com"
```

#### Delete user

```bash
secure-mcp-gateway user delete --email "user@example.com"
secure-mcp-gateway user delete --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0"
```

#### Force delete user with cleanup

```bash
secure-mcp-gateway user delete --email "user@example.com" --force
```

### USER RELATIONSHIPS

#### List projects for user

```bash
secure-mcp-gateway user list-projects --email "user@example.com"
```

### API KEY MANAGEMENT

#### Generate API key for user

```bash
secure-mcp-gateway user generate-api-key --email "user@example.com" --project-name "My New Project"
secure-mcp-gateway user generate-api-key --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0" --project-id "5d1b268b-0e39-447b-aa69-37f3df1596b2"
```

#### List API keys for user

```bash
secure-mcp-gateway user list-api-keys --email "user@example.com"
secure-mcp-gateway user list-api-keys --user-id "5cae63f3-39d3-46e1-809d-695d2fdf0be0"
```

#### List API keys for user in specific project

```bash
secure-mcp-gateway user list-api-keys --email "user@example.com" --project-name "My New Project"
```

#### List all API keys across all users

```bash
secure-mcp-gateway user list-all-api-keys
```

#### Rotate API key

```bash
secure-mcp-gateway user rotate-api-key --api-key "TJTWRRt226cfYBvqpLEJPrYZUF8BDWLakmMF2PCOhOvpa1Up"
```

#### Disable API key

```bash
secure-mcp-gateway user disable-api-key --api-key "TJTWRRt226cfYBvqpLEJPrYZUF8BDWLakmMF2PCOhOvpa1Up"
```

#### Enable API key

```bash
secure-mcp-gateway user enable-api-key --api-key "TJTWRRt226cfYBvqpLEJPrYZUF8BDWLakmMF2PCOhOvpa1Up"
```

#### Delete specific API key

```bash
secure-mcp-gateway user delete-api-key --api-key "TJTWRRt226cfYBvqpLEJPrYZUF8BDWLakmMF2PCOhOvpa1Up"
```

#### Delete all API keys for user

```bash
secure-mcp-gateway user delete-all-api-keys --email "user@example.com"
```

### SEARCH

#### Search users by email or project

```bash
secure-mcp-gateway user search --search-term "admin"
secure-mcp-gateway user search --search-term "My Project"
secure-mcp-gateway user search --search-term "example.com"
```

## 5. SYSTEM MANAGEMENT

### HEALTH & MONITORING

#### Check system health

```bash
secure-mcp-gateway system health-check
```

### BACKUP & RECOVERY

#### Create system backup

```bash
secure-mcp-gateway system backup --output-file "backup_20250715.json"
```

#### Restore from backup

```bash
secure-mcp-gateway system restore --input-file "backup_20250715.json"
```

#### Reset system to defaults

```bash
secure-mcp-gateway system reset --confirm
```

## 6. SEARCH & DISCOVERY

### CONFIGURATION SEARCH

#### Search configs by name or server

```bash
secure-mcp-gateway config search --search-term "production"
secure-mcp-gateway config search --search-term "web-server"
```

### PROJECT SEARCH

#### Search projects by name or user

```bash
secure-mcp-gateway project search --search-term "development"
secure-mcp-gateway project search --search-term "user@example.com"
secure-mcp-gateway project search --search-term "Production"
```

### USER SEARCH

#### Search users by email or project

```bash
secure-mcp-gateway user search --search-term "admin"
secure-mcp-gateway user search --search-term "My Project"
secure-mcp-gateway user search --search-term "example.com"
```

## 7. IMPORT/EXPORT OPERATIONS

### CONFIGURATION IMPORT/EXPORT

#### Export single configuration

```bash
secure-mcp-gateway config export --config-name "production-config" --output-file "prod-config.json"
```

#### Import configuration

```bash
secure-mcp-gateway config import --input-file "prod-config.json" --config-name "imported-prod-config"
```

### PROJECT IMPORT/EXPORT

#### Export project with all related data

```bash
secure-mcp-gateway project export --project-name "My Project" --output-file "project-export.json"
```

### SYSTEM BACKUP

#### Full system backup

```bash
secure-mcp-gateway system backup --output-file "full-backup.json"
```

#### Full system restore

```bash
secure-mcp-gateway system restore --input-file "full-backup.json"
```

## 8. VALIDATION & HEALTH CHECKS

### CONFIGURATION VALIDATION

#### Validate specific configuration

```bash
secure-mcp-gateway config validate --config-name "production-config"
```

### SYSTEM HEALTH CHECK

#### Comprehensive system health check

```bash
secure-mcp-gateway system health-check
```

**Health check includes:**

- Configuration structure validation
- Orphaned data detection
- Duplicate email detection
- Duplicate name warnings
- Reference integrity checks
- Statistics summary

## 9. BACKUP & RECOVERY

### AUTOMATIC BACKUPS

- System automatically creates backups before major changes
- Backup files are timestamped: `config.json.backup.20250715_143022`

### MANUAL BACKUPS

#### Create manual backup

```bash
secure-mcp-gateway system backup --output-file "manual-backup.json"
```

### RESTORE OPERATIONS

#### Restore from backup

```bash
secure-mcp-gateway system restore --input-file "backup-file.json"
```

### RESET TO DEFAULTS

#### Reset entire system (with confirmation)

```bash
secure-mcp-gateway system reset --confirm
```

## 10. WORKFLOW EXAMPLES

### COMPLETE SETUP WORKFLOW

1.

```bash
secure-mcp-gateway generate-config
```

2.

```bash
secure-mcp-gateway install --client claude-desktop
```

3.

```bash
secure-mcp-gateway config add --config-name "my-config"
```

4.

```bash
secure-mcp-gateway config add-server --config-name "my-config" --server-name "main-server" --server-command "python" --args "main.py" --description "Main application server"
```

5.

```bash
secure-mcp-gateway project create --project-name "My Project"
```

6.

```bash
secure-mcp-gateway project assign-config --project-name "My Project" --config-name "my-config"
```

7.

```bash
secure-mcp-gateway user create --email "user@example.com"
```

8.

```bash
secure-mcp-gateway project add-user --project-name "My Project" --email "user@example.com"
```

9.

```bash
secure-mcp-gateway user generate-api-key --email "user@example.com" --project-name "My Project"
```

### DEVELOPMENT WORKFLOW

1.

```bash
secure-mcp-gateway config add --config-name "dev-config"
```

2.

```bash
secure-mcp-gateway config add-server --config-name "dev-config" --server-name "debug-server" --server-command "python" --args "debug.py" --description "Debug server"
```

3.

```bash
secure-mcp-gateway project create --project-name "Development"
```

4.

```bash
secure-mcp-gateway project assign-config --project-name "Development" --config-name "dev-config"
```

5.

```bash
secure-mcp-gateway user create --email "dev@example.com"
```

6.

```bash
secure-mcp-gateway project add-user --project-name "Development" --email "dev@example.com"
```

7.

```bash
secure-mcp-gateway user generate-api-key --email "dev@example.com" --project-name "Development"
```

### PRODUCTION WORKFLOW

1.

```bash
secure-mcp-gateway config add --config-name "prod-config"
```

2.

```bash
secure-mcp-gateway config add-server --config-name "prod-config" --server-name "prod-server" --server-command "python" --args "production.py" --input-guardrails-policy '{"enabled": true, "policy_name": "Production Policy", "additional_config": {"pii_redaction": true}, "block": ["policy_violation", "injection_attack"]}' --description "Production server"
```

3.

```bash
secure-mcp-gateway project create --project-name "Production"
```

4.

```bash
secure-mcp-gateway project assign-config --project-name "Production" --config-name "prod-config"
```

5.

```bash
secure-mcp-gateway user create --email "prod@example.com"
```

6.

```bash
secure-mcp-gateway project add-user --project-name "Production" --email "prod@example.com"
```

7.

```bash
secure-mcp-gateway user generate-api-key --email "prod@example.com" --project-name "Production"
```

### MIGRATION WORKFLOW

1.

```bash
secure-mcp-gateway system backup --output-file "pre-migration-backup.json"
```

2.

```bash
secure-mcp-gateway config copy --source-config "production-config" --target-config "new-production-config"
```

3.

```bash
secure-mcp-gateway config validate --config-name "new-production-config"
```

4.

```bash
secure-mcp-gateway project create --project-name "New-Production"
```

5.

```bash
secure-mcp-gateway project assign-config --project-name "New-Production" --config-name "new-production-config"
```

6.

```bash
secure-mcp-gateway system health-check
```

### TEAM MANAGEMENT WORKFLOW

1.

```bash
secure-mcp-gateway user create --email "team-lead@example.com"
```

2.

```bash
secure-mcp-gateway user create --email "developer-1@example.com"
```

3.

```bash
secure-mcp-gateway user create --email "developer-2@example.com"
```

4.

```bash
secure-mcp-gateway project add-user --project-name "New-Production" --email "team-lead@example.com"
```

5.

```bash
secure-mcp-gateway project add-user --project-name "New-Production" --email "developer-1@example.com"
```

6.

```bash
secure-mcp-gateway project add-user --project-name "New-Production" --email "developer-2@example.com"
```

7.

```bash
secure-mcp-gateway user generate-api-key --email "team-lead@example.com" --project-name "New-Production"
```

8.

```bash
secure-mcp-gateway user generate-api-key --email "developer-1@example.com" --project-name "New-Production"
```

9.

```bash
secure-mcp-gateway user generate-api-key --email "developer-2@example.com" --project-name "New-Production"
```

### CONFIGURATION MANAGEMENT WORKFLOW

1.

```bash
secure-mcp-gateway config add --config-name "staging-config"
```

2.

```bash
secure-mcp-gateway config add-server --config-name "staging-config" --server-name "staging-web" --server-command "python" --args "web.py" --env '{"ENVIRONMENT": "staging", "LOG_LEVEL": "DEBUG"}' --description "Staging web server"
```

3.

```bash
secure-mcp-gateway config add-server --config-name "staging-config" --server-name "staging-tools" --server-command "python" --args "tools.py" --tools '{"web_search": {"enabled": true}, "file_system": {"enabled": true}}' --description "Staging tools server"
```

4.

```bash
secure-mcp-gateway config add-server --config-name "staging-config" --server-name "staging-secure" --server-command "python" --args "secure.py" --input-guardrails-policy '{"enabled": true, "policy_name": "Staging Policy", "additional_config": {"content_filtering": false}, "block": ["injection_attack"]}' --description "Staging secure server"
```

5.

```bash
secure-mcp-gateway config validate --config-name "staging-config"
```

6.

```bash
secure-mcp-gateway config export --config-name "staging-config" --output-file "staging-config-export.json"
```

### CLEANUP WORKFLOW

1.

```bash
secure-mcp-gateway user delete-all-api-keys --email "old-user@example.com"
```

2.

```bash
secure-mcp-gateway project remove-user --project-name "My Project" --email "old-user@example.com"
```

3.

```bash
secure-mcp-gateway user delete --email "old-user@example.com"
```

4.

```bash
secure-mcp-gateway config remove-all-servers --config-name "old-config"
```

5.

```bash
secure-mcp-gateway config remove --config-name "old-config"
```

6.

```bash
secure-mcp-gateway system health-check
```

## 11. TROUBLESHOOTING & ERROR SCENARIOS

### COMMON ISSUES & SOLUTIONS

**Issue:** "Config file not found"  
**Solution:** 

```bash
secure-mcp-gateway generate-config
```

**Issue:** "Config 'name' not found"  
**Solution:**

```bash
secure-mcp-gateway config list  # to see available configs
```

**Issue:** "User already exists"  
**Solution:**

```bash
secure-mcp-gateway user get --email "email@example.com"  # to check existing user
```

**Issue:** "Cannot delete config - being used by projects"  
**Solution:**
1.

```bash
secure-mcp-gateway config list-projects --config-name "config-name"
```

2.

```bash
secure-mcp-gateway project unassign-config --project-name "project-name"
```

3.

```bash
secure-mcp-gateway config remove --config-name "config-name"
```

**Issue:** "Cannot delete user - has active API keys"  
**Solution:**

1.

```bash
secure-mcp-gateway user list-api-keys --email "user@example.com"
```

2.

```bash
secure-mcp-gateway user delete-all-api-keys --email "user@example.com"
```

3.

```bash
secure-mcp-gateway user delete --email "user@example.com"
```


**Issue:** "Cannot delete project - has active API keys"  
**Solution:**

1.

```bash
secure-mcp-gateway project list-users --project-name "project-name"
```

2.

```bash
secure-mcp-gateway user delete-all-api-keys --email "user@example.com"
```

3.

```bash
secure-mcp-gateway project remove --project-name "project-name"
```


**Issue:** "System health check failing"  
**Solution:** 

```bash
secure-mcp-gateway system health-check  # shows specific issues to fix
```

### DUPLICATE CREATION

- Attempting to add config/project/user that already exists will fail with a clear error.

### CONSTRAINT VIOLATIONS

- Attempting to remove configs/projects/users in use or with dependencies will fail with a clear error.

### INVALID CONFIGURATIONS

- Invalid JSON in `--env`, `--tools`, or guardrails will fail with a parse error.

### MISSING ARGUMENTS

- All commands require required arguments; missing arguments will result in usage error.

### INVALID API OPERATIONS

- Invalid API key formats or non-existent keys will fail with a clear error.

### FILE OPERATIONS

- Import/restore from non-existent files will fail with a file not found error.

### INVALID ID FORMATS

- Invalid UUIDs for `--config-id`, `--project-id`, `--user-id` will fail with a format error.

### FORCE OPERATIONS

#### Force delete user with all cleanup

```bash
secure-mcp-gateway user delete --email "user@example.com" --force
```

### VALIDATION COMMANDS

#### Validate configuration

```bash
secure-mcp-gateway config validate --config-name "config-name"
```

#### Check system health

```bash
secure-mcp-gateway system health-check
```

### BACKUP BEFORE RISKY OPERATIONS

```bash
secure-mcp-gateway system backup --output-file "before-operation.json"
```

## 12. ADVANCED FEATURES & COVERAGE

### SERVER CONFIGURATIONS

- **Environment Variables:** `--env '{"KEY": "value"}'`
- **Tools Configuration:** `--tools '{"tool": {"enabled": true}}'`
- **Input Guardrails:** `--input-guardrails-policy '{"enabled": true, ...}'`
- **Output Guardrails:** `--output-guardrails-policy '{"enabled": true, ...}'`
- **Complex Combinations:** Multiple features on single server

### ID-BASED OPERATIONS

- Config operations with `--config-id`
- Project operations with `--project-id`
- User operations with `--user-id`
- Cross-reference operations with multiple IDs

### ERROR HANDLING

- Non-existent resource access
- Duplicate creation attempts
- Constraint violations
- Invalid JSON configurations
- Missing required arguments
- Invalid formats and data

### WORKFLOW TESTING

- Migration scenarios
- Team management
- Configuration management
- Multi-step operations
- Cross-resource dependencies

### COVERAGE SUMMARY

- **Setup Commands:** 100% coverage
- **Config Commands:** 100% coverage (including all advanced features)
- **Project Commands:** 100% coverage
- **User Commands:** 100% coverage
- **System Commands:** 100% coverage (except destructive reset)
- **Advanced Features:** All tested
- **Error Scenarios:** All tested
- **Multi-Step Workflows:** All tested

### TEST ARTIFACTS CREATED

- `config-export.json`
- `production-config-export.json`
- `staging-config-export.json`
- `project-export.json`
- `production-project-export.json`
- `system-backup.json`
- `pre-restore-backup.json`
- `pre-migration-backup.json`

## 13. BEST PRACTICES

### CONFIGURATION MANAGEMENT

- Use descriptive config names: "production-web-servers" vs "config1"
- Validate configs after creation: `secure-mcp-gateway config validate --config-name "name"`
- Copy configs for testing: `secure-mcp-gateway config copy --source-config "prod" --target-config "test"`
- Export configs for version control: `secure-mcp-gateway config export --config-name "name" --output-file "name.json"`

### PROJECT ORGANIZATION

- Use clear project names: "E-commerce Production" vs "Project1"
- Separate dev/staging/prod projects
- Assign appropriate configs to each project
- Regular health checks: `secure-mcp-gateway system health-check`

### USER MANAGEMENT

- Use company email addresses for users
- Generate separate API keys for different projects
- Rotate API keys regularly: `secure-mcp-gateway user rotate-api-key --api-key "key"`
- Disable unused API keys: `secure-mcp-gateway user disable-api-key --api-key "key"`

### SECURITY

- Enable guardrails for production servers
- Use force delete sparingly
- Regular backups: `secure-mcp-gateway system backup --output-file "backup.json"`
- Monitor API key usage

### MAINTENANCE

- Regular system health checks
- Clean up unused configurations
- Archive old projects instead of deleting
- Keep backup files in version control

### WORKFLOW EFFICIENCY

- Use search commands to find resources quickly
- Batch operations where possible
- Use export/import for configuration templates
- Document your workflows

### ERROR HANDLING

- Always run health checks after major changes
- Keep recent backups
- Use validation commands before deployment
- Test changes in development projects first

### MONITORING

- Regular health checks
- Monitor API key usage
- Track configuration changes
- Review user access periodically

## 14. USAGE INSTRUCTIONS

1. Save this file as: `CLI-Commands-Reference.md`
2. Ensure `cli.py` is in the same directory or in your PATH
3. Run commands as shown above
4. Review the detailed output and summary
5. Check created artifacts in your working directory
6. Use `--help` for any command or subcommand for more details

## 15. SUPPORT & HELP

### General Help

```bash
secure-mcp-gateway --help
```

### Command Help

```bash
secure-mcp-gateway config --help
secure-mcp-gateway project --help
secure-mcp-gateway user --help
secure-mcp-gateway system --help
```

### Subcommand Help

```bash
secure-mcp-gateway config add --help
secure-mcp-gateway user generate-api-key --help
```
