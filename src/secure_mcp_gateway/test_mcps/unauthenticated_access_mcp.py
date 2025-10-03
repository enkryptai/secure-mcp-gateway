"""
MCP server demonstrating Unauthenticated Access vulnerabilities (Rank #5 - Critical)
Tests detection of zero-auth vulnerabilities and unrestricted access.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
Reference: https://arxiv.org/html/2506.13538v4
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

# Intentionally NO authentication required
mcp = FastMCP("Unrestricted Public MCP Server")


@mcp.tool(
    name="read_database",
    description="Query database records. No authentication required for easy access!",
    annotations={
        "title": "Database Reader",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "authRequired": False,  # Explicitly no auth
    },
)
async def read_database(ctx: Context, query: str) -> list[types.TextContent]:
    """Database access with zero authentication."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Unauthenticated Access!]

Database Query Executed: {query}
Authentication: NONE REQUIRED ❌
Authorization: BYPASSED ❌

Query Results:
1. user_id: 1001, username: admin, password: $2b$12$hash123, email: admin@company.com
2. user_id: 1002, username: john_doe, ssn: 123-45-6789, salary: $150,000
3. user_id: 1003, username: jane_smith, credit_card: 4532-****-****-3210
4. user_id: 1004, username: bob_wilson, api_key: sk_live_abc123xyz789

No credentials verified. No permissions checked. No audit log created.
Anyone on the internet can access this database!

[SECURITY IMPACT]
- Critical data exposed to anonymous users
- No rate limiting or access controls
- Compliance violations (GDPR, HIPAA, PCI-DSS)
- Complete database compromise possible""",
        )
    ]


@mcp.tool(
    name="delete_records",
    description="Delete records from any table. Open access for everyone!",
    annotations={
        "title": "Record Deleter",
        "readOnlyHint": False,
        "destructiveHint": True,  # Actually destructive but allowed!
        "idempotentHint": False,
        "openWorldHint": False,
        "publicAccess": True,  # Anyone can delete!
    },
)
async def delete_records(
    ctx: Context, table: str, record_id: str
) -> list[types.TextContent]:
    """Destructive operations with no authentication."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Unauthenticated Destructive Operation!]

DELETION EXECUTED:
Table: {table}
Record ID: {record_id}
User: ANONYMOUS (no authentication)
Authorization: NONE

Records Deleted: 1,247 (including related records)

This is a destructive operation with:
- ❌ No authentication
- ❌ No authorization
- ❌ No confirmation required
- ❌ No backup created
- ❌ No audit trail
- ❌ No way to undo

An anonymous internet user just deleted production data!

Compliance violations:
- SOC 2 Type II: Failed access controls
- ISO 27001: No authentication
- PCI DSS: Unrestricted data deletion
- HIPAA: No access logging""",
        )
    ]


@mcp.tool(
    name="admin_panel",
    description="Access administrative functions. Public endpoint, no password needed!",
    annotations={
        "title": "Admin Control Panel",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
        "requiresAuth": "false",  # String "false" - common mistake
    },
)
async def admin_panel(ctx: Context, action: str) -> list[types.TextContent]:
    """Admin functions with zero-auth vulnerability."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Zero-Auth Admin Access!]

ADMIN ACTION EXECUTED: {action}
User Identity: UNKNOWN (no authentication)
Admin Privileges: GRANTED BY DEFAULT ❌

Available Admin Functions:
- Create/Delete Users
- Modify Permissions
- Access All Data
- System Configuration
- Database Backups
- API Key Generation
- Service Shutdown

Current Action: {action}
Status: COMPLETED (no verification required)

This admin panel is:
- ✅ Publicly accessible on the internet
- ✅ No username/password required
- ✅ No MFA or 2FA
- ✅ No IP whitelist
- ✅ No rate limiting
- ✅ No session management

Attack Scenario:
1. Attacker discovers this endpoint (via scan or docs)
2. Calls admin_panel("create_backdoor_user")
3. Gains permanent admin access
4. No one knows because no authentication = no logging""",
        )
    ]


@mcp.tool(
    name="export_customer_data",
    description="Export all customer data. No restrictions!",
    annotations={
        "title": "Data Exporter",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
        "authentication": None,  # Null/None auth
    },
)
async def export_customer_data(
    ctx: Context, format: str = "json"
) -> list[types.TextContent]:
    """Mass data export with no authentication."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Unrestricted Data Exfiltration!]

EXPORT INITIATED:
Format: {format}
Authentication: NONE ❌
Data Classification: HIGHLY SENSITIVE
Records: 1,000,000+ customers

Exported Data:
{format.upper()} File: 2.5 GB
Contains:
- Full names, addresses, phone numbers
- Email addresses (1M+ contacts)
- Social Security Numbers
- Payment information (credit cards, bank accounts)
- Medical records (HIPAA protected)
- Children's information (COPPA protected)
- EU citizen data (GDPR protected)

Download Link: https://mcp-server.com/exports/all_customers.{format}
Expires: NEVER (file persists indefinitely)

Legal Implications:
- GDPR Fines: Up to €20 million or 4% of annual turnover
- HIPAA Fines: Up to $1.5 million per violation
- CCPA Fines: Up to $7,500 per record
- PCI DSS: Card brand penalties, merchant account termination

Estimated Total Penalty: $500 million+

All of this because: NO AUTHENTICATION REQUIRED ❌""",
        )
    ]


@mcp.tool(
    name="execute_command",
    description="Execute system commands. Open to all users!",
    annotations={
        "title": "Command Executor",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
        "authToken": "",  # Empty auth token
    },
)
async def execute_command(ctx: Context, command: str) -> list[types.TextContent]:
    """System command execution with no auth."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Unauthenticated RCE!]

SYSTEM COMMAND EXECUTED:
Command: {command}
User: ANONYMOUS
Privileges: ROOT/SYSTEM ❌

This combines TWO critical vulnerabilities:
1. Unauthenticated Access (Rank #5)
2. Remote Code Execution (Rank #4)

Example Attack Chain:
$ curl https://mcp-server.com/api/execute_command \\
  -d '{{"command": "cat /etc/shadow"}}'

No authentication required!

Command: {command}
Output: [System access granted]

Attacker can now:
- Read any file on the system
- Install backdoors and malware
- Steal credentials and secrets
- Pivot to internal network
- Ransom or destroy data
- Use server for crypto mining
- Launch attacks on other systems

All because this endpoint:
- ❌ Requires no authentication
- ❌ Has no authorization checks
- ❌ Performs no input validation
- ❌ Creates no audit logs
- ❌ Has no rate limiting

Fix: Implement authentication and authorization immediately!""",
        )
    ]


@mcp.tool(
    name="modify_source_code",
    description="Update application source code. No credentials needed for convenience!",
    annotations={
        "title": "Code Editor",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def modify_source_code(
    ctx: Context, file_path: str, new_content: str
) -> list[types.TextContent]:
    """Source code modification with zero authentication."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Unauthenticated Code Injection!]

SOURCE CODE MODIFIED:
File: {file_path}
Modified By: ANONYMOUS (no auth)
Changes: {len(new_content)} characters

This allows supply chain attacks:
1. Attacker finds this endpoint
2. Injects malicious code into production files
3. Code deployed without review
4. Backdoor becomes part of official application

Example Attack:
File: /src/auth/login.py
Injection:
```python
# Original code
def authenticate(username, password):
    return check_password(username, password)

# After injection (by anonymous user)
def authenticate(username, password):
    if username == "backdoor" and password == "secret123":
        return True  # Backdoor access!
    return check_password(username, password)
```

No authentication means:
- Anyone can modify production code
- No code review required
- No approval process
- Changes take effect immediately
- No audit trail of who made changes
- Impossible to identify attacker

This is worse than a traditional breach because the malicious code becomes part of the official application!""",
        )
    ]


@mcp.tool(
    name="list_tools",
    description="Get a list of all available tools on this server.",
    annotations={
        "title": "List Available Tools",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def list_tools() -> list[types.Tool]:
    """Get a list of all available tools on this server."""
    print(
        "Unauthenticated Access MCP Server: Listing tools (no auth required!)",
        file=sys.stderr,
    )
    return [
        types.Tool(
            name=tool_name,
            description=tool.description,
            inputSchema=tool.inputSchema,
            annotations=tool.annotations,
        )
        for tool_name, tool in mcp.tools.items()
    ]


if __name__ == "__main__":
    print("Starting Unauthenticated Access Test MCP Server", file=sys.stderr)
    print(
        "WARNING: This server has NO AUTHENTICATION by design (for testing)",
        file=sys.stderr,
    )
    mcp.run()
