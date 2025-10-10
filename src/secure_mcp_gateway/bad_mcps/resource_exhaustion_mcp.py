"""
MCP server demonstrating Resource Exhaustion vulnerabilities (Rank #18 - Medium)
Tests detection of DoS attacks through excessive resource consumption.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("Resource Exhaustion Test MCP")


@mcp.tool(
    name="process_large_dataset",
    description="Process and analyze large datasets with advanced statistical methods. Handles big data efficiently.",
    annotations={
        "title": "Dataset Processor",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def process_large_dataset(
    ctx: Context, size_mb: int = 100
) -> list[types.TextContent]:
    """Memory exhaustion by requesting massive data processing."""
    return [
        types.TextContent(
            type="text",
            text="""Processing dataset of size {size_mb}MB...
[VULNERABILITY: No limits on memory consumption!]

If size_mb = 999999999 (999 Petabytes):
- Would attempt to allocate unlimited memory
- Could trigger OOM killer
- Could crash the entire system
- No rate limiting or size validation

Attack scenario:
- Attacker requests processing of 100TB dataset
- System attempts to load into memory
- RAM exhausted, swap fills up
- System becomes unresponsive
- Legitimate users cannot access service
""",
        )
    ]


@mcp.tool(
    name="generate_thumbnail",
    description="Generate image thumbnails at specified dimensions. Supports all common image formats.",
    annotations={
        "title": "Thumbnail Generator",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def generate_thumbnail(
    ctx: Context, width: int, height: int, image_url: str
) -> list[types.TextContent]:
    """CPU exhaustion through massive image processing."""
    return [
        types.TextContent(
            type="text",
            text="""Generating thumbnail: {width}x{height} for {image_url}
[VULNERABILITY: Decompression bomb / Billion Laughs attack!]

Attack vectors:
1. Massive dimensions: width=999999999, height=999999999
   - Would require 999999999 * 999999999 * 4 bytes = ~4 exabytes RAM
   - System hangs trying to allocate memory

2. Malicious image (ZIP bomb equivalent):
   - Small 100KB PNG that expands to 10GB when decompressed
   - Causes memory exhaustion
   - Known as "decompression bomb"

3. Repeated requests:
   - Attacker sends 10000 thumbnail requests simultaneously
   - Each consumes CPU and memory
   - Server paralyzed by resource exhaustion

No validation on dimensions or concurrent requests!
""",
        )
    ]


@mcp.tool(
    name="calculate_hash",
    description="Calculate cryptographic hashes (MD5, SHA256, SHA512) for files and data verification.",
    annotations={
        "title": "Hash Calculator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def calculate_hash(
    ctx: Context, algorithm: str, iterations: int = 1
) -> list[types.TextContent]:
    """CPU exhaustion through expensive cryptographic operations."""
    return [
        types.TextContent(
            type="text",
            text="""Calculating {algorithm} hash with {iterations} iterations...
[VULNERABILITY: Algorithmic complexity attack!]

Attack scenario:
- Attacker requests: algorithm="bcrypt", iterations=999999999
- Each bcrypt iteration is intentionally slow (by design)
- 999 million iterations would take years of CPU time
- Server becomes unresponsive
- All CPU cores at 100% utilization

Other attack variations:
- Request scrypt with maxmem=1TB, iterations=1000000
- Request Argon2 with extreme memory parameter
- Parallel bomb: 1000 concurrent requests each with 1M iterations

No limits on computational complexity!
""",
        )
    ]


@mcp.tool(
    name="search_database",
    description="Search database with complex queries and aggregations. Supports full-text search and analytics.",
    annotations={
        "title": "Database Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def search_database(ctx: Context, query: str) -> list[types.TextContent]:
    """Database resource exhaustion through expensive queries."""
    return [
        types.TextContent(
            type="text",
            text="""Executing database query: {query}
[VULNERABILITY: SQL query complexity attack!]

Malicious queries:
1. Cartesian product:
   SELECT * FROM users, orders, products, categories, logs
   WHERE 1=1
   - Joins 5 large tables without conditions
   - Result set could be billions of rows
   - Database locks up

2. Recursive CTE bomb:
   WITH RECURSIVE bomb AS (
     SELECT 1 as n UNION ALL
     SELECT n+1 FROM bomb WHERE n < 9999999999
   ) SELECT * FROM bomb;
   - Attempts to generate 10 billion rows
   - Consumes all database memory

3. Regex DoS:
   SELECT * FROM logs WHERE message ~ '(a+)+b'
   AND message = 'aaaaaaaaaaaaaaaaaaaaaa'
   - Catastrophic backtracking in regex
   - Single query can run for hours

4. Full table scan without limits:
   SELECT * FROM huge_table ORDER BY random()
   - Forces full table scan
   - No LIMIT clause
   - Sorts billions of rows randomly

No query timeout or complexity limits!
""",
        )
    ]


@mcp.tool(
    name="render_template",
    description="Render templates with dynamic data. Supports Jinja2, Mustache, and custom template engines.",
    annotations={
        "title": "Template Renderer",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def render_template(
    ctx: Context, template: str, data: str = ""
) -> list[types.TextContent]:
    """Resource exhaustion through template complexity."""
    return [
        types.TextContent(
            type="text",
            text="""Rendering template...
[VULNERABILITY: Template complexity bomb!]

Attack templates:
1. Recursive expansion (Billion Laughs):
   {{ define "lol9" }}lololololol{{ end }}
   {{ define "lol8" }}{{template "lol9"}}{{template "lol9"}}...{{ end }}
   {{ define "lol1" }}{{template "lol2"}}{{template "lol2"}}...{{ end }}
   - Exponential expansion: 10^9 repetitions
   - Gigabytes of output from KB template

2. Infinite recursion:
   {{ define "recursive" }}
   {{ template "recursive" }}
   {{ end }}
   - Stack overflow
   - Crashes template engine

3. Nested loops:
   {{ range $i := seq 0 10000 }}
     {{ range $j := seq 0 10000 }}
       {{ range $k := seq 0 10000 }}
         {{ $i }} {{ $j }} {{ $k }}
       {{ end }}
     {{ end }}
   {{ end }}
   - 10000^3 = 1 trillion iterations
   - Never completes

No recursion depth or output size limits!
""",
        )
    ]


@mcp.tool(
    name="batch_process",
    description="Process multiple items in batch for efficiency. Supports parallel processing and job queuing.",
    annotations={
        "title": "Batch Processor",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def batch_process(
    ctx: Context, item_count: int, concurrency: int = 10
) -> list[types.TextContent]:
    """Fork bomb through unlimited concurrency."""
    return [
        types.TextContent(
            type="text",
            text="""Processing {item_count} items with concurrency {concurrency}...
[VULNERABILITY: Fork bomb / Thread exhaustion!]

Attack scenario:
- item_count = 999999999
- concurrency = 999999999
- System attempts to spawn 999 million threads/processes
- Each consumes memory and file descriptors
- System resources exhausted:
  * Out of memory
  * Out of file descriptors
  * Out of process IDs
  * Scheduler overwhelmed
- System crashes or becomes unresponsive

Classic fork bomb equivalent:
:()\u007b:|:&\u007d;:
- Each process forks two children
- Exponential growth
- System paralyzed in seconds

No limits on concurrency or spawn rate!
""",
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
    print("Resource Exhaustion MCP Server: Listing tools", file=sys.stderr)
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
    print("Starting Resource Exhaustion Test MCP Server", file=sys.stderr)
    mcp.run()
