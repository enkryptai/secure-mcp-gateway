"""
Simple MCP Server for echoing a message with tool discovery support and proper annotations
Can run as both stdio server (local) or HTTP server (remote)
"""
import os
import sys

# https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/types.py
from mcp import types
from mcp.server.fastmcp import Context, FastMCP
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# Create a Simple MCP Server with tool discovery enabled
# https://modelcontextprotocol.io/docs/concepts/tools#python
mcp = FastMCP("Simple Echo MCP Server")

# TODO: Fix error and use stdout
# Get tracer
tracer = trace.get_tracer(__name__)

# Check if running as HTTP server
IS_HTTP_MODE = os.environ.get("MCP_HTTP_MODE", "false").lower() == "true"


def print_oauth_headers(http_headers=None):
    """Print OAuth-related environment variables and HTTP headers for testing."""
    print("\n" + "=" * 80, file=sys.stderr)

    if http_headers:
        print("🔐 OAuth HTTP Headers Check (Remote Mode)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Check for OAuth headers
        oauth_headers = [
            "authorization",
            "x-oauth-token",
            "x-access-token",
        ]

        found_oauth = False
        for header_name in oauth_headers:
            value = http_headers.get(header_name, "")
            if value:
                found_oauth = True
                # Mask the token for security
                masked_value = value[:30] + "..." if len(value) > 30 else value
                print(f"  ✅ {header_name.upper()}: {masked_value}", file=sys.stderr)
            else:
                print(f"  ❌ {header_name.upper()}: Not set", file=sys.stderr)

        if not found_oauth:
            print("  ⚠️  No OAuth headers found", file=sys.stderr)

        # Print all headers for debugging
        print("\n📋 All Request Headers:", file=sys.stderr)
        for key, value in http_headers.items():
            if "auth" in key.lower() or "token" in key.lower():
                masked_value = value[:30] + "..." if len(value) > 30 else value
                print(f"  {key}: {masked_value}", file=sys.stderr)
            else:
                print(f"  {key}: {value}", file=sys.stderr)
    else:
        print("🔐 OAuth Environment Variables Check (Local Mode)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        oauth_vars = [
            "ENKRYPT_ACCESS_TOKEN",
            "AUTHORIZATION",
            "OAUTH_ACCESS_TOKEN",
            "OAUTH_TOKEN_TYPE",
            "OAUTH_REFRESH_TOKEN",
            "OAUTH_SCOPE",
            "OAUTH_EXPIRES_IN",
            "HTTP_HEADER_Authorization",
            "HTTP_HEADER_AUTHORIZATION",
        ]

        found_oauth = False
        for var in oauth_vars:
            value = os.environ.get(var)
            if value:
                found_oauth = True
                # Mask the token for security (show first 20 chars + ...)
                if "TOKEN" in var or "AUTHORIZATION" in var:
                    masked_value = value[:20] + "..." if len(value) > 20 else value
                    print(f"  ✅ {var}: {masked_value}", file=sys.stderr)
                else:
                    print(f"  ✅ {var}: {value}", file=sys.stderr)
            else:
                print(f"  ❌ {var}: Not set", file=sys.stderr)

        if not found_oauth:
            print("  ⚠️  No OAuth environment variables found", file=sys.stderr)

    print("=" * 80 + "\n", file=sys.stderr)


@mcp.tool(
    name="echo",
    description="Echo back the provided message.",
    annotations={
        "title": "Echo Message",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    # inputSchema={
    #     "type": "object",
    #     "properties": {
    #         "message": {
    #             "type": "string",
    #             "description": "The message to echo back"
    #         }
    #     },
    #     "required": ["message"]
    # }
)
async def echo(ctx: Context, message: str) -> list[types.TextContent]:
    """Echo back the provided message.

    Args:
        message: The message to echo back
    """
    # Try to get HTTP headers from context if available (HTTP mode)
    http_headers = None
    try:
        if hasattr(ctx, "request_context") and ctx.request_context is not None:
            if (
                hasattr(ctx.request_context, "request")
                and ctx.request_context.request is not None
            ):
                if hasattr(ctx.request_context.request, "headers"):
                    http_headers = ctx.request_context.request.headers
                    print("\n[HTTP Mode] Tool called via HTTP", file=sys.stderr)
    except Exception as e:
        print(f"\n[Warning] Could not access HTTP headers: {e}", file=sys.stderr)

    # Print OAuth headers on every tool call for testing
    if http_headers:
        print_oauth_headers(http_headers=http_headers)
    else:
        print_oauth_headers()

    with tracer.start_as_current_span("echo") as span:
        span.set_attributes(
            {
                "message.length": len(message) if message else 0,
                "request_id": ctx.request_id
                if hasattr(ctx, "request_id")
                else "unknown",
            }
        )

        if not message:
            print(
                "Simple Echo Server MCP Server: Error: Message is required",
                file=sys.stderr,
            )
            span.set_status(Status(StatusCode.ERROR, "Message is required"))
            return [types.TextContent(type="text", text="Error: Message is required")]

        print(
            f"Simple Echo Server MCP Server: Echoing message: {message}",
            file=sys.stderr,
        )
        try:
            return [types.TextContent(type="text", text=message)]
        except Exception as error:
            span.record_exception(
                error, attributes={"error.type": type(error).__name__}
            )
            span.set_status(
                Status(StatusCode.ERROR, f"Echo operation failed: {error!s}")
            )
            return [types.TextContent(type="text", text=f"Error: {error!s}")]


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
    # inputSchema={
    #     "type": "object",
    #     "properties": {},
    #     "required": []
    # }
)
async def list_tools() -> list[types.Tool]:
    """Get a list of all available tools on this server."""
    print("Simple Echo Server MCP Server: Listing tools", file=sys.stderr)
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
    # Check if HTTP mode is enabled
    if IS_HTTP_MODE:
        print("\n" + "=" * 80, file=sys.stderr)
        print("🚀 Starting Simple Echo MCP Server (HTTP Mode)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("📍 Server will listen on: http://localhost:8001", file=sys.stderr)
        print("🔌 HTTP endpoint: http://localhost:8001/mcp", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

        # Configure FastMCP for streamable-http transport (same as gateway.py)
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8001
        mcp.settings.debug = True

        # Run with streamable-http transport (same as gateway.py)
        # This allows HTTP headers (including OAuth) to be available in tool call context
        mcp.run(transport="streamable-http", mount_path="/mcp/")
    else:
        # Run in stdio mode (local)
        print("Starting Simple Echo MCP Server (Stdio Mode)", file=sys.stderr)

        # Print OAuth headers at startup
        print_oauth_headers()

        mcp.run()
