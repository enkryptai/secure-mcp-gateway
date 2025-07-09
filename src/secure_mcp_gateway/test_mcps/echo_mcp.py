"""
Dummy MCP server for echoing a message with tool discovery support and proper annotations
"""
import sys
# https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/types.py
from mcp import types
from mcp.server.fastmcp import FastMCP, Context

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# Create a dummy MCP server with tool discovery enabled
# https://modelcontextprotocol.io/docs/concepts/tools#python
mcp = FastMCP("Dummy Echo MCP Server")

# TODO: Fix error and use stdout
# Get tracer
tracer = trace.get_tracer(__name__)

@mcp.tool(
    name="echo",
    description="Echo back the provided message.",
    annotations={
        "title": "Echo Message",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
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
    with tracer.start_as_current_span("echo") as span:
        span.set_attributes({
            "message.length": len(message) if message else 0,
            "request_id": ctx.request_id
        })
        
        if not message:
            print(f"Dummy Echo Server MCP Server: Error: Message is required", file=sys.stderr)
            span.set_status(Status(StatusCode.ERROR, "Message is required"))
            return [
                types.TextContent(
                    type="text",
                    text="Error: Message is required"
                )
            ]
            
        print(f"Dummy Echo Server MCP Server: Echoing message: {message}", file=sys.stderr)
        try:
            return [
                types.TextContent(
                    type="text",
                    text=message
                )
            ]
        except Exception as error:
            span.record_exception(error, attributes={"error.type": type(error).__name__})
            span.set_status(Status(StatusCode.ERROR, f"Echo operation failed: {str(error)}"))
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: {str(error)}"
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
        "openWorldHint": False
    }
    # inputSchema={
    #     "type": "object",
    #     "properties": {},
    #     "required": []
    # }
)
async def list_tools() -> list[types.Tool]:
    """Get a list of all available tools on this server."""
    print(f"Dummy Echo Server MCP Server: Listing tools", file=sys.stderr)
    return [
        types.Tool(
            name=tool_name,
            description=tool.description,
            inputSchema=tool.inputSchema,
            annotations=tool.annotations
        )
        for tool_name, tool in mcp.tools.items()
    ]


if __name__ == "__main__":
    print("Starting Dummy Echo MCP Server", file=sys.stderr)
    mcp.run()
