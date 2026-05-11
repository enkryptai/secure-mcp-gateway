"""Start the echo MCP server on streamable-http transport for remote testing."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ["OTEL_SDK_DISABLED"] = "true"

from secure_mcp_gateway.bad_mcps.echo_mcp import mcp

if __name__ == "__main__":
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 9000
    mcp.run(transport="streamable-http", mount_path="/mcp/")
