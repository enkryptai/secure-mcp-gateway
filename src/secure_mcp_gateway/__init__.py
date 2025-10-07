import sys

# TODO: Fix error and use stdout
print("Initializing Enkrypt Secure MCP Gateway", file=sys.stderr)

from secure_mcp_gateway.client import *
from secure_mcp_gateway.gateway import *
from secure_mcp_gateway.utils import *
