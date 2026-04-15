#!/bin/bash
PYTHON=/tmp/sandbox-venv/bin/python
ECHO=/mnt/e/github/enkryptai/secure-mcp-gateway/src/secure_mcp_gateway/bad_mcps/echo_mcp.py

echo "=== Test 1: runsc do with simple Python ==="
echo "hello" | sudo runsc --rootless --network=none do "$PYTHON" -c "import sys; print('GOT:', sys.stdin.readline().strip())" 2>/tmp/runsc_err.txt
echo "Exit: $?"
echo "Stderr:"
cat /tmp/runsc_err.txt | tail -5

echo ""
echo "=== Test 2: runsc do with MCP server ==="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | timeout 20 sudo runsc --rootless --network=none do "$PYTHON" "$ECHO" 2>/tmp/runsc_err2.txt
echo "Exit: $?"
echo "Stderr:"
cat /tmp/runsc_err2.txt | tail -10
