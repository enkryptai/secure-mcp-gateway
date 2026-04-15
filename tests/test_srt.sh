#!/bin/bash
PYTHON=/tmp/sandbox-venv/bin/python
ECHO=/mnt/e/github/enkryptai/secure-mcp-gateway/src/secure_mcp_gateway/bad_mcps/echo_mcp.py
SRT=$(which srt)

echo "=== srt path: $SRT ==="
echo "=== Test: srt with MCP server ==="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | timeout 20 "$SRT" "$PYTHON $ECHO" 2>/tmp/srt_err.txt
echo "Exit: $?"
echo "Stderr:"
cat /tmp/srt_err.txt | tail -10
