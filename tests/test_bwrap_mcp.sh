#!/bin/bash
PYTHON=/tmp/sandbox-venv/bin/python
ECHO=/mnt/e/github/enkryptai/secure-mcp-gateway/src/secure_mcp_gateway/bad_mcps/echo_mcp.py
VENV=/tmp/sandbox-venv

echo "=== Sending MCP init request through bwrap ==="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | timeout 15 bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --ro-bind "$VENV" "$VENV" \
    --die-with-parent \
    "$PYTHON" "$ECHO" \
    2>/tmp/bwrap_stderr.log

EXIT=$?
echo "=== Exit code: $EXIT ==="
echo "=== Stderr ==="
cat /tmp/bwrap_stderr.log | tail -20
