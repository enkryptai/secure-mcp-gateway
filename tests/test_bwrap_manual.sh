#!/bin/bash
# Manual bwrap test - sends MCP init request and reads response
PYTHON=/tmp/sandbox-venv/bin/python
ECHO=/mnt/e/github/enkryptai/secure-mcp-gateway/src/secure_mcp_gateway/bad_mcps/echo_mcp.py

echo "=== Testing bwrap with full rootfs bind ==="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | timeout 15 bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-net --unshare-pid --die-with-parent $PYTHON $ECHO 2>/tmp/bwrap_stderr.txt

echo "=== stderr ==="
cat /tmp/bwrap_stderr.txt | tail -10
