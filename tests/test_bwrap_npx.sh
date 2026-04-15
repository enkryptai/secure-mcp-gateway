#!/bin/bash
# Test Playwright MCP server with and without Bubblewrap

INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST_REQ='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

echo "============================================"
echo "TEST 1: Playwright MCP - BASELINE (no sandbox)"
echo "============================================"
START=$(date +%s%N)

RESP=$(echo -e "${INIT_REQ}\n${NOTIF}\n${LIST_REQ}" | timeout 30 npx @playwright/mcp@latest 2>/dev/null | head -2)

END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "Time: ${ELAPSED}ms"
echo "Response lines:"
echo "$RESP" | head -2
TOOL_COUNT=$(echo "$RESP" | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',{}).get('tools',[])))" 2>/dev/null)
echo "Tools found: ${TOOL_COUNT:-0}"
echo ""

echo "============================================"
echo "TEST 2: Playwright MCP - BUBBLEWRAP"
echo "============================================"
START=$(date +%s%N)

RESP=$(echo -e "${INIT_REQ}\n${NOTIF}\n${LIST_REQ}" | timeout 30 bwrap \
  --ro-bind / / \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --unshare-pid \
  --die-with-parent \
  npx @playwright/mcp@latest 2>/dev/null | head -2)

END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "Time: ${ELAPSED}ms"
echo "Response lines:"
echo "$RESP" | head -2
TOOL_COUNT=$(echo "$RESP" | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',{}).get('tools',[])))" 2>/dev/null)
echo "Tools found: ${TOOL_COUNT:-0}"
echo ""

echo "============================================"
echo "TEST 3: Playwright MCP - BUBBLEWRAP + NO NETWORK"
echo "============================================"
START=$(date +%s%N)

RESP=$(echo -e "${INIT_REQ}\n${NOTIF}\n${LIST_REQ}" | timeout 30 bwrap \
  --ro-bind / / \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --unshare-net \
  --unshare-pid \
  --die-with-parent \
  npx @playwright/mcp@latest 2>/dev/null | head -2)

END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "Time: ${ELAPSED}ms"
echo "Response lines:"
echo "$RESP" | head -2
TOOL_COUNT=$(echo "$RESP" | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',{}).get('tools',[])))" 2>/dev/null)
echo "Tools found: ${TOOL_COUNT:-0}"

echo ""
echo "============================================"
echo "DONE"
echo "============================================"
