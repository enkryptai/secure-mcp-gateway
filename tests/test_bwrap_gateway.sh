#!/bin/bash
# Test bwrap sandbox via the real gateway HTTP endpoint

GW_URL="http://localhost:8000/mcp/"
API_KEY="bwrap-test-key-001"
PROJECT_ID="bwrap-test-project-001"
USER_ID="bwrap-test-user-001"

send_mcp() {
    local label="$1"
    local body="$2"
    echo ""
    echo "============================================================"
    echo "REQUEST: $label"
    echo "============================================================"
    
    local start_ms=$(($(date +%s%N)/1000000))
    
    local resp
    resp=$(curl -s -X POST "$GW_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "ENKRYPT_GATEWAY_KEY: $API_KEY" \
        -H "project_id: $PROJECT_ID" \
        -H "user_id: $USER_ID" \
        -d "$body")
    
    local end_ms=$(($(date +%s%N)/1000000))
    local elapsed=$((end_ms - start_ms))
    
    echo "Response (${elapsed}ms):"
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    echo ""
}

echo "Testing bwrap sandbox via gateway at $GW_URL"
echo "API Key: $API_KEY"
echo ""

# 1. Initialize session
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"bwrap-test","version":"1.0"}}}'
send_mcp "Initialize" "$INIT_BODY"

# 2. List servers
LIST_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"enkrypt_list_all_servers","arguments":{"gateway_key":"'$API_KEY'"}}}'
send_mcp "List Servers" "$LIST_BODY"

# 3. Discover tools on echo_server (SANDBOXED)
DISCOVER_BODY='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"enkrypt_discover_all_tools","arguments":{"gateway_key":"'$API_KEY'","server_name":"echo_server"}}}'
send_mcp "Discover Tools (echo_server - BWRAP SANDBOXED)" "$DISCOVER_BODY"

# 4. Call echo tool (SANDBOXED)
CALL_BODY='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"enkrypt_secure_call_tools","arguments":{"gateway_key":"'$API_KEY'","server_name":"echo_server","tool_calls":[{"tool_name":"echo","arguments":{"message":"Hello from bwrap sandbox test!"}}]}}}'
send_mcp "Call echo tool (echo_server - BWRAP SANDBOXED)" "$CALL_BODY"

# 5. Discover tools on echo_server_no_sandbox (NOT SANDBOXED)
DISCOVER_NOSB='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"enkrypt_discover_all_tools","arguments":{"gateway_key":"'$API_KEY'","server_name":"echo_server_no_sandbox"}}}'
send_mcp "Discover Tools (echo_server_no_sandbox - NO SANDBOX)" "$DISCOVER_NOSB"

# 6. Call echo tool (NOT SANDBOXED, for comparison)
CALL_NOSB='{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"enkrypt_secure_call_tools","arguments":{"gateway_key":"'$API_KEY'","server_name":"echo_server_no_sandbox","tool_calls":[{"tool_name":"echo","arguments":{"message":"Hello from no-sandbox test!"}}]}}}'
send_mcp "Call echo tool (echo_server_no_sandbox - NO SANDBOX)" "$CALL_NOSB"

echo "============================================================"
echo "ALL GATEWAY TESTS COMPLETE"
echo "============================================================"
