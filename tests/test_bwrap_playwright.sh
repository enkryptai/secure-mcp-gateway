#!/bin/bash

NPX=/usr/bin/npx
BWRAP=/usr/bin/bwrap

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

run_test() {
    local label="$1"
    shift
    local cmd=("$@")
    
    echo ""
    echo "============================================================"
    echo "TEST: $label"
    echo "CMD:  ${cmd[*]}"
    echo "============================================================"
    
    local start_ms=$(($(date +%s%N)/1000000))
    
    local output
    output=$(printf '%s\n%s\n%s\n' "$INIT" "$NOTIF" "$LIST" | timeout 60 "${cmd[@]}" 2>/tmp/playwright_stderr)
    local exit_code=$?
    
    local end_ms=$(($(date +%s%N)/1000000))
    local elapsed=$((end_ms - start_ms))
    
    if [ $exit_code -ne 0 ] && [ $exit_code -ne 124 ]; then
        echo "  EXIT CODE: $exit_code"
    fi
    
    if [ $exit_code -eq 124 ]; then
        echo "  FAIL - timeout after 60s"
        echo "  stderr (last 5 lines):"
        tail -5 /tmp/playwright_stderr 2>/dev/null | sed 's/^/    /'
        return
    fi
    
    # Parse responses (each line is a JSON response)
    local init_resp
    local tools_resp
    local line_num=0
    
    while IFS= read -r line; do
        # Skip empty lines and non-JSON lines
        if [[ -z "$line" ]] || [[ "$line" != {* ]]; then
            continue
        fi
        line_num=$((line_num + 1))
        if [ $line_num -eq 1 ]; then
            init_resp="$line"
        elif [ $line_num -eq 2 ]; then
            tools_resp="$line"
        fi
    done <<< "$output"
    
    if [ -z "$init_resp" ]; then
        echo "  FAIL - no JSON response"
        echo "  Raw output (first 300 chars): ${output:0:300}"
        echo "  stderr (last 5 lines):"
        tail -5 /tmp/playwright_stderr 2>/dev/null | sed 's/^/    /'
        return
    fi
    
    # Extract server info
    local server_name
    server_name=$(echo "$init_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('serverInfo',{}).get('name','?'))" 2>/dev/null)
    local server_ver
    server_ver=$(echo "$init_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('serverInfo',{}).get('version','?'))" 2>/dev/null)
    echo "  Server: $server_name v$server_ver"
    
    # Extract tools
    if [ -n "$tools_resp" ]; then
        local tool_count
        tool_count=$(echo "$tools_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',{}).get('tools',[])))" 2>/dev/null)
        echo "  Tools found: ${tool_count:-0}"
        
        # Print first 5 tool names
        echo "$tools_resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = d.get('result',{}).get('tools',[])
for t in tools[:8]:
    print(f\"    - {t['name']}: {t.get('description','')[:50]}\")
if len(tools) > 8:
    print(f'    ... and {len(tools)-8} more')
" 2>/dev/null
    else
        echo "  No tools response received"
    fi
    
    echo "  Time: ${elapsed}ms"
    echo "  STATUS: PASS"
    
    # Show stderr warnings if any
    local stderr_size
    stderr_size=$(wc -c < /tmp/playwright_stderr 2>/dev/null)
    if [ "$stderr_size" -gt 0 ] 2>/dev/null; then
        echo "  stderr (last 3 lines):"
        tail -3 /tmp/playwright_stderr 2>/dev/null | sed 's/^/    /'
    fi
}

echo "Testing Playwright MCP server (@playwright/mcp) with Bubblewrap"
echo "================================================================"
echo "Node: $(node --version)"
echo "npx:  $($NPX --version)"
echo "bwrap: $($BWRAP --version)"
echo ""

# Test 1: Baseline
run_test "BASELINE (no sandbox)" \
    $NPX @playwright/mcp@latest

# Test 2: bwrap minimal (just PID isolation, full FS access)
run_test "BWRAP minimal (PID isolation only)" \
    $BWRAP \
    --bind / / \
    --dev /dev \
    --proc /proc \
    --unshare-pid \
    --die-with-parent \
    $NPX @playwright/mcp@latest

# Test 3: bwrap read-only FS + writable tmp/cache + PID isolation
run_test "BWRAP (ro FS + writable tmp + PID isolation)" \
    $BWRAP \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "$HOME/.npm" "$HOME/.npm" \
    --unshare-pid \
    --die-with-parent \
    $NPX @playwright/mcp@latest

# Test 4: bwrap + network isolation
run_test "BWRAP (ro FS + PID + no network)" \
    $BWRAP \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "$HOME/.npm" "$HOME/.npm" \
    --unshare-net \
    --unshare-pid \
    --die-with-parent \
    $NPX @playwright/mcp@latest

# Test 5: bwrap strict (ro + no net + tmpfs home)
run_test "BWRAP strict (ro + no net + PID + tmpfs home)" \
    $BWRAP \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --tmpfs /root \
    --tmpfs /home \
    --unshare-net \
    --unshare-pid \
    --die-with-parent \
    $NPX @playwright/mcp@latest

echo ""
echo "============================================================"
echo "ALL TESTS COMPLETE"
echo "============================================================"
