#!/bin/bash
NPX=/usr/bin/npx
BWRAP=/usr/bin/bwrap
NPM_CACHE="$HOME/.npm"

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
    output=$(printf '%s\n%s\n%s\n' "$INIT" "$NOTIF" "$LIST" | timeout 30 "${cmd[@]}" 2>/tmp/npx_stderr)
    local exit_code=$?
    local end_ms=$(($(date +%s%N)/1000000))
    local elapsed=$((end_ms - start_ms))

    if [ $exit_code -eq 124 ]; then
        echo "  FAIL - timeout after 30s"
        echo "  stderr:"; tail -5 /tmp/npx_stderr 2>/dev/null | sed 's/^/    /'
        return
    fi

    local init_resp="" tools_resp="" line_num=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" != {* ]] && continue
        line_num=$((line_num + 1))
        [ $line_num -eq 1 ] && init_resp="$line"
        [ $line_num -eq 2 ] && tools_resp="$line"
    done <<< "$output"

    if [ -z "$init_resp" ]; then
        echo "  FAIL - no response"
        echo "  stderr:"; tail -5 /tmp/npx_stderr 2>/dev/null | sed 's/^/    /'
        return
    fi

    local tool_count
    tool_count=$(echo "$tools_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',{}).get('tools',[])))" 2>/dev/null)
    echo "  Tools: ${tool_count:-0}  |  Time: ${elapsed}ms  |  STATUS: PASS"
    echo "  stderr:"; tail -3 /tmp/npx_stderr 2>/dev/null | sed 's/^/    /'
}

echo "Testing npx offline modes with bwrap network isolation"
echo "======================================================="
echo ""

# Test 1: Baseline (network, @latest)
run_test "Baseline: npx @latest (network)" \
    $NPX @playwright/mcp@latest

# Test 2: npx pinned version (network)
run_test "npx @0.0.70 (network)" \
    $NPX @playwright/mcp@0.0.70

# Test 3: bwrap NO NETWORK + npx @latest (expect fail)
run_test "bwrap NO NET + npx @latest (expect FAIL)" \
    $BWRAP --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$NPM_CACHE" "$NPM_CACHE" \
    --unshare-net --unshare-pid --die-with-parent \
    $NPX @playwright/mcp@latest

# Test 4: bwrap NO NETWORK + npx pinned @0.0.70 (cached)
run_test "bwrap NO NET + npx @0.0.70 (cached)" \
    $BWRAP --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$NPM_CACHE" "$NPM_CACHE" \
    --unshare-net --unshare-pid --die-with-parent \
    $NPX @playwright/mcp@0.0.70

# Test 5: bwrap NO NETWORK + npx --prefer-offline @0.0.70
run_test "bwrap NO NET + npx --prefer-offline @0.0.70" \
    $BWRAP --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$NPM_CACHE" "$NPM_CACHE" \
    --unshare-net --unshare-pid --die-with-parent \
    $NPX --prefer-offline @playwright/mcp@0.0.70

# Test 6: bwrap NO NETWORK + npx --offline @0.0.70
run_test "bwrap NO NET + npx --offline @0.0.70" \
    $BWRAP --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$NPM_CACHE" "$NPM_CACHE" \
    --unshare-net --unshare-pid --die-with-parent \
    $NPX --offline @playwright/mcp@0.0.70

# Test 7: bwrap NO NETWORK + direct node (bypass npx entirely)
CACHED_DIR=$(ls -d "$NPM_CACHE/_npx"/*/node_modules/@playwright/mcp 2>/dev/null | head -1)
if [ -n "$CACHED_DIR" ]; then
    ENTRY=$(python3 -c "import json; d=json.load(open('$CACHED_DIR/package.json')); print(d.get('bin',{}).get('mcp','') or d.get('main',''))" 2>/dev/null)
    if [ -n "$ENTRY" ]; then
        run_test "bwrap NO NET + node direct (bypass npx)" \
            $BWRAP --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
            --unshare-net --unshare-pid --die-with-parent \
            /usr/bin/node "$CACHED_DIR/$ENTRY"
    else
        echo ""
        echo "Could not find entry point in $CACHED_DIR/package.json"
    fi
else
    echo ""
    echo "No cached playwright mcp found, skipping direct node test"
fi

echo ""
echo "============================================================"
echo "ALL TESTS COMPLETE"
echo "============================================================"
