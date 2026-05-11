"""Test Playwright MCP server with Bubblewrap sandbox."""

import asyncio
import json
import shutil
import sys
import time

INIT_REQUEST = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1.0"},
    },
})

NOTIF = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})

LIST_TOOLS = json.dumps({
    "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
})


async def run_test(cmd, label, timeout=60):
    print(f"\n{'='*60}")
    print(f"TEST: {label}")
    print(f"CMD:  {' '.join(cmd)}")
    print(f"{'='*60}")

    t0 = time.time()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    t_boot = time.time()

    async def read_json():
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            if not line:
                return None
            text = line.decode().strip()
            if not text:
                continue
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                print(f"  [non-json stdout] {text[:120]}")
                continue

    try:
        # Initialize
        proc.stdin.write((INIT_REQUEST + "\n").encode())
        await proc.stdin.drain()
        init_resp = await read_json()
        t_init = time.time()

        if not init_resp or "result" not in init_resp:
            stderr = b""
            try:
                stderr = await asyncio.wait_for(proc.stderr.read(2048), timeout=2)
            except:
                pass
            print(f"  FAIL - bad init response: {init_resp}")
            print(f"  stderr: {stderr.decode(errors='replace')[:300]}")
            proc.kill()
            return

        server_name = init_resp["result"].get("serverInfo", {}).get("name", "?")
        server_ver = init_resp["result"].get("serverInfo", {}).get("version", "?")
        print(f"  Server: {server_name} v{server_ver}")
        print(f"  Init time: {int((t_init - t_boot)*1000)}ms")

        # Send notification
        proc.stdin.write((NOTIF + "\n").encode())
        await proc.stdin.drain()

        # List tools
        proc.stdin.write((LIST_TOOLS + "\n").encode())
        await proc.stdin.drain()
        tools_resp = await read_json()
        t_tools = time.time()

        if tools_resp and "result" in tools_resp:
            tools = tools_resp["result"].get("tools", [])
            print(f"  Tools found: {len(tools)}")
            print(f"  Discovery time: {int((t_tools - t_init)*1000)}ms")
            for t in tools[:10]:
                print(f"    - {t['name']}: {t.get('description','')[:60]}")
            if len(tools) > 10:
                print(f"    ... and {len(tools)-10} more")
        else:
            print(f"  Tools response: {tools_resp}")

        t_end = time.time()
        print(f"  Total time: {int((t_end - t0)*1000)}ms")
        print(f"  STATUS: PASS")

    except asyncio.TimeoutError:
        print(f"  FAIL - timeout after {timeout}s")
        stderr = b""
        try:
            stderr = await asyncio.wait_for(proc.stderr.read(2048), timeout=2)
        except:
            pass
        if stderr:
            print(f"  stderr: {stderr.decode(errors='replace')[:300]}")
    except Exception as e:
        print(f"  FAIL - {e}")
    finally:
        try:
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except:
            proc.kill()


async def main():
    npx = "/usr/bin/npx"
    bwrap = "/usr/bin/bwrap"

    # Test 1: Baseline
    await run_test(
        [npx, "@playwright/mcp@latest"],
        "Playwright MCP - BASELINE (no sandbox)"
    )

    # Test 2: bwrap with network (Playwright needs to launch browser)
    await run_test(
        [bwrap,
         "--ro-bind", "/", "/",
         "--dev", "/dev",
         "--proc", "/proc",
         "--tmpfs", "/tmp",
         "--unshare-pid",
         "--die-with-parent",
         npx, "@playwright/mcp@latest"],
        "Playwright MCP - BWRAP (with network, PID isolation)"
    )

    # Test 3: bwrap without network
    await run_test(
        [bwrap,
         "--ro-bind", "/", "/",
         "--dev", "/dev",
         "--proc", "/proc",
         "--tmpfs", "/tmp",
         "--unshare-net",
         "--unshare-pid",
         "--die-with-parent",
         npx, "@playwright/mcp@latest"],
        "Playwright MCP - BWRAP (no network + PID isolation)"
    )

    # Test 4: bwrap strict (read-only filesystem + PID + network isolation)
    await run_test(
        [bwrap,
         "--ro-bind", "/", "/",
         "--dev", "/dev",
         "--proc", "/proc",
         "--tmpfs", "/tmp",
         "--tmpfs", "/root",
         "--tmpfs", "/home",
         "--unshare-net",
         "--unshare-pid",
         "--die-with-parent",
         npx, "@playwright/mcp@latest"],
        "Playwright MCP - BWRAP (strict: ro + no net + PID)"
    )


if __name__ == "__main__":
    asyncio.run(main())
