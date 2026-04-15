"""Test Playwright MCP server with bwrap sandbox through the real gateway."""

import asyncio
import time
import json
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


GW_URL = "http://localhost:8000/mcp/"
API_KEY = "bwrap-test-key-001"
PROJECT_ID = "bwrap-test-project-001"
USER_ID = "bwrap-test-user-001"

HEADERS = {
    "ENKRYPT_GATEWAY_KEY": API_KEY,
    "project_id": PROJECT_ID,
    "user_id": USER_ID,
}


async def main():
    print("=" * 60)
    print("Testing Playwright MCP with bwrap sandbox on real gateway")
    print(f"Gateway: {GW_URL}")
    print("=" * 60)

    t0 = time.time()

    async with streamablehttp_client(GW_URL, headers=HEADERS) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            t_init = time.time()
            print(f"\n[INIT] Connected in {int((t_init - t0)*1000)}ms")

            tools = await session.list_tools()
            gateway_tools = [t.name for t in tools.tools]
            print(f"[TOOLS] Gateway tools: {gateway_tools}")

            # --- TEST 1: List servers ---
            print("\n" + "=" * 60)
            print("TEST 1: List all servers")
            print("=" * 60)
            t1 = time.time()
            result = await session.call_tool("enkrypt_list_all_servers", {
                "gateway_key": API_KEY,
            })
            t1e = time.time()
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    success_servers = data.get("discovery_success_servers", [])
                    failed_servers = data.get("discovery_failed_servers", [])
                    print(f"  Success: {success_servers}")
                    print(f"  Failed:  {failed_servers}")
                    for name, info in data.get("available_servers", {}).items():
                        tools_data = info.get("tools", {})
                        tool_list = tools_data.get("tools", []) if isinstance(tools_data, dict) else []
                        sandbox_note = ""
                        print(f"    {name}: {info.get('status')} — {len(tool_list)} tools")
                except:
                    print(f"  {text[:300]}")
            print(f"  Time: {int((t1e - t1)*1000)}ms")

            # --- TEST 2: Discover tools — playwright_bwrap (SANDBOXED) ---
            print("\n" + "=" * 60)
            print("TEST 2: Discover tools — playwright_bwrap (BWRAP SANDBOXED)")
            print("=" * 60)
            t2 = time.time()
            result = await session.call_tool("enkrypt_discover_all_tools", {
                "gateway_key": API_KEY,
                "server_name": "playwright_bwrap",
            })
            t2e = time.time()
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    tool_entries = data.get("tools", [])
                    if tool_entries and isinstance(tool_entries[0], dict):
                        actual_tools = tool_entries[0].get("tools", [])
                        print(f"  Tools found: {len(actual_tools)}")
                        for t in actual_tools[:8]:
                            print(f"    - {t['name']}: {t.get('description','')[:50]}")
                        if len(actual_tools) > 8:
                            print(f"    ... and {len(actual_tools)-8} more")
                    else:
                        print(f"  {text[:300]}")
                except:
                    print(f"  {text[:300]}")
            print(f"  Time: {int((t2e - t2)*1000)}ms")

            # --- TEST 3: Call a Playwright tool (SANDBOXED) ---
            print("\n" + "=" * 60)
            print("TEST 3: Call browser_navigate — playwright_bwrap (SANDBOXED)")
            print("=" * 60)
            t3 = time.time()
            result = await session.call_tool("enkrypt_secure_call_tools", {
                "gateway_key": API_KEY,
                "server_name": "playwright_bwrap",
                "tool_calls": [
                    {"tool_name": "browser_navigate", "arguments": {"url": "https://example.com"}}
                ],
            })
            t3e = time.time()
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    summary = data.get("summary", {})
                    print(f"  Status: {data.get('status')}")
                    print(f"  Summary: {summary}")
                    results = data.get("results", [])
                    for r in results:
                        print(f"  Tool result status: {r.get('status')}")
                        tool_result = r.get("tool_result", "")
                        if isinstance(tool_result, str):
                            print(f"  Response: {tool_result[:200]}")
                        elif isinstance(tool_result, list):
                            for tr in tool_result:
                                print(f"  Response: {str(tr)[:200]}")
                except:
                    print(f"  {text[:300]}")
            print(f"  Time: {int((t3e - t3)*1000)}ms")

            # --- TEST 4: Discover tools — playwright_no_sandbox (NO SANDBOX) ---
            print("\n" + "=" * 60)
            print("TEST 4: Discover tools — playwright_no_sandbox (NO SANDBOX)")
            print("=" * 60)
            t4 = time.time()
            result = await session.call_tool("enkrypt_discover_all_tools", {
                "gateway_key": API_KEY,
                "server_name": "playwright_no_sandbox",
            })
            t4e = time.time()
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    tool_entries = data.get("tools", [])
                    if tool_entries and isinstance(tool_entries[0], dict):
                        actual_tools = tool_entries[0].get("tools", [])
                        print(f"  Tools found: {len(actual_tools)}")
                    else:
                        print(f"  {text[:300]}")
                except:
                    print(f"  {text[:300]}")
            print(f"  Time: {int((t4e - t4)*1000)}ms")

            # --- TEST 5: Call browser_navigate — NO SANDBOX ---
            print("\n" + "=" * 60)
            print("TEST 5: Call browser_navigate — playwright_no_sandbox (NO SANDBOX)")
            print("=" * 60)
            t5 = time.time()
            result = await session.call_tool("enkrypt_secure_call_tools", {
                "gateway_key": API_KEY,
                "server_name": "playwright_no_sandbox",
                "tool_calls": [
                    {"tool_name": "browser_navigate", "arguments": {"url": "https://example.com"}}
                ],
            })
            t5e = time.time()
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    summary = data.get("summary", {})
                    print(f"  Status: {data.get('status')}")
                    print(f"  Summary: {summary}")
                    results = data.get("results", [])
                    for r in results:
                        print(f"  Tool result status: {r.get('status')}")
                        tool_result = r.get("tool_result", "")
                        if isinstance(tool_result, str):
                            print(f"  Response: {tool_result[:200]}")
                        elif isinstance(tool_result, list):
                            for tr in tool_result:
                                print(f"  Response: {str(tr)[:200]}")
                except:
                    print(f"  {text[:300]}")
            print(f"  Time: {int((t5e - t5)*1000)}ms")

    tend = time.time()
    print("\n" + "=" * 60)
    print(f"ALL TESTS COMPLETE — Total: {int((tend - t0)*1000)}ms")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
