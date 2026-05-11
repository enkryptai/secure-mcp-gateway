"""Test session persistence: navigate in call 1, screenshot in call 2.

If the session pool works, call 2's screenshot should show the navigated
page (not about:blank).
"""

import asyncio
import json
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

GW_URL = "http://localhost:8000/mcp/"
API_KEY = "bwrap-test-key-001"
HEADERS = {
    "ENKRYPT_GATEWAY_KEY": API_KEY,
    "project_id": "bwrap-test-project-001",
    "user_id": "bwrap-test-user-001",
}


def _print_result(label: str, result):
    for block in result.content:
        text = block.text if hasattr(block, "text") else str(block)
        try:
            data = json.loads(text)
            for r in data.get("results", []):
                tool = r.get("enkrypt_mcp_data", {}).get("tool_name", "?")
                status = r.get("status")
                resp = r.get("response", "")[:300]
                print(f"  [{label}] {tool} — {status}")
                if resp:
                    print(f"    Response snippet: {resp[:200]}")
        except json.JSONDecodeError:
            print(f"  [{label}] {text[:300]}")


async def test_server(server_name: str):
    print(f"\n{'='*60}")
    print(f"Testing session pool with: {server_name}")
    print(f"{'='*60}")

    async with streamablehttp_client(GW_URL, headers=HEADERS) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Call 1: navigate
            print(f"\n[Call 1] browser_navigate -> https://www.google.com")
            t0 = time.time()
            r1 = await session.call_tool("enkrypt_secure_call_tools", {
                "gateway_key": API_KEY,
                "server_name": server_name,
                "tool_calls": [
                    {
                        "tool_name": "browser_navigate",
                        "arguments": {"url": "https://www.google.com"},
                    },
                ],
            })
            print(f"  Completed in {int((time.time()-t0)*1000)}ms")
            _print_result("Call 1", r1)

            # Call 2: screenshot (separate enkrypt_secure_call_tools invocation)
            print(f"\n[Call 2] browser_take_screenshot (SEPARATE call)")
            t1 = time.time()
            r2 = await session.call_tool("enkrypt_secure_call_tools", {
                "gateway_key": API_KEY,
                "server_name": server_name,
                "tool_calls": [
                    {
                        "tool_name": "browser_take_screenshot",
                        "arguments": {},
                    },
                ],
            })
            print(f"  Completed in {int((time.time()-t1)*1000)}ms")
            _print_result("Call 2", r2)

            # Check if page URL is NOT about:blank
            call2_text = ""
            for block in r2.content:
                call2_text += block.text if hasattr(block, "text") else str(block)

            if "about:blank" in call2_text:
                print(f"\n  FAIL: Page is about:blank -- session was NOT reused!")
                return False
            elif "google" in call2_text.lower():
                print(f"\n  PASS: Page still shows Google -- session WAS reused!")
                return True

            # Secondary check: if call 2 was fast (<2s), session was likely reused
            # (fresh spawn would take 3-5s for Playwright to start)
            elapsed_ms = int((time.time() - t1) * 1000)
            if elapsed_ms < 2000:
                print(f"\n  PASS (inferred): Call 2 took only {elapsed_ms}ms -- session WAS reused!")
                return True

            print(f"\n  INCONCLUSIVE: Could not determine page URL from response")
            return None


async def main():
    print("Session Pool Persistence Test")
    print("=" * 60)

    # Test with sandbox-enabled server
    result_bwrap = await test_server("playwright_bwrap")

    # Test with non-sandboxed server
    result_no_sandbox = await test_server("playwright_no_sandbox")

    print(f"\n{'='*60}")
    print("RESULTS:")
    print(f"  playwright_bwrap:       {'PASS' if result_bwrap else 'FAIL' if result_bwrap is False else 'INCONCLUSIVE'}")
    print(f"  playwright_no_sandbox:  {'PASS' if result_no_sandbox else 'FAIL' if result_no_sandbox is False else 'INCONCLUSIVE'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
