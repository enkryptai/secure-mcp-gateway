"""Navigate to enkryptai.com and take a screenshot — all in one batched call."""

import asyncio
import base64
import json
import os
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

SCREENSHOT_PATH = os.path.join(os.path.dirname(__file__), "enkryptai_screenshot.png")


async def main():
    print("=" * 60)
    print("Playwright + bwrap: navigate & screenshot (batched)")
    print("=" * 60)

    t0 = time.time()
    async with streamablehttp_client(GW_URL, headers=HEADERS) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print(f"[INIT] Connected in {int((time.time()-t0)*1000)}ms")

            # Batch: navigate then screenshot in one enkrypt_secure_call_tools
            print("\nCalling enkrypt_secure_call_tools with 2 tool_calls:")
            print("  1) browser_navigate -> https://www.enkryptai.com")
            print("  2) browser_take_screenshot")
            t1 = time.time()
            result = await session.call_tool("enkrypt_secure_call_tools", {
                "gateway_key": API_KEY,
                "server_name": "playwright_bwrap",
                "tool_calls": [
                    {
                        "tool_name": "browser_navigate",
                        "arguments": {"url": "https://www.enkryptai.com"},
                    },
                    {
                        "tool_name": "browser_take_screenshot",
                        "arguments": {},
                    },
                ],
            })
            elapsed = int((time.time() - t1) * 1000)

            print(f"\nCompleted in {elapsed}ms")
            print("-" * 60)

            for block in result.content:
                text = block.text if hasattr(block, "text") else str(block)
                try:
                    data = json.loads(text)
                    summary = data.get("summary", {})
                    print(f"Status : {data.get('status')}")
                    print(f"Summary: {summary}")

                    for r in data.get("results", []):
                        idx = r.get("enkrypt_mcp_data", {}).get("call_index", "?")
                        tool = r.get("enkrypt_mcp_data", {}).get("tool_name", "?")
                        status = r.get("status")
                        resp = r.get("response", "")

                        print(f"\n  [{idx}] {tool} — {status}")

                        if tool == "browser_take_screenshot" and status == "success" and resp:
                            # Response may contain base64 image data
                            try:
                                resp_data = json.loads(resp) if isinstance(resp, str) else resp
                                if isinstance(resp_data, list):
                                    for item in resp_data:
                                        if isinstance(item, dict) and item.get("type") == "image":
                                            img_b64 = item.get("data", "")
                                            if img_b64:
                                                img_bytes = base64.b64decode(img_b64)
                                                with open(SCREENSHOT_PATH, "wb") as f:
                                                    f.write(img_bytes)
                                                print(f"      Screenshot saved: {SCREENSHOT_PATH} ({len(img_bytes)} bytes)")
                                elif isinstance(resp_data, dict) and resp_data.get("type") == "image":
                                    img_b64 = resp_data.get("data", "")
                                    if img_b64:
                                        img_bytes = base64.b64decode(img_b64)
                                        with open(SCREENSHOT_PATH, "wb") as f:
                                            f.write(img_bytes)
                                        print(f"      Screenshot saved: {SCREENSHOT_PATH} ({len(img_bytes)} bytes)")
                                else:
                                    print(f"      Response: {str(resp)[:200]}")
                            except (json.JSONDecodeError, Exception):
                                # Might be raw base64 or text
                                if len(resp) > 500 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n" for c in resp[:100]):
                                    img_bytes = base64.b64decode(resp)
                                    with open(SCREENSHOT_PATH, "wb") as f:
                                        f.write(img_bytes)
                                    print(f"      Screenshot saved: {SCREENSHOT_PATH} ({len(img_bytes)} bytes)")
                                else:
                                    print(f"      Response: {resp[:200]}")
                        elif resp:
                            print(f"      Response: {str(resp)[:200]}")
                        else:
                            print(f"      (empty response)")
                except json.JSONDecodeError:
                    print(text[:400])

    total = int((time.time() - t0) * 1000)
    print(f"\nTotal time: {total}ms")


if __name__ == "__main__":
    asyncio.run(main())
