"""List all Playwright tools to find the screenshot tool name."""
import asyncio, json
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

GW_URL = "http://localhost:8000/mcp/"
HEADERS = {"ENKRYPT_GATEWAY_KEY": "bwrap-test-key-001", "project_id": "bwrap-test-project-001", "user_id": "bwrap-test-user-001"}

async def main():
    async with streamablehttp_client(GW_URL, headers=HEADERS) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool("enkrypt_discover_all_tools", {"gateway_key": "bwrap-test-key-001", "server_name": "playwright_bwrap"})
            for block in result.content:
                text = block.text if hasattr(block, 'text') else str(block)
                try:
                    data = json.loads(text)
                    tools = data.get("tools", [])
                    if tools and isinstance(tools[0], dict):
                        actual = tools[0].get("tools", [])
                        for t in actual:
                            print(f"  {t['name']}: {t.get('description','')[:60]}")
                except:
                    print(text[:500])

if __name__ == "__main__":
    asyncio.run(main())
