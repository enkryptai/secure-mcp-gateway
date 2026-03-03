#!/usr/bin/env python3
"""Test echo MCP server with OAuth header."""
import asyncio
import httpx

async def test_echo_with_oauth():
    """Test the echo server with OAuth authorization header."""
    url = "http://localhost:8001/mcp"

    headers = {
        "Authorization": "Bearer test-oauth-token-abc123xyz",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    # MCP protocol request
    request_data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {
                "message": "Hello from OAuth test!"
            }
        }
    }

    print("Testing Echo MCP Server with OAuth")
    print("=" * 60)
    print(f"URL: {url}")
    print(f"OAuth Token: test-oauth-token-abc123xyz")
    print(f"Message: {request_data['params']['arguments']['message']}")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=request_data, headers=headers, timeout=10.0)

            print(f"\nResponse Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"\nResponse Body:")
            print(response.text)

        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    asyncio.run(test_echo_with_oauth())
