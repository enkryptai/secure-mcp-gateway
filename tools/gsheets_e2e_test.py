#!/usr/bin/env python3
"""Standalone MCP test client for the Enkrypt Secure MCP Gateway.

Connects to the gateway's streamable-HTTP endpoint (``/mcp/``) with the same
``apikey`` + ``X-Enkrypt-MCP-Gateway`` headers a real client uses, and exercises
the gateway tools. Written to validate the ``google_sheets`` server end-to-end
(gateway-managed OAuth), but works for any configured server.

No install needed -- run via uv:

    $env:ENKRYPT_GW_APIKEY="<gateway apikey>"   # PowerShell
    uv run --with mcp python tools/gsheets_e2e_test.py gateway-tools
    uv run --with mcp python tools/gsheets_e2e_test.py list
    uv run --with mcp python tools/gsheets_e2e_test.py discover --server google_sheets
    uv run --with mcp python tools/gsheets_e2e_test.py call --server google_sheets \
        --tool create_spreadsheet --args '{"title":"Enkrypt GW Test"}'

Connection (flags override env; env overrides defaults):
    --url      http://localhost:8000/mcp/   (ENKRYPT_GW_URL)
    --apikey   <required>                   (ENKRYPT_GW_APIKEY)
    --gateway  demo_mcp_gateway             (ENKRYPT_GW_NAME)
"""

import argparse
import asyncio
import json
import os
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def _extract(result):
    """Return a JSON-able view of a CallToolResult."""
    out = {}
    sc = getattr(result, "structuredContent", None)
    if sc:
        out["structuredContent"] = sc
    texts = [
        getattr(b, "text", None)
        for b in (getattr(result, "content", None) or [])
        if getattr(b, "text", None) is not None
    ]
    if texts:
        out["text"] = texts
    if getattr(result, "isError", False):
        out["isError"] = True
    return out


@asynccontextmanager
async def _session(url, headers):
    async with streamablehttp_client(url, headers=headers) as (read, write, *_rest):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def run(args):
    headers = {"apikey": args.apikey, "X-Enkrypt-MCP-Gateway": args.gateway}
    async with _session(args.url, headers) as session:
        if args.action == "gateway-tools":
            tools = await session.list_tools()
            print(json.dumps([t.name for t in tools.tools], indent=2))
            return
        if args.action == "gcall":
            # Call an arbitrary gateway tool directly (e.g. enkrypt_oauth_authorize)
            gargs = json.loads(args.args) if args.args else {}
            r = await session.call_tool(args.tool, gargs)
            print(json.dumps(_extract(r), indent=2, default=str))
            return
        if args.action == "list":
            r = await session.call_tool(
                "enkrypt_list_all_servers", {"discover_tools": False}
            )
        elif args.action == "discover":
            r = await session.call_tool(
                "enkrypt_discover_all_tools", {"server_name": args.server}
            )
        elif args.action == "call":
            tool_args = json.loads(args.args) if args.args else {}
            r = await session.call_tool(
                "enkrypt_secure_call_tools",
                {
                    "server_name": args.server,
                    "tool_calls": [{"name": args.tool, "args": tool_args}],
                },
            )
        else:  # pragma: no cover
            raise SystemExit(f"unknown action {args.action}")
        print(json.dumps(_extract(r), indent=2, default=str))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "action", choices=["gateway-tools", "list", "discover", "call", "gcall"]
    )
    p.add_argument("--server", default="google_sheets")
    p.add_argument("--tool")
    p.add_argument("--args", default="", help="JSON object of tool arguments")
    p.add_argument(
        "--url", default=os.environ.get("ENKRYPT_GW_URL", "http://localhost:8000/mcp/")
    )
    p.add_argument("--apikey", default=os.environ.get("ENKRYPT_GW_APIKEY"))
    p.add_argument(
        "--gateway", default=os.environ.get("ENKRYPT_GW_NAME", "demo_mcp_gateway")
    )
    args = p.parse_args()
    if not args.apikey:
        raise SystemExit("Missing apikey: pass --apikey or set ENKRYPT_GW_APIKEY")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
