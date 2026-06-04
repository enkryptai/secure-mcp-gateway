"""Drive the new EnkryptAuthProvider end-to-end against a running gateway.

Run *after* starting the gateway with the cloud auth.config in
``~/.enkrypt/enkrypt_mcp_config.json``::

    python -m secure_mcp_gateway.gateway   # in another shell

Then::

    python tests/manual_cloud_auth_smoke.py

Sequence:
  1. Connect over streamable HTTP with the Enkrypt cloud apikey in the
     ``apikey`` header.
  2. List the gateway's framework tools (sanity check the transport).
  3. Call ``enkrypt_clear_cache`` to wipe the in-process cloud-config cache.
  4. Call ``enkrypt_discover_all_tools`` (FIRST CALL — cloud miss expected).
  5. Call ``enkrypt_discover_all_tools`` again (SECOND CALL — cache hit
     expected; the gateway log should NOT show another fetching line).
  6. Dump both JSON payloads side-by-side so we can spot drift.

The script intentionally lives outside the pytest collection so it doesn't
run on every unit-test pass.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any, Dict

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


GW_URL = os.environ.get("ENKRYPT_GW_URL", "http://localhost:8000/mcp/")
APIKEY = os.environ.get("ENKRYPT_TEST_APIKEY", "fO2Hju6IulLfxpjis1yQMKXXW12u05yg")

HEADERS = {
    "apikey": APIKEY,
}


def _extract_text(result) -> str:
    out = []
    for block in result.content:
        out.append(block.text if hasattr(block, "text") else str(block))
    return "\n".join(out)


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


def _summarise_discovery(payload: Dict[str, Any]) -> None:
    print(f"  status                    : {payload.get('status')}")
    print(f"  message                   : {payload.get('message')}")
    print(f"  discovery_success_servers : {payload.get('discovery_success_servers')}")
    print(f"  discovery_failed_servers  : {payload.get('discovery_failed_servers')}")
    available = payload.get("available_servers") or {}
    print(f"  available_servers ({len(available)}):")
    for name, entry in available.items():
        source = entry.get("source")
        tools_obj = entry.get("tools") or {}
        if isinstance(tools_obj, dict):
            tools_list = tools_obj.get("tools") or []
        else:
            tools_list = []
        tool_names = [t.get("name") for t in tools_list if isinstance(t, dict)]
        denied = entry.get("policy_denied_tools") or []
        igp = entry.get("input_guardrails_config") or {}
        print(f"    - {name}: source={source}, tools={tool_names}")
        print(f"        input_guardrails_config.guardrail_name = {igp.get('guardrail_name')!r}")
        print(f"        input_guardrails_config.block       = {igp.get('block')}")
        print(f"        policy_denied_tools                 = {denied}")


async def main() -> int:
    print("=" * 70)
    print(f"Enkrypt cloud-auth smoke test")
    print(f"Gateway URL : {GW_URL}")
    print(f"Apikey      : ****{APIKEY[-4:]}")
    print("=" * 70)

    t0 = time.time()
    async with streamablehttp_client(GW_URL, headers=HEADERS) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            t_init = time.time()
            print(f"\n[INIT] Connected in {int((t_init - t0) * 1000)} ms")

            tools = await session.list_tools()
            tool_names = sorted(t.name for t in tools.tools)
            print(f"[TOOLS] Gateway exposes {len(tool_names)} framework tools:")
            for name in tool_names:
                print(f"   - {name}")

            print("\n" + "-" * 70)
            print("STEP 1: enkrypt_clear_cache")
            print("-" * 70)
            t1 = time.time()
            r = await session.call_tool("enkrypt_clear_cache", {})
            t1e = time.time()
            print(f"  Completed in {int((t1e - t1) * 1000)} ms")
            print(f"  Response  : {_extract_text(r)[:400]}")

            print("\n" + "-" * 70)
            print("STEP 2: enkrypt_list_all_servers(discover_tools=False)")
            print("        (read-only: skips spawning the actual MCP server)")
            print("-" * 70)
            t2 = time.time()
            r2 = await session.call_tool(
                "enkrypt_list_all_servers", {"discover_tools": False}
            )
            t2e = time.time()
            elapsed_ms = int((t2e - t2) * 1000)
            print(f"  Completed in {elapsed_ms} ms")
            text2 = _extract_text(r2)
            payload2 = _try_parse_json(text2)
            if isinstance(payload2, dict):
                _print_list_servers(payload2)
            else:
                print(f"  Raw response: {text2[:1500]}")

            print("\n" + "-" * 70)
            print("STEP 3: enkrypt_get_server_info(server_name='my-filesystem-server')")
            print("        (returns the merged cloud + override config for one server)")
            print("-" * 70)
            t3 = time.time()
            r3 = await session.call_tool(
                "enkrypt_get_server_info", {"server_name": "my-filesystem-server"}
            )
            t3e = time.time()
            elapsed3_ms = int((t3e - t3) * 1000)
            print(f"  Completed in {elapsed3_ms} ms")
            text3 = _extract_text(r3)
            payload3 = _try_parse_json(text3)
            if isinstance(payload3, dict):
                _print_server_info(payload3)

            # Dump for archival.
            artefact = os.path.join(
                os.path.dirname(__file__), "..", "_smoke_first_call.json"
            )
            with open(artefact, "w", encoding="utf-8") as f:
                json.dump({
                    "list_all_servers": payload2 if isinstance(payload2, dict) else {"raw": text2},
                    "get_server_info": payload3 if isinstance(payload3, dict) else {"raw": text3},
                }, f, indent=2)
            print(f"\nSaved smoke-test payload to {os.path.abspath(artefact)}")
            return 0


def _print_list_servers(payload: Dict[str, Any]) -> None:
    print(f"  status                : {payload.get('status')}")
    servers = payload.get("available_servers") or payload.get("servers") or {}
    if isinstance(servers, dict):
        names = list(servers.keys())
        print(f"  servers ({len(names)}) : {names}")
        for name, entry in servers.items():
            description = (entry or {}).get("description")
            cfg_command = ((entry or {}).get("config") or {}).get("command")
            print(f"    - {name}: command={cfg_command!r} description={description!r}")
    elif isinstance(servers, list):
        print(f"  servers ({len(servers)})")
        for entry in servers:
            print(f"    - {entry.get('server_name') if isinstance(entry, dict) else entry}")


def _print_server_info(payload: Dict[str, Any]) -> None:
    print(f"  status                : {payload.get('status')}")
    info = payload.get("server_info") or payload
    config = info.get("config") if isinstance(info, dict) else {}
    igp = info.get("input_guardrails_config") if isinstance(info, dict) else {}
    sb = info.get("sandbox") if isinstance(info, dict) else None
    print(f"  server_name           : {info.get('server_name')}")
    print(f"  description           : {info.get('description')}")
    print(f"  config.command        : {(config or {}).get('command')}")
    print(f"  config.args           : {(config or {}).get('args')}")
    stg = info.get("server_tools_guardrails_config") if isinstance(info, dict) else {}
    print(f"  server_tools_guardrails_config.enabled: {(stg or {}).get('enabled')}")
    print(f"  input_guardrails_config:")
    print(f"      enabled        : {(igp or {}).get('enabled')}")
    print(f"      guardrail_name : {(igp or {}).get('guardrail_name')!r}")
    print(f"      block          : {(igp or {}).get('block')}")
    if sb is not None:
        print(f"  sandbox (local override applied):")
        print(f"      enabled        : {sb.get('enabled')}")
        print(f"      runtime/image  : {sb.get('runtime') or sb.get('image')}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
