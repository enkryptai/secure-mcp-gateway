#!/usr/bin/env python3
"""Quick per-provider sandbox test with strict timeouts."""

import asyncio
import os
import sys
import time
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

ECHO_MCP = str(project_root / "src" / "secure_mcp_gateway" / "bad_mcps" / "echo_mcp.py")
PYTHON = sys.executable

PROVIDER = sys.argv[1] if len(sys.argv) > 1 else "baseline"


async def test_baseline():
    from mcp import ClientSession
    from secure_mcp_gateway.plugins.sandbox.server_params import build_server_params

    server_entry = {"server_name": "echo_server"}
    t0 = time.perf_counter()

    async with build_server_params(server_entry, PYTHON, [ECHO_MCP], None) as (r, w):
        t_boot = time.perf_counter() - t0
        async with ClientSession(r, w) as session:
            t1 = time.perf_counter()
            await session.initialize()
            t_init = time.perf_counter() - t1

            t2 = time.perf_counter()
            tools = await session.list_tools()
            t_disc = time.perf_counter() - t2

            t3 = time.perf_counter()
            result = await session.call_tool("echo", arguments={"message": "test"})
            t_call = time.perf_counter() - t3

    total = time.perf_counter() - t0
    text = result.content[0].text if result and result.content else "N/A"
    print(f"BASELINE | boot={t_boot*1000:.0f}ms init={t_init*1000:.0f}ms "
          f"disc={t_disc*1000:.0f}ms call={t_call*1000:.0f}ms "
          f"total={total*1000:.0f}ms tools={len(tools.tools)} result={text}")


async def test_docker():
    from mcp import ClientSession
    from secure_mcp_gateway.plugins.sandbox.server_params import build_server_params
    import secure_mcp_gateway.plugins.sandbox.config_manager as cm

    cm._sandbox_config_manager = None
    from secure_mcp_gateway.plugins.sandbox.config_manager import initialize_sandbox_system

    common = {"sandbox": {
        "enabled": True, "runtime": "docker", "default_image": "sandbox-test-mcp",
        "default_memory_limit": "512m", "default_cpu_limit": "1.0",
        "default_pids_limit": 100, "default_network": "none",
        "default_read_only": False, "container_cli": "docker",
    }}
    mgr = initialize_sandbox_system(common)
    p = mgr.get_provider()
    avail, msg = await p.check_availability()
    print(f"Availability: {avail} — {msg}")
    if not avail:
        return

    server_entry = {"server_name": "echo_server", "sandbox": {
        "enabled": True, "image": "sandbox-test-mcp",
    }}

    t0 = time.perf_counter()
    async with build_server_params(server_entry, PYTHON, [ECHO_MCP], None) as (r, w):
        t_boot = time.perf_counter() - t0
        async with ClientSession(r, w) as session:
            t1 = time.perf_counter()
            await session.initialize()
            t_init = time.perf_counter() - t1

            t2 = time.perf_counter()
            tools = await session.list_tools()
            t_disc = time.perf_counter() - t2

            t3 = time.perf_counter()
            result = await session.call_tool("echo", arguments={"message": "test"})
            t_call = time.perf_counter() - t3

    total = time.perf_counter() - t0
    text = result.content[0].text if result and result.content else "N/A"
    print(f"DOCKER | boot={t_boot*1000:.0f}ms init={t_init*1000:.0f}ms "
          f"disc={t_disc*1000:.0f}ms call={t_call*1000:.0f}ms "
          f"total={total*1000:.0f}ms tools={len(tools.tools)} result={text}")


async def test_novavm():
    from mcp import ClientSession
    from secure_mcp_gateway.plugins.sandbox.server_params import build_server_params
    import secure_mcp_gateway.plugins.sandbox.config_manager as cm

    cm._sandbox_config_manager = None
    from secure_mcp_gateway.plugins.sandbox.config_manager import initialize_sandbox_system

    common = {"sandbox": {
        "enabled": True, "runtime": "novavm",
        "nova_api_url": "http://localhost:9800",
    }}
    mgr = initialize_sandbox_system(common)
    p = mgr.get_provider()
    avail, msg = await p.check_availability()
    print(f"Availability: {avail} — {msg}")
    if not avail:
        return

    server_entry = {"server_name": "echo_server", "sandbox": {
        "enabled": True, "image": "python:3.11-slim",
        "memory_limit": "256", "cpu_limit": "1",
    }}

    t0 = time.perf_counter()
    async with build_server_params(server_entry, PYTHON, [ECHO_MCP], None) as (r, w):
        t_boot = time.perf_counter() - t0
        async with ClientSession(r, w) as session:
            t1 = time.perf_counter()
            await session.initialize()
            t_init = time.perf_counter() - t1

            t2 = time.perf_counter()
            tools = await session.list_tools()
            t_disc = time.perf_counter() - t2

            t3 = time.perf_counter()
            result = await session.call_tool("echo", arguments={"message": "test"})
            t_call = time.perf_counter() - t3

    total = time.perf_counter() - t0
    text = result.content[0].text if result and result.content else "N/A"
    print(f"NOVAVM | boot={t_boot*1000:.0f}ms init={t_init*1000:.0f}ms "
          f"disc={t_disc*1000:.0f}ms call={t_call*1000:.0f}ms "
          f"total={total*1000:.0f}ms tools={len(tools.tools)} result={text}")


async def main():
    print(f"Testing provider: {PROVIDER}")
    print(f"Python: {PYTHON}")
    print(f"Echo MCP exists: {os.path.isfile(ECHO_MCP)}")

    try:
        if PROVIDER == "baseline":
            await asyncio.wait_for(test_baseline(), timeout=30)
        elif PROVIDER == "docker":
            await asyncio.wait_for(test_docker(), timeout=60)
        elif PROVIDER == "novavm":
            await asyncio.wait_for(test_novavm(), timeout=60)
        else:
            print(f"Unknown provider: {PROVIDER}")
    except asyncio.TimeoutError:
        print(f"TIMEOUT: {PROVIDER} test exceeded timeout")
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
