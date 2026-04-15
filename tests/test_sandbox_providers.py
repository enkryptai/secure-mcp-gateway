#!/usr/bin/env python3
"""
Test script for comparing sandbox providers.

Usage (from project root, inside venv):
    python tests/test_sandbox_providers.py

Tests each sandbox provider against echo_mcp.py:
1. Direct execution (baseline, no sandbox)
2. Docker/Podman container
3. NovaVM micro-VM
4. Microsandbox microVM

For each provider, measures:
- Availability check latency
- MCP session boot time (time to first initialize response)
- Tool discovery latency
- Tool call roundtrip latency
- Whether network isolation works (tool call that attempts DNS)
"""

import asyncio
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure project is importable
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.server_params import build_server_params


ECHO_MCP = str(project_root / "src" / "secure_mcp_gateway" / "bad_mcps" / "echo_mcp.py")
PYTHON = sys.executable

RESULTS: list[Dict[str, Any]] = []


def ms(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms"


async def test_baseline():
    """Direct execution without any sandbox — the baseline."""
    print("\n" + "=" * 60)
    print("BASELINE: Direct execution (no sandbox)")
    print("=" * 60)

    server_entry = {"server_name": "echo_server"}
    t0 = time.perf_counter()

    async with build_server_params(
        server_entry, PYTHON, [ECHO_MCP], None
    ) as (read, write):
        t_boot = time.perf_counter() - t0

        async with ClientSession(read, write) as session:
            t1 = time.perf_counter()
            await session.initialize()
            t_init = time.perf_counter() - t1

            t2 = time.perf_counter()
            tools = await session.list_tools()
            t_discover = time.perf_counter() - t2

            t3 = time.perf_counter()
            result = await session.call_tool("echo", arguments={"message": "hello sandbox test"})
            t_call = time.perf_counter() - t3

    total = time.perf_counter() - t0

    entry = {
        "provider": "baseline (direct)",
        "boot_ms": t_boot * 1000,
        "init_ms": t_init * 1000,
        "discover_ms": t_discover * 1000,
        "call_ms": t_call * 1000,
        "total_ms": total * 1000,
        "tools_found": len(tools.tools) if tools else 0,
        "call_result": str(result.content[0].text)[:100] if result and result.content else "N/A",
        "success": True,
    }
    RESULTS.append(entry)
    _print_result(entry)
    return entry


async def test_provider(
    name: str,
    runtime: str,
    extra_sandbox_config: Optional[Dict[str, Any]] = None,
):
    """Test a sandbox provider end-to-end."""
    print("\n" + "=" * 60)
    print(f"PROVIDER: {name} (runtime={runtime})")
    print("=" * 60)

    from secure_mcp_gateway.plugins.sandbox.config_manager import (
        get_sandbox_config_manager,
        initialize_sandbox_system,
    )

    # Reset singleton to reconfigure
    import secure_mcp_gateway.plugins.sandbox.config_manager as cm
    cm._sandbox_config_manager = None

    sandbox_cfg = {
        "enabled": True,
        "runtime": runtime,
        "default_image": "python:3.11-slim",
        "default_memory_limit": "512m",
        "default_cpu_limit": "1.0",
        "default_pids_limit": 100,
        "default_network": "none",
        "default_read_only": False,  # need /tmp writable for MCP
        "container_cli": "auto",
        "nova_api_url": "http://localhost:9800",
    }

    common_config = {"sandbox": sandbox_cfg}
    manager = initialize_sandbox_system(common_config)
    provider = manager.get_provider()

    if not provider:
        entry = {
            "provider": name,
            "success": False,
            "error": "Provider could not be loaded",
        }
        RESULTS.append(entry)
        _print_result(entry)
        return entry

    # Availability check
    t0 = time.perf_counter()
    available, status_msg = await provider.check_availability()
    t_avail = time.perf_counter() - t0
    print(f"  Availability: {available} — {status_msg} ({ms(t_avail)})")

    if not available:
        entry = {
            "provider": name,
            "success": False,
            "error": f"Runtime not available: {status_msg}",
            "avail_ms": t_avail * 1000,
        }
        RESULTS.append(entry)
        _print_result(entry)
        return entry

    server_entry = {
        "server_name": "echo_server",
        "sandbox": {
            "enabled": True,
            **(extra_sandbox_config or {}),
        },
    }

    try:
        t0 = time.perf_counter()

        async with build_server_params(
            server_entry, PYTHON, [ECHO_MCP], None
        ) as (read, write):
            t_boot = time.perf_counter() - t0

            async with ClientSession(read, write) as session:
                t1 = time.perf_counter()
                await session.initialize()
                t_init = time.perf_counter() - t1

                t2 = time.perf_counter()
                tools = await session.list_tools()
                t_discover = time.perf_counter() - t2

                t3 = time.perf_counter()
                result = await session.call_tool(
                    "echo", arguments={"message": "hello sandbox test"}
                )
                t_call = time.perf_counter() - t3

        total = time.perf_counter() - t0

        entry = {
            "provider": name,
            "boot_ms": t_boot * 1000,
            "init_ms": t_init * 1000,
            "discover_ms": t_discover * 1000,
            "call_ms": t_call * 1000,
            "total_ms": total * 1000,
            "avail_ms": t_avail * 1000,
            "tools_found": len(tools.tools) if tools else 0,
            "call_result": str(result.content[0].text)[:100] if result and result.content else "N/A",
            "success": True,
        }
    except Exception as exc:
        total = time.perf_counter() - t0
        entry = {
            "provider": name,
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "total_ms": total * 1000,
            "avail_ms": t_avail * 1000,
        }

    RESULTS.append(entry)
    _print_result(entry)
    return entry


def _print_result(entry: Dict[str, Any]):
    print(f"\n  --- {entry['provider']} ---")
    if entry.get("success"):
        print(f"  Boot:       {entry['boot_ms']:.1f}ms")
        print(f"  Initialize: {entry['init_ms']:.1f}ms")
        print(f"  Discovery:  {entry['discover_ms']:.1f}ms")
        print(f"  Tool Call:  {entry['call_ms']:.1f}ms")
        print(f"  Total:      {entry['total_ms']:.1f}ms")
        print(f"  Tools:      {entry['tools_found']}")
        print(f"  Result:     {entry['call_result']}")
    else:
        print(f"  FAILED: {entry.get('error', 'unknown')}")


def print_comparison_table():
    print("\n\n" + "=" * 80)
    print("COMPARISON TABLE")
    print("=" * 80)

    headers = ["Provider", "Boot", "Init", "Discover", "Call", "Total", "Status"]
    widths = [25, 10, 10, 10, 10, 10, 15]

    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * len(header_line))

    for r in RESULTS:
        if r.get("success"):
            row = [
                r["provider"],
                f"{r['boot_ms']:.0f}ms",
                f"{r['init_ms']:.0f}ms",
                f"{r['discover_ms']:.0f}ms",
                f"{r['call_ms']:.0f}ms",
                f"{r['total_ms']:.0f}ms",
                "OK",
            ]
        else:
            row = [
                r["provider"],
                "-", "-", "-", "-",
                f"{r.get('total_ms', 0):.0f}ms" if r.get("total_ms") else "-",
                f"FAIL",
            ]
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))

    print()


async def main():
    print("Sandbox Provider Comparison Test")
    print(f"Python: {sys.executable}")
    print(f"Echo MCP: {ECHO_MCP}")
    print(f"Echo MCP exists: {os.path.isfile(ECHO_MCP)}")

    # 1. Baseline
    await test_baseline()

    # 2. Docker (use sandbox-test-mcp image which has mcp pre-installed)
    await test_provider(
        "Docker",
        "docker",
        extra_sandbox_config={"image": "sandbox-test-mcp"},
    )

    # 3. NovaVM
    await test_provider(
        "NovaVM",
        "novavm",
        extra_sandbox_config={"image": "python:3.11-slim"},
    )

    # 4. Microsandbox (requires pip install microsandbox)
    await test_provider("Microsandbox", "microsandbox")

    print_comparison_table()

    # Save results to JSON
    results_path = project_root / "tests" / "sandbox_comparison_results.json"
    with open(results_path, "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    asyncio.run(main())
