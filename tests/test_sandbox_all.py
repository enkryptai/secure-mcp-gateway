"""
Test all sandbox runtimes for MCP stdio compatibility.

For each runtime, we:
1. Launch echo_mcp.py inside the sandbox
2. Send MCP initialize request via stdin
3. Read MCP response from stdout
4. Measure timing
5. Report pass/fail

Usage:
    python test_sandbox_all.py [runtime]
    Runtimes: baseline, docker, gvisor, bwrap, srt, kata, all
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time

ECHO_MCP = os.path.join(
    os.path.dirname(__file__),
    "..", "src", "secure_mcp_gateway", "bad_mcps", "echo_mcp.py",
)
ECHO_MCP = os.path.abspath(ECHO_MCP)

VENV_PYTHON = "/tmp/sandbox-venv/bin/python"
DOCKER_IMAGE = "sandbox-test-mcp"

INIT_REQUEST = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "sandbox-test", "version": "1.0"},
    },
})

LIST_TOOLS_REQUEST = json.dumps({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {},
})

CALL_TOOL_REQUEST = json.dumps({
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
        "name": "echo",
        "arguments": {"message": "sandbox_test"},
    },
})

INITIALIZED_NOTIFICATION = json.dumps({
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
})


async def run_mcp_test(cmd, env=None, label="test", timeout=30):
    """Run a full MCP roundtrip and return results."""
    result = {
        "runtime": label,
        "status": "FAIL",
        "boot_ms": 0,
        "init_ms": 0,
        "discovery_ms": 0,
        "call_ms": 0,
        "total_ms": 0,
        "tools": 0,
        "call_result": None,
        "error": None,
    }

    t_start = time.time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        t_boot = time.time()
        result["boot_ms"] = int((t_boot - t_start) * 1000)

        async def read_response():
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
                    continue

        # Initialize
        proc.stdin.write((INIT_REQUEST + "\n").encode())
        await proc.stdin.drain()
        init_resp = await read_response()
        t_init = time.time()
        result["init_ms"] = int((t_init - t_boot) * 1000)

        if not init_resp or "result" not in init_resp:
            stderr_data = b""
            try:
                stderr_data = await asyncio.wait_for(proc.stderr.read(4096), timeout=2)
            except Exception:
                pass
            result["error"] = f"Bad init response: {init_resp} | stderr: {stderr_data.decode(errors='replace')[:200]}"
            try:
                proc.kill()
            except Exception:
                pass
            return result

        # Send initialized notification
        proc.stdin.write((INITIALIZED_NOTIFICATION + "\n").encode())
        await proc.stdin.drain()

        # List tools
        proc.stdin.write((LIST_TOOLS_REQUEST + "\n").encode())
        await proc.stdin.drain()
        tools_resp = await read_response()
        t_disc = time.time()
        result["discovery_ms"] = int((t_disc - t_init) * 1000)

        if tools_resp and "result" in tools_resp:
            tools = tools_resp["result"].get("tools", [])
            result["tools"] = len(tools)

        # Call tool
        proc.stdin.write((CALL_TOOL_REQUEST + "\n").encode())
        await proc.stdin.drain()
        call_resp = await read_response()
        t_call = time.time()
        result["call_ms"] = int((t_call - t_disc) * 1000)

        if call_resp and "result" in call_resp:
            content = call_resp["result"].get("content", [])
            if content:
                result["call_result"] = content[0].get("text", "")

        result["total_ms"] = int((t_call - t_start) * 1000)
        result["status"] = "PASS" if result["call_result"] else "FAIL"

        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()

    except asyncio.TimeoutError:
        result["error"] = "Timeout waiting for MCP response"
        try:
            proc.kill()
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)

    return result


async def test_baseline():
    """Direct execution — no sandbox."""
    python = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable
    return await run_mcp_test([python, ECHO_MCP], label="baseline")


async def test_docker():
    """Docker container sandbox."""
    script_dir = os.path.dirname(ECHO_MCP)
    script_name = os.path.basename(ECHO_MCP)
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network=none",
        "--memory=512m",
        "--cpus=1.0",
        "--read-only",
        "--tmpfs=/tmp:size=64m",
        "-v", f"{script_dir}:/app:ro",
        DOCKER_IMAGE,
        "python", f"/app/{script_name}",
    ]
    return await run_mcp_test(cmd, label="docker")


async def test_gvisor():
    """gVisor (runsc do) — user-space kernel sandbox."""
    python = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable
    cmd = [
        "sudo", "runsc", "--rootless", "--network=none",
        "do", python, ECHO_MCP,
    ]
    return await run_mcp_test(cmd, label="gvisor", timeout=30)


async def test_bwrap():
    """Bubblewrap (bwrap) namespace sandbox."""
    python = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable
    venv_dir = os.path.dirname(os.path.dirname(python))

    cmd = [
        "bwrap",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--ro-bind", venv_dir, venv_dir,
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        python, ECHO_MCP,
    ]
    return await run_mcp_test(cmd, label="bwrap")


async def test_srt():
    """Anthropic sandbox-runtime (srt)."""
    if not shutil.which("srt"):
        return {
            "runtime": "srt",
            "status": "SKIP",
            "error": "srt not installed (npm install -g @anthropic-ai/sandbox-runtime)",
            "boot_ms": 0, "init_ms": 0, "discovery_ms": 0,
            "call_ms": 0, "total_ms": 0, "tools": 0, "call_result": None,
        }
    python = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable
    cmd = ["srt", f"{python} {ECHO_MCP}"]
    return await run_mcp_test(cmd, label="srt", timeout=30)


async def test_kata():
    """Kata Containers runtime."""
    result = subprocess.run(
        ["docker", "info", "--format", "{{.Runtimes}}"],
        capture_output=True, text=True,
    )
    if "kata" not in result.stdout.lower() and "io.containerd.kata" not in result.stdout.lower():
        return {
            "runtime": "kata",
            "status": "SKIP",
            "error": "Kata runtime not available in Docker (needs KVM + kata-runtime installed)",
            "boot_ms": 0, "init_ms": 0, "discovery_ms": 0,
            "call_ms": 0, "total_ms": 0, "tools": 0, "call_result": None,
        }

    script_dir = os.path.dirname(ECHO_MCP)
    script_name = os.path.basename(ECHO_MCP)
    cmd = [
        "docker", "run", "--rm", "-i",
        "--runtime=kata",
        "--network=none",
        "--memory=512m",
        "-v", f"{script_dir}:/app:ro",
        DOCKER_IMAGE,
        "python", f"/app/{script_name}",
    ]
    return await run_mcp_test(cmd, label="kata", timeout=60)


TESTS = {
    "baseline": test_baseline,
    "docker": test_docker,
    "gvisor": test_gvisor,
    "bwrap": test_bwrap,
    "srt": test_srt,
    "kata": test_kata,
}


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    if target == "all":
        tests_to_run = list(TESTS.keys())
    elif target in TESTS:
        tests_to_run = [target]
    else:
        print(f"Unknown runtime: {target}")
        print(f"Available: {', '.join(TESTS.keys())}, all")
        sys.exit(1)

    results = []
    for name in tests_to_run:
        print(f"\n{'='*60}")
        print(f"Testing: {name}")
        print(f"{'='*60}")
        try:
            r = await TESTS[name]()
            results.append(r)
            status = r["status"]
            if status == "PASS":
                print(
                    f"  {status} | boot={r['boot_ms']}ms init={r['init_ms']}ms "
                    f"disc={r['discovery_ms']}ms call={r['call_ms']}ms "
                    f"total={r['total_ms']}ms tools={r['tools']} "
                    f"result={r['call_result']}"
                )
            elif status == "SKIP":
                print(f"  {status} | {r['error']}")
            else:
                print(f"  {status} | error={r.get('error', 'unknown')}")
        except Exception as e:
            print(f"  CRASH | {e}")
            results.append({
                "runtime": name, "status": "CRASH", "error": str(e),
                "boot_ms": 0, "init_ms": 0, "discovery_ms": 0,
                "call_ms": 0, "total_ms": 0, "tools": 0, "call_result": None,
            })

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"{'Runtime':<12} {'Status':<8} {'Boot':<8} {'Init':<8} {'Disc':<8} {'Call':<8} {'Total':<8} {'Tools':<6}")
    print("-" * 74)
    for r in results:
        print(
            f"{r['runtime']:<12} {r['status']:<8} "
            f"{r['boot_ms']:<8} {r['init_ms']:<8} "
            f"{r['discovery_ms']:<8} {r['call_ms']:<8} "
            f"{r['total_ms']:<8} {r['tools']:<6}"
        )

    out_path = os.path.join(os.path.dirname(__file__), "sandbox_all_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
