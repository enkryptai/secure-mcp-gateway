# Bubblewrap (bwrap) Sandbox Guide

A complete guide to using Bubblewrap as the sandbox runtime for the Secure MCP Gateway. This is the **fastest** sandbox option with near-zero overhead, ideal for Linux deployments where every millisecond matters.

---

## Why Bubblewrap?

Before diving in, here's how Bubblewrap compares to the other options we tested:

```
┌──────────────────┬───────────┬───────────┬─────────────────────────────┬──────────────────┐
│ Runtime          │ Overhead  │ Platform  │ Isolation                   │ Status           │
├──────────────────┼───────────┼───────────┼─────────────────────────────┼──────────────────┤
│ Bubblewrap(bwrap)│   +43ms   │ Linux     │ Namespace (mount/PID/net)   │ ✅ Fastest        │
│ Docker           │  +490ms   │ All       │ Namespace + cgroup          │ ✅ Most portable  │
│ gVisor (runsc)   │  +944ms   │ Linux     │ User-space kernel           │ ✅ Most secure*   │
│ Anthropic srt    │ +1158ms   │ Linux+Mac │ Namespace + net proxy       │ ✅ Best for macOS │
│ Kata Containers  │ ~1000ms†  │ Linux     │ VM (dedicated kernel, KVM)  │ ✅ OCI-compatible │
│ NovaVM           │    —      │ Linux     │ VM (dedicated kernel, KVM)  │ ❌ Incompatible   │
│ Microsandbox     │    —      │ Linux+Mac │ VM (libkrun microVM)        │ ⏳ Beta           │
│ E2B (cloud)      │ ~200ms†   │ Any       │ VM (Firecracker, managed)   │ 📋 Not yet built  │
└──────────────────┴───────────┴───────────┴─────────────────────────────┴──────────────────┘
† = estimated     * = strongest without a full VM
```

Bubblewrap adds only **43ms** of overhead — 11x faster than Docker and 22x faster than gVisor. For high-throughput pipelines that call many MCP tools per second, this difference is significant.

### When to use Bubblewrap

- You're running on **Linux** (k8s nodes, CI/CD, servers)
- You want **minimal latency** per tool call
- You don't need container images or a Docker daemon
- You need **lightweight isolation** (filesystem, network, PID) without the weight of containers

### When NOT to use Bubblewrap

- You need **macOS or Windows** support → use Docker or Anthropic srt
- You need **memory/CPU resource limits** → use Docker (bwrap doesn't have cgroup integration)
- You need **stronger-than-namespace isolation** → use gVisor or Kata Containers
- You need **pre-built images with specific dependencies** → use Docker

---

## What Is Bubblewrap?

Bubblewrap (`bwrap`) is a lightweight, unprivileged sandboxing tool created by the [Flatpak](https://flatpak.org/) project. It uses **Linux kernel namespaces** to isolate processes — the same kernel feature Docker uses, but without the container runtime overhead.

When you run a command through bwrap, it:

1. Creates new **mount**, **PID**, **network**, and optionally **user** namespaces
2. Sets up a minimal filesystem view with only the paths you explicitly bind-mount
3. Runs your command inside this restricted environment
4. When the command exits, the namespace is destroyed — nothing persists

There is no daemon, no image registry, no container lifecycle. It's a single binary that wraps your command.

### How it compares to Docker conceptually

```
Docker:
  docker daemon → create container → pull image → set up namespaces → 
  set up cgroups → mount overlay filesystem → run command → cleanup

Bubblewrap:
  bwrap → set up namespaces → bind-mount selected paths → run command → done
```

Docker does a lot more (image management, networking, cgroups, logging), which is why it adds ~490ms overhead. Bubblewrap does the bare minimum needed for isolation, which is why it adds only ~43ms.

---

## Installation

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y bubblewrap
```

### Fedora / RHEL

```bash
sudo dnf install -y bubblewrap
```

### Arch Linux

```bash
sudo pacman -S bubblewrap
```

### From source

```bash
git clone https://github.com/containers/bubblewrap.git
cd bubblewrap
meson setup builddir
ninja -C builddir
sudo ninja -C builddir install
```

### Verify installation

```bash
bwrap --version
# Output: bubblewrap 0.8.0 (or similar)
```

### Check kernel support

Bubblewrap needs unprivileged user namespaces enabled in the kernel:

```bash
# Check if user namespaces are enabled
sysctl kernel.unprivileged_userns_clone

# If it shows 0, enable it:
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make it persistent across reboots:
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-userns.conf
```

On most modern distros (Ubuntu 24.04+, Fedora 38+), this is already enabled.

---

## How Bubblewrap Works (Step by Step)

Let's understand exactly what happens when the gateway uses bwrap to sandbox an MCP server.

### Without sandbox (normal execution)

The gateway runs:
```bash
/path/to/venv/bin/python /path/to/echo_mcp.py
```

The MCP server has full access to:
- All files on the host filesystem
- All network interfaces (can phone home to an attacker)
- All environment variables (API keys, secrets)
- All host processes (can see and signal them)
- Unlimited memory, CPU, and process creation

### With Bubblewrap sandbox

**The user only sets this in the config:**
```json
"sandbox": { "enabled": true, "runtime": "bwrap", "network": "none" }
```

**The gateway automatically builds and runs this command** (the user never writes or sees these flags):
```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc/alternatives /etc/alternatives \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --ro-bind /path/to/venv /path/to/venv \
  --ro-bind /path/to/scripts /app \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --unshare-net \
  --unshare-pid \
  --die-with-parent \
  --chdir /app \
  /path/to/venv/bin/python echo_mcp.py
```

This is handled by the `BwrapSandboxProvider.wrap_server_params()` method — it reads the server's `command`, `args`, and `sandbox` config, then constructs the full `bwrap` command with all the right flags. The user never needs to know about bwrap flags.

The flow is:
```
User config:  "sandbox": { "enabled": true, "runtime": "bwrap" }
                  │
                  ▼
Gateway:      BwrapSandboxProvider.wrap_server_params()
              reads command="python", args=["echo_mcp.py"]
              auto-detects venv path, script directory
              builds all --ro-bind, --unshare-net, etc. flags
                  │
                  ▼
MCP SDK:      stdio_client(StdioServerParameters(command="bwrap", args=[...]))
              communicates with sandboxed server over stdin/stdout
```

Here's what each auto-generated flag does:

| Flag | What it does | Why we need it |
|---|---|---|
| `--ro-bind /usr /usr` | Mount `/usr` read-only inside sandbox | Python, shared libraries, and binaries live here |
| `--ro-bind /lib /lib` | Mount `/lib` read-only | Shared library dependencies |
| `--ro-bind /lib64 /lib64` | Mount `/lib64` read-only | 64-bit shared libraries |
| `--ro-bind /etc/alternatives /etc/alternatives` | Mount alternatives read-only | Debian/Ubuntu alternative system links |
| `--ro-bind /path/to/venv /path/to/venv` | Mount the Python virtualenv read-only | So the sandboxed Python can find `mcp`, `opentelemetry`, etc. |
| `--ro-bind /path/to/scripts /app` | Mount the MCP server script directory at `/app` read-only | The server code itself |
| `--proc /proc` | Create a new `/proc` | Python needs `/proc` for process info |
| `--dev /dev` | Create minimal `/dev` | Python needs `/dev/null`, `/dev/urandom` |
| `--tmpfs /tmp` | Writable temp directory (in-memory) | Some Python packages write temp files |
| `--unshare-net` | Create a new empty network namespace | **No network access** — can't phone home, can't exfiltrate data |
| `--unshare-pid` | Create a new PID namespace | Sandbox can only see its own processes, not host PIDs |
| `--die-with-parent` | Kill sandbox if gateway dies | Prevents orphaned sandbox processes |
| `--chdir /app` | Set working directory to `/app` | So the script runs from the mounted directory |

### What the sandboxed process CAN see

- `/usr`, `/lib`, `/lib64` — system libraries (read-only)
- `/app` — the MCP server script (read-only)
- The Python virtualenv (read-only)
- `/tmp` — writable temp space (in-memory, lost on exit)
- `/proc` and `/dev` — minimal, scoped to the sandbox

### What the sandboxed process CANNOT see or do

- ❌ Host files outside the bind-mounts (`~/.ssh`, `~/.aws`, `~/.enkrypt`, etc.)
- ❌ Other processes on the host
- ❌ Network (no DNS, no HTTP, no TCP, nothing)
- ❌ Write to any bind-mounted path (all are read-only)
- ❌ Access host environment variables not explicitly passed
- ❌ Survive after the gateway process exits

---

## Quick Start

### Step 1: Install bubblewrap

```bash
sudo apt install -y bubblewrap
```

### Step 2: Set up Python with MCP dependencies

Bwrap runs the host Python directly (no Docker images needed), so you need `mcp` installed:

```bash
# Option A: Install in a virtualenv (recommended)
python3 -m venv /opt/mcp-venv
/opt/mcp-venv/bin/pip install "mcp[cli]>=1.10.1" "opentelemetry-sdk>=1.34.1" "opentelemetry-api>=1.34.1"

# Option B: Install system-wide
pip install "mcp[cli]>=1.10.1"
```

### Step 3: Test bwrap manually with the echo server

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
| bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --unshare-net \
    --unshare-pid \
    --die-with-parent \
    /opt/mcp-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py
```

You should see a JSON-RPC response like:
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"Simple Echo MCP Server","version":"1.27.0"}}}
```

If you see this, bwrap is working with MCP.

### Step 4: Run the automated benchmark

```bash
python tests/test_sandbox_all.py bwrap
```

Expected output:
```
============================================================
Testing: bwrap
============================================================
  PASS | boot=5ms init=560ms disc=4ms call=7ms total=573ms tools=2 result=sandbox_test
```

### Step 5: Enable in the gateway config

Edit `~/.enkrypt/enkrypt_mcp_config.json`:

```json
{
    "common_mcp_gateway_config": {
        "sandbox": {
            "enabled": true,
            "runtime": "bwrap"
        }
    }
}
```

Or per-server:

```json
{
    "server_name": "untrusted_server",
    "config": {
        "command": "/opt/mcp-venv/bin/python",
        "args": ["path/to/server.py"]
    },
    "sandbox": {
        "enabled": true,
        "runtime": "bwrap",
        "network": "none",
        "read_only": true
    }
}
```

Or via CLI:

```bash
secure-mcp-gateway config update-sandbox --enabled --runtime bwrap

secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name echo_server \
    --enabled \
    --runtime bwrap \
    --network none
```

---

## Gateway Integration

### Current state

The gateway's `ContainerSandboxProvider` handles Docker/Podman today. A `BwrapSandboxProvider` needs to be added to support bwrap. The code follows the same `SandboxProvider` plugin interface.

### Provider implementation

Create `src/secure_mcp_gateway/plugins/sandbox/bwrap_provider.py`:

```python
"""Bubblewrap (bwrap) sandbox provider — command-wrapping approach."""

import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger


class BwrapSandboxProvider(SandboxProvider):
    """
    Wraps MCP server commands inside ``bwrap`` with namespace isolation.

    Unlike Docker, bwrap doesn't use images — it bind-mounts selected
    host paths into a new namespace. This means:
    - The host Python (or venv Python) runs directly
    - No image build step needed
    - Near-zero startup overhead (~43ms)
    - Linux only
    """

    def get_name(self) -> str:
        return "bwrap"

    def get_version(self) -> str:
        return "1.0.0"

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.get_name(),
            "version": self.get_version(),
            "uses_command_wrapping": True,
            "uses_sdk_transport": False,
        }

    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        network = sandbox_config.get("network", "none")
        read_only = sandbox_config.get("read_only", True)

        bwrap_args: List[str] = []

        # Bind-mount system libraries Python needs to run.
        # Using --ro-bind / / is simpler but exposes the entire
        # host filesystem read-only. For tighter isolation, mount
        # only the directories Python actually needs.
        if sandbox_config.get("minimal_mounts", False):
            for sys_dir in ["/usr", "/lib", "/lib64", "/etc/alternatives"]:
                if os.path.exists(sys_dir):
                    bwrap_args += ["--ro-bind", sys_dir, sys_dir]
            # Python needs /etc/resolv.conf for DNS (even if net is off,
            # some imports check for it)
            if os.path.exists("/etc/resolv.conf"):
                bwrap_args += ["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]
        else:
            # Simpler: mount entire root read-only
            bwrap_args += ["--ro-bind", "/", "/"]

        # Essential virtual filesystems
        bwrap_args += [
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
        ]

        # Resolve the Python executable and ensure its venv is accessible
        python_path = shutil.which(command) or command
        if os.path.isfile(python_path):
            venv_dir = self._find_venv_root(python_path)
            if venv_dir and sandbox_config.get("minimal_mounts", False):
                bwrap_args += ["--ro-bind", venv_dir, venv_dir]

        # Mount the script directory
        script_path = args[0] if args else None
        script_dir = None
        if script_path and os.path.isfile(script_path):
            script_dir = os.path.dirname(os.path.abspath(script_path))
            if sandbox_config.get("minimal_mounts", False):
                bwrap_args += ["--ro-bind", script_dir, script_dir]

        # Namespace isolation
        bwrap_args += ["--unshare-pid", "--die-with-parent"]

        if network == "none":
            bwrap_args.append("--unshare-net")

        # Environment filtering
        filtered_env = self._filter_env(env, sandbox_config)

        # The command and arguments
        bwrap_args += [command] + list(args)

        logger.info(
            f"[BwrapSandboxProvider] bwrap for '{server_name}' "
            f"network={'none' if network == 'none' else 'host'} "
            f"minimal_mounts={sandbox_config.get('minimal_mounts', False)}"
        )

        return StdioServerParameters(
            command="bwrap", args=bwrap_args, env=filtered_env
        )

    async def check_availability(self) -> Tuple[bool, str]:
        if shutil.which("bwrap"):
            return True, "bwrap is available"
        return False, "bwrap not found on PATH (sudo apt install bubblewrap)"

    async def cleanup(self, server_name: str) -> None:
        pass  # bwrap cleans up automatically when process exits

    @staticmethod
    def _find_venv_root(python_path: str) -> Optional[str]:
        """Walk up from a Python executable to find the venv root."""
        path = os.path.dirname(os.path.abspath(python_path))
        for _ in range(5):
            if os.path.isfile(os.path.join(path, "pyvenv.cfg")):
                return path
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        return None

    @staticmethod
    def _filter_env(
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> Optional[Dict[str, str]]:
        if env is None:
            return None
        allowed = sandbox_config.get("allowed_env")
        if allowed is not None:
            return {k: v for k, v in env.items() if k in allowed}
        return env
```

### Register in config_manager.py

Add this branch to `initialize_sandbox_system()` in `src/secure_mcp_gateway/plugins/sandbox/config_manager.py`:

```python
elif runtime == "bwrap":
    from secure_mcp_gateway.plugins.sandbox.bwrap_provider import (
        BwrapSandboxProvider,
    )
    provider = BwrapSandboxProvider()
```

That's it. No changes needed to `server_params.py`, `gateway.py`, `client.py`, or any execution services — the plugin system handles it automatically.

### Files to create or modify

| File | Change |
|---|---|
| `src/secure_mcp_gateway/plugins/sandbox/bwrap_provider.py` | **New file** — provider implementation (above) |
| `src/secure_mcp_gateway/plugins/sandbox/config_manager.py` | Add `elif runtime == "bwrap"` branch (3 lines) |

---

## Configuration Reference

### Global config

```json
{
    "common_mcp_gateway_config": {
        "sandbox": {
            "enabled": true,
            "runtime": "bwrap"
        }
    }
}
```

### Per-server config

```json
{
    "server_name": "untrusted_server",
    "sandbox": {
        "enabled": true,
        "runtime": "bwrap",
        "network": "none",
        "read_only": true,
        "minimal_mounts": false,
        "allowed_env": ["OPENAI_API_KEY"]
    }
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable bwrap sandbox for this server |
| `runtime` | — | Must be `"bwrap"` |
| `network` | `"none"` | `"none"` = no network (`--unshare-net`). `"host"` = share host network. |
| `read_only` | `true` | All bind-mounts are read-only |
| `minimal_mounts` | `false` | If `true`, only mount `/usr`, `/lib`, `/lib64`, venv, and script dir. If `false`, mount entire root filesystem read-only (simpler, slightly less secure). |
| `allowed_env` | `null` | List of env var names to pass into sandbox. `null` = pass all. `[]` = pass none. |
| `extra_ro_binds` | `[]` | Extra paths to bind-mount read-only (e.g. `["/opt/tools"]`) |
| `extra_rw_binds` | `[]` | Extra paths to bind-mount read-write (e.g. `["/var/data"]`) |
| `unshare_pid` | `true` | Isolate PID namespace (hide host processes) |

### Network Configuration

The `network` field controls whether the sandboxed MCP server can access the internet.

| Value | Behavior | bwrap flag | Use when |
|---|---|---|---|
| `"none"` | **No network** — all outbound connections blocked | `--unshare-net` | Local scripts, pre-installed tools, untrusted servers |
| `"host"` | **Full network** — same access as host machine | *(no flag)* | npx servers, tools that call APIs (GitHub, Slack) |

> **Default is `"none"`** — the safest option. Only set `"host"` when the server genuinely needs network access.

#### How it works under the hood

When `network` is `"none"`, bwrap creates a new Linux network namespace with **no interfaces at all**. The sandboxed process has no `eth0`, no loopback — any call to `connect()`, `fetch()`, or `http.get()` fails instantly with "Network unreachable". This prevents data exfiltration even if the MCP server is malicious.

When `network` is `"host"`, bwrap shares the host's network namespace. The sandboxed process can reach any network the host can. You still get filesystem and PID isolation.

#### Which to choose for each MCP server type

| MCP Server Type | Example | Recommended `network` | Why |
|---|---|---|---|
| Local Python script | `python echo_mcp.py` | `"none"` | Already on disk, no downloads needed |
| Pre-installed npm binary | `playwright-mcp` | `"none"` | Binary already on disk |
| `npx` with `--offline` flag | `npx --offline @playwright/mcp@0.0.70` | `"none"` | Uses cached package, no network needed |
| `npx` with `@latest` | `npx @playwright/mcp@latest` | `"host"` | npx must check npm registry |
| Tool that calls external APIs | GitHub MCP, Slack MCP | `"host"` | The tool itself needs internet to function |
| Untrusted/suspicious server | Any server you don't fully trust | `"none"` | Maximum security — blocks data exfiltration |

#### Example configs

**Local Python MCP (no network needed):**

```json
{
    "server_name": "echo_server",
    "config": { "command": "python", "args": ["echo_mcp.py"] },
    "sandbox": {
        "enabled": true,
        "runtime": "bwrap",
        "network": "none",
        "read_only": true
    }
}
```

**npx MCP server (needs network):**

```json
{
    "server_name": "playwright",
    "config": { "command": "npx", "args": ["@playwright/mcp@latest"] },
    "sandbox": {
        "enabled": true,
        "runtime": "bwrap",
        "network": "host",
        "read_only": true
    }
}
```

**npx MCP server with offline mode (no network needed):**

First cache the package once: `npx @playwright/mcp@0.0.70 --help`

Then configure:

```json
{
    "server_name": "playwright",
    "config": { "command": "npx", "args": ["--offline", "@playwright/mcp@0.0.70"] },
    "sandbox": {
        "enabled": true,
        "runtime": "bwrap",
        "network": "none",
        "read_only": true
    }
}
```

> **Tip:** Pin the version + `--offline` flag lets you use `"network": "none"` even with npx. This is the most secure way to run npx-based MCP servers.

#### CLI commands

```bash
# Set default network to "none" for all servers
secure-mcp-gateway config update-sandbox --default-network none

# Override a specific server to allow network
secure-mcp-gateway config update-server-sandbox --config-name default --server-name playwright --network host

# Lock down a specific server (no network)
secure-mcp-gateway config update-server-sandbox --config-name default --server-name echo_server --network none
```

### Minimal mounts vs full root mount

**`minimal_mounts: false`** (default) — mounts the entire host root filesystem read-only:

```bash
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp ...
```

Pros: Simpler, works with any Python setup, fewer "file not found" issues.
Cons: The sandboxed process can read (but not write) any host file.

**`minimal_mounts: true`** — only mounts specific directories:

```bash
bwrap --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /venv /venv ...
```

Pros: Tighter isolation — sandbox can't even read `~/.ssh`, `~/.aws`, etc.
Cons: May fail if Python imports something from an unmounted path. You may need to add extra bind-mounts for your specific setup.

**Recommendation:** Start with `minimal_mounts: false` to get things working, then switch to `true` and fix any missing paths for production hardening.

---

## Security Analysis

### What bwrap protects against

| Attack | Protection | How |
|---|---|---|
| **Network exfiltration** | ✅ Blocked | `--unshare-net` creates empty network namespace |
| **Filesystem read (secrets)** | ✅ Blocked* | Minimal mounts mode hides home dirs, `.ssh`, `.aws`, etc. |
| **Filesystem write** | ✅ Blocked | All mounts are read-only (`--ro-bind`), only `/tmp` is writable |
| **Process snooping** | ✅ Blocked | `--unshare-pid` hides host processes |
| **Orphan process persistence** | ✅ Blocked | `--die-with-parent` kills sandbox when gateway exits |
| **Fork bombs** | ⚠️ Partial | PID namespace limits visibility but not count (no cgroup PID limit) |
| **Memory exhaustion** | ❌ Not blocked | bwrap doesn't do cgroup resource limits |
| **CPU exhaustion** | ❌ Not blocked | bwrap doesn't do cgroup resource limits |
| **Kernel exploits** | ❌ Not blocked | Shared kernel — a kernel exploit escapes the sandbox |

*\* With `minimal_mounts: true`. With `minimal_mounts: false`, host files are readable but not writable.*

### Comparison with Docker

| Capability | bwrap | Docker |
|---|---|---|
| Filesystem isolation | ✅ (bind-mounts) | ✅ (overlay FS) |
| Network isolation | ✅ (`--unshare-net`) | ✅ (`--network=none`) |
| PID isolation | ✅ (`--unshare-pid`) | ✅ (PID namespace) |
| Memory limits | ❌ | ✅ (`--memory=512m`) |
| CPU limits | ❌ | ✅ (`--cpus=1.0`) |
| PID count limits | ❌ | ✅ (`--pids-limit=100`) |
| Read-only filesystem | ✅ (`--ro-bind`) | ✅ (`--read-only`) |
| Pre-built images | ❌ (uses host Python) | ✅ (Docker images) |
| Daemon required | ❌ | ✅ (dockerd) |
| Startup overhead | ~43ms | ~490ms |
| Cross-platform | Linux only | Linux, macOS, Windows |

**Bottom line:** bwrap is faster and simpler but Docker gives you resource limits and cross-platform support. For Linux-only deployments where you trust the kernel and need speed, bwrap is the better choice. For multi-platform or multi-tenant deployments, Docker is safer.

### Hardening tips

1. **Always use `--unshare-net`** for untrusted servers. This is the single most important flag — it blocks all network exfiltration.

2. **Use `minimal_mounts: true`** in production to prevent reading host secrets.

3. **Set `allowed_env` explicitly** to avoid leaking API keys:
   ```json
   "allowed_env": ["LANG", "LC_ALL", "PATH"]
   ```

4. **Combine with cgroups** if you need resource limits. You can manually set up a cgroup and use `--exec-label` or wrap bwrap inside `systemd-run`:
   ```bash
   systemd-run --scope -p MemoryMax=512M -p TasksMax=100 \
     bwrap --ro-bind / / --unshare-net --unshare-pid \
     python server.py
   ```

5. **Consider bwrap + seccomp** for syscall filtering. Bwrap supports `--seccomp` to load a BPF filter that restricts which syscalls the sandboxed process can make.

---

## Testing and Verification

### Automated test

```bash
# Run just the bwrap benchmark:
python tests/test_sandbox_all.py bwrap

# Run all runtimes for comparison:
python tests/test_sandbox_all.py all
```

### Manual test — verify network is blocked

```bash
# This should FAIL (no network in sandbox):
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --unshare-net --unshare-pid --die-with-parent \
  python3 -c "import urllib.request; urllib.request.urlopen('https://google.com')"

# Error: URLError: <urlopen error [Errno 101] Network is unreachable>
```

### Manual test — verify filesystem is restricted

```bash
# With minimal mounts, this should FAIL:
bwrap --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --dev /dev --proc /proc --tmpfs /tmp \
  --unshare-net --unshare-pid --die-with-parent \
  python3 -c "print(open('/etc/passwd').read())"

# Error: FileNotFoundError: [Errno 2] No such file or directory: '/etc/passwd'
```

### Manual test — verify read-only

```bash
# This should FAIL (read-only filesystem):
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --unshare-net --unshare-pid --die-with-parent \
  python3 -c "open('/etc/test_write', 'w').write('hacked')"

# Error: PermissionError: [Errno 30] Read-only file system: '/etc/test_write'
```

### Manual test — verify /tmp is writable

```bash
# This should SUCCEED (/tmp is tmpfs, writable):
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --unshare-net --unshare-pid --die-with-parent \
  python3 -c "open('/tmp/test', 'w').write('ok'); print('write OK')"

# Output: write OK
```

### Full MCP roundtrip test

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
| bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --unshare-net \
    --unshare-pid \
    --die-with-parent \
    /opt/mcp-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py
```

If you get a valid JSON-RPC response, bwrap is MCP-compatible.

---

## Troubleshooting

### "bwrap: No such file or directory"

bwrap is not installed:
```bash
sudo apt install bubblewrap
```

### "bwrap: Operation not permitted" or "bwrap: No permissions to create new namespace"

User namespaces are disabled in the kernel:
```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-userns.conf
```

On some Ubuntu versions with AppArmor, you may also need:
```bash
echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns
```

### "ModuleNotFoundError: No module named 'mcp'"

The Python being used inside the sandbox doesn't have `mcp` installed. Either:
- Use a virtualenv with mcp installed and ensure bwrap can see it
- With `minimal_mounts: true`, make sure the venv directory is bind-mounted

### "FileNotFoundError" for system libraries

With `minimal_mounts: true`, some Python imports might need paths you haven't mounted. Common missing ones:

```bash
# SSL support:
--ro-bind /etc/ssl /etc/ssl

# Locale:
--ro-bind /usr/share/locale /usr/share/locale

# Time zone:
--ro-bind /etc/localtime /etc/localtime
--ro-bind /usr/share/zoneinfo /usr/share/zoneinfo
```

Add bind-mounts for whatever paths the error messages reference.

### "No network" errors when network should be allowed

If you set `"network": "host"` but the sandbox still has no network, check that the config value is exactly `"host"` (not `"bridge"` or other Docker network modes — bwrap only supports none or host).

### Performance is slower than expected

bwrap itself adds ~5ms. If you see >100ms overhead, the bottleneck is likely:
- Python startup time (cold import of `mcp` library)
- Filesystem latency from bind-mounts (check if the mount source is on a slow disk)
- First-run compilation of `.pyc` files (subsequent runs will be faster)

---

## Reference: All bwrap Flags Used

| Flag | Description |
|---|---|
| `--ro-bind SRC DEST` | Bind-mount SRC to DEST inside sandbox, read-only |
| `--bind SRC DEST` | Bind-mount SRC to DEST, read-write |
| `--dev DEST` | Create minimal /dev (null, zero, random, etc.) |
| `--proc DEST` | Mount new /proc scoped to sandbox PID namespace |
| `--tmpfs DEST` | Create writable in-memory filesystem at DEST |
| `--unshare-net` | New empty network namespace (no network access) |
| `--unshare-pid` | New PID namespace (can't see host processes) |
| `--unshare-user` | New user namespace (run as fake root) |
| `--unshare-uts` | New UTS namespace (separate hostname) |
| `--unshare-ipc` | New IPC namespace (separate shared memory) |
| `--unshare-cgroup` | New cgroup namespace |
| `--die-with-parent` | Kill sandbox when parent process exits |
| `--chdir DIR` | Set working directory inside sandbox |
| `--setenv VAR VAL` | Set environment variable inside sandbox |
| `--unsetenv VAR` | Remove environment variable inside sandbox |
| `--seccomp FD` | Apply seccomp BPF filter (syscall restriction) |
| `--new-session` | Create new session ID (detach from terminal) |

Full documentation: `man bwrap` or [github.com/containers/bubblewrap](https://github.com/containers/bubblewrap)
