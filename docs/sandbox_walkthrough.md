# Sandbox Isolation Walkthrough

This guide walks you through enabling and testing sandbox isolation for MCP server execution in the Secure MCP Gateway. Sandboxing reduces the blast radius when executing untrusted MCP servers or tools by running them inside isolated environments.

## TL;DR — Which Sandbox Should You Pick?

We tested 7 sandbox runtimes for MCP stdio compatibility. Here's how they compare:

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
† = estimated, not benchmarked in our environment
* = strongest without requiring a full VM
```

### The short answer

| Your situation | Pick this | Why |
|---|---|---|
| **Production on Linux (k8s)** | **Docker** (or **Docker + gVisor** for max security) | Works today, battle-tested, full resource limits. Adding `--runtime=runsc` gives user-space kernel isolation on top. |
| **Need fastest possible** | **Bubblewrap** | Only 43ms overhead. Great for high-throughput, Linux-only deployments. |
| **Need macOS support** | **Docker** or **Anthropic srt** | Docker Desktop works on macOS. srt uses native macOS sandbox-exec (no Docker needed). |
| **Maximum self-hosted security** | **Docker + gVisor** or **Kata Containers** | gVisor intercepts all syscalls (host kernel never exposed). Kata gives a full VM per sandbox. |
| **Managed cloud, don't want to self-host** | **E2B** | Firecracker VMs, ~200ms starts, but requires API key + internet. Not yet implemented. |

### What we recommend

**For our use case (Linux/k8s, self-hosted):**

> **Docker is the primary runtime** — it's production-ready today, works on all platforms, and has full resource controls (memory, CPU, PIDs, network).
>
> For higher-security workloads, **add gVisor as the Docker runtime** (`--runtime=runsc`). This gives Docker's convenience with gVisor's syscall-level protection — the host kernel is never directly exposed to sandboxed code.
>
> **Bubblewrap** is the best choice if you need minimal overhead and are on Linux, but it lacks built-in memory/CPU limits.

All runtimes use the same plugin interface, so switching is a single config change — no code changes needed.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Configuration Reference](#configuration-reference)
- [Building a Sandbox-Ready Docker Image](#building-a-sandbox-ready-docker-image)
- [Testing Sandbox Isolation](#testing-sandbox-isolation)
- [Verifying Sandbox Is Active](#verifying-sandbox-is-active)
- [Supported Runtimes](#supported-runtimes)
  - [Docker / Podman (Recommended)](#docker--podman-recommended)
  - [Bubblewrap (bwrap)](#bubblewrap-bwrap)
  - [gVisor (runsc)](#gvisor-runsc)
  - [Anthropic srt](#anthropic-srt)
  - [Kata Containers](#kata-containers)
  - [Microsandbox](#microsandbox)
  - [NovaVM](#novavm)
- [Runtime Comparison](#runtime-comparison)
- [Reproduce the Benchmarks Yourself](#reproduce-the-benchmarks-yourself)
- [E2B Cloud Sandbox](#e2b-cloud-sandbox)
  - [What Is E2B](#what-is-e2b)
  - [E2B vs Self-Hosted Sandboxes](#e2b-vs-self-hosted-sandboxes)
  - [Code Changes Required for E2B](#code-changes-required-for-e2b)
- [API Endpoints](#api-endpoints)
- [CLI Commands](#cli-commands)
- [Troubleshooting](#troubleshooting)

---

## Overview

By default, the gateway spawns MCP servers as direct subprocesses with full host access. When sandbox is enabled, every MCP server launch is transparently wrapped in an isolated environment:

```
               Without Sandbox                          With Sandbox
               ───────────────                          ────────────
Gateway ──> subprocess(python server.py)       Gateway ──> docker run --rm -i
            Full host access                               --network=none
            - filesystem                                   --memory=512m
            - network                                      --cpus=1.0
            - env vars                                     --read-only
            - unlimited resources                          python server.py
                                                          Isolated environment
```

The sandbox is **ephemeral** — a new sandbox is created for each MCP session and destroyed when the session ends. Nothing persists between calls. If a malicious tool tries to steal credentials, access the filesystem, or phone home to an attacker, it can only affect the disposable sandbox container.

## How It Works

When you call a tool through the gateway, here's what happens behind the scenes:

1. **Gateway receives tool call** from your MCP client (Cursor, Claude Desktop, etc.)
2. **Gateway checks sandbox config** for the target server
3. **If sandbox is enabled**, the gateway wraps the server command. For example, instead of running `python echo_mcp.py` directly, it runs:
   ```
   docker run --rm -i --network=none --memory=512m --read-only \
     -v /path/to/scripts:/app:ro sandbox-test-mcp python echo_mcp.py
   ```
4. **MCP communication happens normally** over stdin/stdout pipes — the MCP client doesn't know the server is sandboxed
5. **When the call completes**, the container is destroyed automatically

You can verify this by watching Docker events:
```bash
docker events --filter "image=sandbox-test-mcp"
```
Each tool call creates containers with lifecycle: `create → start → die → destroy`.

## Prerequisites

- **Python 3.8+** with Secure MCP Gateway installed
- **One of these sandbox runtimes** installed (Docker is the easiest to start with):

| Runtime | Install Command | Platform |
|---|---|---|
| Docker | [docker.com](https://docker.com) | Linux, macOS, Windows |
| Podman | `brew install podman` or `apt install podman` | Linux, macOS |
| Bubblewrap | `sudo apt install bubblewrap` | Linux only |
| gVisor | See [gVisor install guide](#gvisor-runsc) | Linux only |
| Anthropic srt | `npm install -g @anthropic-ai/sandbox-runtime` | Linux, macOS |

## Quick Start (Docker)

This gets you from zero to a sandboxed MCP server in 5 minutes.

### Step 1: Build a Docker image with MCP dependencies

Your MCP servers need their Python packages inside the container. Create a simple image:

```bash
docker build -t sandbox-test-mcp -f tests/Dockerfile.sandbox-test .
```

The Dockerfile is minimal:
```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir "mcp[cli]>=1.10.1" "opentelemetry-sdk>=1.34.1" "opentelemetry-api>=1.34.1"
WORKDIR /app
```

### Step 2: Enable sandbox in the gateway config

**Option A: Via CLI**
```bash
# Enable globally
secure-mcp-gateway config update-sandbox --enabled --runtime docker

# Enable for a specific server
secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name echo_server \
    --enabled \
    --image sandbox-test-mcp \
    --network none \
    --memory-limit 512m
```

**Option B: Edit config directly**

Add to your server entry in `~/.enkrypt/enkrypt_mcp_config.json`:
```json
{
    "server_name": "echo_server",
    "config": {
        "command": "python",
        "args": ["path/to/echo_mcp.py"]
    },
    "sandbox": {
        "enabled": true,
        "runtime": "docker",
        "image": "sandbox-test-mcp",
        "memory_limit": "512m",
        "cpu_limit": "1.0",
        "network": "none",
        "read_only": true
    }
}
```

### Step 3: Start the gateway

```bash
python -m secure_mcp_gateway.gateway
```

Look for these lines in the logs:
```
[SandboxConfigManager] Initializing sandbox runtime: docker
[SandboxConfigManager] Registered provider: container:docker v1.0.0
Registered sandbox providers: ['container:docker']
```

### Step 4: Use normally

Call tools as usual from your MCP client. The sandbox is transparent — your client doesn't know the difference. In the gateway logs you'll see:
```
[ContainerSandboxProvider] docker run for 'echo_server' image=sandbox-test-mcp network=none memory=512m
[build_server_params] SANDBOXED via container:docker: docker run --rm -i --network=none...
```

## Configuration Reference

### Global Sandbox Settings

Added to `common_mcp_gateway_config` in `enkrypt_mcp_config.json`:

```json
{
    "common_mcp_gateway_config": {
        "sandbox": {
            "enabled": false,
            "runtime": "docker",
            "default_image": "python:3.11-slim",
            "default_memory_limit": "512m",
            "default_cpu_limit": "1.0",
            "default_pids_limit": 100,
            "default_network": "none",
            "default_read_only": true,
            "container_cli": "auto"
        }
    }
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch for sandbox isolation |
| `runtime` | `"docker"` | `docker`, `podman`, `bwrap`, `gvisor`, `srt` |
| `default_image` | `"python:3.11-slim"` | Default container image (Docker/Podman only) |
| `default_memory_limit` | `"512m"` | Memory cap per sandbox |
| `default_cpu_limit` | `"1.0"` | CPU cap per sandbox |
| `default_pids_limit` | `100` | Max processes per sandbox |
| `default_network` | `"none"` | Network mode (`none` = no network) |
| `default_read_only` | `true` | Read-only root filesystem |
| `container_cli` | `"auto"` | `docker`, `podman`, or `auto` (detect) |

### Per-Server Sandbox Override

Each server entry can override global defaults:

```json
{
    "server_name": "untrusted_server",
    "config": {
        "command": "python",
        "args": ["path/to/server.py"]
    },
    "sandbox": {
        "enabled": true,
        "runtime": "docker",
        "image": "my-custom-mcp-image:latest",
        "memory_limit": "256m",
        "cpu_limit": "0.5",
        "network": "none",
        "read_only": true,
        "allowed_env": ["OPENAI_API_KEY"]
    }
}
```

| Field | Description |
|---|---|
| `enabled` | Override global enabled/disabled |
| `runtime` | Override global runtime |
| `image` | Container image for this server (Docker/Podman only) |
| `memory_limit` | Memory limit for this server |
| `cpu_limit` | CPU limit for this server |
| `network` | `"none"` = block all networking, `"host"` = full network access |
| `read_only` | Read-only filesystem |
| `allowed_env` | Allowlist of env var names passed into the sandbox (null = pass all) |

Per-server values take precedence over global defaults.

### Network configuration

The `network` field controls whether the sandboxed MCP server can reach the internet:

| Value | Behavior | Use when |
|---|---|---|
| `"none"` (default) | All outbound network blocked | Local scripts, pre-installed tools, untrusted servers |
| `"host"` | Full network access, same as host | npx-based servers, tools that call APIs (GitHub, Slack) |
| `"bridge"` | Docker bridge network (Docker only) | When you need isolated but functional networking |

**For npx-based MCP servers**, you have two choices:

1. **Allow network:** Set `"network": "host"` — simplest, works always.
2. **Block network + use offline mode:** Pin the version and add `--offline`:
   ```json
   {
       "config": { "command": "npx", "args": ["--offline", "@playwright/mcp@0.0.70"] },
       "sandbox": { "enabled": true, "network": "none" }
   }
   ```
   This requires caching the package once first: `npx @playwright/mcp@0.0.70 --help`

## Building a Sandbox-Ready Docker Image

The container running your MCP server needs all Python dependencies pre-installed. The gateway mounts the script directory read-only at `/app` inside the container.

### Base image for most MCP servers

```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir \
    "mcp[cli]>=1.10.1" \
    "opentelemetry-sdk>=1.34.1" \
    "opentelemetry-api>=1.34.1"
WORKDIR /app
```

### Custom image with extra dependencies

```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir \
    "mcp[cli]>=1.10.1" \
    "opentelemetry-sdk>=1.34.1" \
    requests \
    github-mcp-server
WORKDIR /app
```

Build and tag:
```bash
docker build -t my-mcp-sandbox -f Dockerfile.mcp .
```

Then reference in config:
```json
"sandbox": { "enabled": true, "image": "my-mcp-sandbox" }
```

## Testing Sandbox Isolation

### Quick test with the echo server

```bash
# Run the automated test comparing baseline vs Docker:
python tests/test_sandbox_quick.py baseline
python tests/test_sandbox_quick.py docker
```

Expected output:
```
BASELINE | boot=5ms init=866ms disc=10ms call=26ms total=1089ms tools=2 result=test
DOCKER   | boot=7ms init=1728ms disc=11ms call=27ms total=2067ms tools=2 result=test
```

### Test all runtimes (Linux/WSL)

```bash
python tests/test_sandbox_all.py
```

This tests baseline, Docker, bwrap, gVisor, and Anthropic srt, reporting timing and pass/fail for each.

### Test with malicious MCP servers

Add the attack-scenario servers from `bad_mcps/` to your config with sandbox enabled. These demonstrate that even if a server *tries* to be malicious, the sandbox contains the damage:

| Test Server | Attack Type | What Sandbox Prevents |
|---|---|---|
| `command_injection_mcp.py` | OS command injection | Commands run inside container, no host access |
| `path_traversal_mcp.py` | Read files outside allowed dir | Container filesystem is isolated from host |
| `credential_theft_mcp.py` | Steal env vars / API keys | Only allowlisted env vars are passed to container |
| `ssrf_mcp.py` | Server-side request forgery | `--network=none` blocks all outbound connections |
| `resource_exhaustion_mcp.py` | Fork bombs, memory bombs | `--memory=512m`, `--pids-limit=100` caps resource usage |
| `rce_mcp.py` | Remote code execution | Code executes in disposable container, destroyed after call |

## Verifying Sandbox Is Active

Beyond reading gateway logs, here are concrete ways to verify the sandbox is working:

### Method 1: Watch Docker events (real-time)

Open a terminal and run:
```bash
docker events --filter "image=sandbox-test-mcp"
```

Then call a tool through the gateway. You'll see:
```
2026-04-13T10:16:42 container create wizardly_shtern
2026-04-13T10:16:42 container start wizardly_shtern
2026-04-13T10:16:44 container die wizardly_shtern
2026-04-13T10:16:44 container destroy wizardly_shtern
```

Each tool call creates a **new container with a unique name** that is created and destroyed within seconds.

### Method 2: Watch running containers

```bash
# Run this in a loop while making a tool call:
watch -n 0.5 'docker ps --filter ancestor=sandbox-test-mcp --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"'
```

You'll briefly see the container appear and disappear.

### Method 3: Inspect container security settings

Temporarily remove `--rm` from the provider to keep a container around, then inspect it:
```bash
docker inspect <container_id> --format '
  NetworkMode: {{.HostConfig.NetworkMode}}
  ReadonlyRootfs: {{.HostConfig.ReadonlyRootfs}}
  Memory: {{.HostConfig.Memory}}
  PidsLimit: {{.HostConfig.PidsLimit}}'
```

This shows: `NetworkMode: none`, `ReadonlyRootfs: true`, `Memory: 536870912` (512MB), confirming all security constraints are applied.

### Method 4: Check gateway logs

The gateway logs explicit sandbox messages at INFO level:
```
[ContainerSandboxProvider] docker run for 'echo_server' image=sandbox-test-mcp network=none memory=512m
[build_server_params] SANDBOXED via container:docker: docker run --rm -i --network=none...
```

If sandbox is NOT active, you'll see:
```
[build_server_params] server=echo_server sandbox_enabled=False
```

---

## Supported Runtimes

### Docker / Podman (Recommended)

**What it is:** Docker and Podman are container runtimes that use Linux namespaces and cgroups to isolate processes. Docker is the most widely used; Podman is a rootless, daemonless alternative.

**Isolation level:** Process-level (shared kernel with the host, but separate filesystem, network, PIDs, and resource limits).

**Platform:** Linux, macOS, Windows (via Docker Desktop)

**Why choose this:** Works everywhere, well-understood, production-grade tooling. The easiest option to set up and the most portable.

**Setup:**
```bash
# Install Docker (if not already installed)
# macOS: brew install --cask docker
# Linux: curl -fsSL https://get.docker.com | sh
# Windows: Install Docker Desktop from docker.com

# Verify
docker --version
docker ps

# Build the sandbox image
docker build -t sandbox-test-mcp -f tests/Dockerfile.sandbox-test .
```

**Config:**
```json
"sandbox": {
    "enabled": true,
    "runtime": "docker",
    "image": "sandbox-test-mcp",
    "memory_limit": "512m",
    "network": "none",
    "read_only": true
}
```

**To use Podman instead of Docker:**
```json
"sandbox": {
    "enabled": true,
    "runtime": "podman",
    "image": "sandbox-test-mcp"
}
```
Or set `"container_cli": "podman"` in global config. Podman uses the same command-line interface as Docker, so no code changes are needed.

**Performance:** ~1 second overhead per call (container start + Python boot inside container).

---

### Bubblewrap (bwrap)

**What it is:** A lightweight sandbox tool that uses Linux kernel namespaces to isolate a process. No daemon, no container images, no Docker needed. Just a single binary that wraps your command.

**Isolation level:** Namespace-level (separate mount, PID, network, and user namespaces). Same kernel as host but restricted view of the system.

**Platform:** Linux only

**Why choose this:** Fastest sandbox option with near-zero overhead (~43ms). No daemon or images to manage. Used internally by Flatpak for app sandboxing.

**Setup:**
```bash
# Install on Ubuntu/Debian
sudo apt install bubblewrap

# Install on Fedora
sudo dnf install bubblewrap

# Verify
bwrap --version
```

**How it works with the gateway:**

Bubblewrap wraps the MCP server command. Instead of:
```bash
python /path/to/echo_mcp.py
```
The gateway runs:
```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc/alternatives /etc/alternatives \
  --ro-bind /path/to/scripts /app \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --unshare-net \
  --unshare-pid \
  --die-with-parent \
  --chdir /app \
  python echo_mcp.py
```

This gives the process:
- **Read-only access** to system libraries (needed for Python to run)
- **Read-only access** to the script directory (mounted at `/app`)
- **No network** (`--unshare-net`)
- **Separate PID namespace** (`--unshare-pid`)
- **Writable `/tmp`** for temporary files
- **Killed when parent dies** (`--die-with-parent`)

**Config:**
```json
"sandbox": {
    "enabled": true,
    "runtime": "bwrap",
    "network": "none",
    "read_only": true
}
```

**What to implement (code changes needed):**

A `BwrapSandboxProvider` needs to be added to `src/secure_mcp_gateway/plugins/sandbox/`. It follows the same `SandboxProvider` interface as Docker:

```python
class BwrapSandboxProvider(SandboxProvider):
    """Bubblewrap sandbox — command-wrapping approach."""

    def get_name(self) -> str:
        return "bwrap"

    async def wrap_server_params(self, server_name, command, args, env, sandbox_config):
        script_path = args[0] if args else None
        script_dir = os.path.dirname(os.path.abspath(script_path))

        bwrap_args = [
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc/alternatives", "/etc/alternatives",
            "--ro-bind", script_dir, "/app",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--unshare-pid",
            "--die-with-parent",
            "--chdir", "/app",
        ]
        if sandbox_config.get("network") == "none":
            bwrap_args.append("--unshare-net")

        # Bind the Python venv or system Python
        python_path = shutil.which(command) or command
        python_dir = os.path.dirname(python_path)
        bwrap_args += ["--ro-bind", python_dir, python_dir]

        bwrap_args += [command, os.path.basename(script_path)] + list(args[1:])

        return StdioServerParameters(command="bwrap", args=bwrap_args, env=env)
```

**Performance:** ~573ms total (only ~43ms overhead vs baseline). Fastest of all sandbox options.

---

### gVisor (runsc)

**What it is:** A user-space kernel developed by Google. It intercepts all system calls from the sandboxed process and re-implements them in a secure Go runtime. The sandboxed process never talks directly to the host kernel.

**Isolation level:** User-space kernel (syscall interception). Stronger than Docker's namespace isolation because the host kernel is never exposed to the sandboxed process's syscalls.

**Platform:** Linux only (requires root or appropriate capabilities)

**Why choose this:** Strongest isolation you can get without a full VM. Used by Google Cloud Run and GKE Sandbox. Catches kernel exploits that would escape Docker namespaces.

**Setup:**
```bash
# Add the gVisor repository
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null

# Install
sudo apt update && sudo apt install -y runsc

# Verify
runsc --version
```

**Two ways to use gVisor:**

**Option A: Standalone with `runsc do` (no Docker needed)**
```bash
runsc do -- python /path/to/echo_mcp.py
```
This runs the command inside a gVisor sandbox directly. Simple, no images needed.

**Option B: As a Docker runtime**
```bash
# Register gVisor as a Docker runtime
sudo runsc install
sudo systemctl restart docker

# Use it with Docker
docker run --runtime=runsc --rm -i sandbox-test-mcp python echo_mcp.py
```
This gives you Docker's convenience (images, resource limits, network modes) plus gVisor's stronger syscall isolation.

**Config (standalone):**
```json
"sandbox": {
    "enabled": true,
    "runtime": "gvisor",
    "network": "none"
}
```

**Config (as Docker runtime):**
```json
"sandbox": {
    "enabled": true,
    "runtime": "docker",
    "image": "sandbox-test-mcp",
    "docker_runtime": "runsc"
}
```

**What to implement (code changes needed):**

For standalone `runsc do`, a `GVisorSandboxProvider`:

```python
class GVisorSandboxProvider(SandboxProvider):
    """gVisor sandbox using runsc do."""

    def get_name(self) -> str:
        return "gvisor"

    async def wrap_server_params(self, server_name, command, args, env, sandbox_config):
        runsc_args = ["do"]
        if sandbox_config.get("network") == "none":
            runsc_args.append("--network=none")
        runsc_args += ["--", command] + list(args)

        return StdioServerParameters(command="runsc", args=runsc_args, env=env)
```

For Docker + gVisor, add `--runtime=runsc` to the existing `ContainerSandboxProvider` when `docker_runtime` is set in config.

**Performance:** ~1474ms total (~950ms overhead). Slower than plain Docker due to syscall interception, but significantly more secure.

---

### Anthropic srt

**What it is:** A lightweight sandboxing tool built by Anthropic (the company behind Claude). It uses `bubblewrap` on Linux and `sandbox-exec` on macOS, and adds a network proxy that can allowlist specific domains.

**Isolation level:** Namespace isolation (like bwrap) plus network domain filtering via a local proxy.

**Platform:** Linux and macOS

**Why choose this:** The only cross-platform lightweight sandbox (works on both Linux and macOS without Docker). Built specifically for AI agent use cases. Supports network allowlisting — block all network except specific domains.

**Setup:**
```bash
# Requires Node.js / npm
npm install -g @anthropic-ai/sandbox-runtime

# On Linux, also needs bubblewrap and ripgrep:
sudo apt install bubblewrap ripgrep

# Verify
srt --version
```

**How it works:**
```bash
srt run -- python /path/to/echo_mcp.py
```

With network allowlisting:
```bash
srt run --allow-net "api.example.com,*.github.com" -- python /path/to/echo_mcp.py
```

**Config:**
```json
"sandbox": {
    "enabled": true,
    "runtime": "srt",
    "network": "none",
    "allowed_domains": ["api.enkryptai.com"]
}
```

**What to implement (code changes needed):**

```python
class SrtSandboxProvider(SandboxProvider):
    """Anthropic srt sandbox provider."""

    def get_name(self) -> str:
        return "srt"

    async def wrap_server_params(self, server_name, command, args, env, sandbox_config):
        srt_args = ["run"]

        allowed_domains = sandbox_config.get("allowed_domains")
        if allowed_domains:
            srt_args += ["--allow-net", ",".join(allowed_domains)]

        srt_args += ["--", command] + list(args)

        return StdioServerParameters(command="srt", args=srt_args, env=env)
```

**Performance:** ~1688ms total (~1158ms overhead). Slowest of the lightweight options due to the network proxy setup, but the only one supporting macOS without Docker.

---

### Kata Containers

**What it is:** An OCI-compatible container runtime that runs each container inside a lightweight virtual machine (Firecracker or Cloud Hypervisor). Each container gets its own Linux kernel.

**Isolation level:** Hardware-level (dedicated kernel per container via KVM). The strongest self-hosted isolation available.

**Platform:** Linux only (requires KVM/hardware virtualization)

**Why choose this:** When you need VM-level isolation but want to use standard Docker/Podman tooling. Each sandbox gets its own kernel — kernel exploits in one sandbox cannot affect others or the host.

**Setup:**
```bash
# Follow official guide: https://katacontainers.io/docs/install/
# Requires KVM support

# After installation, register as Docker runtime:
sudo kata-runtime install
sudo systemctl restart docker

# Verify
kata-runtime --version
docker run --runtime=kata-runtime hello-world
```

**Config:**
```json
"sandbox": {
    "enabled": true,
    "runtime": "docker",
    "image": "sandbox-test-mcp",
    "docker_runtime": "kata-runtime"
}
```

No new provider code needed — Kata works as a Docker runtime, so the existing `ContainerSandboxProvider` handles it when you set `docker_runtime: "kata-runtime"`.

**Performance:** Not benchmarked yet (complex setup). Expected ~200-500ms overhead for VM start.

---

### Microsandbox

**What it is:** A microVM-based sandbox using `libkrun` (part of the `crun` ecosystem). Provides lightweight VMs on Linux and macOS Apple Silicon.

**Isolation level:** Hardware-level (microVM with dedicated kernel).

**Platform:** Linux, macOS (Apple Silicon)

**Status:** The Python SDK is on PyPI (`microsandbox` v0.1.8) but requires a running `microsandbox` server. The provider code is implemented in the gateway but has not been tested end-to-end because the server component is in beta.

**Future:** When the microsandbox server stabilizes, it will be a strong option for macOS users who want VM-level isolation without Docker Desktop.

---

### NovaVM

**What it is:** A KVM-based hypervisor stack with eBPF observability and OPA policy enforcement.

**Isolation level:** Hardware-level (dedicated kernel via KVM).

**Platform:** Linux only

**Status: Not Compatible.** NovaVM's CLI (`nova shell`) attaches to an interactive console (PTY) instead of providing clean stdin/stdout pipes. The MCP SDK requires piped stdin/stdout for JSON-RPC communication. The console adds escape codes and character echo that corrupt the structured data.

```
What MCP needs:
  Gateway ──stdin pipe──> python server.py ──stdout pipe──> Gateway

What nova shell provides:
  Gateway ──stdin──> nova shell ──PTY/console──> VM ──> python server.py
  (escape codes and echo corrupt JSON-RPC data)
```

**What would fix it:**
- A `nova exec --stdio` mode for clean piped I/O
- A NovaVM SDK providing programmatic process I/O handles
- A gRPC streaming bridge for stdin/stdout

The gateway's NovaVM provider code is implemented and ready — it just needs NovaVM to support raw piped I/O.

---

## Runtime Comparison

Benchmarked on WSL2 Ubuntu 24.04 with the echo MCP server (full MCP roundtrip: initialize + list_tools + call_tool):

| Runtime | Total Time | Overhead | Isolation Level | Platform | Needs Docker? |
|---|---|---|---|---|---|
| **Baseline (no sandbox)** | 530ms | — | None | Any | No |
| **Bubblewrap (bwrap)** | 573ms | +43ms (8%) | Namespace | Linux | No |
| **Docker** | 1020ms | +490ms (92%) | Namespace + cgroup | Linux, macOS, Windows | Yes |
| **gVisor (runsc do)** | 1474ms | +944ms (178%) | User-space kernel | Linux | No |
| **Anthropic srt** | 1688ms | +1158ms (218%) | Namespace + net proxy | Linux, macOS | No |
| **Kata Containers** | ~1500ms* | ~1000ms* | Hardware VM (KVM) | Linux | Docker runtime |
| **NovaVM** | — | — | Hardware VM (KVM) | Linux | N/A (incompatible) |
| **Microsandbox** | — | — | Hardware VM (libkrun) | Linux, macOS | N/A (beta) |

*\* Kata estimated, not yet benchmarked in our environment.*

**Recommendations:**

| Scenario | Best Runtime |
|---|---|
| Fastest possible | **Bubblewrap** — near-zero overhead, Linux only |
| Cross-platform (easiest setup) | **Docker** — works everywhere |
| Strongest self-hosted isolation | **gVisor** — user-space kernel catches syscall attacks |
| macOS without Docker | **Anthropic srt** — uses macOS sandbox-exec |
| Strongest possible isolation | **Kata Containers** — full VM per sandbox (KVM) |

---

## Reproduce the Benchmarks Yourself

Don't take our word for it. Here's how to reproduce every number in the comparison table yourself.

### What the test does

The test script (`tests/test_sandbox_all.py`) performs a **complete MCP roundtrip** for each sandbox runtime:

1. Launches `echo_mcp.py` inside the sandbox
2. Sends `initialize` request via stdin
3. Sends `tools/list` request
4. Sends `tools/call` (echo "sandbox_test")
5. Reads JSON-RPC responses from stdout
6. Measures timing for each step

This is the same code path the gateway uses in production — not a synthetic benchmark.

### Quick start (2 commands)

If you already have Docker installed:

```bash
# Build the sandbox image
docker build -t sandbox-test-mcp -f tests/Dockerfile.sandbox-test .

# Run all tests
python tests/test_sandbox_all.py all
```

Output:
```
============================================================
Testing: baseline
============================================================
  PASS | boot=5ms init=517ms disc=4ms call=7ms total=530ms tools=2 result=sandbox_test

============================================================
Testing: docker
============================================================
  PASS | boot=7ms init=1002ms disc=6ms call=10ms total=1020ms tools=2 result=sandbox_test

...

============================================================
SUMMARY
============================================================
Runtime      Status   Boot     Init     Disc     Call     Total    Tools
--------------------------------------------------------------------------
baseline     PASS     5        517      4        7        530      2
bwrap        PASS     5        560      4        7        573      2
docker       PASS     7        1002     6        10       1020     2
gvisor       PASS     8        1455     7        10       1474     2
srt          PASS     6        1584     5        9        1688     2
```

### Full setup (test every runtime)

This guide uses **Linux or WSL2**. Each step is independent — skip any runtime you don't want to test.

#### Step 1: Set up a Python virtualenv (needed for bwrap/gvisor/srt tests)

```bash
# Create a venv with mcp installed (bwrap/gvisor/srt use host Python)
python3 -m venv /tmp/sandbox-venv
/tmp/sandbox-venv/bin/pip install "mcp[cli]>=1.10.1" "opentelemetry-sdk>=1.34.1" "opentelemetry-api>=1.34.1"
```

The test script auto-detects this venv at `/tmp/sandbox-venv/bin/python`.

#### Step 2: Install the runtimes you want to test

**Docker** (if not already installed):
```bash
# On Linux:
curl -fsSL https://get.docker.com | sh
# On WSL2: Install Docker Desktop on Windows, enable WSL integration

# Build the sandbox image:
docker build -t sandbox-test-mcp -f tests/Dockerfile.sandbox-test .
```

**Bubblewrap:**
```bash
sudo apt install bubblewrap
bwrap --version
```

**gVisor:**
```bash
# Add gVisor repo
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt update && sudo apt install -y runsc
runsc --version
```

**Anthropic srt:**
```bash
# Requires Node.js
npm install -g @anthropic-ai/sandbox-runtime
sudo apt install bubblewrap ripgrep   # dependencies on Linux
srt --version
```

#### Step 3: Run the tests

```bash
# Test a specific runtime:
python tests/test_sandbox_all.py baseline
python tests/test_sandbox_all.py docker
python tests/test_sandbox_all.py bwrap
python tests/test_sandbox_all.py gvisor
python tests/test_sandbox_all.py srt

# Test all at once:
python tests/test_sandbox_all.py all
```

Results are saved to `tests/sandbox_all_results.json`.

#### Step 4: Test individual runtimes manually (optional)

If you want to see exactly what each runtime does under the hood, you can run the MCP server manually through each sandbox:

**Baseline (no sandbox):**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | /tmp/sandbox-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py
```

**Docker:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | docker run --rm -i --network=none --memory=512m --read-only --tmpfs=/tmp:size=64m -v $(pwd)/src/secure_mcp_gateway/bad_mcps:/app:ro sandbox-test-mcp python /app/echo_mcp.py
```

**Bubblewrap:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --unshare-net --unshare-pid --die-with-parent /tmp/sandbox-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py
```

**gVisor:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | sudo runsc --rootless --network=none do /tmp/sandbox-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py
```

**Anthropic srt:**
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | srt "/tmp/sandbox-venv/bin/python src/secure_mcp_gateway/bad_mcps/echo_mcp.py"
```

All of these should return a JSON-RPC response with `"result"` containing server info. If it works, the runtime is MCP-compatible.

### Verify through the gateway (end-to-end)

To test sandbox through the actual running gateway (not just the test script):

**1. Start the gateway with sandbox enabled:**
```bash
python -m secure_mcp_gateway.gateway
```

**2. In another terminal, watch Docker events:**
```bash
docker events --filter "image=sandbox-test-mcp"
```

**3. Call a tool via the gateway's MCP interface (from Cursor, Claude Desktop, or HTTP).**

You'll see containers being created and destroyed in the Docker events terminal:
```
2026-04-13T10:16:42 container create wizardly_shtern
2026-04-13T10:16:42 container start wizardly_shtern
2026-04-13T10:16:44 container die wizardly_shtern
2026-04-13T10:16:44 container destroy wizardly_shtern
```

Each tool call creates a unique, ephemeral container that's destroyed after use.

---

## E2B Cloud Sandbox

### What Is E2B

[E2B](https://e2b.dev/) (by FoundryLabs, Inc.) is a **managed cloud sandbox service** built on Firecracker microVMs — the same technology powering AWS Lambda. Each sandbox runs in its own VM with a dedicated Linux kernel.

| Aspect | Details |
|---|---|
| **Isolation** | Firecracker microVM — dedicated Linux kernel per sandbox (hardware-level via KVM) |
| **Startup** | ~150-200ms cold start (VM snapshotting), near-instant warm resume |
| **Session length** | Up to 1 hour (Hobby) or 24 hours (Pro) |
| **Communication** | REST API for lifecycle, WebSocket for real-time operations |
| **Templates** | Built from Docker images, converted to microVM snapshots |
| **Persistence** | Pause/resume with full memory + filesystem state |
| **SDKs** | Python (`e2b`), JavaScript (`e2b`) |
| **Pricing** | Free tier, then $0.000014/s per vCPU + RAM + $150/mo Pro |

### E2B vs Self-Hosted Sandboxes

| Feature | Docker/Podman | Bubblewrap/gVisor | E2B |
|---|---|---|---|
| **Isolation** | Shared kernel | Shared kernel / user-space kernel | Dedicated kernel (VM) |
| **Self-hosted** | Yes | Yes | No (cloud) |
| **Cost** | Free | Free | Pay-per-use |
| **Startup** | ~1 second | ~50ms | ~150-200ms |
| **Internet required** | No | No | Yes |
| **Offline / air-gapped** | Yes | Yes | No |
| **MCP compatible** | Yes (today) | Yes (today) | Needs custom transport |
| **Managed infra** | No | No | Yes |
| **Pause / resume** | No | No | Yes |

**When E2B makes sense:**
- You need hardware-level (kernel) isolation and don't want to manage Kata/Firecracker yourself
- You're running in a cloud environment with internet access
- You want managed infrastructure with auto-scaling
- You need pause/resume for long-running agent sessions

**When self-hosted is better:**
- You need fully offline / air-gapped operation
- You want zero recurring costs
- You need to comply with data residency requirements
- Your threat model doesn't require kernel-level isolation

### Code Changes Required for E2B

Adding E2B as a sandbox provider requires creating a new provider that uses E2B's Python SDK. Here's what you'd need to build:

#### 1. Install the E2B SDK

```bash
pip install e2b
```

Add `"e2b>=1.0.0"` to `dependencies.py`.

#### 2. Create the E2B provider

Create `src/secure_mcp_gateway/plugins/sandbox/e2b_provider.py`:

```python
"""E2B cloud sandbox provider — SDK-level transport approach."""

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger

try:
    from e2b import Sandbox
    HAS_E2B = True
except ImportError:
    HAS_E2B = False


class E2BSandboxProvider(SandboxProvider):
    """
    E2B cloud sandbox provider.

    Uses E2B's Python SDK to create a Firecracker microVM,
    start the MCP server inside it, and bridge stdin/stdout
    to the MCP SDK's expected transport streams.

    This is an SDK-level provider (like Microsandbox) — it overrides
    create_sandboxed_transport() instead of wrap_server_params().
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.environ.get("E2B_API_KEY")
        self._active_sandboxes: Dict[str, Any] = {}

    def get_name(self) -> str:
        return "e2b"

    def get_version(self) -> str:
        return "1.0.0"

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.get_name(),
            "version": self.get_version(),
            "uses_command_wrapping": False,
            "uses_sdk_transport": True,
        }

    async def check_availability(self) -> Tuple[bool, str]:
        if not HAS_E2B:
            return False, "e2b package not installed (pip install e2b)"
        if not self._api_key:
            return False, "E2B_API_KEY not set"
        return True, "E2B SDK available"

    async def wrap_server_params(self, server_name, command, args, env, sandbox_config):
        raise NotImplementedError("E2B uses SDK transport, not command wrapping")

    async def create_sandboxed_transport(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> Optional[Any]:
        """
        Create an E2B sandbox, upload the MCP server script,
        start the server process, and bridge its I/O to MCP streams.
        """
        if not HAS_E2B:
            return None

        @asynccontextmanager
        async def _transport() -> AsyncIterator[Tuple[
            MemoryObjectReceiveStream, MemoryObjectSendStream
        ]]:
            template = sandbox_config.get("e2b_template", "base")
            timeout = sandbox_config.get("e2b_timeout", 300)

            logger.info(
                f"[E2BSandboxProvider] Creating sandbox for '{server_name}' "
                f"template={template}"
            )

            # Create the E2B sandbox
            sandbox = Sandbox(
                template=template,
                api_key=self._api_key,
                timeout=timeout,
            )
            self._active_sandboxes[server_name] = sandbox

            try:
                # Upload the MCP server script to the sandbox
                script_path = args[0] if args else None
                if script_path and os.path.isfile(script_path):
                    with open(script_path, "r") as f:
                        sandbox.files.write(
                            f"/app/{os.path.basename(script_path)}",
                            f.read()
                        )

                # Start the MCP server process inside the sandbox
                # E2B provides process.stdin / process.stdout for I/O
                cmd = f"{command} /app/{os.path.basename(script_path)}"
                process = sandbox.commands.run(
                    cmd,
                    background=True,
                    envs=env or {},
                )

                # Bridge E2B process I/O to MCP transport streams
                # This is the key integration point — we need to create
                # anyio memory streams that proxy data between the E2B
                # process and the MCP ClientSession.
                read_send, read_recv = anyio.create_memory_object_stream(
                    max_buffer_size=0
                )
                write_send, write_recv = anyio.create_memory_object_stream(
                    max_buffer_size=0
                )

                async def _stdin_pump():
                    """Read from MCP write stream, send to E2B stdin."""
                    async with write_recv:
                        async for msg in write_recv:
                            process.send_stdin(msg.model_dump_json() + "\n")

                async def _stdout_pump():
                    """Read from E2B stdout, send to MCP read stream."""
                    async with read_send:
                        # E2B provides stdout via callbacks or polling
                        # Implementation depends on E2B SDK version
                        for line in process.stdout:
                            await read_send.send(line)

                async with anyio.create_task_group() as tg:
                    tg.start_soon(_stdin_pump)
                    tg.start_soon(_stdout_pump)
                    yield read_recv, write_send
                    tg.cancel_scope.cancel()

            finally:
                sandbox.kill()
                self._active_sandboxes.pop(server_name, None)
                logger.info(f"[E2BSandboxProvider] Destroyed sandbox for '{server_name}'")

        return _transport()

    async def cleanup(self, server_name: str) -> None:
        sandbox = self._active_sandboxes.pop(server_name, None)
        if sandbox:
            sandbox.kill()
```

#### 3. Register the provider in `config_manager.py`

Add a new `elif` branch in `initialize_sandbox_system()`:

```python
elif runtime == "e2b":
    try:
        from secure_mcp_gateway.plugins.sandbox.e2b_provider import E2BSandboxProvider
        api_key = sandbox_cfg.get("e2b_api_key") or os.environ.get("E2B_API_KEY")
        provider = E2BSandboxProvider(api_key=api_key)
    except ImportError as exc:
        logger.warning(f"[SandboxConfigManager] E2B SDK not installed: {exc}")
```

#### 4. Configuration

```json
"sandbox": {
    "enabled": true,
    "runtime": "e2b",
    "e2b_api_key": "e2b_...",
    "e2b_template": "my-mcp-template",
    "e2b_timeout": 300
}
```

#### 5. Create an E2B template

E2B templates are built from Dockerfiles and pre-snapshotted for fast starts:

```bash
# Install the E2B CLI
npm install -g @e2b/cli

# Login
e2b auth login

# Create a template from a Dockerfile
e2b template build --name mcp-sandbox --dockerfile tests/Dockerfile.sandbox-test
```

#### Key Challenges

The main challenge is **I/O bridging**. E2B communicates via its SDK (REST/WebSocket), not via stdin/stdout pipes. The provider must:

1. Create an E2B sandbox and start the MCP server process inside it
2. Bridge E2B's process I/O (SDK-level) to `anyio` memory streams
3. Feed those streams to the MCP `ClientSession` which expects `(read_stream, write_stream)`

This is the same pattern used by the existing Microsandbox provider — it's the `create_sandboxed_transport()` path in `server_params.py`. The exact I/O bridging code depends on how the E2B SDK exposes process stdin/stdout in its current version. The code above shows the architecture; you'll need to adapt the `_stdin_pump` and `_stdout_pump` functions to match the actual E2B SDK's process I/O API.

#### Summary of Files to Change

| File | Change |
|---|---|
| `src/secure_mcp_gateway/plugins/sandbox/e2b_provider.py` | **New file** — E2B provider implementation |
| `src/secure_mcp_gateway/plugins/sandbox/config_manager.py` | Add `elif runtime == "e2b"` branch |
| `src/secure_mcp_gateway/dependencies.py` | Add `"e2b>=1.0.0"` (optional dependency) |
| `src/secure_mcp_gateway/consts.py` | Add `"e2b"` to runtime enum docs |
| CLI / API | Add `"e2b"` as valid runtime option |

No changes needed to `server_params.py`, `gateway.py`, `client.py`, or any execution services — the plugin system handles it automatically.

---

## API Endpoints

### Check sandbox status

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8001/api/v1/sandbox/status
```

Response:
```json
{
    "message": "Sandbox status retrieved",
    "data": {
        "enabled": true,
        "provider": "container:docker",
        "available": true,
        "status": "docker is available",
        "metadata": {
            "name": "container:docker",
            "version": "1.0.0",
            "uses_command_wrapping": true,
            "uses_sdk_transport": false
        }
    }
}
```

### Add server with sandbox config

```bash
curl -X POST \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "server_name": "sandboxed_echo",
       "server_command": "python",
       "args": ["bad_mcps/echo_mcp.py"],
       "description": "Sandboxed echo server",
       "sandbox": {
           "enabled": true,
           "runtime": "docker",
           "image": "sandbox-test-mcp",
           "memory_limit": "256m",
           "network": "none"
       }
     }' \
     http://localhost:8001/api/v1/configs/CONFIG_ID/servers
```

## CLI Commands

### Global sandbox configuration

```bash
# Enable sandbox globally
secure-mcp-gateway config update-sandbox --enabled --runtime docker

# Set global defaults
secure-mcp-gateway config update-sandbox \
    --enabled \
    --runtime docker \
    --default-image python:3.11-slim \
    --default-memory-limit 512m \
    --default-cpu-limit 1.0 \
    --default-network none

# Disable sandbox
secure-mcp-gateway config update-sandbox --disabled

# View current sandbox config
secure-mcp-gateway config get-sandbox
```

### Per-server sandbox configuration

```bash
# Enable sandbox for a specific server
secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name echo_server \
    --enabled \
    --image sandbox-test-mcp \
    --memory-limit 256m \
    --network none

# Set environment allowlist
secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name github_server \
    --enabled \
    --allowed-env GITHUB_TOKEN,GITHUB_API_URL

# Disable sandbox for a specific server
secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name trusted_server \
    --disabled
```

## Troubleshooting

### "No sandbox provider registered"

The configured runtime is not available. Check:
- Is Docker/Podman installed and running? (`docker ps`)
- Is bwrap installed? (`bwrap --version`)
- Is the runtime name correct in config? (`docker`, `podman`, `bwrap`, `gvisor`, `srt`)

### Container fails to start

- Check Docker logs: `docker logs <container_id>`
- Ensure the Docker image has the required Python packages (`mcp`, `opentelemetry`)
- If using `--read-only`, ensure `/tmp` is writable (the gateway adds `--tmpfs=/tmp:size=64m`)

### MCP server can't find dependencies inside sandbox

**Docker/Podman:** Build a custom Docker image with all dependencies pre-installed (see [Building a Sandbox-Ready Docker Image](#building-a-sandbox-ready-docker-image)).

**Bubblewrap/gVisor/srt:** These run the host Python directly (with restricted filesystem access). Make sure the Python in your PATH has `mcp` installed, or use a virtualenv and ensure its `site-packages` path is bind-mounted.

### bwrap: "Permission denied" or "Operation not permitted"

Bubblewrap needs user namespaces enabled:
```bash
# Check if user namespaces are enabled
sysctl kernel.unprivileged_userns_clone
# If 0, enable it:
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

### gVisor: "runsc: error: need root or CAP_SYS_ADMIN"

`runsc do` may need elevated privileges. Options:
- Run with `sudo`
- Use gVisor as a Docker runtime instead (`--runtime=runsc`)
- Grant capabilities: `sudo setcap cap_sys_admin+ep $(which runsc)`

### srt: "Sandbox dependencies not available: ripgrep (rg) not found"

Anthropic srt requires `ripgrep`:
```bash
sudo apt install ripgrep
```

### Performance overhead

Container startup adds ~1 second per MCP session. To reduce this:
- Use lightweight base images (`python:3.11-slim`, not `python:3.11`)
- Pre-pull images: `docker pull sandbox-test-mcp`
- Switch to `bwrap` for near-zero overhead (Linux only)
- Consider Podman for rootless containers

### "sandbox enabled but no provider registered"

The gateway logs this warning and falls through to direct execution. This happens when:
- Sandbox is enabled in config but the runtime binary isn't on PATH
- The runtime SDK failed to import (microsandbox, e2b)

Check gateway startup logs for the specific error.

### E2B: "E2B_API_KEY not set"

Set your E2B API key:
```bash
export E2B_API_KEY="e2b_..."
```
Or add it to the config:
```json
"sandbox": { "runtime": "e2b", "e2b_api_key": "e2b_..." }
```
