"""
Sandbox Plugin System

A pluggable sandbox layer that wraps MCP server processes in isolated
environments (Docker/Podman containers, Microsandbox microVMs, NovaVM KVM VMs),
reducing blast radius when executing untrusted MCP servers or tools.

Supports three runtimes:
- Docker/Podman: Container-level isolation via command wrapping
- Microsandbox: Hardware-level isolation via libkrun microVMs (Linux + macOS)
- NovaVM: KVM isolation with eBPF observability (Linux only)

Example Usage:
    ```python
    from secure_mcp_gateway.plugins.sandbox import (
        initialize_sandbox_system,
        get_sandbox_config_manager,
    )

    config = get_common_config()
    initialize_sandbox_system(config)

    manager = get_sandbox_config_manager()
    available, msg = await manager.check_availability()
    ```
"""

from .base import SandboxProvider
from .config_manager import (
    SandboxConfigManager,
    get_sandbox_config_manager,
    initialize_sandbox_system,
)

__all__ = [
    "SandboxProvider",
    "SandboxConfigManager",
    "get_sandbox_config_manager",
    "initialize_sandbox_system",
]

__version__ = "1.0.0"
