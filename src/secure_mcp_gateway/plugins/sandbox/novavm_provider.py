"""
NovaVM provider — KVM-based isolation with eBPF observability.

Uses ``nova shell`` command wrapping to run MCP server processes
inside a NovaVM lightweight VM. Requires the NovaVM daemon
(``nova serve``) to be running.

Install: ``sudo snap install novavm`` or via Ubuntu PPA
Platforms: Linux only (KVM required)
"""

import shutil
from typing import Any, Dict, List, Optional, Tuple

from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger

try:
    import novavm  # noqa: F401

    HAS_NOVAVM_SDK = True
except ImportError:
    HAS_NOVAVM_SDK = False


class NovaVMProvider(SandboxProvider):
    """
    Wraps MCP servers in NovaVM micro-VMs via ``nova shell``.

    Architecture:
        gateway -> nova shell --memory 512 --cpus 1 -- <command> <args>
                -> KVM micro-VM executing the MCP server
                -> stdin/stdout piped back through nova to stdio_client
    """

    def __init__(self, api_url: str = "http://localhost:9800"):
        self._api_url = api_url
        self._nova_bin: Optional[str] = None

    def get_name(self) -> str:
        return "novavm"

    def get_version(self) -> str:
        return "1.0.0"

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "isolation_level": "hardware (KVM microVM)",
            "platform": "linux",
            "features": ["ebpf_observability", "opa_policy", "four_level_cache"],
            "has_python_sdk": HAS_NOVAVM_SDK,
        }

    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        nova = self._resolve_nova_bin()

        image = sandbox_config.get("image", "python:3.11-slim")

        memory_raw = sandbox_config.get("memory_limit", "256")
        memory_mib = self._parse_memory_mib(memory_raw)

        cpus = sandbox_config.get("cpu_limit", "1")

        full_cmd = f"{command} {' '.join(args)}" if args else command

        nova_args: List[str] = [
            "shell",
            f"--vcpus={cpus}",
            f"--memory={memory_mib}",
            f"--cmd={full_cmd}",
            image,
        ]

        logger.info(
            f"[NovaVMProvider] nova shell for '{server_name}' "
            f"image={image} memory={memory_mib}MiB vcpus={cpus}"
        )

        filtered_env = self._filter_env(env, sandbox_config)

        return StdioServerParameters(command=nova, args=nova_args, env=filtered_env)

    async def check_availability(self) -> Tuple[bool, str]:
        nova = self._resolve_nova_bin()
        if nova:
            msg = f"nova CLI found at {nova}"
            if HAS_NOVAVM_SDK:
                msg += " (Python SDK also available)"
            return True, msg
        return False, "nova CLI not found on PATH. Install with: sudo snap install novavm"

    async def cleanup(self, server_name: str) -> None:
        pass

    def _resolve_nova_bin(self) -> Optional[str]:
        if self._nova_bin:
            return self._nova_bin
        path = shutil.which("nova")
        if path:
            self._nova_bin = path
        return path

    @staticmethod
    def _parse_memory_mib(raw: str) -> str:
        """Convert memory strings like '512m', '1g' to MiB integer string."""
        raw = raw.strip().lower()
        if raw.endswith("g"):
            return str(int(float(raw[:-1]) * 1024))
        if raw.endswith("m"):
            return raw[:-1]
        return raw

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
