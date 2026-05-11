"""Docker / Podman sandbox provider — command-wrapping approach."""

import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger


class ContainerSandboxProvider(SandboxProvider):
    """
    Wraps MCP server commands inside ``docker run`` or ``podman run``
    with strict security flags.

    The resulting StdioServerParameters are consumed by the standard
    ``stdio_client`` — no custom transport needed.
    """

    def __init__(self, preferred_cli: str = "auto"):
        self._cli: Optional[str] = None
        self._preferred_cli = preferred_cli

    # -- SandboxProvider interface ------------------------------------------

    def get_name(self) -> str:
        return f"container:{self._resolve_cli()}"

    def get_version(self) -> str:
        return "1.0.0"

    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        cli = self._resolve_cli()
        image = sandbox_config.get("image") or sandbox_config.get("default_image", "python:3.11-slim")
        memory = sandbox_config.get("memory_limit") or sandbox_config.get("default_memory_limit", "512m")
        cpus = sandbox_config.get("cpu_limit") or sandbox_config.get("default_cpu_limit", "1.0")
        pids = sandbox_config.get("pids_limit") or sandbox_config.get("default_pids_limit", 100)
        network = sandbox_config.get("network") or sandbox_config.get("default_network", "none")
        read_only = sandbox_config.get("read_only", sandbox_config.get("default_read_only", True))

        docker_args: List[str] = [
            "run", "--rm", "-i",
            f"--network={network}",
            f"--memory={memory}",
            f"--cpus={cpus}",
            f"--pids-limit={pids}",
            "--tmpfs=/tmp:size=64m",
        ]

        if sandbox_config.get("no_new_privileges", True):
            docker_args.append("--security-opt=no-new-privileges")

        if read_only:
            docker_args.append("--read-only")

        # Volume-mount the script directory read-only and remap paths.
        # When a host-local script is the first arg, mount its directory
        # into the container and rewrite the command to use the container
        # Python + the mounted script basename.
        container_cmd = command
        container_args = list(args)

        script_path = args[0] if args else None
        if script_path and os.path.isfile(script_path):
            script_dir = os.path.dirname(os.path.abspath(script_path))
            script_basename = os.path.basename(script_path)
            docker_args += ["-v", f"{script_dir}:/app:ro", "-w", "/app"]
            container_cmd = "python"
            container_args = [script_basename] + list(args[1:])
        elif os.path.isfile(command):
            cmd_dir = os.path.dirname(os.path.abspath(command))
            cmd_basename = os.path.basename(command)
            docker_args += ["-v", f"{cmd_dir}:/app:ro", "-w", "/app"]
            container_cmd = cmd_basename

        # Environment allowlisting
        filtered_env = self._filter_env(env, sandbox_config)
        for k, v in (filtered_env or {}).items():
            docker_args += ["-e", f"{k}={v}"]

        docker_args += [image, container_cmd] + container_args

        logger.info(
            f"[ContainerSandboxProvider] {cli} run for '{server_name}' "
            f"image={image} network={network} memory={memory}"
        )

        return StdioServerParameters(command=cli, args=docker_args, env=None)

    async def check_availability(self) -> Tuple[bool, str]:
        cli = self._resolve_cli()
        if cli:
            return True, f"{cli} is available"
        return False, "Neither docker nor podman found on PATH"

    async def cleanup(self, server_name: str) -> None:
        pass

    # -- Internals ----------------------------------------------------------

    def _resolve_cli(self) -> str:
        if self._cli:
            return self._cli

        if self._preferred_cli and self._preferred_cli != "auto":
            if shutil.which(self._preferred_cli):
                self._cli = self._preferred_cli
                return self._cli

        for candidate in ("docker", "podman"):
            if shutil.which(candidate):
                self._cli = candidate
                return self._cli

        self._cli = "docker"
        return self._cli

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
