"""Bubblewrap (bwrap) sandbox provider for Linux systems.

Bubblewrap uses Linux namespaces to create lightweight sandboxes with
minimal overhead (~200-400ms). It supports configurable filesystem,
PID, and network isolation.
"""

import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger


class BwrapSandboxProvider(SandboxProvider):
    """Sandbox provider using bubblewrap (bwrap) on Linux."""

    def get_name(self) -> str:
        return "bwrap"

    def get_version(self) -> str:
        return "1.0.0"

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "platform": "linux",
            "isolation": ["pid", "network", "filesystem", "ipc"],
        }

    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        network = sandbox_config.get("network") or sandbox_config.get("default_network", "none")
        read_only = sandbox_config.get("read_only", sandbox_config.get("default_read_only", True))
        unshare_pid = sandbox_config.get("unshare_pid", True)
        extra_ro_binds = sandbox_config.get("extra_ro_binds", [])
        extra_rw_binds = sandbox_config.get("extra_rw_binds", [])

        bwrap_args: List[str] = []

        # Filesystem: read-only bind of the entire rootfs, or read-write
        if read_only:
            bwrap_args += ["--ro-bind", "/", "/"]
        else:
            bwrap_args += ["--bind", "/", "/"]

        # Essential kernel filesystems
        bwrap_args += ["--dev", "/dev", "--proc", "/proc"]

        # Writable tmpfs areas
        bwrap_args += ["--tmpfs", "/tmp"]

        # Chrome/Chromium needs writable shared memory
        bwrap_args += ["--dev-bind", "/dev/shm", "/dev/shm"]

        # Network isolation
        if network == "none":
            bwrap_args.append("--unshare-net")

        # PID namespace isolation
        if unshare_pid:
            bwrap_args.append("--unshare-pid")

        # Prevent zombie processes when gateway exits
        bwrap_args.append("--die-with-parent")

        # Use writable /tmp as cwd so tools can create data directories
        bwrap_args += ["--chdir", "/tmp"]

        # For npx/npm commands, bind caches rw so --offline and browser profiles work
        if self._is_npm_command(command, args):
            for cache_dir in ("~/.npm", "~/.cache"):
                expanded = os.path.expanduser(cache_dir)
                if os.path.isdir(expanded):
                    bwrap_args += ["--bind", expanded, expanded]

        # For Python venvs, ensure the venv dir is accessible
        venv_path = self._detect_venv(command)
        if venv_path and read_only:
            bwrap_args += ["--ro-bind", venv_path, venv_path]

        # User-specified extra bind mounts
        for path in extra_ro_binds:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                bwrap_args += ["--ro-bind", expanded, expanded]

        for path in extra_rw_binds:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                bwrap_args += ["--bind", expanded, expanded]

        # The actual command to run inside the sandbox
        bwrap_args += [command] + list(args)

        filtered_env = self._filter_env(env, sandbox_config)

        logger.info(
            f"[BwrapSandboxProvider] server={server_name} "
            f"network={network} read_only={read_only} unshare_pid={unshare_pid} "
            f"cmd={command} args_count={len(args)}"
        )

        return StdioServerParameters(command="bwrap", args=bwrap_args, env=filtered_env)

    async def check_availability(self) -> Tuple[bool, str]:
        bwrap = shutil.which("bwrap")
        if bwrap:
            return True, f"bwrap found at {bwrap}"
        return False, "bwrap not found on PATH — install with: sudo apt install bubblewrap"

    async def cleanup(self, server_name: str) -> None:
        pass

    # -- Internals ---------------------------------------------------------

    @staticmethod
    def _is_npm_command(command: str, args: List[str]) -> bool:
        cmd_base = os.path.basename(command).lower()
        return cmd_base in ("npx", "npm", "node", "npx.cmd", "npm.cmd")

    @staticmethod
    def _detect_venv(command: str) -> Optional[str]:
        """If *command* lives inside a Python virtualenv, return the venv root.

        Uses the original path (not realpath) so that symlinked venvs
        inside /tmp are correctly detected.
        """
        for path in (command, os.path.realpath(command)):
            parts = path.replace("\\", "/").split("/")
            for i, part in enumerate(parts):
                if part in ("bin", "Scripts") and i >= 1:
                    candidate = "/".join(parts[:i])
                    pyvenv = os.path.join(candidate, "pyvenv.cfg")
                    if os.path.isfile(pyvenv):
                        return candidate
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
