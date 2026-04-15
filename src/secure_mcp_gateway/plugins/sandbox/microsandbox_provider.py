"""
Microsandbox provider — hardware-isolated microVM via libkrun.

Microsandbox provides a Python SDK with ``exec_stream`` + ``stdin_pipe``
that lets us bridge microVM stdin/stdout into anyio memory streams,
which the MCP ClientSession can consume directly.

Requires: ``pip install microsandbox``
Platforms: Linux, macOS (Apple Silicon)
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from mcp import StdioServerParameters

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider
from secure_mcp_gateway.utils import logger

try:
    import microsandbox  # noqa: F401

    HAS_MICROSANDBOX = True
except ImportError:
    HAS_MICROSANDBOX = False


class MicrosandboxProvider(SandboxProvider):
    """
    Launches MCP servers inside a Microsandbox microVM.

    Uses the Microsandbox Python SDK to stream stdin/stdout between
    the gateway and the sandboxed process. Falls back to command wrapping
    via the ``microsandbox`` CLI if the SDK transport bridge is not
    available.
    """

    def __init__(self):
        if not HAS_MICROSANDBOX:
            raise ImportError(
                "microsandbox package is not installed. "
                "Install it with: pip install microsandbox"
            )

    def get_name(self) -> str:
        return "microsandbox"

    def get_version(self) -> str:
        return "1.0.0"

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "uses_command_wrapping": False,
            "uses_sdk_transport": True,
            "isolation_level": "hardware (microVM / libkrun)",
        }

    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        """Fallback: wrap via the microsandbox CLI if SDK bridge is unavailable."""
        cli_args = ["run"]

        memory = sandbox_config.get("memory_limit", "512m")
        cpus = sandbox_config.get("cpu_limit", "1")
        network = sandbox_config.get("network", "none")

        cli_args += [f"--memory={memory}", f"--cpus={cpus}"]
        if network == "none":
            cli_args.append("--no-network")

        cli_args += ["--", command] + list(args)

        return StdioServerParameters(command="microsandbox", args=cli_args, env=env)

    async def create_sandboxed_transport(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> Optional[Any]:
        """
        Return an async context manager that yields (read, write) streams
        backed by the Microsandbox SDK.

        Uses exec_stream() + stdin_pipe() to get byte-level access to the
        sandboxed process's stdin/stdout, then wraps them into
        MemoryObjectSendStream / MemoryObjectReceiveStream that the MCP
        ClientSession expects.
        """
        try:
            return self._sdk_transport(server_name, command, args, env, sandbox_config)
        except Exception as exc:
            logger.warning(
                f"[MicrosandboxProvider] SDK transport unavailable ({exc}), "
                f"falling back to CLI wrapping"
            )
            return None

    @asynccontextmanager
    async def _sdk_transport(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> AsyncIterator[Tuple[Any, Any]]:
        """
        Bridge Microsandbox exec_stream to anyio memory streams.

        Architecture:
            MCP ClientSession <-> (anyio MemoryObjectStreams) <-> pump tasks
                <-> microsandbox.exec_stream/stdin_pipe <-> microVM process
        """
        import anyio
        from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
        from mcp.types import JSONRPCMessage

        import json
        import microsandbox as msb

        memory = sandbox_config.get("memory_limit", "512m")
        cpus = int(sandbox_config.get("cpu_limit", "1"))
        network = sandbox_config.get("network", "none")

        sandbox = msb.Sandbox(
            name=f"mcp-{server_name}",
            memory=memory,
            cpus=cpus,
            network=(network != "none"),
        )

        await sandbox.start()
        logger.info(f"[MicrosandboxProvider] MicroVM started for '{server_name}'")

        try:
            full_cmd = f"{command} {' '.join(args)}" if args else command
            process = await sandbox.exec_stream(full_cmd, env=env)

            send_to_client: MemoryObjectSendStream
            recv_from_bridge: MemoryObjectReceiveStream
            send_to_client, recv_from_bridge = anyio.create_memory_object_stream(64)

            send_to_bridge: MemoryObjectSendStream
            recv_from_client: MemoryObjectReceiveStream
            send_to_bridge, recv_from_client = anyio.create_memory_object_stream(64)

            async def _pump_stdout():
                """Read from microVM stdout -> parse JSON-RPC -> send to MCP client."""
                buffer = b""
                async for chunk in process.stdout:
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = JSONRPCMessage.model_validate_json(line)
                            await send_to_client.send(msg)
                        except Exception:
                            logger.debug(
                                f"[MicrosandboxProvider] Non-JSON line from VM: {line[:120]}"
                            )

            async def _pump_stdin():
                """Read JSON-RPC messages from MCP client -> write to microVM stdin."""
                async for msg in recv_from_client:
                    line = msg.model_dump_json() + "\n"
                    await process.stdin_pipe(line.encode())

            async with anyio.create_task_group() as tg:
                tg.start_soon(_pump_stdout)
                tg.start_soon(_pump_stdin)

                yield recv_from_bridge, send_to_bridge

                tg.cancel_scope.cancel()
        finally:
            await sandbox.stop()
            logger.info(f"[MicrosandboxProvider] MicroVM stopped for '{server_name}'")

    async def check_availability(self) -> Tuple[bool, str]:
        if not HAS_MICROSANDBOX:
            return False, "microsandbox package not installed"
        try:
            import microsandbox as msb

            ver = getattr(msb, "__version__", "unknown")
            return True, f"microsandbox SDK {ver} is available"
        except Exception as exc:
            return False, f"microsandbox SDK error: {exc}"

    async def cleanup(self, server_name: str) -> None:
        pass
