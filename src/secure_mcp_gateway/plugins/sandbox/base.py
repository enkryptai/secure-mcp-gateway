"""Sandbox plugin base interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from mcp import StdioServerParameters


class SandboxProvider(ABC):
    """
    Abstract base class for sandbox providers.

    Each provider (Docker/Podman, Microsandbox, NovaVM) implements this
    interface to wrap MCP server execution in an isolated environment.

    There are two integration patterns:
    - Command wrapping: override wrap_server_params() to transform the
      command/args into a sandboxed StdioServerParameters (Docker, Podman, NovaVM).
    - SDK-level: override create_sandboxed_transport() to return a custom
      async context manager yielding (read_stream, write_stream) that
      bridges the sandbox SDK to the MCP transport layer (Microsandbox).
    """

    @abstractmethod
    def get_name(self) -> str:
        """Get the unique name of this provider (e.g. 'docker', 'microsandbox', 'novavm')."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Get the version of this provider."""
        pass

    @abstractmethod
    async def wrap_server_params(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> StdioServerParameters:
        """
        Transform raw command/args/env into sandboxed StdioServerParameters.

        This is the primary method for command-wrapping providers (Docker,
        Podman, NovaVM). The returned params are passed directly to
        stdio_client().
        """
        pass

    async def create_sandboxed_transport(
        self,
        server_name: str,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]],
        sandbox_config: Dict[str, Any],
    ) -> Optional[Any]:
        """
        Create a sandboxed transport context manager yielding (read, write) streams.

        SDK-level providers (Microsandbox) override this to bridge their
        exec_stream API to the MCP SDK's expected transport interface.

        Returns None by default, meaning the provider uses command wrapping
        via wrap_server_params() instead.

        When overridden, should return an async context manager that yields
        (MemoryObjectReceiveStream, MemoryObjectSendStream) compatible with
        the MCP ClientSession constructor.
        """
        return None

    @abstractmethod
    async def check_availability(self) -> Tuple[bool, str]:
        """
        Check if the sandbox runtime is available on this system.

        Returns:
            Tuple of (is_available, status_message).
        """
        pass

    @abstractmethod
    async def cleanup(self, server_name: str) -> None:
        """Clean up sandbox resources after a server session exits."""
        pass

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate provider-specific configuration. Override if needed."""
        return True

    def get_required_config_keys(self) -> List[str]:
        """Get list of required configuration keys. Override if needed."""
        return []

    def get_metadata(self) -> Dict[str, Any]:
        """Get provider metadata (capabilities, runtime info)."""
        return {
            "name": self.get_name(),
            "version": self.get_version(),
            "uses_command_wrapping": True,
            "uses_sdk_transport": False,
        }


class SandboxRegistry:
    """Single-slot registry for the active sandbox provider."""

    def __init__(self):
        self._provider: Optional[SandboxProvider] = None

    def register(self, provider: SandboxProvider) -> None:
        self._provider = provider

    def unregister(self) -> None:
        self._provider = None

    def get_provider(self) -> Optional[SandboxProvider]:
        return self._provider

    def list_providers(self) -> List[str]:
        if self._provider:
            return [self._provider.get_name()]
        return []
