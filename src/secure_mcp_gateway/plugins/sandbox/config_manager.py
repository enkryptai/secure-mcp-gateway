"""Sandbox configuration manager."""

from typing import Any, Dict, List, Optional

from secure_mcp_gateway.plugins.sandbox.base import SandboxProvider, SandboxRegistry
from secure_mcp_gateway.utils import logger


class SandboxConfigManager:
    """
    Manages sandbox configuration and provider lifecycle.

    Holds the active sandbox provider and exposes it to the rest of the
    gateway via the singleton pattern used by other plugin managers.
    """

    def __init__(self):
        self.registry = SandboxRegistry()
        self._global_config: Dict[str, Any] = {}

    def register_provider(self, provider: SandboxProvider) -> None:
        self.registry.register(provider)
        logger.info(
            f"[SandboxConfigManager] Registered provider: {provider.get_name()} v{provider.get_version()}"
        )

    def get_provider(self) -> Optional[SandboxProvider]:
        return self.registry.get_provider()

    def list_providers(self) -> List[str]:
        return self.registry.list_providers()

    def set_global_config(self, config: Dict[str, Any]) -> None:
        self._global_config = config

    def get_global_config(self) -> Dict[str, Any]:
        return self._global_config

    def is_sandbox_enabled(self, server_entry: Optional[Dict[str, Any]] = None) -> bool:
        """Check if sandboxing is enabled (globally or per-server)."""
        if server_entry:
            server_sandbox = server_entry.get("sandbox", {})
            if "enabled" in server_sandbox:
                return server_sandbox["enabled"]

        return self._global_config.get("sandbox", {}).get("enabled", False)

    def get_effective_sandbox_config(
        self, server_entry: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Merge global sandbox defaults with per-server overrides.

        Per-server values take precedence over global defaults.
        """
        global_sandbox = self._global_config.get("sandbox", {})
        if not server_entry:
            return global_sandbox

        server_sandbox = server_entry.get("sandbox", {})
        merged = {**global_sandbox, **server_sandbox}
        return merged

    async def check_availability(self) -> tuple:
        """Check if the current provider's runtime is available."""
        provider = self.get_provider()
        if not provider:
            return False, "No sandbox provider registered"
        return await provider.check_availability()


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_sandbox_config_manager: Optional[SandboxConfigManager] = None


def get_sandbox_config_manager() -> SandboxConfigManager:
    global _sandbox_config_manager
    if _sandbox_config_manager is None:
        _sandbox_config_manager = SandboxConfigManager()
    return _sandbox_config_manager


def initialize_sandbox_system(common_config: Dict[str, Any]) -> SandboxConfigManager:
    """
    Initialize the sandbox system based on the gateway's common config.

    Reads ``common_config["sandbox"]["runtime"]`` to decide which provider
    to register. Falls back gracefully if the chosen runtime is not
    available on this machine.
    """
    manager = get_sandbox_config_manager()
    manager.set_global_config(common_config)

    sandbox_cfg = common_config.get("sandbox", {})
    if not sandbox_cfg.get("enabled", False):
        logger.info("[SandboxConfigManager] Sandboxing is disabled in config")
        return manager

    runtime = sandbox_cfg.get("runtime", "docker")
    logger.info(f"[SandboxConfigManager] Initializing sandbox runtime: {runtime}")

    provider: Optional[SandboxProvider] = None

    if runtime in ("docker", "podman"):
        from secure_mcp_gateway.plugins.sandbox.container_provider import (
            ContainerSandboxProvider,
        )

        cli = sandbox_cfg.get("container_cli", "auto")
        provider = ContainerSandboxProvider(preferred_cli=cli)

    elif runtime == "bwrap":
        from secure_mcp_gateway.plugins.sandbox.bwrap_provider import (
            BwrapSandboxProvider,
        )

        provider = BwrapSandboxProvider()

    elif runtime == "microsandbox":
        try:
            from secure_mcp_gateway.plugins.sandbox.microsandbox_provider import (
                MicrosandboxProvider,
            )

            provider = MicrosandboxProvider()
        except ImportError as exc:
            logger.warning(
                f"[SandboxConfigManager] Microsandbox SDK not installed: {exc}"
            )

    elif runtime == "novavm":
        try:
            from secure_mcp_gateway.plugins.sandbox.novavm_provider import (
                NovaVMProvider,
            )

            api_url = sandbox_cfg.get("nova_api_url", "http://localhost:9800")
            provider = NovaVMProvider(api_url=api_url)
        except ImportError as exc:
            logger.warning(
                f"[SandboxConfigManager] NovaVM SDK not installed: {exc}"
            )

    else:
        logger.warning(f"[SandboxConfigManager] Unknown runtime '{runtime}'")

    if provider:
        manager.register_provider(provider)
    else:
        logger.warning(
            "[SandboxConfigManager] No sandbox provider could be loaded — "
            "sandbox calls will fall through to direct execution"
        )

    return manager
