"""Enkrypt authentication provider."""

import json
import os
import time
from typing import Any, Dict, List, Optional

import requests

from secure_mcp_gateway.plugins.auth.base import (
    AuthCredentials,
    AuthMethod,
    AuthProvider,
    AuthResult,
    AuthStatus,
)
from secure_mcp_gateway.plugins.telemetry.metrics_helpers import record_auth_outcome
from secure_mcp_gateway.utils import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    is_docker,
    logger,
    mask_key,
)


class LocalApiKeyProvider(AuthProvider):
    """
    Enkrypt authentication provider.

    Authenticates users using Enkrypt's API key and project-based system.
    """

    def __init__(
        self,
        api_key: str = None,
        base_url: str = "https://api.enkryptai.com",
        use_remote_config: bool = False,
        timeout: int = 30,
    ):
        """
        Initialize the local-apikey auth provider.

        Args:
            api_key: Enkrypt API key (only used by the deprecated
                ``use_remote_config`` fallback below).
            base_url: Base URL for the deprecated remote-fetch endpoint.
            use_remote_config: DEPRECATED. When ``True``, falls back to
                ``/mcp-gateway/get-gateway`` against Enkrypt cloud if the
                gateway_key is not found in the local config. New
                deployments should switch to
                ``plugins.auth.provider = "enkrypt"`` instead, which uses
                the dedicated ``EnkryptAuthProvider`` with cleaner cloud
                semantics, proper caching, and a stable mapped shape.
                The constructor arg is kept for backward-compat — anyone
                with ``common_mcp_gateway_config.enkrypt_use_remote_mcp_config = true``
                in their config continues to work.
            timeout: Request timeout for the deprecated remote-fetch path.
        """
        self.api_key = api_key
        self.base_url = base_url
        self.use_remote_config = use_remote_config
        self.timeout = timeout
        self.auth_url = f"{base_url}/mcp-gateway/get-gateway"

        logger.info(f"Enkrypt auth provider initialized (remote={use_remote_config})")

    def get_name(self) -> str:
        """Get provider name."""
        return "enkrypt"

    def get_version(self) -> str:
        """Get provider version."""
        return "1.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        """Get supported authentication methods."""
        return [AuthMethod.API_KEY]

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate provider configuration."""
        if self.use_remote_config and not self.api_key:
            return False
        return True

    def get_required_config_keys(self) -> List[str]:
        """Get required configuration keys."""
        if self.use_remote_config:
            return ["api_key", "base_url"]
        return []

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate user with Enkrypt credentials.

        Args:
            credentials: Authentication credentials containing gateway_key, project_id, user_id

        Returns:
            AuthResult: Authentication result
        """
        result = await self._authenticate_impl(credentials)
        # Record auth metrics regardless of which return path was taken.
        record_auth_outcome(
            provider=self.get_name(),
            outcome="success" if result.authenticated else "failure",
            failure_reason=(result.error or result.status.value)
            if not result.authenticated
            else None,
        )
        return result

    async def _authenticate_impl(self, credentials: AuthCredentials) -> AuthResult:
        try:
            logger.info("[LocalApiKeyProvider] Starting authentication")

            # Extract credentials
            gateway_key = credentials.gateway_key or credentials.api_key
            project_id = credentials.project_id
            user_id = credentials.user_id

            # Validate required credentials
            if not gateway_key:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Gateway key is required",
                    error="Missing gateway_key",
                )

            # Try local configuration first
            local_config = await self._get_local_config(
                gateway_key, project_id, user_id
            )

            if local_config:
                logger.info(
                    f"[LocalApiKeyProvider] Local authentication successful for user: {user_id}"
                )
                return AuthResult(
                    status=AuthStatus.SUCCESS,
                    authenticated=True,
                    message="Authentication successful (local)",
                    user_id=local_config.get("user_id"),
                    project_id=local_config.get("project_id"),
                    session_id=local_config.get("id"),
                    gateway_config=local_config,
                    mcp_config=local_config.get("mcp_config", []),
                    metadata={
                        "source": "local",
                        "config_id": local_config.get("mcp_config_id"),
                    },
                )

            # Fall back to remote authentication if enabled
            if self.use_remote_config:
                return await self._authenticate_remote(
                    gateway_key, project_id, user_id, credentials
                )

            # No local config and remote disabled
            return AuthResult(
                status=AuthStatus.INVALID_CREDENTIALS,
                authenticated=False,
                message="No configuration found for provided credentials",
                error="Configuration not found",
            )

        except Exception as e:
            logger.error(f"[LocalApiKeyProvider] Authentication error: {e}")
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message=f"Authentication failed: {e}",
                error=str(e),
            )

    async def _authenticate_remote(
        self,
        gateway_key: str,
        project_id: str,
        user_id: str,
        credentials: AuthCredentials,
    ) -> AuthResult:
        """
        Authenticate using remote Enkrypt API.

        Args:
            gateway_key: Gateway API key
            project_id: Project ID
            user_id: User ID
            credentials: Full credentials object

        Returns:
            AuthResult: Authentication result
        """
        logger.info(
            f"[LocalApiKeyProvider] Attempting remote authentication for gateway_key: {mask_key(gateway_key)}"
        )

        try:
            # Get mcp_config_id from local config first
            local_config = await self._get_local_config(
                gateway_key, project_id, user_id
            )
            mcp_config_id = local_config.get("mcp_config_id") if local_config else None

            # Get configurable timeout from TimeoutManager
            import aiohttp

            from secure_mcp_gateway.services.timeout import get_timeout_manager

            timeout_manager = get_timeout_manager()
            timeout_value = timeout_manager.get_timeout("auth")

            # Use aiohttp for async HTTP request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.auth_url,
                    json={
                        "gateway_key": gateway_key,
                        "project_id": project_id,
                        "user_id": user_id,
                        "mcp_config_id": mcp_config_id,
                    },
                    headers={
                        "X-Enkrypt-Gateway-Key": gateway_key,
                        "X-Enkrypt-API-Key": self.api_key,
                    },
                    timeout=aiohttp.ClientTimeout(total=timeout_value),
                ) as response:
                    if response.status != 200:
                        return AuthResult(
                            status=AuthStatus.INVALID_CREDENTIALS,
                            authenticated=False,
                            message="Invalid credentials or unauthorized",
                            error=f"HTTP {response.status}",
                        )

                    gateway_config = await response.json()

            if not gateway_config:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="No configuration found",
                    error="Empty response from server",
                )

            logger.info("[LocalApiKeyProvider] Remote authentication successful")

            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="Authentication successful (remote)",
                user_id=gateway_config.get("user_id"),
                project_id=gateway_config.get("project_id"),
                session_id=gateway_config.get("id"),
                gateway_config=gateway_config,
                mcp_config=gateway_config.get("mcp_config", []),
                metadata={"source": "remote"},
            )

        except requests.Timeout:
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Authentication timeout",
                error="Request timeout",
            )
        except Exception as e:
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Remote authentication failed",
                error=str(e),
            )

    async def _get_local_config(
        self, gateway_key: str, project_id: str = None, user_id: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get configuration from local config file.

        Args:
            gateway_key: Gateway API key
            project_id: Project ID
            user_id: User ID

        Returns:
            Optional[Dict[str, Any]]: Configuration if found, None otherwise
        """
        running_in_docker = is_docker()
        config_path = DOCKER_CONFIG_PATH if running_in_docker else CONFIG_PATH

        if not os.path.exists(config_path):
            logger.debug(f"[LocalApiKeyProvider] Config file not found: {config_path}")
            return None

        try:
            # Use asyncio.to_thread for file I/O in async context
            import asyncio

            def _load_config():
                with open(config_path, encoding="utf-8") as f:
                    return json.load(f)

            json_config = await asyncio.to_thread(_load_config)

            # Check if gateway_key exists in apikeys
            apikeys = json_config.get("apikeys", {})
            if gateway_key not in apikeys:
                logger.debug("[LocalApiKeyProvider] Gateway key not found in config")
                return None

            key_info = apikeys[gateway_key]
            config_project_id = key_info.get("project_id")
            config_user_id = key_info.get("user_id")

            # Use config IDs if not provided (treat "not_provided" as absent)
            if not project_id or project_id == "not_provided":
                project_id = config_project_id
            if not user_id or user_id == "not_provided":
                user_id = config_user_id

            # Validate IDs match
            if project_id != config_project_id or user_id != config_user_id:
                logger.debug("[LocalApiKeyProvider] ID mismatch in config")
                return None

            # Get project and user configurations
            projects = json_config.get("projects", {})
            users = json_config.get("users", {})

            if project_id not in projects or user_id not in users:
                logger.debug(
                    "[LocalApiKeyProvider] Project or user not found in config"
                )
                return None

            project_config = projects[project_id]
            user_config = users[user_id]
            mcp_config_id = project_config.get("mcp_config_id")

            if not mcp_config_id:
                logger.debug("[LocalApiKeyProvider] No MCP config ID found")
                return None

            # Get MCP configuration
            mcp_configs = json_config.get("mcp_configs", {})
            if mcp_config_id not in mcp_configs:
                logger.debug("[LocalApiKeyProvider] MCP config not found")
                return None

            mcp_config_entry = mcp_configs[mcp_config_id]
            servers = self._apply_common_overrides(mcp_config_entry)

            return {
                "id": f"{user_id}_{project_id}_{mcp_config_id}",
                "project_name": project_config.get("project_name", "not_provided"),
                "project_id": project_id,
                "user_id": user_id,
                "email": user_config.get("email", "not_provided"),
                "mcp_config": servers,
                "mcp_config_id": mcp_config_id,
            }

        except Exception as e:
            logger.error(f"[LocalApiKeyProvider] Error reading local config: {e}")
            return None

    @staticmethod
    def _apply_common_overrides(mcp_config_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Promote ``mcp_configs.<id>.common_overrides`` onto every server entry.

        This makes the local config shape match the cloud-auth provider's
        contract (see :class:`EnkryptAuthProvider` docstring): keys that are
        documented as "common-only" are sourced from
        ``mcp_config_entry["common_overrides"]`` and copied onto each server
        before the list is returned to the rest of the gateway. Downstream
        code (``discovery_service`` etc.) keeps reading
        ``server_info["server_tools_guardrails_config"]`` exactly as it did
        for the cloud path — no call-site changes needed.

        Current scope (Flavor 1): only ``server_tools_guardrails_config`` is
        promoted. ``input_guardrails_config`` and ``output_guardrails_config``
        are intentionally NOT promoted; they remain legitimately per-server
        because operators often want different input/output policies on
        different servers.

        Common-wins semantics: if a stale per-server
        ``server_tools_guardrails_config`` exists alongside a common one,
        the common value overwrites it. This matches what the cloud does
        internally (per ``enkrypt_provider.py:27-43``). If common is absent
        but a per-server value is present, we honor the per-server value
        for backward compat and log a one-shot deprecation warning so the
        operator knows to move it under ``common_overrides``.

        The original mcp_config_entry is never mutated — each server dict
        we modify is shallow-copied first, so re-reading the config file
        produces the same in-memory representation every time.
        """
        original_servers = mcp_config_entry.get("mcp_config") or []
        common_overrides = mcp_config_entry.get("common_overrides") or {}

        common_keys: tuple[str, ...] = ("server_tools_guardrails_config",)

        applied: Dict[str, Any] = {
            k: common_overrides[k] for k in common_keys if k in common_overrides
        }

        # Fast path: nothing to promote and no per-server values to warn about.
        if not applied:
            stale = [
                s for s in original_servers
                if isinstance(s, dict) and any(k in s for k in common_keys)
            ]
            if stale:
                stale_names = [s.get("server_name", "<unknown>") for s in stale]
                logger.warning(
                    "[LocalApiKeyProvider] Per-server server_tools_guardrails_config "
                    "found on %s. This field is now COMMON-only. Move it under "
                    "mcp_configs.<id>.common_overrides.server_tools_guardrails_config "
                    "to match the cloud-auth contract. Per-server values are still "
                    "honored for backward compatibility and will be dropped in a "
                    "future release.",
                    stale_names,
                )
            return original_servers

        promoted: List[Dict[str, Any]] = []
        for srv in original_servers:
            if not isinstance(srv, dict):
                promoted.append(srv)
                continue
            srv_copy = dict(srv)
            for key, value in applied.items():
                srv_copy[key] = value  # common always wins
            promoted.append(srv_copy)
        return promoted

    async def validate_session(self, session_id: str) -> bool:
        """
        Validate if a session is still valid.

        Args:
            session_id: Session ID to validate

        Returns:
            bool: True if valid, False otherwise
        """
        # For Enkrypt, sessions are validated by checking if they exist
        # and haven't expired (handled by session manager)
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh authentication (not needed for API key auth).

        Args:
            session_id: Existing session ID
            credentials: Refresh credentials

        Returns:
            AuthResult: New authentication result
        """
        # Re-authenticate with same credentials
        return await self.authenticate(credentials)
