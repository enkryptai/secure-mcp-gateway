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
from secure_mcp_gateway.utils import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    is_docker,
    logger,
    mask_key,
)


class EnkryptAuthProvider(AuthProvider):
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
        Initialize the Enkrypt auth provider.

        Args:
            api_key: Enkrypt API key for remote authentication
            base_url: Base URL for Enkrypt API
            use_remote_config: Whether to fetch config from remote API
            timeout: Request timeout in seconds
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
        try:
            logger.info("[EnkryptAuthProvider] Starting authentication")

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
                    f"[EnkryptAuthProvider] Local authentication successful for user: {user_id}"
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
            logger.error(f"[EnkryptAuthProvider] Authentication error: {e}")
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Authentication failed",
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
            f"[EnkryptAuthProvider] Attempting remote authentication for gateway_key: {mask_key(gateway_key)}"
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

            logger.info("[EnkryptAuthProvider] Remote authentication successful")

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
            logger.debug(f"[EnkryptAuthProvider] Config file not found: {config_path}")
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
                logger.debug("[EnkryptAuthProvider] Gateway key not found in config")
                return None

            key_info = apikeys[gateway_key]
            config_project_id = key_info.get("project_id")
            config_user_id = key_info.get("user_id")

            # Use config IDs if not provided
            if not project_id:
                project_id = config_project_id
            if not user_id:
                user_id = config_user_id

            # Validate IDs match
            if project_id != config_project_id or user_id != config_user_id:
                logger.debug("[EnkryptAuthProvider] ID mismatch in config")
                return None

            # Get project and user configurations
            projects = json_config.get("projects", {})
            users = json_config.get("users", {})

            if project_id not in projects or user_id not in users:
                logger.debug(
                    "[EnkryptAuthProvider] Project or user not found in config"
                )
                return None

            project_config = projects[project_id]
            user_config = users[user_id]
            mcp_config_id = project_config.get("mcp_config_id")

            if not mcp_config_id:
                logger.debug("[EnkryptAuthProvider] No MCP config ID found")
                return None

            # Get MCP configuration
            mcp_configs = json_config.get("mcp_configs", {})
            if mcp_config_id not in mcp_configs:
                logger.debug("[EnkryptAuthProvider] MCP config not found")
                return None

            mcp_config_entry = mcp_configs[mcp_config_id]

            return {
                "id": f"{user_id}_{project_id}_{mcp_config_id}",
                "project_name": project_config.get("project_name", "not_provided"),
                "project_id": project_id,
                "user_id": user_id,
                "email": user_config.get("email", "not_provided"),
                "mcp_config": mcp_config_entry.get("mcp_config", []),
                "mcp_config_id": mcp_config_id,
            }

        except Exception as e:
            logger.error(f"[EnkryptAuthProvider] Error reading local config: {e}")
            return None

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
