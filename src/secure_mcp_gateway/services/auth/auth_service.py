"""
Enkrypt Secure MCP Gateway Authentication Service Module

This module provides comprehensive authentication and authorization functionality for the
Enkrypt Secure MCP Gateway, including:

1. Credential Management:
   - HTTP header extraction
   - Environment variable fallback
   - Multi-source credential validation

2. Authentication Flow:
   - API key validation
   - Project and user authorization
   - Session management
   - Cache integration

3. Authorization:
   - Gateway configuration access
   - Server access control
   - Permission validation

4. Session Management:
   - Session creation and validation
   - Session caching
   - Session expiration handling

Configuration Variables:
    enkrypt_base_url: Base URL for EnkryptAI API
    enkrypt_use_remote_mcp_config: Enable/disable remote MCP config
    enkrypt_remote_mcp_gateway_name: Name of the MCP gateway
    enkrypt_remote_mcp_gateway_version: Version of the MCP gateway

Example Usage:
    ```python
    from secure_mcp_gateway.services.auth.auth_service import AuthService

    auth_service = AuthService()

    # Authenticate user
    auth_result = auth_service.authenticate(ctx)

    # Check if user is authenticated
    is_authenticated = auth_service.is_authenticated(ctx)

    # Get user session
    session = auth_service.get_session(ctx)
    ```
"""

import json
import os
import sys
import time
import traceback
from typing import Any, Dict, Optional, Tuple

import requests
from mcp.server.fastmcp import Context

from secure_mcp_gateway.services.cache.cache_service import cache_service
from secure_mcp_gateway.utils import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    get_common_config,
    is_docker,
    mask_key,
    sys_print,
)
from secure_mcp_gateway.version import __version__

# TODO: Fix error and use stdout
print(
    f"Initializing Enkrypt Secure MCP Gateway Authentication Service v{__version__}",
    file=sys.stderr,
)

# Get configuration
common_config = get_common_config()
ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"
ENKRYPT_BASE_URL = common_config.get("enkrypt_base_url", "https://api.enkryptai.com")
ENKRYPT_USE_REMOTE_MCP_CONFIG = common_config.get(
    "enkrypt_use_remote_mcp_config", False
)
ENKRYPT_REMOTE_MCP_GATEWAY_NAME = common_config.get(
    "enkrypt_remote_mcp_gateway_name", "Test MCP Gateway"
)
ENKRYPT_REMOTE_MCP_GATEWAY_VERSION = common_config.get(
    "enkrypt_remote_mcp_gateway_version", "v1"
)
ENKRYPT_API_KEY = common_config.get("enkrypt_api_key", "null")

# Authentication endpoints
AUTH_SERVER_VALIDATE_URL = f"{ENKRYPT_BASE_URL}/mcp-gateway/get-gateway"

# Global session storage
SESSIONS: Dict[str, Dict[str, Any]] = {}


class AuthService:
    """
    Authentication and authorization service for the Enkrypt Secure MCP Gateway.

    This service handles all authentication-related operations including credential
    extraction, validation, session management, and authorization checks.
    """

    def __init__(self):
        """Initialize the authentication service."""
        self.sessions = SESSIONS
        sys_print("Authentication service initialized")

    def get_gateway_credentials(self, ctx: Context) -> Dict[str, str]:
        """
        Retrieves the gateway credentials from the context or environment variables.

        Args:
            ctx (Context): The MCP context

        Returns:
            Dict[str, str]: Dictionary containing gateway_key, project_id, user_id
        """
        credentials = {}

        # Check context first (request headers) which we get for streamable-http protocol
        if ctx and ctx.request_context and ctx.request_context.request:
            headers = ctx.request_context.request.headers
            credentials["gateway_key"] = headers.get("apikey") or headers.get(
                "ENKRYPT_GATEWAY_KEY"
            )
            credentials["project_id"] = headers.get("project_id")
            credentials["user_id"] = headers.get("user_id")

        # Fallback to environment variables
        if not credentials.get("gateway_key"):
            credentials["gateway_key"] = os.environ.get("ENKRYPT_GATEWAY_KEY")
        if not credentials.get("project_id"):
            credentials["project_id"] = os.environ.get("ENKRYPT_PROJECT_ID")
        if not credentials.get("user_id"):
            credentials["user_id"] = os.environ.get("ENKRYPT_USER_ID")

        if IS_DEBUG_LOG_LEVEL:
            sys_print(
                f"[get_gateway_credentials] Using credentials: gateway_key={mask_key(credentials.get('gateway_key'))}, project_id={credentials.get('project_id')}, user_id={credentials.get('user_id')}",
                is_debug=True,
            )

        return credentials

    def get_local_mcp_config(
        self, gateway_key: str, project_id: str = None, user_id: str = None
    ) -> Dict[str, Any]:
        """
        Reads MCP configuration from local config file with the new flattened structure.

        Args:
            gateway_key (str): API key to look up in apikeys section
            project_id (str): Project ID
            user_id (str): User ID

        Returns:
            Dict[str, Any]: MCP configuration for the given parameters, empty dict if not found
        """
        running_in_docker = is_docker()
        if IS_DEBUG_LOG_LEVEL:
            sys_print(
                f"[get_local_mcp_config] Getting local MCP config for gateway_key={mask_key(gateway_key)}, project_id={project_id}, user_id={user_id}, running_in_docker={running_in_docker}",
                is_debug=True,
            )

        config_path = DOCKER_CONFIG_PATH if running_in_docker else CONFIG_PATH
        if os.path.exists(config_path):
            if IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[get_local_mcp_config] MCP config file found at {config_path}",
                    is_debug=True,
                )

            with open(config_path, encoding="utf-8") as f:
                json_config = json.load(f)

                # Check if gateway_key exists in apikeys
                apikeys = json_config.get("apikeys", {})
                if gateway_key not in apikeys:
                    sys_print(
                        "[get_local_mcp_config] Gateway key not found in apikeys",
                        is_error=True,
                    )
                    return {}

                key_info = apikeys[gateway_key]
                config_project_id = key_info.get("project_id")
                config_user_id = key_info.get("user_id")

                # Use project_id and user_id from config if not provided
                if not project_id:
                    project_id = config_project_id
                if not user_id:
                    user_id = config_user_id

                # Validate that provided IDs match config
                if project_id != config_project_id:
                    sys_print(
                        f"[get_local_mcp_config] Project ID mismatch: provided={project_id}, config={config_project_id}",
                        is_error=True,
                    )
                    return {}
                if user_id != config_user_id:
                    sys_print(
                        f"[get_local_mcp_config] User ID mismatch: provided={user_id}, config={config_user_id}",
                        is_error=True,
                    )
                    return {}

                # Get project configuration
                projects = json_config.get("projects", {})
                if project_id not in projects:
                    sys_print(
                        f"[get_local_mcp_config] Project {project_id} not found in projects",
                        is_error=True,
                    )
                    return {}

                project_config = projects[project_id]

                # Get user configuration
                users = json_config.get("users", {})
                if user_id not in users:
                    sys_print(
                        f"[get_local_mcp_config] User {user_id} not found in users",
                        is_error=True,
                    )
                    return {}

                user_config = users[user_id]

                # Get mcp_config_id from project
                mcp_config_id = project_config.get("mcp_config_id")
                if not mcp_config_id:
                    sys_print(
                        f"[get_local_mcp_config] No mcp_config_id found for project {project_id}",
                        is_error=True,
                    )
                    return {}
                else:
                    sys_print(
                        f"[get_local_mcp_config] Found mcp_config_id for project {project_id}: {mcp_config_id}",
                        is_debug=True,
                    )

                # Get MCP config from the flattened structure
                mcp_configs = json_config.get("mcp_configs", {})
                if mcp_config_id not in mcp_configs:
                    sys_print(
                        f"[get_local_mcp_config] MCP config {mcp_config_id} not found in mcp_configs",
                        is_error=True,
                    )
                    return {}

                mcp_config_entry = mcp_configs[mcp_config_id]
                return {
                    "id": f"{user_id}_{project_id}_{mcp_config_id}",  # Generate a unique ID
                    "project_name": project_config.get("project_name", "not_provided"),
                    "project_id": project_id,
                    "user_id": user_id,
                    "email": user_config.get("email", "not_provided"),
                    "mcp_config": mcp_config_entry.get("mcp_config", []),
                    "mcp_config_id": mcp_config_id,
                }
        else:
            sys_print(
                f"[get_local_mcp_config] MCP config file not found at {config_path}",
                is_error=True,
            )
            return {}

    def create_session_key(
        self, gateway_key: str, project_id: str, user_id: str, mcp_config_id: str
    ) -> str:
        """
        Creates a unique session key for the given credentials.

        Args:
            gateway_key (str): Gateway API key
            project_id (str): Project ID
            user_id (str): User ID
            mcp_config_id (str): MCP configuration ID

        Returns:
            str: Unique session key
        """
        return f"{gateway_key}_{project_id}_{user_id}_{mcp_config_id}"

    def is_session_authenticated(self, session_key: str) -> bool:
        """
        Checks if a session is authenticated.

        Args:
            session_key (str): Session key to check

        Returns:
            bool: True if session is authenticated, False otherwise
        """
        return session_key in self.sessions and self.sessions[session_key].get(
            "authenticated", False
        )

    def get_session(self, session_key: str) -> Optional[Dict[str, Any]]:
        """
        Gets session data for a given session key.

        Args:
            session_key (str): Session key

        Returns:
            Optional[Dict[str, Any]]: Session data if exists, None otherwise
        """
        return self.sessions.get(session_key)

    def create_session(self, session_key: str, gateway_config: Dict[str, Any]) -> None:
        if session_key not in self.sessions:
            self.sessions[session_key] = {}
        self.sessions[session_key].update(
            {
                "authenticated": True,
                "gateway_config": gateway_config,
                "created_at": time.time(),  # Add this
            }
        )

    def authenticate(self, ctx: Context) -> Dict[str, Any]:
        """
        Authenticates a user with the new API key + project + user + MCP config structure.

        This function handles gateway/user authentication, retrieves gateway configuration,
        and manages caching of gateway/user data. It supports both remote and local
        configuration sources.

        Args:
            ctx (Context): The MCP context

        Returns:
            Dict[str, Any]: Authentication result containing:
                - status: Success/error status
                - message: Authentication message
                - id: The authenticated Gateway or User's ID
                - mcp_config: Gateway/user's MCP configuration
                - available_servers: Dictionary of available servers
        """
        try:
            sys_print("[authenticate] Starting authentication")

            # Get credentials
            credentials = self.get_gateway_credentials(ctx)
            gateway_key = credentials.get("gateway_key", "not_provided")
            project_id = credentials.get("project_id", "not_provided")
            user_id = credentials.get("user_id", "not_provided")

            local_mcp_config = self.get_local_mcp_config(
                gateway_key, project_id, user_id
            )
            if not local_mcp_config:
                sys_print(
                    f"[authenticate] No local MCP config found for gateway_key={mask_key(gateway_key)}, project_id={project_id}, user_id={user_id}",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": "No MCP config found. Please check your credentials.",
                }

            mcp_config_id = local_mcp_config.get("mcp_config_id")
            if not mcp_config_id:
                sys_print(
                    f"[authenticate] No MCP config ID found for gateway_key={mask_key(gateway_key)}, project_id={project_id}, user_id={user_id}",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": "No MCP config ID found. Please check your credentials.",
                }

            # Validate gateway key
            if not gateway_key:
                sys_print("[authenticate] No gateway key provided", is_error=True)
                return {
                    "status": "error",
                    "error": "ENKRYPT_GATEWAY_KEY is required in MCP client config.",
                }

            # Create session key
            session_key = self.create_session_key(
                gateway_key, project_id, user_id, mcp_config_id
            )

            # Check if already authenticated
            if self.is_session_authenticated(session_key):
                sys_print("[authenticate] Already authenticated in session")
                mcp_config = self.sessions[session_key]["gateway_config"].get(
                    "mcp_config", []
                )
                return {
                    "status": "success",
                    "message": "Already authenticated",
                    "id": self.sessions[session_key]["gateway_config"].get("id"),
                    "mcp_config": mcp_config,
                    "available_servers": {s["server_name"]: s for s in mcp_config},
                }

            # Check cache for existing authentication
            id = local_mcp_config.get("id")
            if id:
                # Try to get cached gateway config
                # from secure_mcp_gateway.client import get_cached_gateway_config

                # cached_config = get_cached_gateway_config(None, id)
                cached_config = cache_service.get_cached_gateway_config(id)
                if cached_config:
                    sys_print(f"[authenticate] Found cached config for ID: {id}")
                    if session_key not in self.sessions:
                        self.sessions[session_key] = {}
                    self.sessions[session_key].update(
                        {"authenticated": True, "gateway_config": cached_config}
                    )
                    return {
                        "status": "success",
                        "message": "Authentication successful (from cache)",
                        "id": cached_config.get("id"),
                        "mcp_config": cached_config.get("mcp_config", []),
                        "available_servers": {
                            s["server_name"]: s
                            for s in cached_config.get("mcp_config", [])
                        },
                    }
                else:
                    sys_print(f"[authenticate] No cached config found for ID: {id}")

            # Remote authentication if enabled
            if ENKRYPT_USE_REMOTE_MCP_CONFIG:
                sys_print(
                    f"[authenticate] No valid cache, contacting auth server with ENKRYPT_API_KEY: {mask_key(ENKRYPT_API_KEY)}"
                )
                try:
                    response = requests.post(
                        AUTH_SERVER_VALIDATE_URL,
                        json={
                            "gateway_key": gateway_key,
                            "project_id": project_id,
                            "user_id": user_id,
                            "mcp_config_id": mcp_config_id,
                        },
                        headers={
                            "X-Enkrypt-Gateway-Key": gateway_key,
                            "X-Enkrypt-API-Key": ENKRYPT_API_KEY,
                        },
                        timeout=30,
                    )

                    if response.status_code != 200:
                        sys_print(
                            "[authenticate] Invalid API key or credentials",
                            is_error=True,
                        )
                        return {
                            "status": "error",
                            "error": "Invalid API key or credentials",
                        }

                    gateway_config = response.json()
                    if not gateway_config:
                        sys_print(
                            "[authenticate] No gateway config found", is_error=True
                        )
                        return {
                            "status": "error",
                            "error": "No gateway config found. Check your credentials.",
                        }
                except Exception as e:
                    sys_print(
                        f"[authenticate] Error contacting auth server: {e}",
                        is_error=True,
                    )
                    return {
                        "status": "error",
                        "error": f"Authentication server error: {e}",
                    }
            else:
                sys_print("[authenticate] Using local MCP config", is_debug=True)
                gateway_config = local_mcp_config
                if not gateway_config:
                    sys_print("[authenticate] No gateway config found", is_error=True)
                    return {
                        "status": "error",
                        "error": "No gateway config found. Check your credentials.",
                    }

            # Cache the gateway config
            # from secure_mcp_gateway.client import cache_gateway_config

            cache_service.cache_gateway_config(id, gateway_config)

            # Create session
            self.create_session(session_key, gateway_config)

            sys_print(f"[authenticate] Auth successful for ID: {id}")
            return {
                "status": "success",
                "message": "Authentication successful",
                "id": id,
                "mcp_config": gateway_config.get("mcp_config", []),
                "available_servers": {
                    s["server_name"]: s for s in gateway_config.get("mcp_config", [])
                },
            }

        except Exception as e:
            sys_print(f"[authenticate] Exception: {e}", is_error=True)
            traceback.print_exc(file=sys.stderr)
            return {"status": "error", "error": str(e)}

    def is_authenticated(self, ctx: Context) -> bool:
        """
        Checks if the current context is authenticated.

        Args:
            ctx (Context): The MCP context

        Returns:
            bool: True if authenticated, False otherwise
        """
        credentials = self.get_gateway_credentials(ctx)
        gateway_key = credentials.get("gateway_key")
        project_id = credentials.get("project_id")
        user_id = credentials.get("user_id")

        if not all([gateway_key, project_id, user_id]):
            return False

        # Get MCP config to get mcp_config_id
        local_mcp_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_mcp_config:
            return False

        mcp_config_id = local_mcp_config.get("mcp_config_id")
        if not mcp_config_id:
            return False

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        return self.is_session_authenticated(session_key)

    def require_authentication(self, ctx: Context) -> Tuple[bool, Dict[str, Any]]:
        """
        Requires authentication and returns the result.

        Args:
            ctx (Context): The MCP context

        Returns:
            Tuple[bool, Dict[str, Any]]: (is_authenticated, auth_result)
        """
        if self.is_authenticated(ctx):
            return True, {"status": "success", "message": "Already authenticated"}

        auth_result = self.authenticate(ctx)
        return auth_result.get("status") == "success", auth_result

    def get_authenticated_session(self, ctx: Context) -> Optional[Dict[str, Any]]:
        """
        Gets the authenticated session for the current context.

        Args:
            ctx (Context): The MCP context

        Returns:
            Optional[Dict[str, Any]]: Session data if authenticated, None otherwise
        """
        credentials = self.get_gateway_credentials(ctx)
        gateway_key = credentials.get("gateway_key")
        project_id = credentials.get("project_id")
        user_id = credentials.get("user_id")

        if not all([gateway_key, project_id, user_id]):
            return None

        # Get MCP config to get mcp_config_id
        local_mcp_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_mcp_config:
            return None

        mcp_config_id = local_mcp_config.get("mcp_config_id")
        if not mcp_config_id:
            return None

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        return self.get_session(session_key)

    def clear_session(self, ctx: Context) -> bool:
        """
        Clears the session for the current context.

        Args:
            ctx (Context): The MCP context

        Returns:
            bool: True if session was cleared, False otherwise
        """
        credentials = self.get_gateway_credentials(ctx)
        gateway_key = credentials.get("gateway_key")
        project_id = credentials.get("project_id")
        user_id = credentials.get("user_id")

        if not all([gateway_key, project_id, user_id]):
            return False

        # Get MCP config to get mcp_config_id
        local_mcp_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_mcp_config:
            return False

        mcp_config_id = local_mcp_config.get("mcp_config_id")
        if not mcp_config_id:
            return False

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        if session_key in self.sessions:
            del self.sessions[session_key]
            return True

        return False

    def get_session_stats(self) -> Dict[str, Any]:
        """
        Gets session statistics.

        Returns:
            Dict[str, Any]: Session statistics
        """
        total_sessions = len(self.sessions)
        authenticated_sessions = sum(
            1
            for session in self.sessions.values()
            if session.get("authenticated", False)
        )

        return {
            "total_sessions": total_sessions,
            "authenticated_sessions": authenticated_sessions,
            "unauthenticated_sessions": total_sessions - authenticated_sessions,
        }

    def get_session_gateway_config_key_suffix(self, credentials: Dict[str, Any]) -> str:
        """Derive the session key suffix (mcp_config_id) from local config.

        Args:
            credentials: Dict with at least gateway_key, project_id, user_id

        Returns:
            str: mcp_config_id if found, otherwise "not_provided"
        """
        try:
            gateway_key = credentials.get("gateway_key")
            project_id = credentials.get("project_id")
            user_id = credentials.get("user_id")
            local_cfg = self.get_local_mcp_config(gateway_key, project_id, user_id)
            if not local_cfg:
                return "not_provided"
            return local_cfg.get("mcp_config_id", "not_provided")
        except Exception:
            return "not_provided"

    def get_session_gateway_config(self, session_key: str) -> Dict[str, Any]:
        if session_key not in self.sessions:
            raise ValueError(f"Session {session_key} not found")

        session = self.sessions[session_key]
        if not session.get("authenticated", False):
            raise ValueError(f"Session {session_key} not authenticated")

        gateway_config = session.get("gateway_config")
        if not gateway_config:
            raise ValueError(f"Session {session_key} has no gateway configuration")

        return gateway_config

    def cleanup_expired_sessions(self, max_age_hours: int = 24):
        """Clean up sessions older than max_age_hours."""
        current_time = time.time()
        expired_keys = []

        for key, session in self.sessions.items():
            # Add timestamp tracking to sessions
            if "created_at" in session:
                age = (current_time - session["created_at"]) / 3600
                if age > max_age_hours:
                    expired_keys.append(key)

        for key in expired_keys:
            del self.sessions[key]

        return len(expired_keys)


# Global authentication service instance
auth_service = AuthService()
