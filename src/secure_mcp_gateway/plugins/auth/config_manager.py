"""
Authentication Configuration Manager

Manages authentication provider configuration and integrates with the gateway.
Provides utilities for registering providers, extracting credentials, and
managing sessions.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from mcp.server.fastmcp import Context

from secure_mcp_gateway.plugins.auth.base import (
    AuthCredentials,
    AuthProvider,
    AuthProviderRegistry,
    AuthResult,
    SessionData,
)
from secure_mcp_gateway.utils import sys_print


class AuthConfigManager:
    """
    Manages authentication configuration and provider instantiation.
    """

    def __init__(self):
        """Initialize the auth config manager."""
        self.registry = AuthProviderRegistry()
        self.sessions: Dict[str, SessionData] = {}
        self.default_provider = "enkrypt"

        # Import cache service
        from secure_mcp_gateway.services.cache.cache_service import cache_service

        self.cache_service = cache_service

    def register_provider(self, provider: AuthProvider) -> None:
        """
        Register an authentication provider.

        Args:
            provider: Provider to register
        """
        self.registry.register(provider)
        sys_print(f"Registered auth provider: {provider.get_name()}")

    def unregister_provider(self, name: str) -> None:
        """
        Unregister a provider.

        Args:
            name: Provider name
        """
        self.registry.unregister(name)
        sys_print(f"Unregistered auth provider: {name}")

    def get_provider(self, name: Optional[str] = None) -> Optional[AuthProvider]:
        """
        Get the registered provider.

        Args:
            name: Provider name (for compatibility, but ignored since only one provider)

        Returns:
            Optional[AuthProvider]: Provider if found
        """
        return self.registry.get_provider(name)

    def list_providers(self) -> List[str]:
        """
        List all registered providers.

        Returns:
            List[str]: Provider names
        """
        return self.registry.list_providers()

    def extract_credentials(self, ctx: Context) -> AuthCredentials:
        """
        Extract credentials from MCP context.

        Args:
            ctx: MCP context

        Returns:
            AuthCredentials: Extracted credentials
        """
        credentials = AuthCredentials()

        # Extract from request headers (for streamable-http)
        if ctx and ctx.request_context and ctx.request_context.request:
            headers = ctx.request_context.request.headers

            credentials.api_key = headers.get("apikey")
            credentials.gateway_key = headers.get("ENKRYPT_GATEWAY_KEY") or headers.get(
                "apikey"
            )
            credentials.project_id = headers.get("project_id")
            credentials.user_id = headers.get("user_id")
            credentials.access_token = headers.get("Authorization", "").replace(
                "Bearer ", ""
            )
            credentials.username = headers.get("username")
            credentials.password = headers.get("password")
            credentials.headers = dict(headers)

        # Fallback to environment variables
        import os

        if not credentials.gateway_key:
            credentials.gateway_key = os.environ.get("ENKRYPT_GATEWAY_KEY")
        if not credentials.project_id:
            credentials.project_id = os.environ.get("ENKRYPT_PROJECT_ID")
        if not credentials.user_id:
            credentials.user_id = os.environ.get("ENKRYPT_USER_ID")

        return credentials

    async def authenticate(
        self, ctx: Context, provider_name: Optional[str] = None
    ) -> AuthResult:
        """
        Authenticate a request using the specified provider with cache integration.

        Args:
            ctx: MCP context
            provider_name: Provider to use (None for default)

        Returns:
            AuthResult: Authentication result
        """
        sys_print("[AuthConfigManager] Starting authentication")

        # Extract credentials
        credentials = self.extract_credentials(ctx)
        gateway_key = credentials.gateway_key or credentials.api_key
        project_id = credentials.project_id
        user_id = credentials.user_id

        # Validate credentials
        if not gateway_key:
            return AuthResult(
                status="error",
                authenticated=False,
                message="Gateway key is required",
                error="Missing gateway_key",
            )

        # Get local config to find mcp_config_id
        local_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_config:
            return AuthResult(
                status="error",
                authenticated=False,
                message="No configuration found",
                error="Configuration not found",
            )

        mcp_config_id = local_config.get("mcp_config_id")
        if not mcp_config_id:
            return AuthResult(
                status="error",
                authenticated=False,
                message="No MCP config ID found",
                error="Missing mcp_config_id",
            )

        # Create session key
        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )

        # Check if already authenticated in session
        if self.is_session_authenticated(session_key):
            sys_print("[AuthConfigManager] Already authenticated in session")
            session = self.sessions[session_key]
            return AuthResult(
                status="success",
                authenticated=True,
                message="Already authenticated (session)",
                user_id=session.user_id,
                project_id=session.project_id,
                session_id=session_key,
                gateway_config=session.gateway_config,
                mcp_config=session.gateway_config.get("mcp_config", []),
                metadata={"source": "session"},
            )

        # Check cache
        id = local_config.get("id")
        if id:
            cached_config = self.cache_service.get_cached_gateway_config(id)
            if cached_config:
                sys_print(f"[AuthConfigManager] Found cached config for ID: {id}")
                self.create_session(session_key, cached_config)
                return AuthResult(
                    status="success",
                    authenticated=True,
                    message="Authentication successful (cache)",
                    user_id=cached_config.get("user_id"),
                    project_id=cached_config.get("project_id"),
                    session_id=session_key,
                    gateway_config=cached_config,
                    mcp_config=cached_config.get("mcp_config", []),
                    metadata={"source": "cache"},
                )

        # Get provider and authenticate
        provider = self.get_provider(provider_name)
        if not provider:
            return AuthResult(
                status="error",
                authenticated=False,
                message=f"Provider '{provider_name or self.default_provider}' not found",
                error="Provider not registered",
            )

        # Authenticate with provider
        result = await provider.authenticate(credentials)

        # Cache and create session if successful
        if result.is_success:
            # Cache gateway config
            if id and result.gateway_config:
                self.cache_service.cache_gateway_config(id, result.gateway_config)

            # Create session
            self.create_session(session_key, result.gateway_config)

            # Update result with session info
            result.session_id = session_key
            result.metadata = result.metadata or {}
            result.metadata["session_created"] = True

        return result

    def _create_session(self, auth_result: AuthResult) -> SessionData:
        """
        Create a session from authentication result.

        Args:
            auth_result: Authentication result

        Returns:
            SessionData: Created session
        """
        session_id = auth_result.session_id or self._generate_session_id(auth_result)

        return SessionData(
            session_id=session_id,
            user_id=auth_result.user_id,
            project_id=auth_result.project_id,
            authenticated=True,
            created_at=time.time(),
            last_accessed=time.time(),
            gateway_config=auth_result.gateway_config,
            metadata=auth_result.metadata,
        )

    def _generate_session_id(self, auth_result: AuthResult) -> str:
        """Generate a unique session ID."""
        import hashlib

        data = f"{auth_result.user_id}_{auth_result.project_id}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get session data.

        Args:
            session_id: Session ID

        Returns:
            Optional[SessionData]: Session data if exists
        """
        session = self.sessions.get(session_id)
        if session:
            session.last_accessed = time.time()
        return session

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session ID

        Returns:
            bool: True if deleted
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """
        Clean up expired sessions.

        Args:
            max_age_hours: Maximum session age in hours

        Returns:
            int: Number of sessions cleaned up
        """
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        expired_keys = []

        for session_id, session in self.sessions.items():
            age = current_time - session.created_at
            if age > max_age_seconds:
                expired_keys.append(session_id)

        for key in expired_keys:
            del self.sessions[key]

        return len(expired_keys)

    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session statistics.

        Returns:
            Dict[str, Any]: Session stats
        """
        total = len(self.sessions)
        authenticated = sum(1 for s in self.sessions.values() if s.authenticated)

        return {
            "total_sessions": total,
            "authenticated_sessions": authenticated,
            "unauthenticated_sessions": total - authenticated,
            "providers": self.list_providers(),
        }

    # ========================================================================
    # BACKWARD-COMPATIBLE METHODS (matching auth_service API)
    # ========================================================================

    def get_gateway_credentials(self, ctx: Context) -> Dict[str, str]:
        """
        Backward-compatible method matching auth_service.get_gateway_credentials()

        Returns dict with keys: gateway_key, project_id, user_id
        """
        creds = self.extract_credentials(ctx)
        return {
            "gateway_key": creds.gateway_key or creds.api_key,
            "project_id": creds.project_id,
            "user_id": creds.user_id,
        }

    def get_local_mcp_config(
        self, gateway_key: str, project_id: str = None, user_id: str = None
    ) -> Dict[str, Any]:
        """
        Backward-compatible method matching auth_service.get_local_mcp_config()

        Delegates to EnkryptAuthProvider._get_local_config()
        """
        provider = self.get_provider("enkrypt")
        if not provider or not hasattr(provider, "_get_local_config"):
            return {}

        return provider._get_local_config(gateway_key, project_id, user_id)

    def create_session_key(
        self, gateway_key: str, project_id: str, user_id: str, mcp_config_id: str
    ) -> str:
        """
        Backward-compatible method for creating session keys.
        """
        return f"{gateway_key}_{project_id}_{user_id}_{mcp_config_id}"

    def is_session_authenticated(self, session_key: str) -> bool:
        """
        Backward-compatible method for checking session authentication.
        """
        session = self.sessions.get(session_key)
        return session is not None and session.authenticated

    def create_session(self, session_key: str, gateway_config: Dict[str, Any]) -> None:
        """
        Backward-compatible session creation.
        """
        if session_key not in self.sessions:
            self.sessions[session_key] = SessionData(
                session_id=session_key,
                user_id=gateway_config.get("user_id", ""),
                project_id=gateway_config.get("project_id"),
                authenticated=True,
                created_at=time.time(),
                last_accessed=time.time(),
                gateway_config=gateway_config,
                metadata={},
            )
        else:
            # Update existing session
            self.sessions[session_key].authenticated = True
            self.sessions[session_key].gateway_config = gateway_config
            self.sessions[session_key].last_accessed = time.time()

    def is_authenticated(self, ctx: Context) -> bool:
        """
        Backward-compatible authentication check.
        """
        credentials = self.extract_credentials(ctx)
        gateway_key = credentials.gateway_key or credentials.api_key
        project_id = credentials.project_id
        user_id = credentials.user_id

        if not all([gateway_key, project_id, user_id]):
            return False

        # Get MCP config to get mcp_config_id
        local_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_config:
            return False

        mcp_config_id = local_config.get("mcp_config_id")
        if not mcp_config_id:
            return False

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        return self.is_session_authenticated(session_key)

    def require_authentication(self, ctx: Context) -> Tuple[bool, Dict[str, Any]]:
        """
        Backward-compatible authentication requirement check.

        Returns:
            Tuple[bool, Dict]: (is_authenticated, auth_result)
        """
        if self.is_authenticated(ctx):
            return True, {"status": "success", "message": "Already authenticated"}

        # Use async authenticate in sync context
        import asyncio

        auth_result = asyncio.run(self.authenticate(ctx))

        return auth_result.is_success, {
            "status": auth_result.status.value,
            "message": auth_result.message,
            "error": auth_result.error,
        }

    def get_authenticated_session(self, ctx: Context) -> Optional[SessionData]:
        """
        Backward-compatible authenticated session retrieval.
        """
        credentials = self.extract_credentials(ctx)
        gateway_key = credentials.gateway_key or credentials.api_key
        project_id = credentials.project_id
        user_id = credentials.user_id

        if not all([gateway_key, project_id, user_id]):
            return None

        local_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_config:
            return None

        mcp_config_id = local_config.get("mcp_config_id")
        if not mcp_config_id:
            return None

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        return self.get_session(session_key)

    def clear_session(self, ctx: Context) -> bool:
        """
        Backward-compatible session clearing.
        """
        credentials = self.extract_credentials(ctx)
        gateway_key = credentials.gateway_key or credentials.api_key
        project_id = credentials.project_id
        user_id = credentials.user_id

        if not all([gateway_key, project_id, user_id]):
            return False

        local_config = self.get_local_mcp_config(gateway_key, project_id, user_id)
        if not local_config:
            return False

        mcp_config_id = local_config.get("mcp_config_id")
        if not mcp_config_id:
            return False

        session_key = self.create_session_key(
            gateway_key, project_id, user_id, mcp_config_id
        )
        return self.delete_session(session_key)

    def get_session_gateway_config_key_suffix(self, credentials: Dict[str, Any]) -> str:
        """
        Backward-compatible config key suffix extraction.
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
        """
        Backward-compatible gateway config retrieval from session.
        """
        session = self.get_session(session_key)
        if not session:
            raise ValueError(f"Session {session_key} not found")

        if not session.authenticated:
            raise ValueError(f"Session {session_key} not authenticated")

        if not session.gateway_config:
            raise ValueError(f"Session {session_key} has no gateway configuration")

        return session.gateway_config


# ============================================================================
# Response Format Conversion Utilities
# ============================================================================


def convert_auth_result_to_legacy_format(auth_result: AuthResult) -> Dict[str, Any]:
    """
    Convert new AuthResult to legacy dict format for backward compatibility.

    Args:
        auth_result: New format AuthResult

    Returns:
        Dict in legacy format
    """
    if auth_result.is_success:
        return {
            "status": "success",
            "message": auth_result.message,
            "id": auth_result.session_id,
            "mcp_config": auth_result.mcp_config or [],
            "available_servers": {
                s["server_name"]: s for s in (auth_result.mcp_config or [])
            },
            "gateway_config": auth_result.gateway_config,
        }
    else:
        return {
            "status": "error",
            "message": auth_result.message,
            "error": auth_result.error or auth_result.message,
        }


def convert_legacy_format_to_auth_result(legacy_result: Dict[str, Any]) -> AuthResult:
    """
    Convert legacy dict format to new AuthResult format.

    Args:
        legacy_result: Legacy format dict

    Returns:
        AuthResult object
    """
    from secure_mcp_gateway.plugins.auth.base import AuthStatus

    if legacy_result.get("status") == "success":
        return AuthResult(
            status=AuthStatus.SUCCESS,
            authenticated=True,
            message=legacy_result.get("message", "Authentication successful"),
            user_id=legacy_result.get("gateway_config", {}).get("user_id"),
            project_id=legacy_result.get("gateway_config", {}).get("project_id"),
            session_id=legacy_result.get("id"),
            gateway_config=legacy_result.get("gateway_config", {}),
            mcp_config=legacy_result.get("mcp_config", []),
            metadata={"source": "legacy_conversion"},
        )
    else:
        return AuthResult(
            status=AuthStatus.ERROR,
            authenticated=False,
            message=legacy_result.get("message", "Authentication failed"),
            error=legacy_result.get("error"),
        )


# ============================================================================
# Global Instance
# ============================================================================

_auth_config_manager: Optional[AuthConfigManager] = None


def get_auth_config_manager() -> AuthConfigManager:
    """
    Get or create the global AuthConfigManager instance.

    Returns:
        AuthConfigManager: Global instance
    """
    global _auth_config_manager
    if _auth_config_manager is None:
        _auth_config_manager = AuthConfigManager()
    return _auth_config_manager


def initialize_auth_system(config: Dict[str, Any] = None) -> AuthConfigManager:
    """
    Initialize the authentication system with providers.

    Args:
        config: Configuration dict containing auth settings

    Returns:
        AuthConfigManager: Initialized manager
    """
    manager = get_auth_config_manager()

    if config is None:
        return manager

    # Use the new centralized plugin loader with fallback mechanism
    from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

    PluginLoader.load_plugin_providers(config, "auth", manager)

    return manager
