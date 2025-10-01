"""
Authentication Configuration Manager

Manages authentication provider configuration and integrates with the gateway.
Provides utilities for registering providers, extracting credentials, and
managing sessions.
"""

import time
from typing import Any, Dict, List, Optional

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
        Get a provider by name.

        Args:
            name: Provider name (None for default)

        Returns:
            Optional[AuthProvider]: Provider if found
        """
        if name is None:
            name = self.default_provider
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
        Authenticate a request using the specified provider.

        Args:
            ctx: MCP context
            provider_name: Provider to use (None for default)

        Returns:
            AuthResult: Authentication result
        """
        # Extract credentials
        credentials = self.extract_credentials(ctx)

        # Get provider
        provider = self.get_provider(provider_name)
        if not provider:
            return AuthResult(
                status="error",
                authenticated=False,
                message=f"Provider '{provider_name or self.default_provider}' not found",
                error="Provider not registered",
            )

        # Authenticate
        result = await provider.authenticate(credentials)

        # Create session if successful
        if result.is_success:
            session_data = self._create_session(result)
            self.sessions[session_data.session_id] = session_data

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

    # Register Enkrypt provider by default
    enkrypt_api_key = config.get("enkrypt_api_key")
    enkrypt_base_url = config.get("enkrypt_base_url", "https://api.enkryptai.com")
    enkrypt_use_remote = config.get("enkrypt_use_remote_mcp_config", False)

    if enkrypt_api_key or not enkrypt_use_remote:
        # Check if enkrypt provider is already registered
        if "enkrypt" not in manager.list_providers():
            from secure_mcp_gateway.plugins.auth.enkrypt_provider import (
                EnkryptAuthProvider,
            )

            provider = EnkryptAuthProvider(
                api_key=enkrypt_api_key,
                base_url=enkrypt_base_url,
                use_remote_config=enkrypt_use_remote,
            )
            manager.register_provider(provider)
            sys_print("✓ Registered Enkrypt auth provider")
        else:
            sys_print("i Enkrypt auth provider already registered")

    # Register additional providers from config
    auth_plugins = config.get("auth_plugins", {})

    if auth_plugins.get("enabled", False):
        sys_print("Loading auth plugins from config...")

        from secure_mcp_gateway.plugins.provider_loader import (
            create_provider_from_config,
        )

        for provider_config in auth_plugins.get("providers", []):
            provider_name = provider_config.get("name")
            provider_class = provider_config.get("class")
            provider_cfg = provider_config.get("config", {})

            sys_print(f"Loading provider: {provider_name}")

            try:
                # Skip if already registered
                if provider_name in manager.list_providers():
                    sys_print(f"[i] Provider {provider_name} already registered")
                    continue

                if not provider_class:
                    sys_print(
                        f"Provider '{provider_name}' must have 'class' field",
                        is_error=True,
                    )
                    continue

                provider = create_provider_from_config(
                    {
                        "name": provider_name,
                        "class": provider_class,
                        "config": provider_cfg,
                    },
                    plugin_type="auth",
                )
                manager.register_provider(provider)
                sys_print(f"✓ Registered provider: {provider_name}")

            except Exception as e:
                sys_print(
                    f"Error registering provider {provider_name}: {e}", is_error=True
                )

    return manager
