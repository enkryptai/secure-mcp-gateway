"""
Authentication Plugin System - Base Interfaces

This module defines the core abstractions for the authentication plugin system,
following SOLID principles to enable extensible, maintainable authentication
providers.

The system supports multiple authentication providers:
- Enkrypt API authentication
- OAuth 2.0
- JWT tokens
- API keys
- Custom authentication mechanisms

Design Principles:
- Single Responsibility: Each class has one clear purpose
- Open/Closed: Open for extension, closed for modification
- Liskov Substitution: All providers are interchangeable
- Interface Segregation: Separate concerns into focused interfaces
- Dependency Inversion: Depend on abstractions, not implementations
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol

# ============================================================================
# Enums
# ============================================================================


class AuthStatus(Enum):
    """Authentication status codes."""

    SUCCESS = "success"
    FAILURE = "failure"
    EXPIRED = "expired"
    INVALID_CREDENTIALS = "invalid_credentials"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class AuthMethod(Enum):
    """Authentication method types."""

    API_KEY = "api_key"
    OAUTH = "oauth"
    JWT = "jwt"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    CUSTOM = "custom"


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class AuthCredentials:
    """
    Authentication credentials container.

    Supports multiple credential types and sources.
    """

    # Primary credentials
    api_key: Optional[str] = None
    gateway_key: Optional[str] = None
    project_id: Optional[str] = None
    user_id: Optional[str] = None

    # OAuth/JWT
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None

    # Basic auth
    username: Optional[str] = None
    password: Optional[str] = None

    # Additional metadata
    headers: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Mask sensitive data in string representation."""
        self._masked_fields = {
            "api_key",
            "gateway_key",
            "access_token",
            "refresh_token",
            "password",
        }

    def __repr__(self) -> str:
        """Safe string representation with masked sensitive fields."""
        safe_dict = {}
        for key, value in self.__dict__.items():
            if key.startswith("_"):
                continue
            if key in self._masked_fields and value:
                safe_dict[key] = f"****{value[-4:]}" if len(value) > 4 else "****"
            else:
                safe_dict[key] = value
        return f"AuthCredentials({safe_dict})"


@dataclass
class AuthResult:
    """
    Authentication result containing status and user information.
    """

    status: AuthStatus
    authenticated: bool
    message: str

    # User/Session information
    user_id: Optional[str] = None
    project_id: Optional[str] = None
    session_id: Optional[str] = None

    # Configuration
    gateway_config: Optional[Dict[str, Any]] = None
    mcp_config: Optional[List[Dict[str, Any]]] = None

    # Permissions
    permissions: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """Check if authentication was successful."""
        return self.status == AuthStatus.SUCCESS and self.authenticated


@dataclass
class SessionData:
    """
    Session data for authenticated users.
    """

    session_id: str
    user_id: str
    project_id: Optional[str] = None

    authenticated: bool = False
    created_at: float = 0.0
    last_accessed: float = 0.0
    expires_at: Optional[float] = None

    gateway_config: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Core Interfaces
# ============================================================================


class AuthProvider(ABC):
    """
    Abstract base class for authentication providers.

    All authentication providers must implement this interface.
    """

    @abstractmethod
    def get_name(self) -> str:
        """
        Get the unique name of this provider.

        Returns:
            str: Provider name (e.g., "enkrypt", "oauth", "jwt")
        """
        pass

    @abstractmethod
    def get_version(self) -> str:
        """
        Get the version of this provider.

        Returns:
            str: Provider version
        """
        pass

    @abstractmethod
    def get_supported_methods(self) -> List[AuthMethod]:
        """
        Get the authentication methods supported by this provider.

        Returns:
            List[AuthMethod]: List of supported authentication methods
        """
        pass

    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate user with provided credentials.

        Args:
            credentials: Authentication credentials

        Returns:
            AuthResult: Authentication result
        """
        pass

    @abstractmethod
    async def validate_session(self, session_id: str) -> bool:
        """
        Validate if a session is still valid.

        Args:
            session_id: Session ID to validate

        Returns:
            bool: True if session is valid, False otherwise
        """
        pass

    @abstractmethod
    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh authentication for an existing session.

        Args:
            session_id: Existing session ID
            credentials: Credentials for refresh (e.g., refresh token)

        Returns:
            AuthResult: New authentication result
        """
        pass

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate provider configuration.

        Args:
            config: Configuration to validate

        Returns:
            bool: True if configuration is valid, False otherwise
        """
        return True

    def get_required_config_keys(self) -> List[str]:
        """
        Get list of required configuration keys.

        Returns:
            List[str]: List of required configuration keys
        """
        return []


class CredentialExtractor(Protocol):
    """
    Protocol for extracting credentials from different sources.
    """

    def extract(self, context: Any) -> AuthCredentials:
        """
        Extract credentials from the given context.

        Args:
            context: Source context (e.g., HTTP request, MCP context)

        Returns:
            AuthCredentials: Extracted credentials
        """
        ...


class SessionManager(Protocol):
    """
    Protocol for managing user sessions.
    """

    def create_session(self, auth_result: AuthResult) -> SessionData:
        """
        Create a new session from authentication result.

        Args:
            auth_result: Authentication result

        Returns:
            SessionData: Created session data
        """
        ...

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get session data by ID.

        Args:
            session_id: Session ID

        Returns:
            Optional[SessionData]: Session data if exists, None otherwise
        """
        ...

    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """
        Update session data.

        Args:
            session_id: Session ID
            data: Data to update

        Returns:
            bool: True if updated successfully, False otherwise
        """
        ...

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session ID

        Returns:
            bool: True if deleted successfully, False otherwise
        """
        ...

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            int: Number of sessions cleaned up
        """
        ...


class ConfigurationProvider(Protocol):
    """
    Protocol for providing gateway/user configuration.
    """

    def get_config(
        self, user_id: str, project_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get configuration for a user/project.

        Args:
            user_id: User ID
            project_id: Optional project ID

        Returns:
            Dict[str, Any]: Configuration data
        """
        ...


# ============================================================================
# Registry and Factory
# ============================================================================


class AuthProviderRegistry:
    """
    Registry for managing authentication providers.
    """

    def __init__(self):
        """Initialize the registry."""
        self._provider: Optional[AuthProvider] = None

    def register(self, provider: AuthProvider) -> None:
        """
        Register an authentication provider.

        Args:
            provider: Provider to register
        """
        self._provider = provider

    def unregister(self, name: str = None) -> None:
        """
        Unregister the authentication provider.

        Args:
            name: Provider name (for compatibility, but ignored since only one provider)
        """
        self._provider = None

    def get_provider(self, name: str = None) -> Optional[AuthProvider]:
        """
        Get the registered provider.

        Args:
            name: Provider name (for compatibility, but ignored since only one provider)

        Returns:
            Optional[AuthProvider]: Provider instance or None if not registered
        """
        return self._provider

    def list_providers(self) -> List[str]:
        """
        Get list of registered provider names.

        Returns:
            List containing the provider name if registered, empty list otherwise
        """
        if self._provider:
            return [self._provider.get_name()]
        return []

    def get_all_providers(self) -> Dict[str, AuthProvider]:
        """
        Get all registered providers.

        Returns:
            Dict[str, AuthProvider]: Dictionary containing the single provider if registered
        """
        if self._provider:
            return {self._provider.get_name(): self._provider}
        return {}


class AuthProviderFactory:
    """
    Factory for creating authentication provider instances.
    """

    @staticmethod
    def create_provider(
        provider_type: str, config: Dict[str, Any]
    ) -> Optional[AuthProvider]:
        """
        Create a provider instance.

        Args:
            provider_type: Type of provider to create
            config: Provider configuration

        Returns:
            Optional[AuthProvider]: Created provider instance, None if type unknown
        """
        # Import here to avoid circular dependencies
        from secure_mcp_gateway.plugins.auth.enkrypt_provider import (
            EnkryptAuthProvider,
        )

        if provider_type == "enkrypt":
            return EnkryptAuthProvider(**config)

        # Add more provider types as needed
        return None


# ============================================================================
# Helper Functions
# ============================================================================


def mask_sensitive_value(value: Optional[str], visible_chars: int = 4) -> str:
    """
    Mask a sensitive value, showing only last N characters.

    Args:
        value: Value to mask
        visible_chars: Number of characters to show at the end

    Returns:
        str: Masked value
    """
    if not value:
        return "****"
    if len(value) <= visible_chars:
        return "****"
    return f"****{value[-visible_chars:]}"
