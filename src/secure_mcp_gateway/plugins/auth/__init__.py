"""
Authentication Plugin System

A flexible, extensible authentication system following SOLID principles.

This package provides:
- Multiple authentication providers (Enkrypt, OAuth, JWT, API keys, etc.)
- Pluggable architecture for custom auth providers
- Session management
- Credential extraction
- Configuration management

Example Usage:
    ```python
    from secure_mcp_gateway.plugins.auth import (
        initialize_auth_system,
        get_auth_config_manager,
        AuthCredentials,
        AuthResult,
    )

    # Initialize system
    config = {"enkrypt_api_key": "your-key"}
    initialize_auth_system(config)

    # Get manager
    manager = get_auth_config_manager()

    # Register custom provider
    manager.register_provider(MyCustomProvider())

    # Authenticate
    result = await manager.authenticate(ctx, provider_name="enkrypt")
    ```
"""

# Core interfaces and data models
from .base import (
    # Data models
    AuthCredentials,
    AuthMethod,
    # Interfaces
    AuthProvider,
    AuthProviderFactory,
    # Registry and Factory
    AuthProviderRegistry,
    AuthResult,
    # Enums
    AuthStatus,
    ConfigurationProvider,
    CredentialExtractor,
    SessionData,
    SessionManager,
    # Utilities
    mask_sensitive_value,
)

# Configuration management
from .config_manager import (
    AuthConfigManager,
    get_auth_config_manager,
    initialize_auth_system,
)

# Providers
from .enkrypt_provider import EnkryptAuthProvider

__all__ = [
    # Enums
    "AuthStatus",
    "AuthMethod",
    # Data models
    "AuthCredentials",
    "AuthResult",
    "SessionData",
    # Interfaces
    "AuthProvider",
    "CredentialExtractor",
    "SessionManager",
    "ConfigurationProvider",
    # Registry and Factory
    "AuthProviderRegistry",
    "AuthProviderFactory",
    # Configuration
    "AuthConfigManager",
    "get_auth_config_manager",
    "initialize_auth_system",
    # Providers
    "EnkryptAuthProvider",
    # Utilities
    "mask_sensitive_value",
]

__version__ = "1.0.0"
