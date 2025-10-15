"""OAuth 2.0/2.1 service for MCP Gateway."""

from secure_mcp_gateway.services.oauth.integration import (
    get_oauth_headers,
    inject_oauth_into_args,
    inject_oauth_into_env,
    invalidate_server_oauth_token,
    prepare_oauth_for_server,
    refresh_server_oauth_token,
    validate_oauth_config,
)
from secure_mcp_gateway.services.oauth.metrics import (
    OAuthMetrics,
    get_oauth_metrics,
)
from secure_mcp_gateway.services.oauth.models import (
    OAuthConfig,
    OAuthGrantType,
    OAuthToken,
    OAuthVersion,
)
from secure_mcp_gateway.services.oauth.oauth_service import (
    OAuthService,
    get_oauth_service,
)
from secure_mcp_gateway.services.oauth.token_manager import (
    TokenManager,
    get_token_manager,
)

__all__ = [
    # Services
    "OAuthService",
    "TokenManager",
    "OAuthMetrics",
    "get_oauth_service",
    "get_token_manager",
    "get_oauth_metrics",
    # Models
    "OAuthConfig",
    "OAuthToken",
    "OAuthVersion",
    "OAuthGrantType",
    # Integration utilities
    "prepare_oauth_for_server",
    "inject_oauth_into_env",
    "inject_oauth_into_args",
    "get_oauth_headers",
    "refresh_server_oauth_token",
    "invalidate_server_oauth_token",
    "validate_oauth_config",
]
