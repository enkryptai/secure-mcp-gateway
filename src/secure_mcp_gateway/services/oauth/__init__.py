"""OAuth 2.0/2.1 services for MCP servers."""

from secure_mcp_gateway.services.oauth.integration import (
    get_oauth_headers,
    inject_oauth_into_args,
    inject_oauth_into_env,
    invalidate_server_oauth_token,
    prepare_oauth_for_server,
    refresh_server_oauth_token,
    validate_oauth_config,
)
from secure_mcp_gateway.services.oauth.metrics import OAuthMetrics, get_oauth_metrics
from secure_mcp_gateway.services.oauth.models import (
    OAuthConfig,
    OAuthError,
    OAuthGrantType,
    OAuthToken,
    OAuthVersion,
    TokenStatus,
)
from secure_mcp_gateway.services.oauth.oauth_service import (
    OAuthService,
    get_oauth_service,
    reset_oauth_service,
)
from secure_mcp_gateway.services.oauth.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
    generate_state,
    validate_code_challenge,
    validate_code_verifier,
    verify_code_challenge,
)
from secure_mcp_gateway.services.oauth.remote_callback import (
    authorize_with_auto_detection,
    authorize_with_remote_callback,
    is_remote_callback,
)
from secure_mcp_gateway.services.oauth.token_manager import (
    TokenManager,
    get_token_manager,
)
from secure_mcp_gateway.services.oauth.validation import (
    OAuthConfigValidator,
    check_oauth_compliance,
)

__all__ = [
    # Models
    "OAuthConfig",
    "OAuthToken",
    "OAuthError",
    "OAuthVersion",
    "OAuthGrantType",
    "TokenStatus",
    # Services
    "OAuthService",
    "get_oauth_service",
    "reset_oauth_service",
    "TokenManager",
    "get_token_manager",
    # Integration
    "prepare_oauth_for_server",
    "inject_oauth_into_env",
    "inject_oauth_into_args",
    "get_oauth_headers",
    "refresh_server_oauth_token",
    "invalidate_server_oauth_token",
    "validate_oauth_config",
    # PKCE
    "generate_code_verifier",
    "generate_code_challenge",
    "generate_pkce_pair",
    "generate_state",
    "validate_code_verifier",
    "validate_code_challenge",
    "verify_code_challenge",
    # Validation
    "OAuthConfigValidator",
    "check_oauth_compliance",
    # Metrics
    "OAuthMetrics",
    "get_oauth_metrics",
    # Remote Callback
    "authorize_with_auto_detection",
    "authorize_with_remote_callback",
    "is_remote_callback",
]
