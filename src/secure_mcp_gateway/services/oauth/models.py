"""OAuth data models and types."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional


class OAuthVersion(Enum):
    """OAuth version."""

    OAUTH_2_0 = "2.0"
    OAUTH_2_1 = "2.1"


class OAuthGrantType(Enum):
    """OAuth grant types."""

    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class TokenStatus(Enum):
    """Token status."""

    VALID = "valid"
    EXPIRED = "expired"
    REFRESHING = "refreshing"
    INVALID = "invalid"


@dataclass
class OAuthConfig:
    """
    OAuth configuration for MCP servers.

    Supports both OAuth 2.0 and 2.1 specifications.
    """

    # Core configuration
    enabled: bool = False
    version: OAuthVersion = OAuthVersion.OAUTH_2_0
    grant_type: OAuthGrantType = OAuthGrantType.CLIENT_CREDENTIALS
    token_url: str = ""

    # Client credentials
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    # Optional parameters
    audience: Optional[str] = None
    organization: Optional[str] = None
    scope: Optional[str] = None

    # OAuth 2.1 specific
    resource: Optional[str] = None  # Resource Indicator (RFC 8707)
    use_pkce: bool = False  # PKCE for Authorization Code flow

    # Authorization Code Grant specific
    authorization_url: Optional[str] = None  # Authorization endpoint
    redirect_uri: Optional[str] = None  # Callback URL
    state: Optional[str] = None  # CSRF protection state
    code_verifier: Optional[str] = None  # PKCE code verifier (generated)
    code_challenge: Optional[str] = None  # PKCE code challenge (generated)
    code_challenge_method: str = "S256"  # S256 (SHA-256) or plain

    # Token management
    token_expiry_buffer: int = 300  # Refresh token 5 minutes before expiry

    # Security settings (OAuth 2.1 requirements)
    use_basic_auth: bool = True  # client_secret_basic vs client_secret_post
    enforce_https: bool = True  # Enforce HTTPS (required for OAuth 2.1)
    token_in_header_only: bool = True  # Never use query params (OAuth 2.1)

    # mTLS (Mutual TLS) settings (RFC 8705)
    use_mtls: bool = False  # Enable mutual TLS authentication
    client_cert_path: Optional[str] = None  # Path to client certificate (.pem)
    client_key_path: Optional[str] = None  # Path to client private key (.pem)
    ca_bundle_path: Optional[str] = None  # Path to CA bundle for server verification

    # Token revocation (RFC 7009)
    revocation_url: Optional[str] = None  # Token revocation endpoint

    # Scope validation
    validate_scopes: bool = True  # Validate returned token has requested scopes

    # Advanced settings
    additional_params: Dict[str, Any] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OAuthConfig":
        """
        Create OAuthConfig from dictionary.

        Args:
            data: Dictionary containing OAuth configuration

        Returns:
            OAuthConfig instance
        """
        # Parse version
        version_str = data.get("OAUTH_VERSION", "2.0")
        version = (
            OAuthVersion.OAUTH_2_1 if "2.1" in version_str else OAuthVersion.OAUTH_2_0
        )

        # Parse grant type
        grant_type_str = data.get("OAUTH_GRANT_TYPE", "client_credentials").lower()
        grant_type = OAuthGrantType.CLIENT_CREDENTIALS
        if grant_type_str == "authorization_code":
            grant_type = OAuthGrantType.AUTHORIZATION_CODE
        elif grant_type_str == "refresh_token":
            grant_type = OAuthGrantType.REFRESH_TOKEN

        return cls(
            enabled=data.get("enabled", False),
            version=version,
            grant_type=grant_type,
            token_url=data.get("OAUTH_TOKEN_URL", ""),
            client_id=data.get("OAUTH_CLIENT_ID"),
            client_secret=data.get("OAUTH_CLIENT_SECRET"),
            audience=data.get("OAUTH_AUDIENCE"),
            organization=data.get("OAUTH_ORGANIZATION"),
            scope=data.get("OAUTH_SCOPE"),
            resource=data.get("OAUTH_RESOURCE"),
            use_pkce=data.get("OAUTH_USE_PKCE", False),
            # Authorization Code Grant fields
            authorization_url=data.get("OAUTH_AUTHORIZATION_URL"),
            redirect_uri=data.get("OAUTH_REDIRECT_URI"),
            state=data.get("OAUTH_STATE"),
            code_verifier=data.get("OAUTH_CODE_VERIFIER"),
            code_challenge=data.get("OAUTH_CODE_CHALLENGE"),
            code_challenge_method=data.get("OAUTH_CODE_CHALLENGE_METHOD", "S256"),
            # Token management
            token_expiry_buffer=data.get("OAUTH_TOKEN_EXPIRY_BUFFER", 300),
            use_basic_auth=data.get("OAUTH_USE_BASIC_AUTH", True),
            enforce_https=data.get(
                "OAUTH_ENFORCE_HTTPS", version == OAuthVersion.OAUTH_2_1
            ),
            token_in_header_only=data.get(
                "OAUTH_TOKEN_IN_HEADER_ONLY", version == OAuthVersion.OAUTH_2_1
            ),
            # mTLS settings
            use_mtls=data.get("OAUTH_USE_MTLS", False),
            client_cert_path=data.get("OAUTH_CLIENT_CERT_PATH"),
            client_key_path=data.get("OAUTH_CLIENT_KEY_PATH"),
            ca_bundle_path=data.get("OAUTH_CA_BUNDLE_PATH"),
            # Token revocation
            revocation_url=data.get("OAUTH_REVOCATION_URL"),
            # Scope validation
            validate_scopes=data.get("OAUTH_VALIDATE_SCOPES", True),
            # Advanced
            additional_params=data.get("OAUTH_ADDITIONAL_PARAMS", {}),
            custom_headers=data.get("OAUTH_CUSTOM_HEADERS", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert OAuthConfig to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "enabled": self.enabled,
            "OAUTH_VERSION": self.version.value,
            "OAUTH_GRANT_TYPE": self.grant_type.value,
            "OAUTH_TOKEN_URL": self.token_url,
            "OAUTH_CLIENT_ID": self.client_id,
            "OAUTH_CLIENT_SECRET": "****" if self.client_secret else None,
            "OAUTH_AUDIENCE": self.audience,
            "OAUTH_ORGANIZATION": self.organization,
            "OAUTH_SCOPE": self.scope,
            "OAUTH_RESOURCE": self.resource,
            "OAUTH_USE_PKCE": self.use_pkce,
            "OAUTH_AUTHORIZATION_URL": self.authorization_url,
            "OAUTH_REDIRECT_URI": self.redirect_uri,
            "OAUTH_STATE": self.state[:10] + "..." if self.state else None,
            "OAUTH_CODE_VERIFIER": "****" if self.code_verifier else None,
            "OAUTH_CODE_CHALLENGE": self.code_challenge[:10] + "..."
            if self.code_challenge
            else None,
            "OAUTH_CODE_CHALLENGE_METHOD": self.code_challenge_method,
            "OAUTH_TOKEN_EXPIRY_BUFFER": self.token_expiry_buffer,
            "OAUTH_USE_BASIC_AUTH": self.use_basic_auth,
            "OAUTH_ENFORCE_HTTPS": self.enforce_https,
            "OAUTH_TOKEN_IN_HEADER_ONLY": self.token_in_header_only,
            "OAUTH_USE_MTLS": self.use_mtls,
            "OAUTH_CLIENT_CERT_PATH": self.client_cert_path,
            "OAUTH_CLIENT_KEY_PATH": self.client_key_path,
            "OAUTH_CA_BUNDLE_PATH": self.ca_bundle_path,
            "OAUTH_REVOCATION_URL": self.revocation_url,
            "OAUTH_VALIDATE_SCOPES": self.validate_scopes,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate OAuth configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.enabled:
            return True, None

        # Check required fields
        if not self.token_url or not self.token_url.strip():
            return False, "OAUTH_TOKEN_URL is required and cannot be empty"

        # Validate URL format
        if not self.token_url.startswith(("http://", "https://")):
            return False, "OAUTH_TOKEN_URL must start with http:// or https://"

        if self.grant_type == OAuthGrantType.CLIENT_CREDENTIALS:
            if not self.client_id or not self.client_id.strip():
                return (
                    False,
                    "OAUTH_CLIENT_ID is required and cannot be empty for client_credentials grant",
                )
            if not self.client_secret or not self.client_secret.strip():
                return (
                    False,
                    "OAUTH_CLIENT_SECRET is required and cannot be empty for client_credentials grant",
                )
        elif self.grant_type == OAuthGrantType.AUTHORIZATION_CODE:
            if not self.client_id or not self.client_id.strip():
                return (
                    False,
                    "OAUTH_CLIENT_ID is required and cannot be empty for authorization_code grant",
                )
            if not self.authorization_url or not self.authorization_url.strip():
                return (
                    False,
                    "OAUTH_AUTHORIZATION_URL is required and cannot be empty for authorization_code grant",
                )
            if not self.redirect_uri or not self.redirect_uri.strip():
                return (
                    False,
                    "OAUTH_REDIRECT_URI is required and cannot be empty for authorization_code grant",
                )
            # OAuth 2.1 requires PKCE for authorization code flow
            if self.version == OAuthVersion.OAUTH_2_1 and not self.use_pkce:
                return (
                    False,
                    "OAuth 2.1 requires PKCE for authorization_code grant (set OAUTH_USE_PKCE: true)",
                )
            # Validate authorization URL format
            if not self.authorization_url.startswith(("http://", "https://")):
                return (
                    False,
                    "OAUTH_AUTHORIZATION_URL must start with http:// or https://",
                )
            # Validate redirect URI format
            if not self.redirect_uri.startswith(
                ("http://", "https://", "http://localhost", "http://127.0.0.1")
            ):
                return (
                    False,
                    "OAUTH_REDIRECT_URI must be a valid URL (http:// or https://)",
                )

        # OAuth 2.1 HTTPS enforcement
        if self.version == OAuthVersion.OAUTH_2_1 and self.enforce_https:
            if not self.token_url.startswith("https://"):
                return False, "OAuth 2.1 requires HTTPS for token_url"

        # OAuth 2.0 HTTPS recommendation
        if self.version == OAuthVersion.OAUTH_2_0 and self.enforce_https:
            if not self.token_url.startswith("https://"):
                return (
                    False,
                    "HTTPS is required for token_url (OAuth 2.0 best practice)",
                )

        # mTLS validation
        if self.use_mtls:
            if not self.client_cert_path or not self.client_cert_path.strip():
                return False, "OAUTH_CLIENT_CERT_PATH is required when using mTLS"
            if not self.client_key_path or not self.client_key_path.strip():
                return False, "OAUTH_CLIENT_KEY_PATH is required when using mTLS"
            # CA bundle is optional

        return True, None


@dataclass
class OAuthToken:
    """
    OAuth access token with metadata.
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

    # Computed fields
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    # Metadata
    server_name: Optional[str] = None
    config_id: Optional[str] = None

    def __post_init__(self):
        """Calculate expiration time."""
        if self.expires_in and not self.expires_at:
            self.expires_at = self.created_at + timedelta(seconds=self.expires_in)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def is_expiring_soon(self, buffer_seconds: int = 300) -> bool:
        """
        Check if token is expiring soon.

        Args:
            buffer_seconds: Buffer time before expiry (default 5 minutes)

        Returns:
            True if token expires within buffer time
        """
        if not self.expires_at:
            return False
        buffer_time = datetime.now(timezone.utc) + timedelta(seconds=buffer_seconds)
        return buffer_time >= self.expires_at

    @property
    def status(self) -> TokenStatus:
        """Get token status."""
        if self.is_expired:
            return TokenStatus.EXPIRED
        return TokenStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "access_token": self.access_token[:20] + "..."
            if len(self.access_token) > 20
            else "***",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired,
            "status": self.status.value,
        }

    @classmethod
    def from_response(
        cls,
        response_data: Dict[str, Any],
        server_name: str = None,
        config_id: str = None,
    ) -> "OAuthToken":
        """
        Create OAuthToken from token endpoint response.

        Args:
            response_data: Response from token endpoint
            server_name: Name of the server
            config_id: Configuration ID

        Returns:
            OAuthToken instance
        """
        return cls(
            access_token=response_data["access_token"],
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in"),
            refresh_token=response_data.get("refresh_token"),
            scope=response_data.get("scope"),
            server_name=server_name,
            config_id=config_id,
        )


@dataclass
class OAuthError:
    """OAuth error response."""

    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
    status_code: Optional[int] = None

    @classmethod
    def from_response(
        cls, response_data: Dict[str, Any], status_code: int = None
    ) -> "OAuthError":
        """Create from error response."""
        return cls(
            error=response_data.get("error", "unknown_error"),
            error_description=response_data.get("error_description"),
            error_uri=response_data.get("error_uri"),
            status_code=status_code,
        )

    def __str__(self) -> str:
        """String representation."""
        msg = f"OAuth Error: {self.error}"
        if self.error_description:
            msg += f" - {self.error_description}"
        if self.status_code:
            msg += f" (HTTP {self.status_code})"
        return msg
