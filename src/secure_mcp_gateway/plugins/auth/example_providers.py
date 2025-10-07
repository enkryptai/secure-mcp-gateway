"""
Example Authentication Providers

This module contains example implementations of different authentication providers
to demonstrate the plugin system's flexibility.

Providers included:
- OAuth2Provider - OAuth 2.0 authentication
- JWTProvider - JWT token authentication
- APIKeyProvider - Simple API key authentication
- BasicAuthProvider - HTTP Basic authentication
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

try:
    import jwt
except ImportError:
    jwt = None

import requests

from secure_mcp_gateway.plugins.auth.base import (
    AuthCredentials,
    AuthMethod,
    AuthProvider,
    AuthResult,
    AuthStatus,
)
from secure_mcp_gateway.utils import sys_print

# ============================================================================
# OAuth 2.0 Provider
# ============================================================================


class OAuth2Provider(AuthProvider):
    """
    OAuth 2.0 authentication provider.

    Supports various OAuth flows including authorization code and client credentials.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authorization_url: str,
        token_url: str,
        user_info_url: str = None,
        scopes: List[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize OAuth2 provider.

        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            authorization_url: URL for authorization
            token_url: URL for token exchange
            user_info_url: URL for user information
            scopes: List of OAuth scopes
            timeout: Request timeout
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.user_info_url = user_info_url
        self.scopes = scopes or []
        self.timeout = timeout

    def get_name(self) -> str:
        return "oauth2"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        return [AuthMethod.OAUTH, AuthMethod.BEARER_TOKEN]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate using OAuth access token.

        Args:
            credentials: Credentials containing access_token

        Returns:
            AuthResult: Authentication result
        """
        try:
            access_token = credentials.access_token

            if not access_token:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Access token required",
                    error="Missing access_token",
                )

            # Validate token by fetching user info
            if self.user_info_url:
                user_info = await self._get_user_info(access_token)
                if not user_info:
                    return AuthResult(
                        status=AuthStatus.INVALID_CREDENTIALS,
                        authenticated=False,
                        message="Invalid or expired token",
                        error="Token validation failed",
                    )

                return AuthResult(
                    status=AuthStatus.SUCCESS,
                    authenticated=True,
                    message="OAuth authentication successful",
                    user_id=user_info.get("sub") or user_info.get("id"),
                    metadata={"user_info": user_info, "provider": "oauth2"},
                )

            # If no user_info_url, assume token is valid
            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="OAuth authentication successful",
                metadata={"provider": "oauth2"},
            )

        except Exception as e:
            sys_print(f"[OAuth2Provider] Authentication error: {e}", is_error=True)
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="OAuth authentication failed",
                error=str(e),
            )

    async def _get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Get user information using access token.

        Args:
            access_token: OAuth access token

        Returns:
            Optional[Dict]: User information if successful
        """
        try:
            response = requests.get(
                self.user_info_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                return response.json()

            return None

        except Exception as e:
            sys_print(f"[OAuth2Provider] Error fetching user info: {e}", is_error=True)
            return None

    async def validate_session(self, session_id: str) -> bool:
        """Validate OAuth session."""
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh OAuth authentication using refresh token.

        Args:
            session_id: Current session ID
            credentials: Credentials containing refresh_token

        Returns:
            AuthResult: New authentication result
        """
        try:
            refresh_token = credentials.refresh_token

            if not refresh_token:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Refresh token required",
                    error="Missing refresh_token",
                )

            # Exchange refresh token for new access token
            response = requests.post(
                self.token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=self.timeout,
            )

            if response.status_code != 200:
                return AuthResult(
                    status=AuthStatus.EXPIRED,
                    authenticated=False,
                    message="Token refresh failed",
                    error="Invalid refresh token",
                )

            token_data = response.json()
            new_access_token = token_data.get("access_token")

            # Create new credentials with new access token
            new_credentials = AuthCredentials(access_token=new_access_token)

            return await self.authenticate(new_credentials)

        except Exception as e:
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Token refresh failed",
                error=str(e),
            )


# ============================================================================
# JWT Provider
# ============================================================================


class JWTProvider(AuthProvider):
    """
    JWT (JSON Web Token) authentication provider.

    Validates JWT tokens and extracts user information.
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        verify_exp: bool = True,
        verify_signature: bool = True,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        """
        Initialize JWT provider.

        Args:
            secret_key: Secret key for JWT validation
            algorithm: JWT algorithm (HS256, RS256, etc.)
            verify_exp: Verify token expiration
            verify_signature: Verify token signature
            audience: Expected audience claim
            issuer: Expected issuer claim
        """
        if jwt is None:
            raise ImportError(
                "PyJWT is required for JWTProvider. Install with: pip install PyJWT"
            )

        self.secret_key = secret_key
        self.algorithm = algorithm
        self.verify_exp = verify_exp
        self.verify_signature = verify_signature
        self.audience = audience
        self.issuer = issuer

    def get_name(self) -> str:
        return "jwt"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        return [AuthMethod.JWT, AuthMethod.BEARER_TOKEN]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate using JWT token.

        Args:
            credentials: Credentials containing access_token (JWT)

        Returns:
            AuthResult: Authentication result
        """
        try:
            token = credentials.access_token or credentials.api_key

            if not token:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="JWT token required",
                    error="Missing token",
                )

            # Decode and validate JWT
            try:
                payload = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    options={
                        "verify_exp": self.verify_exp,
                        "verify_signature": self.verify_signature,
                    },
                    audience=self.audience,
                    issuer=self.issuer,
                )
            except jwt.ExpiredSignatureError:
                return AuthResult(
                    status=AuthStatus.EXPIRED,
                    authenticated=False,
                    message="Token has expired",
                    error="Token expired",
                )
            except jwt.InvalidTokenError as e:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Invalid token",
                    error=str(e),
                )

            # Extract user information from payload
            user_id = payload.get("sub") or payload.get("user_id")

            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="JWT authentication successful",
                user_id=user_id,
                metadata={
                    "jwt_payload": payload,
                    "provider": "jwt",
                    "exp": payload.get("exp"),
                },
            )

        except Exception as e:
            sys_print(f"[JWTProvider] Authentication error: {e}", is_error=True)
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="JWT authentication failed",
                error=str(e),
            )

    async def validate_session(self, session_id: str) -> bool:
        """Validate JWT session."""
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh JWT authentication (re-decode token).

        Args:
            session_id: Current session ID
            credentials: Credentials containing JWT

        Returns:
            AuthResult: New authentication result
        """
        return await self.authenticate(credentials)


# ============================================================================
# API Key Provider
# ============================================================================


class APIKeyProvider(AuthProvider):
    """
    Simple API key authentication provider.

    Validates API keys against a predefined list or database.
    """

    def __init__(
        self,
        valid_keys: Dict[str, Dict[str, Any]] = None,
        key_validator: callable = None,
    ):
        """
        Initialize API key provider.

        Args:
            valid_keys: Dictionary mapping API keys to user info
            key_validator: Optional custom validation function
        """
        self.valid_keys = valid_keys or {}
        self.key_validator = key_validator

    def get_name(self) -> str:
        return "apikey"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        return [AuthMethod.API_KEY]

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate using API key.

        Args:
            credentials: Credentials containing api_key

        Returns:
            AuthResult: Authentication result
        """
        try:
            api_key = credentials.api_key or credentials.gateway_key

            if not api_key:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="API key required",
                    error="Missing api_key",
                )

            # Use custom validator if provided
            if self.key_validator:
                is_valid = await self.key_validator(api_key)
                if not is_valid:
                    return AuthResult(
                        status=AuthStatus.INVALID_CREDENTIALS,
                        authenticated=False,
                        message="Invalid API key",
                        error="Key validation failed",
                    )

                return AuthResult(
                    status=AuthStatus.SUCCESS,
                    authenticated=True,
                    message="API key authentication successful",
                    metadata={"provider": "apikey"},
                )

            # Check against valid keys
            if api_key not in self.valid_keys:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Invalid API key",
                    error="Key not found",
                )

            user_info = self.valid_keys[api_key]

            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="API key authentication successful",
                user_id=user_info.get("user_id"),
                project_id=user_info.get("project_id"),
                metadata={"provider": "apikey", "user_info": user_info},
            )

        except Exception as e:
            sys_print(f"[APIKeyProvider] Authentication error: {e}", is_error=True)
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="API key authentication failed",
                error=str(e),
            )

    async def validate_session(self, session_id: str) -> bool:
        """Validate API key session."""
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh API key authentication (re-validate key).

        Args:
            session_id: Current session ID
            credentials: Credentials containing API key

        Returns:
            AuthResult: New authentication result
        """
        return await self.authenticate(credentials)


# ============================================================================
# Basic Auth Provider
# ============================================================================


class BasicAuthProvider(AuthProvider):
    """
    HTTP Basic authentication provider.

    Validates username/password combinations.
    """

    def __init__(
        self,
        users: Dict[str, str] = None,
        password_validator: callable = None,
        hash_algorithm: str = "sha256",
    ):
        """
        Initialize Basic Auth provider.

        Args:
            users: Dictionary mapping usernames to password hashes
            password_validator: Optional custom password validation function
            hash_algorithm: Algorithm for password hashing
        """
        self.users = users or {}
        self.password_validator = password_validator
        self.hash_algorithm = hash_algorithm

    def get_name(self) -> str:
        return "basic-auth"

    def get_version(self) -> str:
        return "1.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        return [AuthMethod.BASIC_AUTH]

    def _hash_password(self, password: str) -> str:
        """Hash a password using the configured algorithm."""
        if self.hash_algorithm == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif self.hash_algorithm == "sha512":
            return hashlib.sha512(password.encode()).hexdigest()
        return password

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        """
        Authenticate using username and password.

        Args:
            credentials: Credentials containing username and password

        Returns:
            AuthResult: Authentication result
        """
        try:
            username = credentials.username
            password = credentials.password

            if not username or not password:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Username and password required",
                    error="Missing credentials",
                )

            # Use custom validator if provided
            if self.password_validator:
                is_valid = await self.password_validator(username, password)
                if not is_valid:
                    return AuthResult(
                        status=AuthStatus.INVALID_CREDENTIALS,
                        authenticated=False,
                        message="Invalid username or password",
                        error="Validation failed",
                    )

                return AuthResult(
                    status=AuthStatus.SUCCESS,
                    authenticated=True,
                    message="Basic auth successful",
                    user_id=username,
                    metadata={"provider": "basic-auth"},
                )

            # Check against stored users
            if username not in self.users:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Invalid username or password",
                    error="User not found",
                )

            # Verify password
            password_hash = self._hash_password(password)
            if password_hash != self.users[username]:
                return AuthResult(
                    status=AuthStatus.INVALID_CREDENTIALS,
                    authenticated=False,
                    message="Invalid username or password",
                    error="Password mismatch",
                )

            return AuthResult(
                status=AuthStatus.SUCCESS,
                authenticated=True,
                message="Basic auth successful",
                user_id=username,
                metadata={"provider": "basic-auth"},
            )

        except Exception as e:
            sys_print(f"[BasicAuthProvider] Authentication error: {e}", is_error=True)
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Basic auth failed",
                error=str(e),
            )

    async def validate_session(self, session_id: str) -> bool:
        """Validate basic auth session."""
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        """
        Refresh basic auth (re-authenticate).

        Args:
            session_id: Current session ID
            credentials: Credentials containing username/password

        Returns:
            AuthResult: New authentication result
        """
        return await self.authenticate(credentials)
