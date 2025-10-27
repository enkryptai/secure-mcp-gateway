"""OAuth 2.0/2.1 service implementation."""

import base64
import ssl
import time
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode

import aiohttp
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from secure_mcp_gateway.exceptions import (
    AuthenticationError,
    ErrorCode,
    ErrorContext,
    create_auth_error,
)
from secure_mcp_gateway.services.oauth.metrics import get_oauth_metrics
from secure_mcp_gateway.services.oauth.models import (
    OAuthConfig,
    OAuthError,
    OAuthGrantType,
    OAuthToken,
    OAuthVersion,
)
from secure_mcp_gateway.services.oauth.pkce import (
    generate_pkce_pair,
    generate_state,
    validate_code_verifier,
)
from secure_mcp_gateway.services.oauth.token_manager import (
    TokenManager,
    get_token_manager,
)
from secure_mcp_gateway.services.timeout import get_timeout_manager
from secure_mcp_gateway.utils import logger


class OAuthService:
    """
    OAuth 2.0/2.1 service for obtaining and managing access tokens.

    Supports:
    - Client Credentials grant (OAuth 2.0/2.1)
    - Authorization Code grant with PKCE (OAuth 2.1)
    - Token caching and refresh
    - OAuth 2.1 security requirements
    - Resource Indicators (RFC 8707)
    """

    def __init__(self, token_manager: Optional[TokenManager] = None):
        """
        Initialize OAuth service.

        Args:
            token_manager: Optional token manager instance
        """
        self.token_manager = token_manager or get_token_manager()
        self.timeout_manager = get_timeout_manager()
        self.metrics = get_oauth_metrics()
        logger.info("[OAuthService] Initialized")

    async def get_access_token(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
        config_id: str,
        project_id: str,
        force_refresh: bool = False,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get access token for server.

        Args:
            server_name: Name of the server (required)
            oauth_config: OAuth configuration (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)
            force_refresh: Force token refresh even if cached

        Returns:
            Tuple of (access_token, error_message)
        """
        # Validate configuration
        is_valid, error_msg = oauth_config.validate()
        if not is_valid:
            logger.error(
                f"[OAuthService] Invalid OAuth config for {server_name}: {error_msg}"
            )
            return None, error_msg

        # Check cache unless force refresh
        if not force_refresh:
            cached_token = await self.token_manager.get_token(
                server_name, oauth_config, config_id, project_id
            )
            if cached_token:
                logger.debug(f"[OAuthService] Using cached token for {server_name}")
                self.metrics.record_cache_hit()
                return cached_token.access_token, None
            else:
                self.metrics.record_cache_miss()

        # Obtain new token with retry logic
        logger.info(f"[OAuthService] Obtaining new token for {server_name}")
        start_time = time.time()

        try:
            if oauth_config.grant_type == OAuthGrantType.CLIENT_CREDENTIALS:
                # Use exponential backoff retry for network errors
                token = await self._client_credentials_flow_with_retry(
                    server_name, oauth_config
                )
            elif oauth_config.grant_type == OAuthGrantType.AUTHORIZATION_CODE:
                # Authorization Code flow requires user interaction
                # This should not be called directly - use generate_authorization_url first
                self.metrics.record_token_acquisition(False)
                return (
                    None,
                    "Authorization Code flow requires user authorization. "
                    "Use generate_authorization_url() to start the flow, "
                    "then exchange_authorization_code() after receiving the callback.",
                )
            else:
                self.metrics.record_token_acquisition(False)
                return None, f"Unsupported grant type: {oauth_config.grant_type.value}"

            latency_ms = (time.time() - start_time) * 1000

            if token:
                # Store in cache
                await self.token_manager.store_token(
                    server_name, token, config_id, project_id
                )
                self.metrics.record_token_acquisition(True, latency_ms)
                return token.access_token, None

            self.metrics.record_token_acquisition(False, latency_ms)
            return None, "Failed to obtain token"

        except RetryError as e:
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.record_token_acquisition(False, latency_ms)
            logger.error(
                f"[OAuthService] Token acquisition failed after retries for {server_name}: {e}"
            )
            return (
                None,
                f"Token acquisition failed after retries: {e.last_attempt.exception()}",
            )
        except AuthenticationError as e:
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.record_token_acquisition(False, latency_ms)
            logger.error(f"[OAuthService] Authentication error for {server_name}: {e}")
            return None, str(e)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.record_token_acquisition(False, latency_ms)
            logger.error(f"[OAuthService] Unexpected error for {server_name}: {e}")
            return None, f"Unexpected error: {e}"

    async def _client_credentials_flow_with_retry(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
    ) -> Optional[OAuthToken]:
        """
        Execute Client Credentials flow with exponential backoff retry.

        Retries on network errors only, not on authentication errors.

        Args:
            server_name: Server name
            oauth_config: OAuth configuration

        Returns:
            OAuthToken if successful

        Raises:
            RetryError: If all retries are exhausted
            AuthenticationError: If authentication fails (not retried)
        """
        async for attempt in AsyncRetrying(
            retry=retry_if_exception_type(aiohttp.ClientError),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            reraise=True,
        ):
            with attempt:
                if attempt.retry_state.attempt_number > 1:
                    logger.warning(
                        f"[OAuthService] Retrying token acquisition for {server_name}, "
                        f"attempt {attempt.retry_state.attempt_number}/3"
                    )
                return await self._client_credentials_flow(server_name, oauth_config)

    async def _client_credentials_flow(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
    ) -> Optional[OAuthToken]:
        """
        Execute Client Credentials flow.

        OAuth 2.0/2.1 compliant implementation.

        Args:
            server_name: Server name
            oauth_config: OAuth configuration

        Returns:
            OAuthToken if successful, None otherwise

        Raises:
            AuthenticationError: If authentication fails
        """
        logger.info(
            f"[OAuthService] Starting Client Credentials flow for {server_name} "
            f"(OAuth {oauth_config.version.value})"
        )

        # Build request
        headers, data = self._build_token_request(oauth_config)

        # Make request
        timeout_value = self.timeout_manager.get_timeout("auth")

        # Setup SSL context for mTLS if enabled
        ssl_context = self._create_ssl_context(oauth_config)

        # Generate correlation ID for request tracing
        correlation_id = str(uuid.uuid4())
        headers["X-Correlation-ID"] = correlation_id
        headers["X-Request-ID"] = correlation_id

        logger.debug(
            f"[OAuthService] Token request correlation_id={correlation_id} for {server_name}"
        )

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else None
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    oauth_config.token_url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout_value),
                ) as response:
                    # Handle JSON parsing errors
                    try:
                        response_data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError) as e:
                        logger.error(
                            f"[OAuthService] Failed to parse JSON response from {server_name}: {e}"
                        )
                        response_text = await response.text()
                        raise create_auth_error(
                            code=ErrorCode.AUTH_INVALID_CREDENTIALS,
                            message=f"OAuth server returned invalid JSON response: {response_text[:200]}",
                            context=ErrorContext(
                                operation="oauth_client_credentials",
                                additional_context={
                                    "server_name": server_name,
                                    "status_code": response.status,
                                },
                            ),
                        )

                    if response.status == 200:
                        token = OAuthToken.from_response(
                            response_data,
                            server_name=server_name,
                        )

                        # Validate scopes if requested
                        if oauth_config.validate_scopes and oauth_config.scope:
                            scope_valid = self._validate_token_scopes(
                                token, oauth_config.scope
                            )
                            if not scope_valid:
                                logger.warning(
                                    f"[OAuthService] Token scopes validation failed for {server_name}. "
                                    f"Requested: {oauth_config.scope}, Received: {token.scope}"
                                )

                        logger.info(
                            f"[OAuthService] Successfully obtained token for {server_name}, "
                            f"expires in {token.expires_in}s"
                        )
                        return token

                    # Handle error response
                    oauth_error = OAuthError.from_response(
                        response_data, response.status
                    )
                    logger.error(
                        f"[OAuthService] Token request failed for {server_name}: {oauth_error}"
                    )

                    raise create_auth_error(
                        code=ErrorCode.AUTH_INVALID_CREDENTIALS,
                        message=f"OAuth token request failed: {oauth_error}",
                        context=ErrorContext(
                            operation="oauth_client_credentials",
                            additional_context={
                                "server_name": server_name,
                                "oauth_version": oauth_config.version.value,
                                "status_code": response.status,
                            },
                        ),
                    )

        except aiohttp.ClientError as e:
            logger.error(f"[OAuthService] HTTP error for {server_name}: {e}")
            raise create_auth_error(
                code=ErrorCode.AUTH_SERVICE_UNAVAILABLE,
                message=f"Failed to connect to OAuth server: {e}",
                context=ErrorContext(operation="oauth_client_credentials"),
            )

    def _build_token_request(
        self, oauth_config: OAuthConfig
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Build token request headers and data.

        Implements OAuth 2.0/2.1 requirements:
        - OAuth 2.1: Prefer client_secret_basic (HTTP Basic Auth)
        - OAuth 2.0: Support both client_secret_basic and client_secret_post

        Args:
            oauth_config: OAuth configuration

        Returns:
            Tuple of (headers, data)
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        # Add custom headers
        headers.update(oauth_config.custom_headers)

        data = {
            "grant_type": oauth_config.grant_type.value,
        }

        # Client authentication
        if oauth_config.use_basic_auth:
            # client_secret_basic (RFC 6749 Section 2.3.1)
            # Preferred for OAuth 2.1
            credentials = f"{oauth_config.client_id}:{oauth_config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
            logger.debug("[OAuthService] Using client_secret_basic authentication")
        else:
            # client_secret_post (RFC 6749 Section 2.3.1)
            # Legacy method, not recommended for OAuth 2.1
            data["client_id"] = oauth_config.client_id
            data["client_secret"] = oauth_config.client_secret
            logger.debug("[OAuthService] Using client_secret_post authentication")

        # Add optional parameters
        if oauth_config.scope:
            data["scope"] = oauth_config.scope

        if oauth_config.audience:
            data["audience"] = oauth_config.audience

        if oauth_config.organization:
            data["organization"] = oauth_config.organization

        # OAuth 2.1: Resource Indicators (RFC 8707)
        if oauth_config.resource and oauth_config.version == OAuthVersion.OAUTH_2_1:
            data["resource"] = oauth_config.resource
            logger.debug(
                f"[OAuthService] Using resource indicator: {oauth_config.resource}"
            )

        # Additional custom parameters
        data.update(oauth_config.additional_params)

        return headers, data

    async def invalidate_token(
        self,
        server_name: str,
        config_id: str,
        project_id: str,
    ) -> None:
        """
        Invalidate cached token.

        Args:
            server_name: Server name (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)
        """
        await self.token_manager.invalidate_token(server_name, config_id, project_id)
        self.metrics.record_token_invalidation()

    async def refresh_token(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
        config_id: str,
        project_id: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Force refresh token.

        Args:
            server_name: Server name (required)
            oauth_config: OAuth configuration (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)

        Returns:
            Tuple of (access_token, error_message)
        """
        self.metrics.record_token_refresh()
        return await self.get_access_token(
            server_name, oauth_config, config_id, project_id, force_refresh=True
        )

    def get_authorization_header(self, access_token: str) -> Dict[str, str]:
        """
        Get Authorization header with access token.

        OAuth 2.1 compliant: Token in header only, never in query params.

        Args:
            access_token: Access token

        Returns:
            Dictionary with Authorization header
        """
        return {"Authorization": f"Bearer {access_token}"}

    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from cache.

        Returns:
            Number of tokens removed
        """
        return await self.token_manager.cleanup_expired_tokens()

    def get_token_info(
        self,
        server_name: str,
        config_id: str,
        project_id: str,
    ) -> Optional[Dict]:
        """
        Get cached token information.

        Args:
            server_name: Server name (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)

        Returns:
            Token info dictionary or None
        """
        return self.token_manager.get_token_info(server_name, config_id, project_id)

    def get_metrics(self) -> Dict:
        """
        Get OAuth service metrics.

        Returns:
            Dictionary of metrics
        """
        metrics = self.metrics.get_metrics()
        metrics["active_tokens"] = self.token_manager.token_count
        return metrics

    def _create_ssl_context(
        self, oauth_config: OAuthConfig
    ) -> Optional[ssl.SSLContext]:
        """
        Create SSL context for mTLS if enabled.

        Args:
            oauth_config: OAuth configuration

        Returns:
            SSL context or None
        """
        if not oauth_config.use_mtls:
            return None

        logger.info("[OAuthService] Creating mTLS SSL context")

        try:
            ssl_context = ssl.create_default_context()

            # Load client certificate and key
            if oauth_config.client_cert_path and oauth_config.client_key_path:
                cert_path = Path(oauth_config.client_cert_path).expanduser()
                key_path = Path(oauth_config.client_key_path).expanduser()

                if not cert_path.exists():
                    logger.error(
                        f"[OAuthService] Client certificate not found: {cert_path}"
                    )
                    return None

                if not key_path.exists():
                    logger.error(f"[OAuthService] Client key not found: {key_path}")
                    return None

                ssl_context.load_cert_chain(
                    certfile=str(cert_path), keyfile=str(key_path)
                )
                logger.info("[OAuthService] Loaded client certificate and key for mTLS")

            # Load CA bundle if provided
            if oauth_config.ca_bundle_path:
                ca_path = Path(oauth_config.ca_bundle_path).expanduser()
                if ca_path.exists():
                    ssl_context.load_verify_locations(cafile=str(ca_path))
                    logger.info(f"[OAuthService] Loaded CA bundle: {ca_path}")
                else:
                    logger.warning(
                        f"[OAuthService] CA bundle not found: {ca_path}, using default"
                    )

            return ssl_context

        except Exception as e:
            logger.error(f"[OAuthService] Failed to create SSL context: {e}")
            return None

    def _validate_token_scopes(self, token: OAuthToken, requested_scopes: str) -> bool:
        """
        Validate that token contains requested scopes.

        Args:
            token: OAuth token
            requested_scopes: Space-separated requested scopes

        Returns:
            True if token has all requested scopes
        """
        if not token.scope:
            logger.warning("[OAuthService] Token has no scopes")
            return False

        # Parse scopes
        requested_scope_set = set(requested_scopes.split())
        token_scope_set = set(token.scope.split())

        # Check if all requested scopes are in token
        if not requested_scope_set.issubset(token_scope_set):
            missing_scopes = requested_scope_set - token_scope_set
            logger.warning(f"[OAuthService] Token missing scopes: {missing_scopes}")
            return False

        return True

    async def revoke_token(
        self,
        server_name: str,
        token: str,
        oauth_config: OAuthConfig,
        token_type_hint: str = "access_token",
    ) -> Tuple[bool, Optional[str]]:
        """
        Revoke OAuth token (RFC 7009).

        Args:
            server_name: Server name
            token: Token to revoke
            oauth_config: OAuth configuration
            token_type_hint: Type of token (access_token or refresh_token)

        Returns:
            Tuple of (success, error_message)
        """
        if not oauth_config.revocation_url:
            return False, "Token revocation not configured (no revocation_url)"

        logger.info(f"[OAuthService] Revoking token for {server_name}")

        # Build request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        # Add custom headers
        headers.update(oauth_config.custom_headers)

        # Add correlation ID
        correlation_id = str(uuid.uuid4())
        headers["X-Correlation-ID"] = correlation_id
        headers["X-Request-ID"] = correlation_id

        data = {
            "token": token,
            "token_type_hint": token_type_hint,
        }

        # Client authentication
        if oauth_config.use_basic_auth:
            credentials = f"{oauth_config.client_id}:{oauth_config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        else:
            data["client_id"] = oauth_config.client_id
            data["client_secret"] = oauth_config.client_secret

        # Setup SSL context for mTLS if enabled
        ssl_context = self._create_ssl_context(oauth_config)
        timeout_value = self.timeout_manager.get_timeout("auth")

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else None
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    oauth_config.revocation_url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout_value),
                ) as response:
                    # RFC 7009: Revocation endpoint returns 200 on success
                    if response.status == 200:
                        logger.info(
                            f"[OAuthService] Successfully revoked token for {server_name}"
                        )
                        return True, None
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"[OAuthService] Token revocation failed for {server_name}: "
                            f"HTTP {response.status} - {error_text[:200]}"
                        )
                        return False, f"Revocation failed: HTTP {response.status}"

        except aiohttp.ClientError as e:
            logger.error(f"[OAuthService] HTTP error during revocation: {e}")
            return False, f"Network error: {e}"
        except Exception as e:
            logger.error(f"[OAuthService] Unexpected error during revocation: {e}")
            return False, f"Unexpected error: {e}"

    def generate_authorization_url(
        self,
        oauth_config: OAuthConfig,
        state: Optional[str] = None,
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """
        Generate authorization URL for Authorization Code flow.

        This is the first step in the Authorization Code grant flow.
        The user should be redirected to this URL to authorize the application.

        Args:
            oauth_config: OAuth configuration
            state: Optional state parameter (generated if not provided)

        Returns:
            Tuple of (authorization_url, state, code_verifier, code_challenge)

        Raises:
            ValueError: If required configuration is missing
        """
        if not oauth_config.authorization_url:
            raise ValueError(
                "OAUTH_AUTHORIZATION_URL is required for authorization code flow"
            )

        if not oauth_config.redirect_uri:
            raise ValueError(
                "OAUTH_REDIRECT_URI is required for authorization code flow"
            )

        # Generate state for CSRF protection
        if not state:
            state = generate_state()

        logger.info(
            f"[OAuthService] Generating authorization URL for OAuth {oauth_config.version.value}"
        )

        # Build base parameters
        params = {
            "response_type": "code",
            "client_id": oauth_config.client_id,
            "redirect_uri": oauth_config.redirect_uri,
            "state": state,
        }

        # Add scope if provided
        if oauth_config.scope:
            params["scope"] = oauth_config.scope

        # Add audience if provided (Auth0, etc.)
        if oauth_config.audience:
            params["audience"] = oauth_config.audience

        # Add organization if provided (Auth0, etc.)
        if oauth_config.organization:
            params["organization"] = oauth_config.organization

        # Generate PKCE parameters
        code_verifier = None
        code_challenge = None

        if oauth_config.use_pkce:
            code_verifier, code_challenge = generate_pkce_pair(
                method=oauth_config.code_challenge_method
            )
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = oauth_config.code_challenge_method

            logger.info(
                f"[OAuthService] Generated PKCE challenge using {oauth_config.code_challenge_method}"
            )
        elif oauth_config.version == OAuthVersion.OAUTH_2_1:
            logger.warning(
                "[OAuthService] OAuth 2.1 requires PKCE for authorization code flow, "
                "but use_pkce is False"
            )

        # Build authorization URL
        auth_url = f"{oauth_config.authorization_url}?{urlencode(params)}"

        logger.info(
            f"[OAuthService] Generated authorization URL with state={state[:10]}..."
        )

        return auth_url, state, code_verifier, code_challenge

    async def exchange_authorization_code(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
        authorization_code: str,
        code_verifier: Optional[str] = None,
        state: Optional[str] = None,
        expected_state: Optional[str] = None,
        config_id: str = None,
        project_id: str = None,
    ) -> Tuple[Optional[OAuthToken], Optional[str]]:
        """
        Exchange authorization code for access token.

        This is the second step in the Authorization Code grant flow,
        called after the user has authorized the application and been
        redirected back to the redirect_uri with an authorization code.

        Args:
            server_name: Server name
            oauth_config: OAuth configuration
            authorization_code: Authorization code from callback
            code_verifier: PKCE code verifier (required if use_pkce=True)
            state: State parameter from callback
            expected_state: Expected state value for CSRF protection
            config_id: MCP config ID
            project_id: Project ID

        Returns:
            Tuple of (OAuthToken, error_message)
        """
        logger.info(f"[OAuthService] Exchanging authorization code for {server_name}")

        # Validate state for CSRF protection
        if expected_state and state != expected_state:
            return (
                None,
                f"State mismatch: expected {expected_state[:10]}..., got {state[:10] if state else 'None'}...",
            )

        # Validate PKCE
        if oauth_config.use_pkce:
            if not code_verifier:
                return None, "PKCE code_verifier is required but not provided"

            if not validate_code_verifier(code_verifier):
                return None, "Invalid PKCE code_verifier format"

            logger.info(f"[OAuthService] Using PKCE code verifier for {server_name}")

        # Build token request
        headers, data = self._build_authorization_code_token_request(
            oauth_config, authorization_code, code_verifier
        )

        # Make token request
        timeout_value = self.timeout_manager.get_timeout("auth")
        ssl_context = self._create_ssl_context(oauth_config)

        # Generate correlation ID
        correlation_id = str(uuid.uuid4())
        headers["X-Correlation-ID"] = correlation_id
        headers["X-Request-ID"] = correlation_id

        logger.debug(f"[OAuthService] Token exchange correlation_id={correlation_id}")

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else None
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    oauth_config.token_url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout_value),
                ) as response:
                    try:
                        response_data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError) as e:
                        logger.error(
                            f"[OAuthService] Failed to parse JSON response: {e}"
                        )
                        response_text = await response.text()
                        return None, f"Invalid JSON response: {response_text[:200]}"

                    if response.status == 200:
                        token = OAuthToken.from_response(
                            response_data,
                            server_name=server_name,
                            config_id=config_id,
                        )

                        # Validate scopes
                        if oauth_config.validate_scopes and oauth_config.scope:
                            scope_valid = self._validate_token_scopes(
                                token, oauth_config.scope
                            )
                            if not scope_valid:
                                logger.warning(
                                    f"[OAuthService] Token scopes validation failed for {server_name}. "
                                    f"Requested: {oauth_config.scope}, Received: {token.scope}"
                                )

                        logger.info(
                            f"[OAuthService] Successfully obtained token for {server_name}, "
                            f"expires in {token.expires_in}s"
                        )

                        # Cache the token
                        if config_id and project_id:
                            await self.token_manager.store_token(
                                server_name, token, config_id, project_id
                            )

                        return token, None

                    # Handle error response
                    oauth_error = OAuthError.from_response(
                        response_data, response.status
                    )
                    logger.error(
                        f"[OAuthService] Token exchange failed for {server_name}: {oauth_error}"
                    )

                    return None, str(oauth_error)

        except aiohttp.ClientError as e:
            logger.error(f"[OAuthService] HTTP error during token exchange: {e}")
            return None, f"Failed to connect to OAuth server: {e}"
        except Exception as e:
            logger.error(f"[OAuthService] Unexpected error during token exchange: {e}")
            return None, f"Unexpected error: {e}"

    def _build_authorization_code_token_request(
        self,
        oauth_config: OAuthConfig,
        authorization_code: str,
        code_verifier: Optional[str] = None,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Build token request for authorization code exchange.

        Args:
            oauth_config: OAuth configuration
            authorization_code: Authorization code from callback
            code_verifier: PKCE code verifier (if using PKCE)

        Returns:
            Tuple of (headers, data)
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        # Add custom headers
        headers.update(oauth_config.custom_headers)

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": oauth_config.redirect_uri,
            "client_id": oauth_config.client_id,
        }

        # Add PKCE code verifier if using PKCE
        if oauth_config.use_pkce and code_verifier:
            data["code_verifier"] = code_verifier
            logger.debug("[OAuthService] Including PKCE code_verifier in token request")

        # Client authentication
        # For authorization code flow, client_secret may be optional (public clients)
        if oauth_config.client_secret:
            if oauth_config.use_basic_auth:
                # client_secret_basic (RFC 6749 Section 2.3.1)
                credentials = f"{oauth_config.client_id}:{oauth_config.client_secret}"
                encoded_credentials = base64.b64encode(credentials.encode()).decode()
                headers["Authorization"] = f"Basic {encoded_credentials}"
                logger.debug("[OAuthService] Using client_secret_basic authentication")
            else:
                # client_secret_post (RFC 6749 Section 2.3.1)
                data["client_secret"] = oauth_config.client_secret
                logger.debug("[OAuthService] Using client_secret_post authentication")
        else:
            logger.info("[OAuthService] No client_secret provided (public client)")

        # Add optional parameters
        if oauth_config.audience:
            data["audience"] = oauth_config.audience

        if oauth_config.organization:
            data["organization"] = oauth_config.organization

        # OAuth 2.1: Resource Indicators (RFC 8707)
        if oauth_config.resource and oauth_config.version == OAuthVersion.OAUTH_2_1:
            data["resource"] = oauth_config.resource

        # Additional custom parameters
        data.update(oauth_config.additional_params)

        return headers, data


# Global OAuth service instance
_oauth_service: Optional[OAuthService] = None


def get_oauth_service() -> OAuthService:
    """
    Get global OAuth service instance.

    Returns:
        OAuthService instance
    """
    global _oauth_service
    if _oauth_service is None:
        _oauth_service = OAuthService()
    return _oauth_service


def reset_oauth_service() -> None:
    """Reset global OAuth service (for testing)."""
    global _oauth_service
    _oauth_service = None
