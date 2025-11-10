"""
Centralized OAuth callback support for app.enkryptai.com.

This module provides utilities for OAuth Authorization Code flow
using a centralized callback URL (https://app.enkryptai.com/oauth/callback)
that relays authorization codes back to individual gateway instances.
"""

import base64
import json
import time
from typing import Optional, Tuple
from urllib.parse import urlencode, urlparse

from secure_mcp_gateway.services.oauth import OAuthConfig
from secure_mcp_gateway.services.oauth.oauth_service import get_oauth_service
from secure_mcp_gateway.services.oauth.pkce import generate_pkce_pair, generate_state
from secure_mcp_gateway.utils import logger


def get_gateway_base_url() -> str:
    """
    Get the base URL of this gateway instance.

    This URL is where the centralized callback page will relay
    the authorization code.

    Priority:
    1. ENKRYPT_GATEWAY_URL environment variable
    2. Auto-detect from running API server
    3. Default to https://localhost:8001

    Returns:
        Gateway base URL (e.g., "https://my-gateway.com")
    """
    import os

    # Check environment variable first
    gateway_url = os.getenv("ENKRYPT_GATEWAY_URL")
    if gateway_url:
        logger.info(f"[OAuth Centralized] Using gateway URL from env: {gateway_url}")
        return gateway_url.rstrip("/")

    # Try to detect from running server
    # (In a real implementation, this would check the actual server config)
    try:
        from secure_mcp_gateway.utils import get_common_config

        config = get_common_config()
        gateway_host = config.get("enkrypt_gateway_host", "localhost")
        gateway_port = config.get("enkrypt_api_port", 8001)

        # Use HTTPS by default for production
        protocol = "https" if gateway_host != "localhost" else "http"
        gateway_url = f"{protocol}://{gateway_host}:{gateway_port}"

        logger.info(f"[OAuth Centralized] Using gateway URL from config: {gateway_url}")
        return gateway_url

    except Exception as e:
        logger.warning(f"[OAuth Centralized] Failed to detect gateway URL: {e}")

    # Default fallback
    default_url = "http://localhost:8001"
    logger.info(f"[OAuth Centralized] Using default gateway URL: {default_url}")
    return default_url


def build_centralized_state(
    gateway_url: str,
    nonce: str,
    pkce_verifier: Optional[str] = None,
) -> str:
    """
    Build state parameter for centralized OAuth callback.

    The state parameter is base64-encoded JSON containing:
    - gateway_url: URL of this gateway instance
    - nonce: Random CSRF token
    - timestamp: Current timestamp (for expiration)
    - pkce_verifier: PKCE code verifier (optional)

    Args:
        gateway_url: Base URL of this gateway instance
        nonce: Random CSRF protection token
        pkce_verifier: Optional PKCE code verifier

    Returns:
        Base64-encoded JSON state parameter

    Example:
        >>> state = build_centralized_state(
        ...     "https://my-gateway.com",
        ...     "abc123xyz",
        ...     "pkce_verifier_string"
        ... )
        >>> # state = "eyJnYXRld2F5X3VybCI6Imh0dHBzOi8vbXktZ2F0..."
    """
    state_data = {
        "gateway_url": gateway_url,
        "nonce": nonce,
        "timestamp": int(time.time() * 1000),  # Milliseconds
    }

    if pkce_verifier:
        state_data["pkce_verifier"] = pkce_verifier

    # Encode as base64 URL-safe JSON
    state_json = json.dumps(state_data, separators=(",", ":"))
    state_b64 = base64.urlsafe_b64encode(state_json.encode()).decode()

    return state_b64


def parse_centralized_state(state: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Parse and validate centralized OAuth state parameter.

    Args:
        state: Base64-encoded state parameter

    Returns:
        Tuple of (state_dict, error_message)

    Example:
        >>> state_dict, error = parse_centralized_state(state)
        >>> if error:
        ...     print(f"Invalid state: {error}")
        >>> else:
        ...     print(f"Gateway URL: {state_dict['gateway_url']}")
    """
    if not state:
        return None, "State parameter is required"

    try:
        # Decode base64
        state_json = base64.urlsafe_b64decode(state.encode()).decode()
        state_dict = json.loads(state_json)

        # Validate required fields
        if "gateway_url" not in state_dict:
            return None, "State missing required field: gateway_url"

        if "nonce" not in state_dict:
            return None, "State missing required field: nonce"

        # Validate gateway URL
        try:
            parsed = urlparse(state_dict["gateway_url"])
            if not parsed.scheme or not parsed.netloc:
                return None, "Invalid gateway_url in state"
        except Exception:
            return None, "Malformed gateway_url in state"

        # Check timestamp if present (30 second max)
        if "timestamp" in state_dict:
            state_age_ms = (time.time() * 1000) - state_dict["timestamp"]
            if state_age_ms > 30000:  # 30 seconds
                return None, f"State expired ({state_age_ms/1000:.1f}s old)"

        return state_dict, None

    except Exception as e:
        return None, f"Failed to parse state: {e}"


async def initiate_centralized_oauth_flow(
    server_name: str,
    oauth_config: OAuthConfig,
    config_id: str,
    project_id: str,
    centralized_callback_url: str = "https://app.enkryptai.com/oauth/callback",
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Initiate OAuth Authorization Code flow with centralized callback.

    This function:
    1. Generates PKCE code_verifier and code_challenge
    2. Generates unique nonce for CSRF protection
    3. Builds state parameter with gateway URL and nonce
    4. Generates authorization URL with centralized redirect_uri
    5. Registers pending OAuth request in gateway
    6. Returns authorization URL for user to visit

    Args:
        server_name: Name of the server
        oauth_config: OAuth configuration
        config_id: MCP config ID
        project_id: Project ID
        centralized_callback_url: Centralized callback URL (default: app.enkryptai.com)

    Returns:
        Tuple of (authorization_url, nonce, error_message)

    Example:
        ```python
        auth_url, nonce, error = await initiate_centralized_oauth_flow(
            server_name="github_server",
            oauth_config=config,
            config_id="config-123",
            project_id="project-456"
        )

        if error:
            print(f"Failed to initiate OAuth: {error}")
        else:
            print(f"Visit this URL to authorize: {auth_url}")
            print(f"State nonce: {nonce}")
        ```
    """
    logger.info(
        f"[OAuth Centralized] Initiating OAuth flow for {server_name}",
        extra={
            "server_name": server_name,
            "config_id": config_id,
            "project_id": project_id,
            "centralized_callback_url": centralized_callback_url,
        },
    )

    # Validate OAuth configuration
    is_valid, error_msg = oauth_config.validate()
    if not is_valid:
        logger.error(f"[OAuth Centralized] Invalid OAuth config: {error_msg}")
        return None, None, f"Invalid OAuth configuration: {error_msg}"

    # Generate PKCE parameters if enabled
    code_verifier = None
    code_challenge = None
    code_challenge_method = None

    if oauth_config.use_pkce:
        code_verifier, code_challenge, code_challenge_method = generate_pkce_pair()
        logger.info(
            "[OAuth Centralized] Generated PKCE parameters",
            extra={
                "code_verifier": code_verifier[:20] + "...",
                "code_challenge": code_challenge[:20] + "...",
                "code_challenge_method": code_challenge_method,
            },
        )

    # Generate unique nonce for CSRF protection
    nonce = generate_state()
    logger.info(
        f"[OAuth Centralized] Generated nonce: {nonce[:20]}...",
        extra={"nonce": nonce[:20] + "..."},
    )

    # Get gateway base URL
    gateway_url = get_gateway_base_url()

    # Build state parameter with gateway URL and nonce
    state = build_centralized_state(
        gateway_url=gateway_url,
        nonce=nonce,
        pkce_verifier=code_verifier,
    )

    logger.info(
        "[OAuth Centralized] Built state parameter",
        extra={
            "gateway_url": gateway_url,
            "state_length": len(state),
        },
    )

    # Override redirect_uri to use centralized callback
    original_redirect_uri = oauth_config.redirect_uri
    oauth_config.redirect_uri = centralized_callback_url

    logger.info(
        "[OAuth Centralized] Overriding redirect_uri",
        extra={
            "original": original_redirect_uri,
            "centralized": centralized_callback_url,
        },
    )

    # Build authorization URL
    params = {
        "response_type": "code",
        "client_id": oauth_config.client_id,
        "redirect_uri": centralized_callback_url,
        "state": state,
    }

    if oauth_config.scope:
        params["scope"] = oauth_config.scope

    if oauth_config.audience:
        params["audience"] = oauth_config.audience

    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method

    # Add any additional parameters
    if oauth_config.additional_params:
        params.update(oauth_config.additional_params)

    auth_url = f"{oauth_config.authorization_url}?{urlencode(params)}"

    logger.info(
        "[OAuth Centralized] Generated authorization URL",
        extra={
            "url_length": len(auth_url),
            "has_pkce": bool(code_challenge),
            "scope": oauth_config.scope,
        },
    )

    # Register pending OAuth request
    from secure_mcp_gateway.api_routes import (
        OAuthPendingRequest,
        _pending_oauth_requests,
    )

    pending_request = OAuthPendingRequest(
        server_name=server_name,
        config_id=config_id,
        project_id=project_id,
        expected_state=nonce,
        code_verifier=code_verifier,
        timestamp=time.time(),
    )

    _pending_oauth_requests[nonce] = pending_request

    logger.info(
        "[OAuth Centralized] Registered pending OAuth request",
        extra={
            "nonce": nonce[:20] + "...",
            "pending_requests_count": len(_pending_oauth_requests),
        },
    )

    # Restore original redirect_uri
    oauth_config.redirect_uri = original_redirect_uri

    return auth_url, nonce, None


def cleanup_expired_pending_requests(max_age_seconds: float = 30):
    """
    Clean up expired pending OAuth requests.

    This should be called periodically (e.g., every minute) to prevent
    memory leaks from expired/abandoned OAuth requests.

    Args:
        max_age_seconds: Maximum age in seconds (default: 30)

    Returns:
        Number of requests cleaned up
    """
    from secure_mcp_gateway.api_routes import _pending_oauth_requests

    current_time = time.time()
    expired_nonces = []

    for nonce, request in _pending_oauth_requests.items():
        age = current_time - request.timestamp
        if age > max_age_seconds:
            expired_nonces.append(nonce)

    for nonce in expired_nonces:
        _pending_oauth_requests.pop(nonce, None)

    if expired_nonces:
        logger.info(
            f"[OAuth Centralized] Cleaned up {len(expired_nonces)} expired pending requests",
            extra={"count": len(expired_nonces)},
        )

    return len(expired_nonces)


async def authorize_with_centralized_callback(
    server_name: str,
    oauth_config: OAuthConfig,
    config_id: str,
    project_id: str,
    open_browser: bool = True,
    centralized_callback_url: str = "https://app.enkryptai.com/oauth/callback",
) -> Tuple[Optional[str], Optional[str]]:
    """
    Complete OAuth Authorization Code flow with centralized callback.

    This is a high-level function that:
    1. Initiates the OAuth flow
    2. Opens browser to authorization URL
    3. Waits for callback to be received
    4. Returns success/error message

    Args:
        server_name: Name of the server
        oauth_config: OAuth configuration
        config_id: MCP config ID
        project_id: Project ID
        open_browser: Whether to automatically open browser (default: True)
        centralized_callback_url: Centralized callback URL

    Returns:
        Tuple of (success_message, error_message)

    Example:
        ```python
        success, error = await authorize_with_centralized_callback(
            server_name="github_server",
            oauth_config=config,
            config_id="config-123",
            project_id="project-456"
        )

        if error:
            print(f"Authorization failed: {error}")
        else:
            print(f"Success: {success}")
        ```
    """
    import webbrowser

    # Initiate OAuth flow
    auth_url, nonce, error = await initiate_centralized_oauth_flow(
        server_name=server_name,
        oauth_config=oauth_config,
        config_id=config_id,
        project_id=project_id,
        centralized_callback_url=centralized_callback_url,
    )

    if error:
        return None, error

    # Display instructions
    print("\n" + "=" * 80)
    print("[*] OAUTH AUTHORIZATION REQUIRED (CENTRALIZED CALLBACK)")
    print("=" * 80)
    print(f"\nServer: {server_name}")
    print(f"OAuth Version: {oauth_config.version.value}")
    print(f"Grant Type: {oauth_config.grant_type.value}")
    print(f"PKCE: {'Enabled (S256)' if oauth_config.use_pkce else 'Disabled'}")
    print(f"Centralized Callback: {centralized_callback_url}")

    if open_browser:
        print("\n[*] Opening browser for authorization...")
        print("   If the browser doesn't open, visit this URL:")
        print(f"   {auth_url}\n")
    else:
        print("\n[*] Please visit this URL to authorize:")
        print(f"   {auth_url}\n")

    print("[*] After authorization, the callback page will automatically relay")
    print("    the authorization code to your gateway instance.")
    print("\n[*] This window will show the result once complete.")
    print("=" * 80 + "\n")

    # Open browser (if enabled)
    if open_browser:
        try:
            webbrowser.open(auth_url)
            logger.info("[OAuth Centralized] Browser opened successfully")
        except Exception as e:
            logger.warning(f"[OAuth Centralized] Failed to open browser: {e}")
            print(
                "⚠️  Failed to open browser automatically. Please visit the URL manually."
            )

    # Wait for callback (the callback endpoint will handle the token exchange)
    print("\n[*] Waiting for authorization callback...")
    print(
        "[*] Authorize in your browser, and the callback page will handle the rest.\n"
    )

    return ("OAuth flow initiated. Complete authorization in your browser.", None)
