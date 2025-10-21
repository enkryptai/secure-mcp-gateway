"""
Remote OAuth callback support with manual code entry.

This module provides utilities for OAuth Authorization Code flow
when using a remote callback URL instead of localhost.
"""

import asyncio
from typing import Optional, Tuple
from urllib.parse import urlparse

from secure_mcp_gateway.services.oauth import OAuthConfig, OAuthToken
from secure_mcp_gateway.services.oauth.oauth_service import get_oauth_service
from secure_mcp_gateway.utils import logger


def is_remote_callback(redirect_uri: str) -> bool:
    """
    Check if redirect URI is a remote URL (not localhost).

    Args:
        redirect_uri: The OAuth redirect URI

    Returns:
        True if remote, False if localhost
    """
    if not redirect_uri:
        return False

    try:
        parsed = urlparse(redirect_uri)
        hostname = parsed.hostname

        # If no hostname could be parsed, treat as invalid (not remote)
        if not hostname:
            return False

        # Check if localhost
        localhost_patterns = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]

        return not any(hostname.lower() == pattern for pattern in localhost_patterns)
    except Exception:
        # If parsing fails, treat as invalid (not remote)
        return False


async def authorize_with_remote_callback(
    server_name: str,
    oauth_config: OAuthConfig,
    config_id: str,
    project_id: str,
    open_browser: bool = True,
    timeout: int = 600,
) -> Tuple[Optional[OAuthToken], Optional[str]]:
    """
    Complete OAuth Authorization Code flow with remote callback URL.

    This function:
    1. Generates authorization URL with PKCE
    2. Opens browser to authorization URL (optional)
    3. Displays instructions for manual code entry
    4. Prompts user to enter the authorization code
    5. Exchanges code for token
    6. Returns token

    Args:
        server_name: Name of the server
        oauth_config: OAuth configuration
        config_id: MCP config ID
        project_id: Project ID
        open_browser: Whether to automatically open browser (default: True)
        timeout: Timeout in seconds for user to enter code (default: 600 = 10 minutes)

    Returns:
        Tuple of (OAuthToken, error_message)

    Example:
        ```python
        token, error = await authorize_with_remote_callback(
            server_name="my_server",
            oauth_config=config,
            config_id="config-123",
            project_id="project-456"
        )

        if error:
            print(f"Authorization failed: {error}")
        else:
            print(f"Token obtained: {token.access_token[:20]}...")
        ```
    """
    import webbrowser

    logger.info(
        f"[OAuth Remote] Starting remote callback authorization for {server_name}"
    )

    # Step 1: Generate authorization URL
    oauth_service = get_oauth_service()

    try:
        (
            auth_url,
            state,
            code_verifier,
            code_challenge,
        ) = oauth_service.generate_authorization_url(oauth_config=oauth_config)

        logger.info("[OAuth Remote] Generated authorization URL")
        logger.info(f"[OAuth Remote] State: {state[:20]}...")
        logger.info(f"[OAuth Remote] Code verifier: {code_verifier[:20]}...")

    except Exception as e:
        error_msg = f"Failed to generate authorization URL: {e}"
        logger.error(f"[OAuth Remote] {error_msg}")
        return None, error_msg

    # Step 2: Display instructions
    print("\n" + "=" * 80)
    print("[*] OAUTH AUTHORIZATION REQUIRED (REMOTE CALLBACK)")
    print("=" * 80)
    print(f"\nServer: {server_name}")
    print(f"OAuth Version: {oauth_config.version.value}")
    print(f"Grant Type: {oauth_config.grant_type.value}")
    print(f"PKCE: {'Enabled (S256)' if oauth_config.use_pkce else 'Disabled'}")
    print(f"Redirect URI: {oauth_config.redirect_uri}")

    if open_browser:
        print("\n[*] Opening browser for authorization...")
        print("   If the browser doesn't open, visit this URL:")
        print(f"   {auth_url}\n")
    else:
        print("\n[*] Please visit this URL to authorize:")
        print(f"   {auth_url}\n")

    print("[*] After authorization, you will be redirected to:")
    print(f"   {oauth_config.redirect_uri}")
    print("\n[*] The callback page will display your authorization code.")
    print("[*] Copy the authorization code and paste it below when prompted.")
    print(f"\n[*] Timeout: {timeout} seconds")
    print("=" * 80 + "\n")

    # Step 3: Open browser (if enabled)
    if open_browser:
        try:
            webbrowser.open(auth_url)
            logger.info("[OAuth Remote] Browser opened successfully")
        except Exception as e:
            logger.warning(f"[OAuth Remote] Failed to open browser: {e}")
            print(
                "⚠️  Failed to open browser automatically. Please visit the URL manually."
            )

    # Step 4: Wait for user to enter authorization code
    print("\n[*] Waiting for authorization code...")
    print(
        "[*] After authorizing, copy the code from the callback page and paste it here:\n"
    )

    try:
        # Prompt for authorization code with timeout
        loop = asyncio.get_event_loop()

        async def get_code_input():
            """Get authorization code from user input."""
            return await loop.run_in_executor(
                None, lambda: input("Enter authorization code: ").strip()
            )

        # Wait for input with timeout
        try:
            code = await asyncio.wait_for(get_code_input(), timeout=timeout)
        except asyncio.TimeoutError:
            error_msg = (
                f"Timeout: No authorization code entered within {timeout} seconds"
            )
            logger.error(f"[OAuth Remote] {error_msg}")
            print(f"\n[FAIL] {error_msg}\n")
            return None, error_msg

        if not code:
            error_msg = "No authorization code entered"
            logger.error(f"[OAuth Remote] {error_msg}")
            print(f"\n[FAIL] {error_msg}\n")
            return None, error_msg

        logger.info(f"[OAuth Remote] Authorization code received: {code[:20]}...")
        print(f"\n[OK] Authorization code received: {code[:20]}...")

    except KeyboardInterrupt:
        error_msg = "Authorization cancelled by user"
        logger.warning(f"[OAuth Remote] {error_msg}")
        print(f"\n\n[CANCELLED] {error_msg}\n")
        return None, error_msg
    except Exception as e:
        error_msg = f"Failed to read authorization code: {e}"
        logger.error(f"[OAuth Remote] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    # Step 5: Exchange code for token
    print("\n[*] Exchanging authorization code for token...")

    token, error = await oauth_service.exchange_authorization_code(
        server_name=server_name,
        oauth_config=oauth_config,
        authorization_code=code,
        code_verifier=code_verifier,
        state=None,  # State is not validated for manual entry
        expected_state=state,
        config_id=config_id,
        project_id=project_id,
    )

    if error:
        error_msg = f"Token exchange failed: {error}"
        logger.error(f"[OAuth Remote] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    logger.info("[OAuth Remote] Token obtained successfully")
    print("\n[SUCCESS] Token obtained successfully!")
    print(f"   Access Token: {token.access_token[:30]}...")
    print(f"   Token Type: {token.token_type}")
    print(f"   Expires In: {token.expires_in} seconds")
    print(f"   Scope: {token.scope}")
    print("=" * 80 + "\n")

    return token, None


async def authorize_with_auto_detection(
    server_name: str,
    oauth_config: OAuthConfig,
    config_id: str,
    project_id: str,
    open_browser: bool = True,
    callback_port: int = 8080,
    timeout: int = 300,
) -> Tuple[Optional[OAuthToken], Optional[str]]:
    """
    Automatically detect callback type and use appropriate authorization flow.

    - If redirect_uri is localhost: use local callback server
    - If redirect_uri is remote: use manual code entry

    Args:
        server_name: Name of the server
        oauth_config: OAuth configuration
        config_id: MCP config ID
        project_id: Project ID
        open_browser: Whether to automatically open browser
        callback_port: Port for local callback server (only used for localhost)
        timeout: Timeout in seconds

    Returns:
        Tuple of (OAuthToken, error_message)
    """
    if not oauth_config.redirect_uri:
        error_msg = "OAUTH_REDIRECT_URI is required for authorization code flow"
        logger.error(f"[OAuth Auto] {error_msg}")
        return None, error_msg

    # Detect callback type
    if is_remote_callback(oauth_config.redirect_uri):
        logger.info(
            f"[OAuth Auto] Detected remote callback URL: {oauth_config.redirect_uri}"
        )
        logger.info("[OAuth Auto] Using remote callback flow (manual code entry)")

        return await authorize_with_remote_callback(
            server_name=server_name,
            oauth_config=oauth_config,
            config_id=config_id,
            project_id=project_id,
            open_browser=open_browser,
            timeout=timeout,
        )
    else:
        logger.info(
            f"[OAuth Auto] Detected local callback URL: {oauth_config.redirect_uri}"
        )
        logger.info("[OAuth Auto] Using local callback server")

        # Import here to avoid circular dependency
        from secure_mcp_gateway.services.oauth.browser_auth import (
            authorize_with_browser,
        )

        return await authorize_with_browser(
            server_name=server_name,
            oauth_config=oauth_config,
            config_id=config_id,
            project_id=project_id,
            open_browser=open_browser,
            callback_port=callback_port,
            timeout=timeout,
        )
