"""
OAuth Authorization Code flow helper with automatic browser opening and callback handling.

This module provides utilities to:
1. Automatically open browser for user authorization
2. Start a local HTTP server to capture the authorization code
3. Automatically exchange the code for a token
"""

import asyncio
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlparse

from secure_mcp_gateway.services.oauth import OAuthConfig, OAuthToken
from secure_mcp_gateway.services.oauth.oauth_service import get_oauth_service
from secure_mcp_gateway.utils import logger


class AuthorizationCodeHandler(BaseHTTPRequestHandler):
    """HTTP handler to capture OAuth authorization code from callback."""

    # Class variables to store results
    authorization_code: Optional[str] = None
    state: Optional[str] = None
    error: Optional[str] = None
    server_should_stop = False

    def do_GET(self):
        """Handle GET request from OAuth callback."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        # Extract code and state
        code = query_params.get("code", [None])[0]
        state = query_params.get("state", [None])[0]
        error = query_params.get("error", [None])[0]
        error_description = query_params.get("error_description", [None])[0]

        if error:
            # Authorization failed
            AuthorizationCodeHandler.error = f"{error}: {error_description}"
            self._send_error_response(error, error_description)
        elif code and state:
            # Authorization successful
            AuthorizationCodeHandler.authorization_code = code
            AuthorizationCodeHandler.state = state
            self._send_success_response()
        else:
            # Invalid callback
            AuthorizationCodeHandler.error = "Invalid callback: missing code or state"
            self._send_error_response("invalid_request", "Missing code or state")

        # Signal server to stop
        AuthorizationCodeHandler.server_should_stop = True

    def _send_success_response(self):
        """Send success response to browser."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Successful</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f0f0f0;
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                }
                .success {
                    color: #4CAF50;
                    font-size: 48px;
                    margin-bottom: 20px;
                }
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                }
                p {
                    color: #666;
                    font-size: 16px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success">✓</div>
                <h1>Authorization Successful!</h1>
                <p>You have successfully authorized the application.</p>
                <p>You can close this window and return to your terminal.</p>
            </div>
            <script>
                // Auto-close after 3 seconds
                setTimeout(function() {
                    window.close();
                }, 3000);
            </script>
        </body>
        </html>
        """

        self.wfile.write(html.encode())

    def _send_error_response(self, error: str, description: Optional[str]):
        """Send error response to browser."""
        self.send_response(400)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Failed</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f0f0f0;
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                .error {{
                    color: #f44336;
                    font-size: 48px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                }}
                p {{
                    color: #666;
                    font-size: 16px;
                }}
                .error-details {{
                    background: #ffebee;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 20px;
                    color: #c62828;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error">✗</div>
                <h1>Authorization Failed</h1>
                <p>There was an error during authorization.</p>
                <div class="error-details">
                    <strong>Error:</strong> {error}<br>
                    {f'<strong>Description:</strong> {description}' if description else ''}
                </div>
                <p style="margin-top: 20px;">You can close this window.</p>
            </div>
        </body>
        </html>
        """

        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_callback_server(
    port: int = 8080, timeout: int = 300, max_port_attempts: int = 10
) -> Tuple[Optional[str], Optional[str], Optional[str], int]:
    """
    Start local HTTP server to capture OAuth callback.
    Automatically tries next available port if specified port is in use.

    Args:
        port: Starting port to listen on (default: 8080)
        timeout: Timeout in seconds (default: 300 = 5 minutes)
        max_port_attempts: Maximum number of ports to try (default: 10)

    Returns:
        Tuple of (authorization_code, state, error, actual_port)
    """
    # Reset class variables
    AuthorizationCodeHandler.authorization_code = None
    AuthorizationCodeHandler.state = None
    AuthorizationCodeHandler.error = None
    AuthorizationCodeHandler.server_should_stop = False

    # Try to find an available port
    server = None
    actual_port = port
    last_error = None

    for attempt in range(max_port_attempts):
        try_port = port + attempt
        try:
            logger.info(
                f"[OAuth Callback] Trying to start callback server on http://localhost:{try_port}"
            )
            server = HTTPServer(("localhost", try_port), AuthorizationCodeHandler)
            actual_port = try_port
            logger.info(
                f"[OAuth Callback] Successfully started callback server on http://localhost:{actual_port}"
            )
            break
        except OSError as e:
            last_error = e
            if attempt < max_port_attempts - 1:
                logger.warning(
                    f"[OAuth Callback] Port {try_port} is in use, trying next port..."
                )
            else:
                error_msg = f"Failed to start callback server after trying ports {port}-{try_port}: {e}"
                logger.error(f"[OAuth Callback] {error_msg}")
                return None, None, error_msg, port

    if server is None:
        error_msg = f"Failed to start callback server: {last_error}"
        logger.error(f"[OAuth Callback] {error_msg}")
        return None, None, error_msg, port

    def serve():
        """Serve requests until code is received or timeout."""
        import time

        start_time = time.time()
        while not AuthorizationCodeHandler.server_should_stop:
            server.timeout = 0.5  # Check every 0.5 seconds
            server.handle_request()

            # Check timeout
            if time.time() - start_time > timeout:
                AuthorizationCodeHandler.error = f"Timeout: No authorization callback received within {timeout} seconds"
                break

        server.server_close()
        logger.info("[OAuth Callback] Callback server stopped")

    # Start server in background thread
    server_thread = Thread(target=serve, daemon=True)
    server_thread.start()

    # Wait for server to receive callback or timeout
    server_thread.join(timeout=timeout + 1)

    return (
        AuthorizationCodeHandler.authorization_code,
        AuthorizationCodeHandler.state,
        AuthorizationCodeHandler.error,
        actual_port,
    )


async def authorize_with_browser(
    server_name: str,
    oauth_config: OAuthConfig,
    config_id: str,
    project_id: str,
    open_browser: bool = True,
    callback_port: int = 8080,
    timeout: int = 300,
) -> Tuple[Optional[OAuthToken], Optional[str]]:
    """
    Complete OAuth Authorization Code flow with automatic browser opening.

    This function:
    1. Generates authorization URL with PKCE
    2. Starts local callback server
    3. Opens browser to authorization URL (optional)
    4. Waits for user to authorize
    5. Captures authorization code from callback
    6. Exchanges code for token
    7. Returns token

    Args:
        server_name: Name of the server
        oauth_config: OAuth configuration
        config_id: MCP config ID
        project_id: Project ID
        open_browser: Whether to automatically open browser (default: True)
        callback_port: Port for callback server (default: 8080)
        timeout: Timeout in seconds (default: 300 = 5 minutes)

    Returns:
        Tuple of (OAuthToken, error_message)

    Example:
        ```python
        token, error = await authorize_with_browser(
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
    logger.info(f"[OAuth Browser] Starting browser authorization for {server_name}")

    # Step 1: Generate authorization URL
    oauth_service = get_oauth_service()

    try:
        (
            auth_url,
            state,
            code_verifier,
            code_challenge,
        ) = oauth_service.generate_authorization_url(oauth_config=oauth_config)

        logger.info("[OAuth Browser] Generated authorization URL")
        logger.info(f"[OAuth Browser] State: {state[:20]}...")
        logger.info(f"[OAuth Browser] Code verifier: {code_verifier[:20]}...")

    except Exception as e:
        error_msg = f"Failed to generate authorization URL: {e}"
        logger.error(f"[OAuth Browser] {error_msg}")
        return None, error_msg

    # Step 2: Start callback server
    logger.info(f"[OAuth Browser] Starting callback server on port {callback_port}")

    print("\n" + "=" * 80)
    print("[*] OAUTH AUTHORIZATION REQUIRED")
    print("=" * 80)
    print(f"\nServer: {server_name}")
    print(f"OAuth Version: {oauth_config.version.value}")
    print(f"Grant Type: {oauth_config.grant_type.value}")
    print(f"PKCE: {'Enabled (S256)' if oauth_config.use_pkce else 'Disabled'}")

    if open_browser:
        print("\n[*] Opening browser for authorization...")
        print("   If the browser doesn't open, visit this URL:")
        print(f"   {auth_url}\n")
    else:
        print("\n[*] Please visit this URL to authorize:")
        print(f"   {auth_url}\n")

    print(f"[*] Waiting for authorization (timeout: {timeout} seconds)...")
    print(
        f"[*] Callback server listening on: http://localhost:{callback_port}/callback"
    )
    print("=" * 80 + "\n")

    # Step 3: Open browser (if enabled)
    if open_browser:
        try:
            webbrowser.open(auth_url)
            logger.info("[OAuth Browser] Browser opened successfully")
        except Exception as e:
            logger.warning(f"[OAuth Browser] Failed to open browser: {e}")
            print(
                "⚠️  Failed to open browser automatically. Please visit the URL manually."
            )

    # Step 4: Wait for callback (in background thread)
    loop = asyncio.get_event_loop()
    code, received_state, error, actual_port = await loop.run_in_executor(
        None, start_callback_server, callback_port, timeout
    )

    # Update displayed port if it changed
    if actual_port != callback_port:
        logger.info(
            f"[OAuth Browser] Using port {actual_port} instead of {callback_port}"
        )
        print(
            f"\n[INFO] Callback server started on port {actual_port} (port {callback_port} was in use)"
        )
        print(f"[INFO] Listening on: http://localhost:{actual_port}/callback\n")

    if error:
        error_msg = f"Authorization failed: {error}"
        logger.error(f"[OAuth Browser] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    if not code or not received_state:
        error_msg = "No authorization code received"
        logger.error(f"[OAuth Browser] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    # Step 5: Validate state
    if received_state != state:
        error_msg = (
            f"State mismatch: expected {state[:20]}..., got {received_state[:20]}..."
        )
        logger.error(f"[OAuth Browser] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    logger.info("[OAuth Browser] Authorization code received")
    print("\n[OK] Authorization code received")
    print("[OK] State validated")

    # Step 6: Exchange code for token
    print("\n[*] Exchanging authorization code for token...")

    token, error = await oauth_service.exchange_authorization_code(
        server_name=server_name,
        oauth_config=oauth_config,
        authorization_code=code,
        code_verifier=code_verifier,
        state=received_state,
        expected_state=state,
        config_id=config_id,
        project_id=project_id,
    )

    if error:
        error_msg = f"Token exchange failed: {error}"
        logger.error(f"[OAuth Browser] {error_msg}")
        print(f"\n[FAIL] {error_msg}\n")
        return None, error_msg

    logger.info("[OAuth Browser] Token obtained successfully")
    print("\n[SUCCESS] Token obtained successfully!")
    print(f"   Access Token: {token.access_token[:30]}...")
    print(f"   Token Type: {token.token_type}")
    print(f"   Expires In: {token.expires_in} seconds")
    print(f"   Scope: {token.scope}")
    print("=" * 80 + "\n")

    return token, None
