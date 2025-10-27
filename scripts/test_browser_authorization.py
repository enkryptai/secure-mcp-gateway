"""
Test script for automatic browser-based OAuth authorization.

This demonstrates the complete automatic flow:
1. Opens browser automatically
2. User authorizes in browser
3. Code is captured automatically
4. Token is exchanged and cached
5. No manual copy/paste required!
"""

import asyncio
import sys

from secure_mcp_gateway.services.oauth import OAuthConfig
from secure_mcp_gateway.services.oauth.browser_auth import authorize_with_browser

# Test configuration for Auth0
TEST_CONFIG = {
    "enabled": True,
    "OAUTH_VERSION": "2.1",
    "OAUTH_GRANT_TYPE": "authorization_code",
    "OAUTH_CLIENT_ID": "your-client-id",
    "OAUTH_CLIENT_SECRET": "your-client-secret",
    "OAUTH_AUTHORIZATION_URL": "https://auth.example.com/authorize",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
    "OAUTH_REDIRECT_URI": "http://localhost:8080/callback",
    "OAUTH_AUDIENCE": "https://api.example.com",
    "OAUTH_SCOPE": "repo user read:org",
    "OAUTH_USE_PKCE": True,
    "OAUTH_CODE_CHALLENGE_METHOD": "S256",
}


async def main():
    """Test automatic browser authorization."""

    print("\n[*] Starting Automatic Browser Authorization Test\n")
    print("="*80)
    print("TEST: Automatic OAuth 2.1 Authorization Code + PKCE Flow")
    print("="*80)
    print("\nThis test will:")
    print("  1. Generate authorization URL with PKCE")
    print("  2. Open your browser automatically")
    print("  3. Wait for you to authorize")
    print("  4. Capture the authorization code automatically")
    print("  5. Exchange code for token")
    print("  6. Cache the token")
    print("\nNo manual copy/paste required!")
    print("="*80 + "\n")

    # Parse configuration
    oauth_config = OAuthConfig.from_dict(TEST_CONFIG)

    # Run automatic browser authorization
    token, error = await authorize_with_browser(
        server_name="echo_server",
        oauth_config=oauth_config,
        config_id="e96e93d0-b482-4531-9312-9d90b9667b56",
        project_id="4b3d6f82-31e2-42ae-8fb1-12e40a7c7ec1",
        open_browser=True,  # Set to False to disable auto-open
        callback_port=8080,
        timeout=300  # 5 minutes
    )

    if error:
        print(f"\n[FAIL] Authorization failed: {error}\n")
        return False

    print(f"\n[SUCCESS] All tests passed!")
    print(f"\nToken details:")
    print(f"  Access Token: {token.access_token[:50]}...")
    print(f"  Token Type: {token.token_type}")
    print(f"  Expires In: {token.expires_in} seconds")
    print(f"  Scope: {token.scope}")
    print(f"  Expires At: {token.expires_at}")

    # Verify token is cached
    print(f"\n[VERIFY] Checking if token is cached...")
    from secure_mcp_gateway.services.oauth.token_manager import get_token_manager

    token_manager = get_token_manager()
    cached_token = await token_manager.get_token(
        "echo_server",
        oauth_config,
        "e96e93d0-b482-4531-9312-9d90b9667b56",
        "4b3d6f82-31e2-42ae-8fb1-12e40a7c7ec1"
    )

    if cached_token:
        print(f"[OK] Token is cached successfully!")
        print(f"  Cached token matches: {cached_token.access_token == token.access_token}")
    else:
        print(f"[FAIL] Token not found in cache")
        return False

    print("\n" + "="*80)
    print("[SUCCESS] AUTOMATIC BROWSER AUTHORIZATION TEST PASSED!")
    print("="*80 + "\n")

    return True


if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\n[INFO] Test cancelled by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
