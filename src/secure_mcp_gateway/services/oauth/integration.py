"""OAuth integration utilities for MCP client."""

from typing import Dict, Optional, Tuple

from secure_mcp_gateway.services.oauth.models import OAuthConfig
from secure_mcp_gateway.services.oauth.oauth_service import get_oauth_service
from secure_mcp_gateway.utils import logger


async def prepare_oauth_for_server(
    server_name: str,
    server_entry: Dict,
    config_id: str,
    project_id: str,
) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Prepare OAuth configuration for MCP server.

    Extracts oauth_config from server entry, obtains access token,
    and prepares environment variables and/or command args for the server.

    Supports both Client Credentials and Authorization Code flows.

    Args:
        server_name: Name of the server (required)
        server_entry: Server configuration entry (required)
        config_id: MCP configuration ID (required)
        project_id: Project ID (required)

    Returns:
        Tuple of (oauth_data_dict, error_message)
        oauth_data_dict contains:
            - env_vars: Dict of environment variables with OAuth tokens
            - header_args: List of args to inject Authorization header (for remote servers)
            - access_token: The raw access token
    """
    # Check if OAuth is configured
    oauth_config_data = server_entry.get("oauth_config")
    if not oauth_config_data:
        logger.debug(f"[OAuth Integration] No OAuth config for server: {server_name}")
        return None, None

    # Parse OAuth configuration
    try:
        oauth_config = OAuthConfig.from_dict(oauth_config_data)
    except Exception as e:
        error_msg = f"Failed to parse OAuth config: {e}"
        logger.error(f"[OAuth Integration] {error_msg}")
        return None, error_msg

    # Check if OAuth is enabled
    if not oauth_config.enabled:
        logger.debug(f"[OAuth Integration] OAuth disabled for server: {server_name}")
        return None, None

    logger.info(
        f"[OAuth Integration] Obtaining OAuth token for {server_name} "
        f"(OAuth {oauth_config.version.value}, grant_type: {oauth_config.grant_type.value})"
    )

    # Obtain access token
    oauth_service = get_oauth_service()

    # For authorization_code flow, check cache first
    # If no token exists, automatically trigger browser authorization
    if oauth_config.grant_type.value == "authorization_code":
        # Try to get cached token
        from secure_mcp_gateway.services.oauth.token_manager import get_token_manager

        token_manager = get_token_manager()
        cached_token = await token_manager.get_token(
            server_name, oauth_config, config_id, project_id
        )

        if cached_token:
            logger.info(f"[OAuth Integration] Using cached token for {server_name}")
            access_token = cached_token.access_token
            error_msg = None
        else:
            # No token - trigger automatic browser authorization
            logger.warning(
                f"[OAuth Integration] No token found for {server_name} - starting browser authorization"
            )

            try:
                # Import auto-detection helper (handles both local and remote callbacks)
                from secure_mcp_gateway.services.oauth.remote_callback import (
                    authorize_with_auto_detection,
                )

                logger.info(
                    f"[OAuth Integration] Triggering automatic browser authorization for {server_name}"
                )

                # Trigger browser authorization with auto-detection
                # (automatically detects if callback is localhost or remote)
                token, auth_error = await authorize_with_auto_detection(
                    server_name=server_name,
                    oauth_config=oauth_config,
                    config_id=config_id,
                    project_id=project_id,
                    open_browser=True,  # Automatically open browser
                    callback_port=8080,  # Only used for localhost callbacks
                    timeout=300,  # 5 minutes
                )

                if auth_error or not token:
                    error_msg = f"Browser authorization failed: {auth_error}"
                    logger.error(f"[OAuth Integration] {error_msg}")
                    return None, error_msg

                # Token obtained successfully
                logger.info(
                    f"[OAuth Integration] Browser authorization successful for {server_name}"
                )
                access_token = token.access_token
                error_msg = None

            except Exception as e:
                error_msg = f"Browser authorization failed: {e}"
                logger.error(f"[OAuth Integration] {error_msg}")
                return None, error_msg
    else:
        # Client Credentials flow - automatic token acquisition
        access_token, error_msg = await oauth_service.get_access_token(
            server_name=server_name,
            oauth_config=oauth_config,
            config_id=config_id,
            project_id=project_id,
        )

    if error_msg or not access_token:
        logger.error(
            f"[OAuth Integration] Failed to obtain token for {server_name}: {error_msg}"
        )
        return None, error_msg or "Failed to obtain access token"

    logger.info(f"[OAuth Integration] Successfully obtained token for {server_name}")

    # Prepare OAuth data for MCP server
    # Check if this is a remote server (uses npx, mcp-remote, etc.)
    config = server_entry.get("config", {})
    command = config.get("command", "")
    args = config.get("args", [])

    # Check for explicit is_remote flag, or auto-detect
    oauth_config_dict = server_entry.get("oauth_config", {})
    is_remote_explicit = oauth_config_dict.get("is_remote")

    if is_remote_explicit is not None:
        is_remote_server = bool(is_remote_explicit)
        logger.info(
            f"[OAuth Integration] Using explicit is_remote={is_remote_server} for {server_name}"
        )
    else:
        # Detect remote servers (npx mcp-remote, curl, etc.)
        is_remote_server = (
            "npx" in command.lower()
            or "mcp-remote" in " ".join(str(arg) for arg in args).lower()
            or "curl" in command.lower()
            or "http://" in " ".join(str(arg) for arg in args)
            or "https://" in " ".join(str(arg) for arg in args)
        )
        logger.debug(
            f"[OAuth Integration] Auto-detected is_remote={is_remote_server} for {server_name}"
        )

    # Prepare environment variables (always include for compatibility)
    # Note: We use AUTH_HEADER env var for mcp-remote header injection (see below)
    env_vars = {
        "ENKRYPT_ACCESS_TOKEN": access_token,
        "AUTHORIZATION": f"Bearer {access_token}",
        "OAUTH_ACCESS_TOKEN": access_token,
        "OAUTH_TOKEN_TYPE": "Bearer",
        "HTTP_HEADER_Authorization": f"Bearer {access_token}",
        "HTTP_HEADER_AUTHORIZATION": f"Bearer {access_token}",
        "AUTH_HEADER": f"Bearer {access_token}",  # For mcp-remote --header
    }

    # Prepare header args for remote servers
    header_args = []
    if is_remote_server:
        # For remote servers, we inject the Authorization header via --header arguments
        # mcp-remote supports --header arguments for passing HTTP headers
        #
        # IMPORTANT: Windows npx has a bug where spaces in args aren't escaped properly.
        # Workaround: Use "Authorization:${AUTH_HEADER}" instead of "Authorization: Bearer {token}"
        # and pass the token value via AUTH_HEADER environment variable.
        # See: https://www.npmjs.com/package/mcp-remote#header-authentication
        #
        # NOTE: Using lowercase "authorization" for HTTP/2 compatibility and to match
        # the example pattern from mcp-remote docs (e.g., apikey:${ENKRYPT_GATEWAY_KEY})
        header_args = [
            "--header",
            "authorization:${AUTH_HEADER}",  # lowercase for HTTP/2 compatibility
        ]
        logger.info(
            f"[OAuth Integration] Detected remote server {server_name}, "
            "will inject authorization header (lowercase) via --header argument with AUTH_HEADER env var"
        )

    # Prepare HTTP headers for direct HTTP transport
    http_headers = {"Authorization": f"Bearer {access_token}"}

    oauth_data = {
        "env_vars": env_vars,
        "header_args": header_args,
        "http_headers": http_headers,
        "access_token": access_token,
        "is_remote": is_remote_server,
    }

    return oauth_data, None


def inject_oauth_into_env(
    existing_env: Optional[Dict[str, str]],
    oauth_data: Optional[Dict],
) -> Dict[str, str]:
    """
    Inject OAuth environment variables into existing environment.

    OAuth variables are added without overwriting existing ones.

    Args:
        existing_env: Existing environment variables
        oauth_data: OAuth data dictionary (contains env_vars key) or
                    legacy dict of env vars (for backward compatibility)

    Returns:
        Combined environment dictionary
    """
    if not oauth_data:
        return existing_env or {}

    # Handle backward compatibility: oauth_data might be a dict of env vars
    # or the new structure with env_vars, header_args, etc.
    oauth_env = oauth_data.get("env_vars", oauth_data)

    if not oauth_env:
        return existing_env or {}

    result = existing_env.copy() if existing_env else {}

    # Add OAuth variables (don't overwrite existing)
    for key, value in oauth_env.items():
        if key not in result:
            result[key] = value
        else:
            logger.warning(
                f"[OAuth Integration] Environment variable '{key}' already exists, "
                "not overwriting with OAuth value"
            )

    return result


def inject_oauth_into_args(
    existing_args: list,
    oauth_data: Optional[Dict],
) -> list:
    """
    Inject OAuth header arguments into existing command args.

    For remote MCP servers using mcp-remote, we inject --header arguments
    to pass HTTP headers to the remote server.

    Args:
        existing_args: Existing command arguments
        oauth_data: OAuth data dictionary containing header_args

    Returns:
        Combined arguments list with OAuth headers injected
    """
    if not oauth_data or not oauth_data.get("header_args"):
        return existing_args or []

    # Inject header arguments for remote servers
    header_args = oauth_data.get("header_args", [])
    combined_args = (existing_args or []) + header_args

    return combined_args


def get_oauth_headers(access_token: str) -> Dict[str, str]:
    """
    Get HTTP headers with OAuth access token.

    OAuth 2.1 compliant: Token in Authorization header only.

    Args:
        access_token: OAuth access token

    Returns:
        Dictionary with Authorization header
    """
    return {"Authorization": f"Bearer {access_token}"}


async def refresh_server_oauth_token(
    server_name: str,
    server_entry: Dict,
    config_id: str,
    project_id: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Force refresh OAuth token for server.

    Args:
        server_name: Name of the server (required)
        server_entry: Server configuration entry (required)
        config_id: MCP configuration ID (required)
        project_id: Project ID (required)

    Returns:
        Tuple of (access_token, error_message)
    """
    oauth_config_data = server_entry.get("oauth_config")
    if not oauth_config_data:
        return None, "No OAuth configuration found"

    try:
        oauth_config = OAuthConfig.from_dict(oauth_config_data)
    except Exception as e:
        return None, f"Failed to parse OAuth config: {e}"

    if not oauth_config.enabled:
        return None, "OAuth is not enabled"

    oauth_service = get_oauth_service()
    return await oauth_service.refresh_token(
        server_name=server_name,
        oauth_config=oauth_config,
        config_id=config_id,
        project_id=project_id,
    )


async def invalidate_server_oauth_token(
    server_name: str,
    config_id: str,
    project_id: str,
) -> None:
    """
    Invalidate cached OAuth token for server.

    Args:
        server_name: Name of the server (required)
        config_id: MCP configuration ID (required)
        project_id: Project ID (required)
    """
    oauth_service = get_oauth_service()
    await oauth_service.invalidate_token(server_name, config_id, project_id)
    logger.info(f"[OAuth Integration] Invalidated token for server: {server_name}")


def validate_oauth_config(server_entry: Dict) -> Tuple[bool, Optional[str]]:
    """
    Validate OAuth configuration in server entry.

    Args:
        server_entry: Server configuration entry

    Returns:
        Tuple of (is_valid, error_message)
    """
    oauth_config_data = server_entry.get("oauth_config")
    if not oauth_config_data:
        return True, None  # No OAuth config is valid

    try:
        oauth_config = OAuthConfig.from_dict(oauth_config_data)
        return oauth_config.validate()
    except Exception as e:
        return False, f"Failed to parse OAuth config: {e}"
