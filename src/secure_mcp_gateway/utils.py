"""Common utilities for MCP Gateway."""

import json
import os
import secrets
import socket
import string
import sys
import time
from functools import lru_cache
from typing import Any, Dict, Union
from urllib.parse import urlparse

from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DEFAULT_COMMON_CONFIG,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    EXAMPLE_CONFIG_PATH,
)

# Lazy import to avoid circular imports
#
# We expose a single, centralized logger for the whole application via a
# lazy accessor. Most modules should import and use `utils.logger`, which
# routes to the active telemetry provider's logger when telemetry is
# enabled. This centralizes formatting, context, and export behavior.
#
# IMPORTANT: Telemetry modules themselves (e.g. providers under
# `plugins/telemetry`) MUST NOT import from `utils` to fetch this logger,
# because `utils` depends on telemetry during initialization. Those
# modules should instead create a local module logger with
# `logging.getLogger(...)` to avoid circular imports during bootstrap.
_logger_cache = None


def get_logger():
    """Return the active application logger lazily.

    This defers importing the telemetry config/manager until first use,
    preventing circular imports during process startup. If telemetry is
    disabled or unavailable, this returns None and `LazyLogger` will
    no-op calls.
    """
    global _logger_cache
    if _logger_cache is None:
        try:
            from secure_mcp_gateway.plugins.telemetry import (
                get_telemetry_config_manager,
            )

            telemetry_manager = get_telemetry_config_manager()
            _logger_cache = telemetry_manager.get_logger()
            # print("[utils] Logger initialized successfully", file=sys.stderr)
        except Exception as e:
            # If telemetry is not available, return None
            # print(f"[utils] Logger initialization failed: {e}", file=sys.stderr)
            _logger_cache = None
    return _logger_cache


# For backward compatibility, expose logger as a module-level variable
class LazyLogger:
    """Lazy logger wrapper used by application modules.

    Accessing any logging method (e.g., `.info`, `.debug`) forwards the
    call to the real telemetry-backed logger when available. Otherwise it
    becomes a safe no-op. This allows importing `logger` from `utils`
    everywhere without eagerly initializing telemetry.
    """

    def __getattr__(self, name):
        logger = get_logger()
        if logger:
            return getattr(logger, name)
        # No-op if logger not available
        # print(
        #     f"[utils] LazyLogger: No logger available for method {name}",
        #     file=sys.stderr,
        # )
        return lambda *args, **kwargs: None


# Central application logger for non-telemetry modules.
#
# Usage guidance:
# - In most modules, prefer: `from secure_mcp_gateway.utils import logger`
# - In telemetry provider/config modules, prefer a local
#   `logging.getLogger("enkrypt.telemetry")` to avoid importing `utils`
#   (which depends on telemetry initialization) and creating a circular
#   dependency.
logger = LazyLogger()
from secure_mcp_gateway.version import __version__


# Get debug log level (lazy-loaded to avoid circular imports)
def _get_debug_log_level():
    return get_common_config().get("enkrypt_log_level", "INFO").lower() == "debug"


# Use a property-like approach to avoid circular imports
class _DebugLevel:
    def __bool__(self):
        return _get_debug_log_level()


IS_DEBUG_LOG_LEVEL = _DebugLevel()

# NOTE:
# This module is imported very early in the gateway startup sequence by multiple
# subsystems. At that time, the telemetry provider (which owns the logger
# configuration) may not yet be initialized. As a result, calls to acquire a
# logger can return None, and the LazyLogger will no-op. To ensure critical
# bootstrap diagnostics are visible, we mirror key messages to stderr via
# print() in addition to logger calls. Once telemetry is initialized, logger
# messages will flow through the configured provider as usual.
# Initialize logger for this module
# print(
#     f"[utils] Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}",
#     file=sys.stderr,
# )
# logger.info(
#     f"[utils] Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}"
# )

IS_TELEMETRY_ENABLED = None

# --------------------------------------------------------------------------
# Also redefined funcations in telemetry.py to avoid circular imports
# If logic changes, please make changes in both files
# --------------------------------------------------------------------------


def get_file_from_root(file_name):
    """
    Get the absolute path of a file from the root directory (two levels up from current script)
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
    return os.path.join(root_dir, file_name)


def get_absolute_path(file_name):
    """
    Get the absolute path of a file
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, file_name)


def does_file_exist(file_name_or_path, is_absolute_path=None):
    """
    Check if a file exists in the current directory
    """
    if is_absolute_path is None:
        # Try to determine if it's an absolute path
        is_absolute_path = os.path.isabs(file_name_or_path)

    if is_absolute_path:
        return os.path.exists(file_name_or_path)
    else:
        return os.path.exists(get_absolute_path(file_name_or_path))


def is_docker():
    """
    Check if the code is running inside a Docker container.
    """
    # Check for Docker environment markers
    docker_env_indicators = ["/.dockerenv", "/run/.containerenv"]
    for indicator in docker_env_indicators:
        if os.path.exists(indicator):
            return True

    # Check cgroup for any containerization system entries
    container_identifiers = ["docker", "kubepods", "containerd", "lxc"]
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as f:
            for line in f:
                if any(keyword in line for keyword in container_identifiers):
                    return True
    except FileNotFoundError:
        # /proc/1/cgroup doesn't exist, which is common outside of Linux
        pass

    return False


@lru_cache(maxsize=16)
def get_common_config(print_debug=False):
    """
    Get the common configuration for the Enkrypt Secure MCP Gateway
    """
    config = {}

    # NOTE: Using sys_print here will cause a circular import between get_common_config, is_telemetry_enabled, and sys_print functions.
    # So we are using print instead.

    # TODO: Fix error and use stdout
    # print("[utils] Getting Enkrypt Common Configuration", file=sys.stderr)
    # logger.info("[utils] Getting Enkrypt Common Configuration")

    if print_debug:
        logger.debug(f"[utils] config_path: {CONFIG_PATH}")
        logger.debug(f"[utils] docker_config_path: {DOCKER_CONFIG_PATH}")
        logger.debug(f"[utils] example_config_path: {EXAMPLE_CONFIG_PATH}")

    is_running_in_docker = is_docker()
    # logger.debug(f"[utils] is_running_in_docker: {is_running_in_docker}")
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
    if does_file_exist(picked_config_path):
        print(f"[utils] Loading {picked_config_path} file...", file=sys.stderr)
        logger.info(f"[utils] Loading {picked_config_path} file...")
        with open(picked_config_path, encoding="utf-8") as f:
            config = json.load(f)
    else:
        logger.info("[utils] No config file found. Loading example config.")
        if does_file_exist(EXAMPLE_CONFIG_PATH):
            if print_debug:
                logger.debug(f"[utils] Loading {EXAMPLE_CONFIG_NAME} file...")
            with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                config = json.load(f)
        else:
            logger.info(
                "[utils] Example config file not found. Using default common config."
            )

    if print_debug and config:
        logger.debug(f"[utils] config: {config}")

    common_config = config.get("common_mcp_gateway_config", {})
    plugins_config = config.get("plugins", {})
    # Merge with defaults to ensure all required fields exist
    return {**DEFAULT_COMMON_CONFIG, **common_config, "plugins": plugins_config}


def is_telemetry_enabled():
    """
    Check if telemetry is enabled
    """
    global IS_TELEMETRY_ENABLED
    if IS_TELEMETRY_ENABLED:
        return True
    elif IS_TELEMETRY_ENABLED is not None:
        return False

    config = get_common_config()
    telemetry_plugin_config = config.get("plugins", {}).get("telemetry", {})
    telemetry_config = telemetry_plugin_config.get("config", {})
    if not telemetry_config.get("enabled", False):
        IS_TELEMETRY_ENABLED = False
        return False

    endpoint = telemetry_config.get("url", "http://localhost:4317")

    try:
        parsed_url = urlparse(endpoint)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if not hostname or not port:
            logger.error(f"[utils] Invalid OTLP endpoint URL: {endpoint}")
            IS_TELEMETRY_ENABLED = False
            return False

        # Get configurable timeout from TimeoutManager
        from secure_mcp_gateway.services.timeout import get_timeout_manager

        timeout_manager = get_timeout_manager()
        timeout_value = timeout_manager.get_timeout("connectivity")

        with socket.create_connection((hostname, port), timeout=timeout_value):
            IS_TELEMETRY_ENABLED = True
            return True
    except (OSError, AttributeError, TypeError, ValueError) as e:
        logger.error(
            f"[utils] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}"
        )
        IS_TELEMETRY_ENABLED = False
        return False


def generate_custom_id():
    """
    Generate a unique identifier consisting of 34 random characters followed by current timestamp.

    Returns:
        str: A string in format '{random_chars}_{timestamp_ms}' that can be used as a unique identifier
    """
    try:
        # Generate 34 random characters (letters + digits)
        charset = string.ascii_letters + string.digits
        random_part = "".join(secrets.choice(charset) for _ in range(34))

        # Get current epoch time in milliseconds
        timestamp_ms = int(time.time() * 1000)

        return f"{random_part}_{timestamp_ms}"
    except Exception as e:
        logger.error(f"[utils] Error generating custom ID: {e}")
        # Fallback to a simpler ID if there's an error
        return f"fallback_{int(time.time())}"


def sys_print(*args, **kwargs):
    """
    Print a message using the logger system.

    Args:
        *args: Arguments to log
        **kwargs: Keyword arguments including:
            - is_error (bool): If True, use logger.error
            - is_debug (bool): If True, use logger.debug
    """
    is_error = kwargs.pop("is_error", False)
    is_debug = kwargs.pop("is_debug", False)

    # Using try/except to avoid any logging errors blocking the flow for edge cases
    try:
        if args:
            # Join all arguments into a single message
            message = " ".join(str(arg) for arg in args)

            # Route to appropriate logger method
            if is_error:
                logger.error(message)
            elif is_debug:
                logger.debug(message)
            else:
                logger.info(message)
    except Exception as e:
        # Fallback to print if logger fails
        print(f"[utils] Error logging using sys_print: {e}", file=sys.stderr)
        pass


def mask_key(key):
    """
    Masks the last 4 characters of the key.
    """
    if not key or len(key) < 4:
        return "****"
    return "****" + key[-4:]


def build_log_extra(ctx, custom_id=None, server_name=None, error=None, **kwargs):
    """Build structured log extras. Tolerates missing/invalid ctx.

    Falls back to 'not_provided' values if ctx is not an MCP Context or
    if credentials/config cannot be resolved.
    """
    project_id = "not_provided"
    user_id = "not_provided"
    project_name = "not_provided"
    email = "not_provided"
    mcp_config_id = "not_provided"

    try:
        # Only attempt auth lookups when ctx looks like an MCP Context
        has_ctx_attrs = hasattr(ctx, "request_context") or hasattr(ctx, "__dict__")
        if has_ctx_attrs:
            from secure_mcp_gateway.plugins.auth import get_auth_config_manager

            auth_manager = get_auth_config_manager()
            credentials = auth_manager.get_gateway_credentials(ctx)
            gateway_key = credentials.get("gateway_key")
            project_id = credentials.get("project_id", project_id)
            user_id = credentials.get("user_id", user_id)

            if gateway_key:
                try:
                    import asyncio

                    # Check if we're already in an async context
                    try:
                        # Try to get the current event loop
                        loop = asyncio.get_running_loop()
                        # If we get here, we're in an async context, skip the call
                        # to avoid creating unawaited coroutines
                        pass
                    except RuntimeError:
                        # No event loop running, safe to use asyncio.run()
                        try:
                            gateway_config = (
                                asyncio.run(
                                    auth_manager.get_local_mcp_config(
                                        gateway_key, project_id, user_id
                                    )
                                )
                                or {}
                            )
                            project_name = gateway_config.get(
                                "project_name", project_name
                            )
                            email = gateway_config.get("email", email)
                            mcp_config_id = gateway_config.get(
                                "mcp_config_id", mcp_config_id
                            )
                        except Exception:
                            # If anything fails, just use defaults
                            pass
                except Exception:
                    # If anything fails, just use defaults
                    pass
    except Exception:
        # Swallow errors and use defaults to avoid breaking logging
        pass

    # Filter out None values from kwargs
    filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}

    return {
        "custom_id": custom_id or "",
        "server_name": server_name or "",
        "project_id": project_id or "",
        "project_name": project_name or "",
        "user_id": user_id or "",
        "email": email or "",
        "mcp_config_id": mcp_config_id or "",
        "error": error or "",
        **filtered_kwargs,
    }


def mask_server_config_sensitive_data(server_info):
    """
    Masks sensitive data in server configuration before returning to client.

    Args:
        server_info (dict): Server configuration dictionary

    Returns:
        dict: Server configuration with sensitive data masked
    """
    if not server_info:
        return server_info

    # Create a deep copy to avoid modifying the original
    import copy

    masked_server_info = copy.deepcopy(server_info)

    # Mask environment variables in config
    if "config" in masked_server_info and "env" in masked_server_info["config"]:
        masked_server_info["config"]["env"] = mask_sensitive_env_vars(
            masked_server_info["config"]["env"]
        )

    return masked_server_info


def mask_sensitive_env_vars(env_vars):
    """
    Masks sensitive environment variables that may contain tokens, keys, or secrets.

    Args:
        env_vars (dict): Dictionary of environment variables

    Returns:
        dict: Environment variables with sensitive values masked
    """
    if not env_vars:
        return env_vars

    sensitive_keys = [
        "token",
        "key",
        "secret",
        "password",
        "pass",
        "auth",
        "credential",
        "api_key",
        "access_token",
        "refresh_token",
        "bearer",
        "jwt",
        "github_token",
        "github_key",
        "gitlab_token",
        "bitbucket_token",
        "aws_key",
        "aws_secret",
        "azure_key",
        "gcp_key",
        "database_url",
        "connection_string",
        "uri",
        "url",
    ]

    masked_env = {}
    for key, value in env_vars.items():
        key_lower = key.lower()
        is_sensitive = any(
            sensitive_key in key_lower for sensitive_key in sensitive_keys
        )

        if is_sensitive and value:
            # Mask the value, showing only first 4 and last 4 characters
            if len(value) <= 8:
                masked_env[key] = "****"
            else:
                masked_env[key] = value[:4] + "****" + value[-4:]
        else:
            masked_env[key] = value

    return masked_env


def get_server_info_by_name(gateway_config, server_name):
    """
    Retrieves server configuration by server name from gateway config.

    Args:
        gateway_config (dict): Gateway/user's configuration containing server details
        server_name (str): Name of the server to look up

    Returns:
        dict: Server configuration if found, None otherwise
    """
    if IS_DEBUG_LOG_LEVEL:
        logger.debug(f"[get_server_info_by_name] Getting server info for {server_name}")
    mcp_config = gateway_config.get("mcp_config", [])
    if IS_DEBUG_LOG_LEVEL:
        # Mask sensitive data in debug logs
        masked_mcp_config = []
        for server in mcp_config:
            masked_server = server.copy()
            if "config" in masked_server and "env" in masked_server["config"]:
                masked_server["config"] = masked_server["config"].copy()
                masked_server["config"]["env"] = mask_sensitive_env_vars(
                    masked_server["config"]["env"]
                )
            masked_mcp_config.append(masked_server)
        logger.debug(f"[get_server_info_by_name] mcp_config: {masked_mcp_config}")
    return next((s for s in mcp_config if s.get("server_name") == server_name), None)


def mask_sensitive_headers(
    headers: Union[Dict[str, str], Dict[str, Any]],
) -> Dict[str, str]:
    """
    Mask sensitive information in HTTP headers for logging purposes.

    Args:
        headers: Dictionary of HTTP headers

    Returns:
        Dictionary with sensitive headers masked
    """
    if not headers:
        return {}

    # Define sensitive header patterns (case-insensitive)
    sensitive_patterns = [
        # Authentication headers
        "authorization",
        "auth",
        "bearer",
        "token",
        "apikey",
        "api-key",
        "api_key",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-auth",
        "x-token",
        "x-enkrypt-api-key",
        "x-enkrypt-gateway-key",
        # Security headers
        "cookie",
        "set-cookie",
        "x-csrf-token",
        "x-csrf",
        "csrf-token",
        "x-requested-with",
        "x-forwarded-for",
        "x-real-ip",
        # Sensitive data headers
        "password",
        "passwd",
        "pwd",
        "secret",
        "private",
        "key",
        "session",
        "sessionid",
        "session-id",
        "sess",
        # Custom sensitive headers
        "x-session",
        "x-user",
        "x-tenant",
        "x-org",
        "x-organization",
        "x-client",
        "x-device",
        "x-device-id",
        "x-deviceid",
        # OAuth and JWT
        "oauth",
        "jwt",
        "access-token",
        "refresh-token",
        "id-token",
        "x-oauth",
        "x-jwt",
        "x-access",
        "x-refresh",
    ]

    masked_headers = {}

    for key, value in headers.items():
        key_lower = key.lower()

        # Check if this header should be masked
        should_mask = any(pattern in key_lower for pattern in sensitive_patterns)

        if should_mask:
            # Mask the value but preserve the structure
            if isinstance(value, str) and len(value) > 0:
                if len(value) <= 4:
                    masked_headers[key] = "***"
                else:
                    # Show first 2 and last 2 characters for longer values
                    masked_headers[key] = f"{value[:2]}***{value[-2:]}"
            else:
                masked_headers[key] = "***"
        else:
            # Keep non-sensitive headers as-is
            masked_headers[key] = value

    return masked_headers


def mask_sensitive_data(
    data: Dict[str, Any], sensitive_keys: list = None
) -> Dict[str, Any]:
    """
    Recursively mask sensitive information in a dictionary.

    Args:
        data: Dictionary to mask
        sensitive_keys: List of keys to mask (defaults to common sensitive keys)

    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "private",
            "key",
            "token",
            "apikey",
            "api_key",
            "api-key",
            "auth",
            "authorization",
            "bearer",
            "session",
            "sessionid",
            "session-id",
            "cookie",
            "csrf",
            "oauth",
            "jwt",
            "access-token",
            "refresh-token",
            "id-token",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-csrf-token",
            "x-enkrypt-api-key",
            "x-enkrypt-gateway-key",
        ]

    if not isinstance(data, dict):
        return data

    masked_data = {}

    for key, value in data.items():
        key_lower = key.lower()

        # Check if this key should be masked
        should_mask = any(pattern in key_lower for pattern in sensitive_keys)

        if should_mask:
            if isinstance(value, str) and len(value) > 0:
                if len(value) <= 4:
                    masked_data[key] = "***"
                else:
                    masked_data[key] = f"{value[:2]}***{value[-2:]}"
            else:
                masked_data[key] = "***"
        elif isinstance(value, dict):
            # Recursively mask nested dictionaries
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
        elif isinstance(value, list):
            # Mask items in lists
            masked_data[key] = [
                mask_sensitive_data(item, sensitive_keys)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            masked_data[key] = value

    return masked_data
