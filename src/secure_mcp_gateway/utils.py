"""
Enkrypt Secure MCP Gateway Common Utilities Module

This module provides common utilities for the Enkrypt Secure MCP Gateway
"""

import json
import os
import secrets
import socket
import string
import sys
import time
from functools import lru_cache
from urllib.parse import urlparse

from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DEFAULT_COMMON_CONFIG,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    EXAMPLE_CONFIG_PATH,
)

# Lazy import to avoid circular imports
_logger_cache = None


def get_logger():
    """Lazy logger retrieval to avoid circular imports and early initialization."""
    global _logger_cache
    if _logger_cache is None:
        try:
            from secure_mcp_gateway.plugins.telemetry import (
                get_telemetry_config_manager,
            )

            telemetry_manager = get_telemetry_config_manager()
            _logger_cache = telemetry_manager.get_logger()
        except Exception:
            # If telemetry is not available, return None
            _logger_cache = None
    return _logger_cache


# For backward compatibility, expose logger as a module-level variable
class LazyLogger:
    """Lazy logger wrapper for backward compatibility."""

    def __getattr__(self, name):
        logger = get_logger()
        if logger:
            return getattr(logger, name)
        # No-op if logger not available
        return lambda *args, **kwargs: None


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

# TODO: Fix error and use stdout
print(
    f"[utils] Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}",
    file=sys.stderr,
)

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
    print("[utils] Getting Enkrypt Common Configuration", file=sys.stderr)

    if print_debug:
        print(f"[utils] config_path: {CONFIG_PATH}", file=sys.stderr)
        print(f"[utils] docker_config_path: {DOCKER_CONFIG_PATH}", file=sys.stderr)
        print(f"[utils] example_config_path: {EXAMPLE_CONFIG_PATH}", file=sys.stderr)

    is_running_in_docker = is_docker()
    print(f"[utils] is_running_in_docker: {is_running_in_docker}", file=sys.stderr)
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
    if does_file_exist(picked_config_path):
        print(f"[utils] Loading {picked_config_path} file...", file=sys.stderr)
        with open(picked_config_path, encoding="utf-8") as f:
            config = json.load(f)
    else:
        print("[utils] No config file found. Loading example config.", file=sys.stderr)
        if does_file_exist(EXAMPLE_CONFIG_PATH):
            if print_debug:
                print(f"[utils] Loading {EXAMPLE_CONFIG_NAME} file...", file=sys.stderr)
            with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                config = json.load(f)
        else:
            print(
                "[utils] Example config file not found. Using default common config.",
                file=sys.stderr,
            )

    if print_debug and config:
        print(f"[utils] config: {config}", file=sys.stderr)

    common_config = config.get("common_mcp_gateway_config", {})
    # Merge with defaults to ensure all required fields exist
    return {**DEFAULT_COMMON_CONFIG, **common_config}


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
    telemetry_config = config.get("enkrypt_telemetry", {})
    if not telemetry_config.get("enabled", False):
        IS_TELEMETRY_ENABLED = False
        return False

    endpoint = telemetry_config.get("endpoint", "http://localhost:4317")

    try:
        parsed_url = urlparse(endpoint)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if not hostname or not port:
            print(f"[utils] Invalid OTLP endpoint URL: {endpoint}", file=sys.stderr)
            IS_TELEMETRY_ENABLED = False
            return False

        with socket.create_connection((hostname, port), timeout=1):
            IS_TELEMETRY_ENABLED = True
            return True
    except (OSError, AttributeError, TypeError, ValueError) as e:
        print(
            f"[utils] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}",
            file=sys.stderr,
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
        print(f"[utils] Error generating custom ID: {e}", file=sys.stderr)
        # Fallback to a simpler ID if there's an error
        return f"fallback_{int(time.time())}"


def sys_print(*args, **kwargs):
    """
    Print a message to the console and optionally log it via telemetry.

    Args:
        *args: Arguments to print
        **kwargs: Keyword arguments including:
            - is_error (bool): If True, print to stderr and log as error
            - is_debug (bool): If True, log as debug instead of info
    """
    is_error = kwargs.pop("is_error", False)
    is_debug = kwargs.pop("is_debug", False)

    # If is_error is True, print to stderr
    if is_error:
        kwargs.setdefault("file", sys.stderr)
    else:
        # TODO: Fix error and use stdout
        # kwargs.setdefault('file', sys.stdout)
        kwargs.setdefault("file", sys.stderr)

    # Using try/except to avoid any print errors blocking the flow for edge cases
    try:
        if args:
            # Always print to console
            print(*args, **kwargs)

            # Also log via telemetry if enabled
            if is_telemetry_enabled():
                # Format args similar to how print() does it
                sep = kwargs.get("sep", " ")
                log_message = sep.join(str(arg) for arg in args)
                if is_error:
                    logger.error(log_message)
                elif is_debug:
                    logger.debug(log_message)
                else:
                    logger.info(log_message)
    except Exception as e:
        # Ignore any print errors
        print(f"[utils] Error printing using sys_print: {e}", file=sys.stderr)
        pass


def mask_key(key):
    """
    Masks the last 4 characters of the key.
    """
    if not key or len(key) < 4:
        return "****"
    return "****" + key[-4:]


def build_log_extra(ctx, custom_id=None, server_name=None, error=None, **kwargs):
    from secure_mcp_gateway.plugins.auth import get_auth_config_manager

    auth_manager = get_auth_config_manager()
    credentials = auth_manager.get_gateway_credentials(ctx)
    gateway_key = credentials.get("gateway_key")
    project_id = credentials.get("project_id", "not_provided")
    user_id = credentials.get("user_id", "not_provided")
    # if project_id == "not_provided" or user_id == "not_provided" or mcp_config_id == "not_provided":
    #     sys_print(f"[build_log_extra] Project ID, User ID or MCP Config ID is not provided", is_error=True)
    #     return {}

    gateway_config = auth_manager.get_local_mcp_config(gateway_key, project_id, user_id)
    project_name = gateway_config.get("project_name", "not_provided")
    email = gateway_config.get("email", "not_provided")
    mcp_config_id = gateway_config.get("mcp_config_id", "not_provided")
    # Filter out None values from kwargs
    filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}

    return {
        # "request_id": getattr(ctx, 'request_id', None),
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
        sys_print(
            f"[get_server_info_by_name] Getting server info for {server_name}",
            is_debug=True,
        )
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
        sys_print(
            f"[get_server_info_by_name] mcp_config: {masked_mcp_config}", is_debug=True
        )
    return next((s for s in mcp_config if s.get("server_name") == server_name), None)
