"""
Enkrypt Secure MCP Gateway Common Utilities Module

This module provides common utilities for the Enkrypt Secure MCP Gateway
"""

import os
import sys
import json
import time
import string
import socket
import secrets
from urllib.parse import urlparse
from functools import lru_cache
from importlib.resources import files
from secure_mcp_gateway.telemetry import logger
from secure_mcp_gateway.version import __version__

from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    DEFAULT_COMMON_CONFIG
)

# TODO: Fix error and use stdout
print(f"[utils] Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}", file=sys.stderr)

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
    docker_env_indicators = ['/.dockerenv', '/run/.containerenv']
    for indicator in docker_env_indicators:
        if os.path.exists(indicator):
            return True

    # Check cgroup for any containerization system entries
    container_identifiers = ['docker', 'kubepods', 'containerd', 'lxc']
    try:
        with open('/proc/1/cgroup', 'rt', encoding='utf-8') as f:
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
    print(f"[utils] Getting Enkrypt Common Configuration", file=sys.stderr)

    if print_debug:
        print(f"[utils] config_path: {CONFIG_PATH}", file=sys.stderr)
        print(f"[utils] docker_config_path: {DOCKER_CONFIG_PATH}", file=sys.stderr)
        print(f"[utils] example_config_path: {EXAMPLE_CONFIG_PATH}", file=sys.stderr)

    is_running_in_docker = is_docker()
    print(f"[utils] is_running_in_docker: {is_running_in_docker}", file=sys.stderr)
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
    if does_file_exist(picked_config_path):
        print(f"[utils] Loading {picked_config_path} file...", file=sys.stderr)
        with open(picked_config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    else:
        print("[utils] No config file found. Loading example config.", file=sys.stderr)
        if does_file_exist(EXAMPLE_CONFIG_PATH):
            if print_debug:
                print(f"[utils] Loading {EXAMPLE_CONFIG_NAME} file...", file=sys.stderr)
            with open(EXAMPLE_CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            print("[utils] Example config file not found. Using default common config.", file=sys.stderr)

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
    except (socket.error, AttributeError, TypeError, ValueError) as e:
        print(f"[utils] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}", file=sys.stderr)
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
        random_part = ''.join(secrets.choice(charset) for _ in range(34))

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
    is_error=kwargs.pop('is_error', False)
    is_debug=kwargs.pop('is_debug', False)

    # If is_error is True, print to stderr
    if is_error:
        kwargs.setdefault('file', sys.stderr)
    else:
        # TODO: Fix error and use stdout
        # kwargs.setdefault('file', sys.stdout)
        kwargs.setdefault('file', sys.stderr)

    # Using try/except to avoid any print errors blocking the flow for edge cases
    try:
        if args:
            if is_telemetry_enabled():
                # Format args similar to how print() does it
                sep = kwargs.get('sep', ' ')
                log_message = sep.join(str(arg) for arg in args)
                if is_error:
                    logger.error(log_message)
                elif is_debug:
                    logger.debug(log_message)
                else:
                    logger.info(log_message)
            else:
                print(*args, **kwargs)
    except Exception as e:
        # Ignore any print errors
        print(f"[utils] Error printing using sys_print: {e}", file=sys.stderr)
        pass

