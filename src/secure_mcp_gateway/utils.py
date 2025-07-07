"""
Enkrypt Secure MCP Gateway Common Utilities Module

This module provides common utilities for the Enkrypt Secure MCP Gateway
"""

import os
import sys
import json
from importlib.resources import files
from secure_mcp_gateway.version import __version__

# TODO: Fix error and use stdout
print(f"Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}", file=sys.stderr)

CONFIG_NAME = "enkrypt_mcp_config.json"
DOCKER_CONFIG_PATH = f"/app/.enkrypt/docker/{CONFIG_NAME}"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".enkrypt", CONFIG_NAME)

BASE_DIR = str(files('secure_mcp_gateway'))
EXAMPLE_CONFIG_NAME = f"example_{CONFIG_NAME}"
EXAMPLE_CONFIG_PATH = os.path.join(BASE_DIR, EXAMPLE_CONFIG_NAME)

DEFAULT_COMMON_CONFIG = {
    "enkrypt_log_level": "INFO",
    "enkrypt_guardrails_enabled": False,
    "enkrypt_base_url": "https://api.enkryptai.com",
    "enkrypt_api_key": "YOUR_ENKRYPT_API_KEY",
    "enkrypt_use_remote_mcp_config": False,
    "enkrypt_remote_mcp_gateway_name": "enkrypt-secure-mcp-gateway-1",
    "enkrypt_remote_mcp_gateway_version": "v1",
    "enkrypt_mcp_use_external_cache": False,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": None,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_async_input_guardrails_enabled": False,
    "enkrypt_async_output_guardrails_enabled": False
}


def sys_print(*args, **kwargs):
    """
    Print a message to the console
    """
    # If is_error is True, print to stderr
    if kwargs.get('is_error', False):
        kwargs.setdefault('file', sys.stderr)
    else:
        # TODO: Fix error and use stdout
        # kwargs.setdefault('file', sys.stdout)
        kwargs.setdefault('file', sys.stderr)

    # Remove invalid params for print
    if 'is_error' in kwargs:
        del kwargs['is_error']

    # Using try/except to avoid any print errors blocking the flow for edge cases
    try:
        print(*args, **kwargs)
    except Exception as e:
        # Ignore any print errors
        print(f"Error printing using sys_print: {e}", file=sys.stderr)


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


def get_common_config(print_debug=False):
    """
    Get the common configuration for the Enkrypt Secure MCP Gateway
    """
    config = {}

    if print_debug:
        sys_print("Getting Enkrypt Common Configuration")
        sys_print(f"config_path: {CONFIG_PATH}")
        sys_print(f"docker_config_path: {DOCKER_CONFIG_PATH}")
        sys_print(f"example_config_path: {EXAMPLE_CONFIG_PATH}")

    is_running_in_docker = is_docker()
    sys_print(f"is_running_in_docker: {is_running_in_docker}")
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
    if does_file_exist(picked_config_path):
        sys_print(f"Loading {picked_config_path} file...")
        with open(picked_config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    else:
        sys_print("No config file found. Loading example config.")
        if does_file_exist(EXAMPLE_CONFIG_PATH):
            if print_debug:
                sys_print(f"Loading {EXAMPLE_CONFIG_NAME} file...")
            with open(EXAMPLE_CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            sys_print("Example config file not found. Using default common config.")

    if print_debug and config:
        sys_print(f"config: {config}")

    common_config = config.get("common_mcp_gateway_config", {})
    # Merge with defaults to ensure all required fields exist
    return {**DEFAULT_COMMON_CONFIG, **common_config}
