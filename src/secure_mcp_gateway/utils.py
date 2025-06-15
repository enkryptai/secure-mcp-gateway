"""
Enkrypt Secure MCP Gateway Common Utilities Module

This module provides common utilities for the Enkrypt Secure MCP Gateway
"""

import os
import sys
import json
from importlib.resources import files
from secure_mcp_gateway.version import __version__

print(f"Initializing Enkrypt Secure MCP Gateway Common Utilities Module v{__version__}", file=sys.stderr)

BASE_DIR = str(files('secure_mcp_gateway'))
CONFIG_NAME = "enkrypt_mcp_config.json"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".enkrypt", CONFIG_NAME)

EXAMPLE_CONFIG_NAME = f"example_{CONFIG_NAME}"
# EXAMPLE_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), EXAMPLE_CONFIG_NAME)
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


def sys_print(message, file=sys.stderr):
    """
    Print a message to the console
    """
    print(message, file=file)


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


def does_file_exist(file_name_or_path, is_absolute_path=False):
    """
    Check if a file exists in the current directory
    """
    if is_absolute_path:
        return os.path.exists(file_name_or_path)
    else:
        return os.path.exists(get_absolute_path(file_name_or_path))


def get_common_config(print_debug=False):
    """
    Get the common configuration for the Enkrypt Secure MCP Gateway
    """
    config = {}

    if print_debug:
        print("Getting Enkrypt Common Configuration", file=sys.stderr)
    if print_debug:
        print(f"config_path: {CONFIG_PATH}", file=sys.stderr)
        print(f"example_config_path: {EXAMPLE_CONFIG_PATH}", file=sys.stderr)

    if does_file_exist(CONFIG_PATH, True):
        if print_debug:
            print(f"Loading {CONFIG_NAME} file...", file=sys.stderr)
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
    elif does_file_exist(EXAMPLE_CONFIG_PATH, True):
        if print_debug:
            print(f"No {CONFIG_NAME} file found. Defaulting to {EXAMPLE_CONFIG_NAME}", file=sys.stderr)
        with open(EXAMPLE_CONFIG_PATH, 'r') as f:
            config = json.load(f)
    else:
        sys_print("Both config file or example config file not found.")

    if print_debug:
        print(f"config: {config}", file=sys.stderr)
    if config:
        return config.get("common_mcp_gateway_config")

    sys_print("Config not found in ~/.enkrypt directory. Checking /app/ if this is docker container")
    docker_config_path = f"/app/{CONFIG_NAME}"
    docker_example_config_path = f"/app/example_{CONFIG_NAME}"

    if does_file_exist(docker_config_path, True):
        if print_debug:
            print(f"Loading {CONFIG_NAME} file from docker container...", file=sys.stderr)
        with open(docker_config_path, 'r') as f:
            config = json.load(f)
        if print_debug:
            print(f"config: {config}", file=sys.stderr)
    elif does_file_exist(docker_example_config_path, True):
        if print_debug:
            print(f"No {CONFIG_NAME} file found. Defaulting to {EXAMPLE_CONFIG_NAME} from docker container", file=sys.stderr)
        with open(docker_example_config_path, 'r') as f:
            config = json.load(f)
        if print_debug:
            print(f"{EXAMPLE_CONFIG_NAME}: {config}", file=sys.stderr)
    else:
        if print_debug:
            print("Both config file or example config file not found in ~/.enkrypt directory or docker container path. Defaulting to hard coded config", file=sys.stderr)

    return config.get("common_mcp_gateway_config", DEFAULT_COMMON_CONFIG)
