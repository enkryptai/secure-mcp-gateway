"""
Enkrypt Secure MCP Gateway Common Utilities Module

This module provides common utilities for the Enkrypt Secure MCP Gateway
"""

import os
import sys
import time
import json

print("Initializing Enkrypt Secure MCP Gateway Common Utilities Module", file=sys.stderr)


def sys_print(message, file=sys.stderr):
    """
    Print a message to the console
    """
    print(message, file=file)

def get_absolute_path_from_parent_dir(file_name):
    """
    Get the absolute path of a file from the parent directory of the current script
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    return os.path.join(parent_dir, file_name)

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
    if print_debug:
        print("Getting Enkrypt Common Configuration", file=sys.stderr)
    file_name = 'enkrypt_mcp_config.json'
    example_file_name = f'example_{file_name}'
    config_path = get_absolute_path_from_parent_dir(file_name)
    example_config_path = get_absolute_path_from_parent_dir(example_file_name)
    if print_debug:
        print(f"config_path: {config_path}", file=sys.stderr)
        print(f"example_config_path: {example_config_path}", file=sys.stderr)

    config = {}
    if does_file_exist(config_path, True):
        if print_debug:
          print(f"Loading {file_name} file...", file=sys.stderr)
        with open(config_path, 'r') as f:
            config = json.load(f)
        if print_debug:
            print(f"config: {config}", file=sys.stderr)
    elif does_file_exist(example_config_path, True):
        if print_debug:
            print(f"No {file_name} file found. Defaulting to {example_file_name}", file=sys.stderr)
        with open(example_config_path, 'r') as f:
            config = json.load(f)
        if print_debug:
            print(f"{example_file_name}: {config}", file=sys.stderr)
    else:
        if print_debug:
            print("Both config file or example config file not found. Defaulting to hard coded config", file=sys.stderr)

    return config.get("common_mcp_gateway_config", {
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
    })

