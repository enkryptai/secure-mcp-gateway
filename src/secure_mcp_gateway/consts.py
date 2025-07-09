"""
Enkrypt Secure MCP Gateway Common Constants Module

This module provides common constants for the Enkrypt Secure MCP Gateway
"""

import os
import sys
from importlib.resources import files
from secure_mcp_gateway.version import __version__

# TODO: Fix error and use stdout
print(f"Initializing Enkrypt Secure MCP Gateway Common Constants Module v{__version__}", file=sys.stderr)

CONFIG_NAME = "enkrypt_mcp_config.json"
DOCKER_CONFIG_PATH = f"/app/.enkrypt/docker/{CONFIG_NAME}"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".enkrypt", CONFIG_NAME)

BASE_DIR = files('secure_mcp_gateway')
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
    "enkrypt_async_output_guardrails_enabled": False,
    "enkrypt_telemetry": {
      "enabled": False,
      "insecure": True,
      "endpoint": "http://localhost:4317"
    }
}

