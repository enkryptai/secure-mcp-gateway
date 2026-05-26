"""Common constants for MCP Gateway."""

import os
import sys
from importlib.resources import files

from secure_mcp_gateway.version import __version__

# TODO: Fix error and use stdout
# print(
#     f"Initializing Enkrypt Secure MCP Gateway Common Constants Module v{__version__}",
#     file=sys.stderr,
# )

CONFIG_NAME = "enkrypt_mcp_config.json"
DOCKER_CONFIG_PATH = f"/app/.enkrypt/docker/{CONFIG_NAME}"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".enkrypt", CONFIG_NAME)
HOST_DOCKER_CONFIG_PATH = os.path.join(
    os.path.expanduser("~"), ".enkrypt", "docker", CONFIG_NAME
)

# TTL for the in-process cache that the Enkrypt cloud-auth provider uses to
# avoid hitting GET /mcp-gateway/get-gateway-config on every tool call.
# Operators can override per-deployment via auth.config.cache_ttl_seconds.
ENKRYPT_REMOTE_CONFIG_TTL_SECONDS = 600

BASE_DIR = files("secure_mcp_gateway")
EXAMPLE_CONFIG_NAME = f"example_{CONFIG_NAME}"
EXAMPLE_CONFIG_PATH = os.path.join(BASE_DIR, EXAMPLE_CONFIG_NAME)

# ``enkrypt_config`` only holds credentials/endpoints for talking to
# Enkrypt cloud. The local REST admin API key (``admin_apikey``) used to
# live here but was moved to root-level because it has no relationship
# with Enkrypt cloud; nesting it under ``enkrypt_config`` was misleading.
# ``auth_policy.resolve_admin_keys`` still accepts the legacy nested
# location for backward-compat.
DEFAULT_ENKRYPT_CONFIG = {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com",
}

DEFAULT_COMMON_CONFIG = {
    "enkrypt_log_level": "INFO",
    # NOTE: ``enkrypt_use_remote_mcp_config`` /
    # ``enkrypt_remote_mcp_gateway_name`` /
    # ``enkrypt_remote_mcp_gateway_version`` are *deprecated*. They only
    # drive the legacy ``LocalApiKeyProvider``'s "fetch config from Enkrypt
    # cloud" fallback (``utils.use_remote_mcp_config``). New deployments
    # should use ``plugins.auth.provider = "enkrypt"`` instead, which has
    # its own cleaner cloud-config flow (see EnkryptAuthProvider). The
    # accessor functions in ``utils`` default to False / sensible strings
    # when these keys are absent, so leaving them out of the defaults
    # here is safe.
    "enkrypt_mcp_use_external_cache": False,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": None,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_gateway_cache_expiration_minutes": 5,
    "enkrypt_config_watcher_poll_seconds": 2.0,
    "enkrypt_async_input_guardrails_enabled": False,
    "enkrypt_async_output_guardrails_enabled": False,
    # Session Pool Configuration
    "session_pool_enabled": True,
    "session_pool_ttl": 300,
    # Sandbox Configuration
    "sandbox": {
        "enabled": False,
        "runtime": "docker",
        "default_image": "python:3.11-slim",
        "default_memory_limit": "512m",
        "default_cpu_limit": "1.0",
        "default_pids_limit": 100,
        "default_network": "none",
        "default_read_only": True,
        "container_cli": "auto",
        "nova_api_url": "http://localhost:9800",
    },
    # Timeout Management Configuration
    "timeout_settings": {
        "default_timeout": 30,
        "guardrail_timeout": 130,
        "auth_timeout": 10,
        "tool_execution_timeout": 120,
        "discovery_timeout": 180,
        "cache_timeout": 5,
        "connectivity_timeout": 2,
        "escalation_policies": {
            "warn_threshold": 0.8,
            "timeout_threshold": 1.0,
            "fail_threshold": 1.2,
        },
    },
}
