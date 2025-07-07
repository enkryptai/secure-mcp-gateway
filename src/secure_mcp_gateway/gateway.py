"""
Enkrypt Secure MCP Gateway Module

This module provides the main gateway functionality for the Enkrypt Secure MCP Gateway, handling:
1. Authentication and Authorization:
   - API key validation
   - Gateway configuration management
   - Server access control

2. Tool Management:
   - Tool discovery and caching
   - Secure tool invocation
   - Server configuration management

3. Guardrail Integration:
   - Input/output guardrails
   - PII handling
   - Content quality checks

4. Cache Management:
   - Tool caching
   - Gateway config caching
   - Cache invalidation

Configuration Variables:
    enkrypt_base_url: Base URL for EnkryptAI API
    enkrypt_use_remote_mcp_config: Enable/disable remote MCP config
    enkrypt_remote_mcp_gateway_name: Name of the MCP gateway
    enkrypt_remote_mcp_gateway_version: Version of the MCP gateway
    enkrypt_tool_cache_expiration: Tool cache expiration in hours
    enkrypt_gateway_cache_expiration: Gateway config cache expiration in hours
    enkrypt_mcp_use_external_cache: Enable/disable external cache
    enkrypt_async_input_guardrails_enabled: Enable/disable async input guardrails

Example Usage:
    ```python
    # Authenticate gateway/user
    auth_result = enkrypt_authenticate(ctx)

    # Discover server tools
    tools = await enkrypt_discover_all_tools(ctx, "server1")

    # Call a tool securely
    result = await enkrypt_secure_call_tool(ctx, "server1", "tool1", args)

    # Get server information
    info = await enkrypt_get_server_info(ctx, "server1")
    ```
"""

import os
import sys
import subprocess

# Printing system info before importing other modules
# As MCP Clients like Claude Desktop use their own Python interpreter, it may not have the modules installed
# So, we can use this debug system info to identify that python interpreter to install the missing modules using that specific interpreter
# So, debugging this in gateway module as this info can be used for fixing such issues in other modules
# TODO: Fix error and use stdout
print("Initializing Enkrypt Secure MCP Gateway Module", file=sys.stderr)
print("--------------------------------", file=sys.stderr)
print("SYSTEM INFO: ", file=sys.stderr)
print(f"Using Python interpreter: {sys.executable}", file=sys.stderr)
print(f"Python version: {sys.version}", file=sys.stderr)
print(f"Current working directory: {os.getcwd()}", file=sys.stderr)
print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}", file=sys.stderr)
print("--------------------------------", file=sys.stderr)

# Error: Can't find secure_mcp_gateway
# import importlib
# # Force module initialization to resolve pip installation issues
# try:
#     importlib.import_module("secure_mcp_gateway")
# except ImportError as e:
#     sys.stderr.write(f"Error importing secure_mcp_gateway: {e}\n")
#     sys.exit(1)

# Error: Can't find secure_mcp_gateway
# Add src directory to Python path
# from importlib.resources import files
# BASE_DIR = str(files('secure_mcp_gateway'))
# if BASE_DIR not in sys.path:
#     sys.path.insert(0, BASE_DIR)

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, '..'))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Try to install the package if not found to cater for clients like Claude Desktop who use a separate python interpreter
try:
    import secure_mcp_gateway
except ImportError:
    # TODO: Fix error and use stdout
    print("Installing secure_mcp_gateway package...", file=sys.stderr)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", src_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    import secure_mcp_gateway

from secure_mcp_gateway.utils import (
    sys_print,
    is_docker,
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    get_common_config,
)
from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.dependencies import __dependencies__

sys_print(f"Successfully imported secure_mcp_gateway v{__version__} in gateway module")

try:
    sys_print("Installing dependencies...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", *__dependencies__],
        stdout=subprocess.DEVNULL,  # Suppress output
        stderr=subprocess.DEVNULL
    )
    sys_print("All dependencies installed successfully.")
except Exception as e:
    sys_print(f"Error installing dependencies: {e}", is_error=True)

import json
import time
import asyncio
import requests
import traceback
# from starlette.requests import Request # This is the class of ctx.request_context.request
from mcp.server.fastmcp.tools import Tool
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP, Context
from mcp import ClientSession, StdioServerParameters

from secure_mcp_gateway.client import (
    initialize_cache,
    forward_tool_call,
    get_cached_tools,
    cache_tools,
    get_cached_gateway_config,
    cache_gateway_config,
    cache_key_to_id,
    get_id_from_key,
    clear_cache_for_servers,
    clear_gateway_config_cache,
    get_cache_statistics
)

from secure_mcp_gateway.guardrail import (
    anonymize_pii,
    deanonymize_pii,
    call_guardrail,
    check_relevancy,
    check_adherence,
    check_hallucination
)


common_config = get_common_config(True)

ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"
FASTMCP_LOG_LEVEL = ENKRYPT_LOG_LEVEL.upper()

ENKRYPT_BASE_URL = common_config.get("enkrypt_base_url", "https://api.enkryptai.com")
ENKRYPT_USE_REMOTE_MCP_CONFIG = common_config.get("enkrypt_use_remote_mcp_config", False)
ENKRYPT_REMOTE_MCP_GATEWAY_NAME = common_config.get("enkrypt_remote_mcp_gateway_name", "Test MCP Gateway")
ENKRYPT_REMOTE_MCP_GATEWAY_VERSION = common_config.get("enkrypt_remote_mcp_gateway_version", "v1")
ENKRYPT_TOOL_CACHE_EXPIRATION = int(common_config.get("enkrypt_tool_cache_expiration", 4))  # 4 hours
ENKRYPT_GATEWAY_CACHE_EXPIRATION = int(common_config.get("enkrypt_gateway_cache_expiration", 24))  # 24 hours (1 day)
ENKRYPT_MCP_USE_EXTERNAL_CACHE = common_config.get("enkrypt_mcp_use_external_cache", False)
ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED = common_config.get("enkrypt_async_input_guardrails_enabled", False)
ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED = common_config.get("enkrypt_async_output_guardrails_enabled", False)

ENKRYPT_API_KEY = common_config.get("enkrypt_api_key", "null")

sys_print("--------------------------------")
sys_print(f'enkrypt_log_level: {ENKRYPT_LOG_LEVEL}')
sys_print(f'is_debug_log_level: {IS_DEBUG_LOG_LEVEL}')
sys_print(f'enkrypt_base_url: {ENKRYPT_BASE_URL}')
sys_print(f'enkrypt_use_remote_mcp_config: {ENKRYPT_USE_REMOTE_MCP_CONFIG}')
if ENKRYPT_USE_REMOTE_MCP_CONFIG:
    sys_print(f'enkrypt_remote_mcp_gateway_name: {ENKRYPT_REMOTE_MCP_GATEWAY_NAME}')
    sys_print(f'enkrypt_remote_mcp_gateway_version: {ENKRYPT_REMOTE_MCP_GATEWAY_VERSION}')
sys_print(f'enkrypt_api_key: {"****" + ENKRYPT_API_KEY[-4:]}')
sys_print(f'enkrypt_tool_cache_expiration: {ENKRYPT_TOOL_CACHE_EXPIRATION}')
sys_print(f'enkrypt_gateway_cache_expiration: {ENKRYPT_GATEWAY_CACHE_EXPIRATION}')
sys_print(f'enkrypt_mcp_use_external_cache: {ENKRYPT_MCP_USE_EXTERNAL_CACHE}')
sys_print(f'enkrypt_async_input_guardrails_enabled: {ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED}')
if IS_DEBUG_LOG_LEVEL:
    sys_print(f'enkrypt_async_output_guardrails_enabled: {ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED}')
sys_print("--------------------------------")

# TODO
AUTH_SERVER_VALIDATE_URL = f"{ENKRYPT_BASE_URL}/mcp-gateway/get-gateway"

# For Output Checks if they are enabled in output_guardrails_policy['additional_config']
RELEVANCY_THRESHOLD = 0.75
ADHERENCE_THRESHOLD = 0.75


# --- Session data (for current session only, not persistent) ---
SESSIONS = {
    # "sample_gateway_key_1": {
    #     "authenticated": False,
    #     "gateway_config": None
    # }
}

# Initialize External Cache connection
if ENKRYPT_MCP_USE_EXTERNAL_CACHE:
    sys_print("Initializing External Cache connection")
    cache_client = initialize_cache()
else:
    sys_print("External Cache is not enabled. Using local cache only.")
    cache_client = None


# --- Helper functions ---

def mask_key(key):
    """
    Masks the last 4 characters of the key.
    """
    if not key or len(key) < 4:
        return "****"
    return "****" + key[-4:]


# Getting gateway key per request instead of global variable
# As we can support multuple gateway configs in the same Secure MCP Gateway server
def get_gateway_key(ctx: Context):
    """
    Retrieves the gateway key from the context.
    """
    gateway_key = None
    # Check context first which is different per request
    if ctx and ctx.request_context and ctx.request_context.request:
        gateway_key = ctx.request_context.request.headers.get("apikey")
        if gateway_key:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_gateway_key] Using gateway key from request context: {mask_key(gateway_key)}")
            return gateway_key
        
    # Fallback to environment variable
    gateway_key = os.environ.get("ENKRYPT_GATEWAY_KEY", None)
    if gateway_key:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_gateway_key] Using gateway key from environment variable: {mask_key(gateway_key)}")
        return gateway_key
    
    if IS_DEBUG_LOG_LEVEL:
        sys_print("[get_gateway_key] No gateway key found")
    return None


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
        sys_print(f"[get_server_info_by_name] Getting server info for {server_name}")
    mcp_config = gateway_config.get("mcp_config", [])
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[get_server_info_by_name] mcp_config: {mcp_config}")
    return next((s for s in mcp_config if s.get("server_name") == server_name), None)


def mcp_config_to_dict(mcp_config):
    """
    Converts MCP configuration list to a dictionary keyed by server name.

    Args:
        mcp_config (list): List of server configurations

    Returns:
        dict: Dictionary of server configurations keyed by server name
    """
    if IS_DEBUG_LOG_LEVEL:
        sys_print("[mcp_config_to_dict] Converting MCP config to dict")
    return {s["server_name"]: s for s in mcp_config}


def get_latest_server_info(server_info, id, cache_client):
    """
    Returns a fresh copy of server info with the latest tools.

    Args:
        server_info (dict): Original server configuration
        id (str): ID of the Gateway or User
        cache_client: Cache client instance

    Returns:
        dict: Updated server info with latest tools from config or cache
    """
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[get_latest_server_info] Getting latest server info for {id}")
    server_info_copy = server_info.copy()
    config_tools = server_info_copy.get("tools", {})
    server_name = server_info_copy.get("server_name")
    sys_print(f"[get_latest_server_info] Server name: {server_name}")

    # If tools is empty {}, then we discover them
    if not config_tools:
        sys_print(f"[get_latest_server_info] No config tools found for {server_name}")
        cached_tools = get_cached_tools(cache_client, id, server_name)
        if cached_tools:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_latest_server_info] Found cached tools for {server_name}")
            server_info_copy["tools"] = cached_tools
            server_info_copy["has_cached_tools"] = True
            server_info_copy["tools_source"] = "cache"
        else:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_latest_server_info] No cached tools found for {server_name}. Need to discover them")
            server_info_copy["tools"] = {}
            server_info_copy["has_cached_tools"] = False
            server_info_copy["tools_source"] = "needs_discovery"
    else:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_latest_server_info] Tools defined in config already for {server_name}")
        server_info_copy["tools_source"] = "config"
    return server_info_copy


# Read from local MCP config file
def get_local_mcp_config(gateway_key):
    """
    Reads MCP configuration from local config file.

    Args:
        gateway_key (str): Key to look up in config

    Returns:
        dict: MCP configuration for the given key, None if not found
    """
    running_in_docker = is_docker()
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[get_local_mcp_config] Getting local MCP config for {gateway_key} with running_in_docker: {running_in_docker}")

    config_path = DOCKER_CONFIG_PATH if running_in_docker else CONFIG_PATH
    if os.path.exists(config_path):
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_local_mcp_config] MCP config file found at {config_path}")
        with open(config_path, 'r', encoding='utf-8') as f:
            jsonConfig = json.load(f)
            return jsonConfig["gateways"].get(gateway_key)  # Only return the config for the given gateway_key
    else:
        sys_print(f"[get_local_mcp_config] MCP config file not found at {config_path}", is_error=True)
        return None


def enkrypt_authenticate(ctx: Context):
    """
    Authenticates a gateway/user with the Enkrypt Secure MCP Gateway.

    This function handles gateway/user authentication, retrieves gateway configuration,
    and manages caching of gateway/user data. It supports both remote and local
    configuration sources.

    Args:
        ctx (Context): The MCP context

    Returns:
        dict: Authentication result containing:
            - status: Success/error status
            - message: Authentication message
            - id: The authenticated Gateway or User's ID
            - mcp_config: Gateway/user's MCP configuration
            - available_servers: Dictionary of available servers
    """
    if IS_DEBUG_LOG_LEVEL:
        sys_print("[authenticate] Starting authentication")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if not enkrypt_gateway_key:
        sys_print("Error: Gateway key is required. Please update your mcp client config and try again.")
        return {"status": "error", "error": "arg --gateway-key is required in MCP client config."}
    
    # We may get null if it's not passed in headers or if client is installing for the first time
    if enkrypt_gateway_key == "NULL":
        # sys_print(f"ctx: {ctx}")
        # sys_print(f"ctx.fastmcp: {ctx.fastmcp}")
        # sys_print(f"ctx.request_context: {ctx.request_context}")
        # sys_print(f"ctx.request_context.request: {ctx.request_context.request}")
        if ctx and ctx.request_context and ctx.request_context.request:
            enkrypt_gateway_key = ctx.request_context.request.headers.get("apikey")

    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[authenticate] Attempting auth for gateway key: {mask_key(enkrypt_gateway_key)}")

    # Check if we're already authenticated with this API key
    if enkrypt_gateway_key in SESSIONS and SESSIONS[enkrypt_gateway_key]["authenticated"]:
        if IS_DEBUG_LOG_LEVEL:
            sys_print("[authenticate] Already authenticated in session")
        mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f'mcp_config: {mcp_config}')
        return {
            "status": "success",
            "message": "Already authenticated",
            "id": SESSIONS[enkrypt_gateway_key]["gateway_config"].get("id"),
            "mcp_config": mcp_config,
            "available_servers": mcp_config_to_dict(mcp_config)
        }
    else:
        sys_print("[authenticate] Not authenticated yet in session", is_error=True)

    # Check if we have cached mapping from Gateway key to gateway/user ID
    cached_id = get_id_from_key(cache_client, enkrypt_gateway_key)

    if cached_id:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[authenticate] Found cached gateway/user ID: {cached_id}")
        # Use the mapping to get cached config
        cached_config = get_cached_gateway_config(cache_client, cached_id)
        if cached_config:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[authenticate] Found cached config for gateway/user: {cached_id}")
            # Use cached config
            if enkrypt_gateway_key not in SESSIONS:
                SESSIONS[enkrypt_gateway_key] = {}
            SESSIONS[enkrypt_gateway_key].update({
                "authenticated": True,
                "gateway_config": cached_config
            })
            mcp_config = cached_config.get("mcp_config", [])
            return {
                "status": "success",
                "message": "Authentication successful (from cache)",
                "id": cached_config["id"],
                "mcp_config": mcp_config,
                "available_servers": mcp_config_to_dict(mcp_config)
            }
        else:
            sys_print(f"[authenticate] No cached config found for gateway/user: {cached_id}")
    else:
        sys_print("[authenticate] No cached gateway/user ID found", is_error=True)

    try:
        if ENKRYPT_USE_REMOTE_MCP_CONFIG:
            sys_print(f"[authenticate] No valid cache, contacting auth server with ENKRYPT_API_KEY: {mask_key(ENKRYPT_API_KEY)}")
            # No valid cache, contact auth server
            response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION
            })
            if response.status_code != 200:
                sys_print("[authenticate] Invalid API key", is_error=True)
                return {"status": "error", "error": "Invalid API key"}
            gateway_config = response.json()
        else:
            if IS_DEBUG_LOG_LEVEL:
                sys_print("[authenticate] Using local MCP config")
            gateway_config = get_local_mcp_config(enkrypt_gateway_key)

        if not gateway_config:
            sys_print("[authenticate] No gateway config found", is_error=True)
            return {"status": "error", "error": "No gateway config found. Probably the gateway key is invalid."}

        id = gateway_config.get("id")

        # Cache the API key to gateway/user ID mapping
        cache_key_to_id(cache_client, enkrypt_gateway_key, id)

        # Cache the gateway config
        cache_gateway_config(cache_client, id, gateway_config)

        # Update session
        if enkrypt_gateway_key not in SESSIONS:
            SESSIONS[enkrypt_gateway_key] = {}
        SESSIONS[enkrypt_gateway_key].update({
            "authenticated": True,
            "gateway_config": gateway_config
        })

        sys_print(f"[authenticate] Auth successful for gateway/user: {id}")
        mcp_config = gateway_config.get("mcp_config", [])
        return {
            "status": "success",
            "message": "Authentication successful",
            "id": id,
            "mcp_config": mcp_config,
            "available_servers": mcp_config_to_dict(mcp_config)
        }

    except Exception as e:
        sys_print(f"[authenticate] Exception: {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        return {"status": "error", "error": str(e)}


# --- MCP Tools ---


# NOTE: inputSchema is not supported here if we explicitly define it.
# But it is defined in the SDK - https://modelcontextprotocol.io/docs/concepts/tools#python
# As FastMCP automatically generates an input schema based on the function's parameters and type annotations.
# See: https://gofastmcp.com/servers/tools#the-%40tool-decorator
# Annotations can be explicitly defined - https://gofastmcp.com/servers/tools#annotations-2

# NOTE: If we use the name "enkrypt_list_available_servers", for some reason claude-desktop throws internal server error.
# So we use a different name as it doesn't even print any logs for us to troubleshoot the issue.
async def enkrypt_list_all_servers(ctx: Context, discover_tools: bool = True):
    """
    Lists available servers with their tool information.

    This function provides a comprehensive list of available servers,
    including their tools and configuration status.

    Args:
        ctx (Context): The MCP context

    Returns:
        dict: Server listing containing:
            - status: Success/error status
            - available_servers: Dictionary of available servers
            - servers_needing_discovery: List of servers requiring tool discovery
    """
    sys_print("[list_available_servers] Request received")

    enkrypt_gateway_key = get_gateway_key(ctx)
    try:
        if not enkrypt_gateway_key:
            sys_print("[list_available_servers] No gateway key provided")
            return {"status": "error", "error": "No gateway key provided."}

        if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
            result = enkrypt_authenticate(ctx)
            if result.get("status") != "success":
                if IS_DEBUG_LOG_LEVEL:
                    sys_print("[list_available_servers] Not authenticated", is_error=True)
                return {"status": "error", "error": "Not authenticated."}

        id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]
        mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f'mcp_config: {mcp_config}')
        servers_with_tools = {}
        servers_needing_discovery = []
        for server_info in mcp_config:
            server_name = server_info["server_name"]
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[list_available_servers] Processing server: {server_name}")
            # server_info_copy = server_info.copy()
            server_info_copy = get_latest_server_info(server_info, id, cache_client)
            if server_info_copy.get("tools_source") == "needs_discovery":
                servers_needing_discovery.append(server_name)
            servers_with_tools[server_name] = server_info_copy

        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[list_available_servers] Returning {len(servers_with_tools)} servers with tools")
        if not discover_tools:
            return {
                "status": "success",
                "available_servers": servers_with_tools,
                "servers_needing_discovery": servers_needing_discovery
            }
        else:
            # Discover tools for all servers
            status = "success"
            message = "Tools discovery tried for all servers"
            discovery_failed_servers = []
            discovery_success_servers = []
            for server_name in servers_needing_discovery:
                discover_server_result = await enkrypt_discover_all_tools(ctx, server_name)
                if discover_server_result.get("status") != "success":
                    status = "error"
                    discovery_failed_servers.append(server_name)
                else:
                    discovery_success_servers.append(server_name)
                    servers_with_tools[server_name] = discover_server_result
            return {
                "status": status,
                "message": message,
                "discovery_failed_servers": discovery_failed_servers,
                "discovery_success_servers": discovery_success_servers,
                "available_servers": servers_with_tools
            }

    except Exception as e:
        sys_print(f"[list_available_servers] Exception: {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        return {"status": "error", "error": f"Tool discovery failed: {e}"}


async def enkrypt_get_server_info(ctx: Context, server_name: str):
    """
    Gets detailed information about a server, including its tools.

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server

    Returns:
        dict: Server information containing:
            - status: Success/error status
            - server_name: Name of the server
            - server_info: Detailed server configuration
    """
    sys_print(f"[get_server_info] Requested for server: {server_name}")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
        result = enkrypt_authenticate(ctx)
        if result.get("status") != "success":
            sys_print("[get_server_info] Not authenticated")
            return {"status": "error", "error": "Not authenticated."}

    server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
    if not server_info:
        sys_print(f"[get_server_info] Server '{server_name}' not available")
        return {"status": "error", "error": f"Server '{server_name}' not available."}

    server_info_copy = get_latest_server_info(server_info, SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"], cache_client)
    return {
        "status": "success",
        "server_name": server_name,
        "server_info": server_info_copy
    }


# NOTE: Using name "enkrypt_discover_server_tools" is not working in Cursor for some reason.
# So using a different name "enkrypt_discover_all_tools" which works.
async def enkrypt_discover_all_tools(ctx: Context, server_name: str = None):
    """
    Discovers and caches available tools for a specific server or all servers if server_name is None.

    This function handles tool discovery for a server, with support for
    caching discovered tools and fallback to configured tools.

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server to discover tools for

    Returns:
        dict: Discovery result containing:
            - status: Success/error status
            - message: Discovery result message
            - tools: Dictionary of discovered tools
            - source: Source of the tools (config/cache/discovery)
    """
    sys_print(f"[discover_server_tools] Requested for server: {server_name}")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
        result = enkrypt_authenticate(ctx)
        if result.get("status") != "success":
            if IS_DEBUG_LOG_LEVEL:
                sys_print("[discover_server_tools] Not authenticated", is_error=True)
            return {"status": "error", "error": "Not authenticated."}

    # If server_name is empty, then we discover all tools for all servers
    if not server_name:
        sys_print("[discover_server_tools] Discovering tools for all servers as server_name is empty")
        all_servers = await enkrypt_list_all_servers(ctx, discover_tools=False)
        all_servers_with_tools = all_servers.get("available_servers", {})
        servers_needing_discovery = all_servers.get("servers_needing_discovery", [])

        status = "success"
        message = "Tools discovery tried for all servers"
        discovery_failed_servers = []
        discovery_success_servers = []
        for server_name in servers_needing_discovery:
            discover_server_result = await enkrypt_discover_all_tools(ctx, server_name)
            if discover_server_result.get("status") != "success":
                status = "error"
                discovery_failed_servers.append(server_name)
            else:
                discovery_success_servers.append(server_name)
                all_servers_with_tools[server_name] = discover_server_result
        return {
            "status": status,
            "message": message,
            "discovery_failed_servers": discovery_failed_servers,
            "discovery_success_servers": discovery_success_servers,
            "available_servers": all_servers_with_tools
        }

    server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
    if not server_info:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[discover_server_tools] Server '{server_name}' not available", is_error=True)
        return {"status": "error", "error": f"Server '{server_name}' not available."}

    id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]

    # Check if server has configured tools in the gateway config
    # i.e., tools is not empty {} and are defined explicitly in the gateway config
    # In this case, we don't discover them and return the ones in the gateway config
    # As the gateway/user may not have intended access to all tools but only the ones defined in the gateway config
    config_tools = server_info.get("tools", {})
    if config_tools:
        sys_print(f"[discover_server_tools] Tools already defined in config for {server_name}")
        return {
            "status": "success",
            "message": f"Tools already defined in config for {server_name}",
            "tools": config_tools,
            "source": "config"
        }

    # If tools are empty {}, then we discover them
    try:
        cached_tools = get_cached_tools(cache_client, id, server_name)
        if cached_tools:
            sys_print(f"[discover_server_tools] Tools already cached for {server_name}")
            return {
                "status": "success",
                "message": f"Tools retrieved from cache for {server_name}",
                "tools": cached_tools,
                "source": "cache"
            }
        else:
            sys_print(f"[discover_server_tools] No cached tools found for {server_name}")

        result = await forward_tool_call(server_name, None, None, SESSIONS[enkrypt_gateway_key]["gateway_config"])
        tools = result["tools"] if isinstance(result, dict) and "tools" in result else result

        if tools:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[discover_server_tools] Success: {server_name} tools discovered: {tools}")
            cache_tools(cache_client, id, server_name, tools)
        else:
            sys_print(f"[discover_server_tools] No tools discovered for {server_name}")

        return {
            "status": "success",
            "message": f"Tools discovered for {server_name}",
            "tools": tools,
            "source": "discovery"
        }
    except Exception as e:
        sys_print(f"[discover_server_tools] Exception: {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        return {"status": "error", "error": f"Tool discovery failed: {e}"}


async def enkrypt_secure_call_tools(ctx: Context, server_name: str, tool_calls: list = []):
    """
    If there are multiple tool calls to be made, please pass all of them in a single list. If there is only one tool call, pass it as a single object in the list.

    First check the number of tools needed for the prompt and then pass all of them in a single list. Because if tools are multiple and we pass one by one, it will create a new session for each tool call and that may fail.

    This has the ability to execute multiple tool calls in sequence within the same session, with guardrails and PII handling.

    This function provides secure batch execution with comprehensive guardrail checks for each tool call:
    - Input guardrails (PII, policy violations)
    - Output guardrails (relevancy, adherence, hallucination)
    - PII handling (anonymization/de-anonymization)

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server containing the tools
        tool_calls (list): List of {"name": str, "args": dict, "env": dict} objects
            - name: Name of the tool to call
            - args: Arguments to pass to the tool

            # env is not supported by MCP protocol used by Claude Desktop for some reason
            # But it is defined in the SDK
            # https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/stdio/__init__.py
            # - env: Optional environment variables to pass to the tool

    Example:
        tool_calls = [
            {"name": "navigate", "args": {"url": "https://enkryptai.com"}},
            {"name": "screenshot", "args": {"filename": "enkryptai-homepage.png"}}
        ]

    Returns:
        dict: Batch execution results with guardrails responses
            - status: Success/error status
            - message: Response message
            - Additional response data or error details
    """
    tool_calls = tool_calls or []
    num_tool_calls = len(tool_calls)
    sys_print(f"[secure_call_tools] Starting secure batch execution for {num_tool_calls} tools for server: {server_name}")
    if num_tool_calls == 0:
        sys_print("[secure_call_tools] No tools provided. Treating this as a discovery call")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
        result = enkrypt_authenticate(ctx)
        if result.get("status") != "success":
            sys_print("[get_server_info] Not authenticated", is_error=True)
            return {"status": "error", "error": "Not authenticated."}

    server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
    if not server_info:
        sys_print(f"[secure_call_tools] Server '{server_name}' not available", is_error=True)
        return {"status": "error", "error": f"Server '{server_name}' not available."}

    try:
        # Get guardrails policies from server info
        input_guardrails_policy = server_info['input_guardrails_policy']
        output_guardrails_policy = server_info['output_guardrails_policy']
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"Input Guardrails Policy: {input_guardrails_policy}")
            sys_print(f"Output Guardrails Policy: {output_guardrails_policy}")
        input_policy_enabled = input_guardrails_policy['enabled']
        output_policy_enabled = output_guardrails_policy['enabled']
        input_policy_name = input_guardrails_policy['policy_name']
        output_policy_name = output_guardrails_policy['policy_name']
        input_blocks = input_guardrails_policy['block']
        output_blocks = output_guardrails_policy['block']
        pii_redaction = input_guardrails_policy['additional_config']['pii_redaction']
        relevancy = output_guardrails_policy['additional_config']['relevancy']
        adherence = output_guardrails_policy['additional_config']['adherence']
        hallucination = output_guardrails_policy['additional_config']['hallucination']

        server_config = server_info["config"]
        server_command = server_config["command"]
        server_args = server_config["args"]
        server_env = server_config.get("env", None)

        sys_print(f"[secure_call_tools] Starting secure batch call for {num_tool_calls} tools for server: {server_name}")
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[secure_call_tools] Using command: {server_command} with args: {server_args}")

        results = []
        id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]

        server_config_tools = server_info.get("tools", {})
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[secure_call_tools] Server config tools before discovery: {server_config_tools}")
        if not server_config_tools:
            server_config_tools = get_cached_tools(cache_client, id, server_name)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[secure_call_tools] Server config tools after get_cached_tools: {server_config_tools}")
            if not server_config_tools:
                try:
                    discovery_result = await enkrypt_discover_all_tools(ctx, server_name)
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[enkrypt_secure_call_tools] Discovery result: {discovery_result}")

                    if discovery_result.get("status") != "success":
                        return {"status": "error", "error": "Failed to discover tools for this server."}

                    server_config_tools = discovery_result.get("tools", {})
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[enkrypt_secure_call_tools] Discovered tools: {server_config_tools}")
                except Exception as e:
                    sys_print(f"[enkrypt_secure_call_tools] Exception: {e}", is_error=True)
                    traceback.print_exc(file=sys.stderr)
                    return {"status": "error", "error": f"Failed to discover tools: {e}"}
            else:
                sys_print(f"[enkrypt_secure_call_tools] Found cached tools for {server_name}")

        if not server_config_tools:
            return {"status": "error", "error": f"No tools found for {server_name} even after discovery"}

        if num_tool_calls == 0:
            # Handle tuple return from get_cached_tools() which returns (tools, expires_at)
            if isinstance(server_config_tools, tuple) and len(server_config_tools) == 2:
                server_config_tools = server_config_tools[0]  # Extract the tools, ignoring expires_at
            return {
                "status": "success",
                "message": f"Successfully discovered tools for {server_name}",
                "tools": server_config_tools
            }

        # Single session for all calls
        async with stdio_client(StdioServerParameters(command=server_command, args=server_args, env=server_env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                sys_print(f"[secure_call_tools] Session initialized successfully for {server_name}")

                for i, tool_call in enumerate(tool_calls):
                    try:
                        tool_name = tool_call.get("name") or tool_call.get("tool_name") or tool_call.get("tool") or tool_call.get("function") or tool_call.get("function_name") or tool_call.get("function_id")
                        args = tool_call.get("args", {}) or tool_call.get("arguments", {}) or tool_call.get("parameters", {}) or tool_call.get("input", {}) or tool_call.get("params", {})
                        # server_env = tool_call.get("env", {})

                        if not tool_name:
                            results.append({
                                "status": "error",
                                "error": "No tool_name provided",
                                "message": "No tool_name provided",
                                "enkrypt_mcp_data": {
                                    "call_index": i,
                                    "server_name": server_name,
                                    "tool_name": tool_name,
                                    "args": args
                                }
                            })
                            break

                        sys_print(f"[secure_call_tools] Processing call {i}: {tool_name} with args: {args}")

                        tool_found = False
                        if server_config_tools:
                            # Handle tuple return from get_cached_tools() which returns (tools, expires_at)
                            if isinstance(server_config_tools, tuple) and len(server_config_tools) == 2:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] server_config_tools is a tuple from cache: {server_config_tools}")
                                server_config_tools = server_config_tools[0]  # Extract the tools, ignoring expires_at

                            # Handles various formats of tools
                            # like dictionary-style tools, ListToolsResult format, etc.
                            if hasattr(server_config_tools, 'tools'):
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print("[secure_call_tools] server_config_tools is a class with tools")
                                if isinstance(server_config_tools.tools, list):
                                    # ListToolsResult format
                                    if IS_DEBUG_LOG_LEVEL:
                                        sys_print(f"[secure_call_tools] server_config_tools is ListToolsResult format: {server_config_tools}")
                                    for tool in server_config_tools.tools:
                                        if hasattr(tool, 'name') and tool.name == tool_name:
                                            tool_found = True
                                            break
                                elif isinstance(server_config_tools.tools, dict):
                                    if IS_DEBUG_LOG_LEVEL:
                                        sys_print("[secure_call_tools] server_config_tools.tools is in Dictionary format")
                                    # Dictionary format like {"echo": "Echo a message"}
                                    if tool_name in server_config_tools.tools:
                                        tool_found = True
                            elif isinstance(server_config_tools, dict):
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print("[secure_call_tools] server_config_tools is in Dictionary format")
                                if "tools" in server_config_tools:
                                    if IS_DEBUG_LOG_LEVEL:
                                        sys_print("[secure_call_tools] server_config_tools is a dict and also has tools in Dictionary format")
                                    if isinstance(server_config_tools.get("tools", {}), list):
                                        for tool in server_config_tools.get("tools", []):
                                            if isinstance(tool, dict):
                                                # Handle the case where tools can be a list of dicts like [{"name": "echo", "description": "Echo a message"}]
                                                if tool.get("name") == tool_name:
                                                    tool_found = True
                                                    break
                                                # Handle the case where tools can be a dict like [{"echo": "Echo a message"}]
                                                elif tool_name in tool:
                                                    tool_found = True
                                                    break
                                    elif isinstance(server_config_tools.get("tools", {}), dict):
                                        # Dictionary format like {"echo": "Echo a message"}
                                        if tool_name in server_config_tools.get("tools", {}):
                                            tool_found = True
                                # Dictionary format like {"echo": "Echo a message"}
                                elif tool_name not in server_config_tools:
                                    if IS_DEBUG_LOG_LEVEL:
                                        sys_print(f"[secure_call_tools] Tool '{tool_name}' not found in server_config_tools", is_error=True)
                            else:
                                sys_print(f"[secure_call_tools] Unknown tool format: {type(server_config_tools)}", is_error=True)

                        if not tool_found:
                            sys_print(f"[enkrypt_secure_call_tools] Tool '{tool_name}' not found for this server.", is_error=True)
                            return {"status": "error", "error": f"Tool '{tool_name}' not found for this server."}

                        # Initialize guardrail responses for this call
                        redaction_key = None
                        input_guardrail_response = {}
                        output_guardrail_response = {}
                        output_relevancy_response = {}
                        output_adherence_response = {}
                        output_hallucination_response = {}

                        # Prepare input for guardrails
                        input_json_string = json.dumps(args)

                        # INPUT GUARDRAILS PROCESSING
                        if input_policy_enabled:
                            sys_print(f"[secure_call_tools] Call {i} : Input guardrails enabled for {tool_name} of server {server_name}")

                            # PII Redaction
                            if pii_redaction:
                                sys_print(f"[secure_call_tools] Call {i}: PII redaction enabled for {tool_name} of server {server_name}")
                                anonymized_text, redaction_key = anonymize_pii(input_json_string)
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] Call {i}: Anonymized text: {anonymized_text}")
                                # Using the anonymized text for input guardrails and tool call
                                input_json_string = anonymized_text
                                args = json.loads(anonymized_text)
                            else:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] Call {i}: PII redaction not enabled for {tool_name} of server {server_name}")

                            # Input guardrail check
                            if ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED:
                                guardrail_task = asyncio.create_task(call_guardrail(input_json_string, input_blocks, input_policy_name))
                                tool_call_task = asyncio.create_task(session.call_tool(tool_name, arguments=args))

                                input_violations_detected, input_violation_types, input_guardrail_response = await guardrail_task
                            else:
                                input_violations_detected, input_violation_types, input_guardrail_response = await call_guardrail(input_json_string, input_blocks, input_policy_name)

                            sys_print(f"input_violations: {input_violations_detected}, {input_violation_types}")

                            # Check for input violations
                            if input_violations_detected:
                                sys_print(f"[secure_call_tools] Call {i}: Blocked due to input violations: {input_violation_types} for {tool_name} of server {server_name}")
                                results.append({
                                    "status": "blocked_input",
                                    "message": f"Request blocked due to input guardrail violations: {', '.join(input_violation_types)}",
                                    "response": "",
                                    "enkrypt_mcp_data": {
                                        "call_index": i,
                                        "server_name": server_name,
                                        "tool_name": tool_name,
                                        "args": args
                                    },
                                    "enkrypt_policy_detections": {
                                        "input_guardrail_policy": input_guardrails_policy,
                                        "input_guardrail_response": input_guardrail_response,
                                        "output_guardrail_policy": output_guardrails_policy,
                                        "output_guardrail_response": output_guardrail_response,
                                        "output_relevancy_response": output_relevancy_response,
                                        "output_adherence_response": output_adherence_response,
                                        "output_hallucination_response": output_hallucination_response
                                    }
                                })
                                # Break to not proceed with next call if detected
                                break

                            # Get tool result if async was used
                            if ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] Call {i}: Waiting for tool call to complete in async mode")
                                result = await tool_call_task
                            else:
                                result = await session.call_tool(tool_name, arguments=args)
                        else:
                            sys_print(f"[secure_call_tools] Call {i}: Input guardrails not enabled for {tool_name} of server {server_name}")
                            # No input guardrails, execute tool directly
                            result = await session.call_tool(tool_name, arguments=args)

                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[secure_call_tools] Call {i}: Success: {server_name}.{tool_name}")
                            sys_print(f"[secure_call_tools] Call {i}: type of result: {type(result)}")
                            sys_print(f"[secure_call_tools] Call {i}: Tool call result: {result}")

                        # result is a CallToolResult object. Example:
                        # Tool call result: <class 'mcp.types.CallToolResult'> meta=None content=[TextContent(type='text', text='{\n  "status": "success",\n  "message": "test"\n}', annotations=None)] isError=False

                        # Process tool result
                        text_result = ""
                        if result and hasattr(result, 'content') and result.content and len(result.content) > 0:
                            # ----------------------------------
                            # # If we want to get all text contents
                            # texts = [c.text for c in result.content if hasattr(c, "text")]
                            # if IS_DEBUG_LOG_LEVEL:
                            #     sys_print(f"texts: {texts}")
                            # text_result = "\n".join(texts)
                            # ----------------------------------
                            # Check type is text or else we don't process it for output guardrails at the moment
                            result_type = result.content[0].type
                            if result_type == "text":
                                text_result = result.content[0].text
                                sys_print(f"[secure_call_tools] Call {i}: Tool executed and is text, checking output guardrails")
                            else:
                                sys_print(f"[secure_call_tools] Call {i}: Tool result is not text, skipping output guardrails")

                        if text_result:
                            # OUTPUT GUARDRAILS PROCESSING
                            if output_policy_enabled:
                                sys_print(f"[secure_call_tools] Call {i}: Output guardrails enabled for {tool_name} of server {server_name}")
                                output_violations_detected, output_violation_types, output_guardrail_response = await call_guardrail(text_result, output_blocks, output_policy_name)
                                sys_print(f"output_violation_types: {output_violation_types}")
                                if output_violations_detected:
                                    sys_print(f"[secure_call_tools] Call {i}: Blocked due to output violations: {output_violation_types}")
                                    results.append({
                                        "status": "blocked_output",
                                        "message": f"Request blocked due to output guardrail violations: {', '.join(output_violation_types)}",
                                        "response": text_result,
                                        "enkrypt_mcp_data": {
                                            "call_index": i,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "args": args
                                        },
                                        "enkrypt_policy_detections": {
                                            "input_guardrail_policy": input_guardrails_policy,
                                            "input_guardrail_response": input_guardrail_response,
                                            "output_guardrail_policy": output_guardrails_policy,
                                            "output_guardrail_response": output_guardrail_response,
                                            "output_relevancy_response": output_relevancy_response,
                                            "output_adherence_response": output_adherence_response,
                                            "output_hallucination_response": output_hallucination_response
                                        }
                                    })
                                    break
                                else:
                                    sys_print(f"[secure_call_tools] Call {i}: No output violations detected for {tool_name} of server {server_name}")

                            # RELEVANCY CHECK
                            if relevancy:
                                sys_print(f"[secure_call_tools] Call {i}: Checking relevancy for {tool_name} of server {server_name}")
                                output_relevancy_response = check_relevancy(input_json_string, text_result)
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f'relevancy response: {output_relevancy_response}')
                                if "relevancy" in output_blocks and output_relevancy_response.get("summary", {}).get("relevancy_score") > RELEVANCY_THRESHOLD:
                                    results.append({
                                        "status": "blocked_output_relevancy",
                                        "message": "Request blocked due to output relevancy violation",
                                        "response": text_result,
                                        "enkrypt_mcp_data": {
                                            "call_index": i,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "args": args
                                        },
                                        "enkrypt_policy_detections": {
                                            "input_guardrail_policy": input_guardrails_policy,
                                            "input_guardrail_response": input_guardrail_response,
                                            "output_guardrail_policy": output_guardrails_policy,
                                            "output_guardrail_response": output_guardrail_response,
                                            "output_relevancy_response": output_relevancy_response,
                                            "output_adherence_response": output_adherence_response,
                                            "output_hallucination_response": output_hallucination_response
                                        }
                                    })
                                    break
                                else:
                                    sys_print(f"[secure_call_tools] Call {i}: No relevancy violations detected or relevancy is not in output_blocks for {tool_name} of server {server_name}")

                            # ADHERENCE CHECK
                            if adherence:
                                sys_print(f"[secure_call_tools] Call {i}: Checking adherence for {tool_name} of server {server_name}")
                                output_adherence_response = check_adherence(input_json_string, text_result)
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f'adherence response: {output_adherence_response}')
                                if "adherence" in output_blocks and output_adherence_response.get("summary", {}).get("adherence_score") > ADHERENCE_THRESHOLD:
                                    results.append({
                                        "status": "blocked_output_adherence",
                                        "message": "Request blocked due to output adherence violation",
                                        "response": text_result,
                                        "enkrypt_mcp_data": {
                                            "call_index": i,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "args": args
                                        },
                                        "enkrypt_policy_detections": {
                                            "input_guardrail_policy": input_guardrails_policy,
                                            "input_guardrail_response": input_guardrail_response,
                                            "output_guardrail_policy": output_guardrails_policy,
                                            "output_guardrail_response": output_guardrail_response,
                                            "output_relevancy_response": output_relevancy_response,
                                            "output_adherence_response": output_adherence_response,
                                            "output_hallucination_response": output_hallucination_response
                                        }
                                    })
                                    break
                                else:
                                    sys_print(f"[secure_call_tools] Call {i}: No adherence violations detected or adherence is not in output_blocks for {tool_name} of server {server_name}")

                            # HALLUCINATION CHECK
                            if hallucination:
                                sys_print(f"[secure_call_tools] Call {i}: Checking hallucination for {tool_name} of server {server_name}")
                                output_hallucination_response = check_hallucination(input_json_string, text_result)
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f'hallucination response: {output_hallucination_response}')
                                if "hallucination" in output_blocks and output_hallucination_response.get("summary", {}).get("is_hallucination") > 0:
                                    results.append({
                                        "status": "blocked_output_hallucination",
                                        "message": "Request blocked due to output hallucination violation",
                                        "response": text_result,
                                        "enkrypt_mcp_data": {
                                            "call_index": i,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "args": args
                                        },
                                        "enkrypt_policy_detections": {
                                            "input_guardrail_policy": input_guardrails_policy,
                                            "input_guardrail_response": input_guardrail_response,
                                            "output_guardrail_policy": output_guardrails_policy,
                                            "output_guardrail_response": output_guardrail_response,
                                            "output_relevancy_response": output_relevancy_response,
                                            "output_adherence_response": output_adherence_response,
                                            "output_hallucination_response": output_hallucination_response
                                        }
                                    })
                                    break
                                else:
                                    sys_print(f"[secure_call_tools] Call {i}: No hallucination violations detected or hallucination is not in output_blocks for {tool_name} of server {server_name}")

                            # PII DE-ANONYMIZATION
                            if pii_redaction and redaction_key:
                                sys_print(f"[secure_call_tools] Call {i}: De-anonymizing PII for {tool_name} of server {server_name} with redaction key: {redaction_key}")
                                deanonymized_text = deanonymize_pii(text_result, redaction_key)
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] Call {i}: De-anonymized text for {tool_name} of server {server_name}: {deanonymized_text}")
                                text_result = deanonymized_text
                            else:
                                sys_print(f"[secure_call_tools] Call {i}: PII redaction not enabled or redaction key {redaction_key} not found for {tool_name} of server {server_name}")

                        sys_print(f"[secure_call_tools] Call {i}: Completed successfully for {tool_name} of server {server_name}")

                        # Successful result
                        results.append({
                            "status": "success",
                            "message": "Request processed successfully",
                            "response": text_result,
                            "enkrypt_mcp_data": {
                                "call_index": i,
                                "server_name": server_name,
                                "tool_name": tool_name,
                                "args": args
                            },
                            "enkrypt_policy_detections": {
                                "input_guardrail_policy": input_guardrails_policy,
                                "input_guardrail_response": input_guardrail_response,
                                "output_guardrail_policy": output_guardrails_policy,
                                "output_guardrail_response": output_guardrail_response,
                                "output_relevancy_response": output_relevancy_response,
                                "output_adherence_response": output_adherence_response,
                                "output_hallucination_response": output_hallucination_response
                            }
                        })

                    except Exception as tool_error:
                        sys_print(f"[secure_call_tools] Error in call {i} ({tool_name}): {tool_error}", is_error=True)
                        traceback.print_exc(file=sys.stderr)

                        results.append({
                            "status": "error",
                            "error": str(tool_error),
                            "message": "Error while processing tool call",
                            "enkrypt_mcp_data": {
                                "call_index": i,
                                "server_name": server_name,
                                "tool_name": tool_name,
                                "args": args
                            }
                        })
                        break

        # Calculate summary statistics
        successful_calls = len([r for r in results if r["status"] == "success"])
        blocked_calls = len([r for r in results if r["status"].startswith("blocked")])
        failed_calls = len([r for r in results if r["status"] == "error"])

        sys_print(f"[secure_call_tools] Batch execution completed: {successful_calls} successful, {blocked_calls} blocked, {failed_calls} failed")

        return {
            "server_name": server_name,
            "status": "success",
            "summary": {
                "total_calls": num_tool_calls,
                "successful_calls": successful_calls,
                "blocked_calls": blocked_calls,
                "failed_calls": failed_calls
            },
            "guardrails_applied": {
                "input_guardrails_enabled": input_policy_enabled,
                "output_guardrails_enabled": output_policy_enabled,
                "pii_redaction_enabled": pii_redaction,
                "relevancy_check_enabled": relevancy,
                "adherence_check_enabled": adherence,
                "hallucination_check_enabled": hallucination
            },
            "results": results
        }

    except Exception as e:
        sys_print(f"[secure_call_tools] Critical error during batch execution: {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        return {"status": "error", "error": f"Secure batch tool call failed: {e}"}


# # Using GATEWAY_TOOLS instead of @mcp.tool decorator
# @mcp.tool(
#     name="enkrypt_get_cache_status",
#     description="Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered. This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed. Use this only if you need to debug cache issues or asked specifically for cache status.",
#     annotations={
#         "title": "Get Cache Status",
#         "readOnlyHint": True,
#         "destructiveHint": False,
#         "idempotentHint": True,
#         "openWorldHint": False
#     }
#     # inputSchema={
#     #     "type": "object",
#     #     "properties": {},
#     #     "required": []
#     # }
# )
async def enkrypt_get_cache_status(ctx: Context):
    """
    Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered.
    This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed.
    Use this only if you need to debug cache issues or asked specifically for cache status.

    This function provides detailed information about the cache state,
    including gateway/user-specific and global cache statistics.

    Args:
        ctx (Context): The MCP context

    Returns:
        dict: Cache status containing:
            - status: Success/error status
            - cache_status: Detailed cache statistics and status
    """
    sys_print("[get_cache_status] Request received")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
        result = enkrypt_authenticate(ctx)
        if result.get("status") != "success":
            sys_print("[get_cache_status] Not authenticated", is_error=True)
            return {"status": "error", "error": "Not authenticated."}

    id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]

    # Get cache statistics (handles both External and local cache)
    sys_print("[get_cache_status] Getting cache statistics")
    stats = get_cache_statistics(cache_client)

    cache_status = {
        "gateway_specific": {
            "config": {
                "exists": False
            }
        },
        "global": {
            "total_gateways": stats.get("total_gateways", 0),
            "total_tool_caches": stats.get("total_tool_caches", 0),
            "total_config_caches": stats.get("total_config_caches", 0),
            "tool_cache_expiration_hours": ENKRYPT_TOOL_CACHE_EXPIRATION,
            "config_cache_expiration_hours": ENKRYPT_GATEWAY_CACHE_EXPIRATION,
            "cache_type": stats.get("cache_type", "unknown")
        }
    }

    # Gateway config status
    sys_print(f"[get_cache_status] Getting gateway config for Gateway or User {id}")
    cached_result = get_cached_gateway_config(cache_client, id)
    if cached_result:
        gateway_config, expires_at = cached_result
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_cache_status] Cached gateway config: {gateway_config}")
        # For local cache, we can't get TTL, so just mark as exists
        cache_status["gateway_specific"]["config"] = {
            "exists": True,
            "expires_at": expires_at,
            "expires_in_hours": (expires_at - time.time()) / 3600,
            "is_expired": False
        }
    else:
        sys_print(f"[get_cache_status] No cached gateway config found for {id}")
        cache_status["gateway_specific"]["config"] = {
            "exists": False,
            "expires_at": None,
            "expires_in_hours": None,
            "is_expired": True
        }

    # Servers cache status
    sys_print("[get_cache_status] Getting server cache status")
    mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f'mcp_configs: {mcp_config}')
    local_gateway_config = get_local_mcp_config(enkrypt_gateway_key)
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f'local gateway_config: {local_gateway_config}')
    servers_cache = {}
    for server_info in mcp_config:
        server_name = server_info["server_name"]
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_cache_status] Getting tool cache for server: {server_name}")
        cached_result = get_cached_tools(cache_client, id, server_name)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_cache_status] Cached result: {cached_result}")
        if cached_result:
            tools, expires_at = cached_result
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_cache_status] Tools found for server: {server_name}")
                # Handle ListToolsResult format
                if hasattr(tools, 'tools') and isinstance(tools.tools, list):
                    tool_count = len(tools.tools)
                # Handle dictionary with "tools" list
                elif isinstance(tools, dict) and "tools" in tools and isinstance(tools["tools"], list):
                    tool_count = len(tools["tools"])
                # Handle flat dictionary format
                elif isinstance(tools, dict):
                    tool_count = len(tools)
                else:
                    sys_print(f"[get_cache_status] ERROR: Unknown tool format for server: {server_name} - type: {type(tools)}", is_error=True)
                    tool_count = None
            servers_cache[server_name] = {
                "tool_count": tool_count if tool_count is not None else 0,
                "error": "Unknown tool format" if tool_count is None else None,
                "are_tools_explicitly_defined": False,
                "needs_discovery": False,
                "exists": True,
                "expires_at": expires_at,
                "expires_in_hours": (expires_at - time.time()) / 3600,
                "is_expired": False
            }
        else:
            needs_discovery = True
            are_tools_explicitly_defined = False
            if local_gateway_config:
                local_server_info = get_server_info_by_name(local_gateway_config, server_name)
                if local_server_info and "tools" in local_server_info:
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[get_cache_status] Server {server_name} tools are defined in the local gateway config")
                    are_tools_explicitly_defined = True
                    needs_discovery = False
            else:
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[get_cache_status] No tools found for server that needs discovery: {server_name}")

            servers_cache[server_name] = {
                "tool_count": 0,
                "error": None,
                "are_tools_explicitly_defined": are_tools_explicitly_defined,
                "needs_discovery": needs_discovery,
                "exists": False,
                "expires_at": None,
                "expires_in_hours": None,
                "is_expired": True
            }
    cache_status["gateway_specific"]["tools"] = {
        "server_count": len(servers_cache),
        "servers": servers_cache
    }

    sys_print(f"[get_cache_status] Returning cache status for Gateway or User {id}")
    return {
        "status": "success",
        "cache_status": cache_status
    }


# # Using GATEWAY_TOOLS instead of @mcp.tool decorator
# @mcp.tool(
#     name="enkrypt_clear_cache",
#     description="Clear the gateway cache for all/specific servers/gateway config. Use this only if you need to debug cache issues or asked specifically to clear cache.",
#     annotations={
#         "title": "Clear Cache",
#         "readOnlyHint": False,
#         "destructiveHint": True,
#         "idempotentHint": False,
#         "openWorldHint": True
#     }
#     # inputSchema={
#     #     "type": "object",
#     #     "properties": {
#     #         "id": {
#     #             "type": "string",
#     #             "description": "The ID of the Gateway or User to clear cache for"
#     #         },
#     #         "server_name": {
#     #             "type": "string",
#     #             "description": "The name of the server to clear cache for"
#     #         },
#     #         "cache_type": {
#     #             "type": "string",
#     #             "description": "The type of cache to clear"
#     #         }
#     #     },
#     #     "required": []
#     # }
# )
async def enkrypt_clear_cache(ctx: Context, id: str = None, server_name: str = None, cache_type: str = None):
    """
    Clears various types of caches in the MCP Gateway.
    Use this only if you need to debug cache issues or asked specifically to clear cache.

    This function can clear:
    - Tool cache for a specific server
    - Tool cache for all servers
    - Gateway config cache
    - All caches

    Args:
        ctx (Context): The MCP context
        id (str, optional): ID of the Gateway or User whose cache to clear
        server_name (str, optional): Name of the server whose cache to clear
        cache_type (str, optional): Type of cache to clear ('all', 'gateway_config', 'server_config')

    Returns:
        dict: Cache clearing result containing:
            - status: Success/error status
            - message: Cache clearing result message
    """
    sys_print(f"[clear_cache] Requested with id={id}, server_name={server_name}, cache_type={cache_type}")

    enkrypt_gateway_key = get_gateway_key(ctx)
    if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
        result = enkrypt_authenticate(ctx)
        if result.get("status") != "success":
            sys_print("[clear_cache] Not authenticated", is_error=True)
            return {"status": "error", "error": "Not authenticated."}

    # Default id from session if not provided
    if not id:
        id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]

    sys_print(f"[clear_cache] Gateway/User ID: {id}, Server Name: {server_name}, Cache Type: {cache_type}")

    if not cache_type:
        if IS_DEBUG_LOG_LEVEL:
            sys_print("[clear_cache] No cache type provided. Defaulting to 'all'")
        cache_type = "all"

    # Clear all caches (tool + gateway config)
    if cache_type == "all":
        sys_print("[clear_cache] Clearing all caches")
        cleared_servers = clear_cache_for_servers(cache_client, id)
        cleared_gateway = clear_gateway_config_cache(cache_client, id, enkrypt_gateway_key)
        if ENKRYPT_USE_REMOTE_MCP_CONFIG:
            if IS_DEBUG_LOG_LEVEL:
                sys_print("[clear_cache] Refreshing remote MCP config")
            refresh_response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                "X-Enkrypt-Refresh-Cache": "true"
            })
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[clear_cache] Refresh response: {refresh_response}")
        return {
            "status": "success",
            "message": f"Cache cleared for all servers ({cleared_servers} servers) and gateway config ({'cleared' if cleared_gateway else 'none'})"
        }

    # Clear gateway config cache
    if cache_type == "gateway_config" or cache_type == "gateway" or cache_type == "gateway_cache" or cache_type == "gateway_config_cache":
        sys_print("[clear_cache] Clearing gateway config cache")
        cleared = clear_gateway_config_cache(cache_client, id, enkrypt_gateway_key)
        if ENKRYPT_USE_REMOTE_MCP_CONFIG:
            if IS_DEBUG_LOG_LEVEL:
                sys_print("[clear_cache] Refreshing remote MCP config")
            refresh_response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                "X-Enkrypt-Refresh-Cache": "true"
            })
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[clear_cache] Refresh response: {refresh_response}")
        if cleared:
            return {"status": "success", "message": f"Gateway config cache cleared for {id}"}
        else:
            return {"status": "info", "message": f"No config cache found for {id}"}

    # Clear server config cache
    sys_print("[clear_cache] Clearing server config cache")

    # Clear tool cache for a specific server
    if server_name:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[clear_cache] Clearing tool cache for server: {server_name}")
        cleared = clear_cache_for_servers(cache_client, id, server_name)
        if cleared:
            return {
                "status": "success",
                "message": f"Cache cleared for server: {server_name}"
            }
        else:
            return {
                "status": "info",
                "message": f"No cache found for server: {server_name}"
            }
    # Clear all server caches (tool cache)
    else:
        sys_print("[clear_cache] Clearing all server caches")
        cleared = clear_cache_for_servers(cache_client, id)
        return {
            "status": "success",
            "message": f"Cache cleared for all servers ({cleared} servers)"
        }


# --- MCP Gateway Server ---

GATEWAY_TOOLS = [
    Tool.from_function(
        fn=enkrypt_list_all_servers,
        name="enkrypt_list_all_servers",
        description="Get detailed information about all available servers, including their tools and configuration status.",
        annotations={
            "title": "List Available Servers",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {},
        #     "required": []
        # }
    ),
    Tool.from_function(
        fn=enkrypt_get_server_info,
        name="enkrypt_get_server_info",
        description="Get detailed information about a server, including its tools.",
        annotations={
            "title": "Get Server Info",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to get info for"
        #         }
        #     },
        #     "required": ["server_name"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_discover_all_tools,
        name="enkrypt_discover_all_tools",
        description="Discover available tools for a specific server or all servers if server_name is None",
        annotations={
            "title": "Discover Server Tools",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to discover tools for"
        #         }
        #     },
        #     "required": ["server_name"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_secure_call_tools,
        name="enkrypt_secure_call_tools",
        description="Securely call tools for a specific server. If there are multiple tool calls to be made, please pass all of them in a single list. If there is only one tool call, pass it as a single object in the list. First check the number of tools needed for the prompt and then pass all of them in a single list. Because if tools are multiple and we pass one by one, it will create a new session for each tool call and that may fail. If tools need to be discovered, pass empty list for tool_calls.",
        annotations={
            "title": "Securely Call Tools",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to call tools for"
        #         },
        #         "tool_calls": {
        #             "type": "array",
        #             "description": "The list of tool calls to make",
        #             "items": {
        #                 "type": "object",
        #                 "properties": {
        #                     "name": {
        #                         "type": "string",
        #                         "description": "The name of the tool to call"
        #                     },
        #                     "args": {
        #                         "type": "object",
        #                         "description": "The arguments to pass to the tool"
        #                     }
        # #                     "env": {
        # #                         "type": "object",
        # #                         "description": "The environment variables to pass to the tool"
        # #                     }
        #                 }
        #             }
        #         }
        #     },
        #     "required": ["server_name", "tool_calls"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_get_cache_status,
        name="enkrypt_get_cache_status",
        description="Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered. This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed. Use this only if you need to debug cache issues or asked specifically for cache status.",
        annotations={
            "title": "Get Cache Status",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {},
        #     "required": []
        # }
    ),
    Tool.from_function(
        fn=enkrypt_clear_cache,
        name="enkrypt_clear_cache",
        description="Clear the gateway cache for all/specific servers/gateway config. Use this only if you need to debug cache issues or asked specifically to clear cache.",
        annotations={
            "title": "Clear Cache",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True
        }
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "id": {
        #             "type": "string",
        #             "description": "The ID of the Gateway or User to clear cache for"
        #         },
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to clear cache for"
        #         },
        #         "cache_type": {
        #             "type": "string",
        #             "description": "The type of cache to clear"
        #         }
        #     },
        #     "required": []
        # }
    )
]


# NOTE: Settings defined directly do not seem to work
# But when we do it later in main, it works. Not sure why.
mcp = FastMCP(
    name="Enkrypt Secure MCP Gateway",
    instructions="This is the Enkrypt Secure MCP Gateway. It is used to secure the MCP calls to the servers by authenticating with a gateway key and using guardrails to check both requests and responses.",
    # auth_server_provider=None,
    # event_store=None,
    # TODO: Not sure if we need to specify tools as it discovers them automatically
    tools=GATEWAY_TOOLS,
    settings={
        "debug": True if FASTMCP_LOG_LEVEL == "DEBUG" else False,
        "log_level": FASTMCP_LOG_LEVEL,
        "host": "0.0.0.0",
        "port": 8000,
        "mount_path": "/",
        # "sse_path": "/sse/",
        # "message_path": "/messages/",
        "streamable_http_path": "/mcp/",
        "json_response": True,
        "stateless_http": False,
        "dependencies": __dependencies__,
    }
)


# --- Run ---
if __name__ == "__main__":
    sys_print("Starting Enkrypt Secure MCP Gateway")
    try:
        # --------------------------------------------
        # Settings defined on top do not seem to work
        # But when we do it here, it works. Not sure why.
        # --------------------------------------------
        mcp.name = "Enkrypt Secure MCP Gateway"
        mcp.instructions = "This is the Enkrypt Secure MCP Gateway. It is used to secure the MCP calls to the servers by authenticating with a gateway key and using guardrails to check both requests and responses."
        mcp.tools = GATEWAY_TOOLS
        # --------------------------------------------
        mcp.settings.debug = True if FASTMCP_LOG_LEVEL == "DEBUG" else False
        mcp.settings.log_level = FASTMCP_LOG_LEVEL
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8000
        mcp.settings.mount_path = "/"
        mcp.settings.streamable_http_path = "/mcp/"
        mcp.settings.json_response = True
        mcp.settings.stateless_http = False
        mcp.settings.dependencies = __dependencies__
        # --------------------------------------------
        mcp.run(transport="streamable-http", mount_path="/mcp/")
        sys_print("Enkrypt Secure MCP Gateway is running")
    except Exception as e:
        sys_print(f"Exception in mcp.run(): {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

