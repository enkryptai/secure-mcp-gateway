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

# ENKRYPT_ENVIRONMENT = os.environ.get("ENKRYPT_ENVIRONMENT", "production")
# IS_LOCAL_ENVIRONMENT = ENKRYPT_ENVIRONMENT == "local"

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
# print(f"ENKRYPT_ENVIRONMENT: {ENKRYPT_ENVIRONMENT}", file=sys.stderr)
# print(f"IS_LOCAL_ENVIRONMENT: {IS_LOCAL_ENVIRONMENT}", file=sys.stderr)
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
# BASE_DIR = files('secure_mcp_gateway')
# if BASE_DIR not in sys.path:
#     sys.path.insert(0, BASE_DIR)

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, '..'))
# Go up one more level to reach project root
root_dir = os.path.abspath(os.path.join(src_dir, '..')) 
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

print("--------------------------------", file=sys.stderr)
print("PATHS: ", file=sys.stderr)
print(f"src_dir: {src_dir}", file=sys.stderr)
print(f"root_dir: {root_dir}", file=sys.stderr)
print("--------------------------------", file=sys.stderr)

# Try to install the package if not found to cater for clients like Claude Desktop who use a separate python interpreter
try:
    import secure_mcp_gateway
except ImportError:
    # What if user is intalling a specific version of the package?
    # package_name = src_dir if IS_LOCAL_ENVIRONMENT else "secure_mcp_gateway"

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
    generate_custom_id
)
from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.dependencies import __dependencies__

sys_print(f"Successfully imported secure_mcp_gateway v{__version__} in gateway module")

from secure_mcp_gateway.telemetry import (
    tracer,
    logger, 
    list_servers_call_count,
    servers_discovered_count,
    # request_duration,
    # request_size,
    # response_size,
    # request_errors,
    cache_hit_counter,
    cache_miss_counter,
    tool_call_counter,
    tool_call_duration,
    guardrail_violation_counter,
    guardrail_api_request_counter,
    guardrail_api_request_duration

)

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
ENKRYPT_TELEMETRY_ENABLED = common_config.get("enkrypt_telemetry", {}).get("enabled", False)
ENKRYPT_TELEMETRY_ENDPOINT = common_config.get("enkrypt_telemetry", {}).get("endpoint", "http://localhost:4317")

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
    sys_print(f'enkrypt_async_output_guardrails_enabled: {ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED}', is_debug=True)
sys_print(f'enkrypt_telemetry_enabled: {ENKRYPT_TELEMETRY_ENABLED}')
sys_print(f'enkrypt_telemetry_endpoint: {ENKRYPT_TELEMETRY_ENDPOINT}')
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
                sys_print(f"[get_gateway_key] Using gateway key from request context: {mask_key(gateway_key)}", is_debug=True)
            return gateway_key
        
    # Fallback to environment variable
    gateway_key = os.environ.get("ENKRYPT_GATEWAY_KEY", None)
    if gateway_key:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_gateway_key] Using gateway key from environment variable: {mask_key(gateway_key)}", is_debug=True)
        return gateway_key
    
    if IS_DEBUG_LOG_LEVEL:
        sys_print("[get_gateway_key] No gateway key found", is_debug=True)
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
        sys_print(f"[get_server_info_by_name] Getting server info for {server_name}", is_debug=True)
    mcp_config = gateway_config.get("mcp_config", [])
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[get_server_info_by_name] mcp_config: {mcp_config}", is_debug=True)
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
        sys_print("[mcp_config_to_dict] Converting MCP config to dict", is_debug=True)
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
        sys_print(f"[get_latest_server_info] Getting latest server info for {id}", is_debug=True)
    server_info_copy = server_info.copy()
    config_tools = server_info_copy.get("tools", {})
    server_name = server_info_copy.get("server_name")
    sys_print(f"[get_latest_server_info] Server name: {server_name}")

    # If tools is empty {}, then we discover them
    if not config_tools:
        sys_print(f"[get_latest_server_info] No config tools found for {server_name}")
        cached_tools = get_cached_tools(cache_client, id, server_name)
        if cached_tools:
            cache_hit_counter.add(1)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_latest_server_info] Found cached tools for {server_name}", is_debug=True)
            server_info_copy["tools"] = cached_tools
            server_info_copy["has_cached_tools"] = True
            server_info_copy["tools_source"] = "cache"
        else:
            cache_miss_counter.add(1)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[get_latest_server_info] No cached tools found for {server_name}. Need to discover them", is_debug=True)
            server_info_copy["tools"] = {}
            server_info_copy["has_cached_tools"] = False
            server_info_copy["tools_source"] = "needs_discovery"
    else:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_latest_server_info] Tools defined in config already for {server_name}", is_debug=True)
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
        sys_print(f"[get_local_mcp_config] Getting local MCP config for {gateway_key} with running_in_docker: {running_in_docker}", is_debug=True)

    config_path = DOCKER_CONFIG_PATH if running_in_docker else CONFIG_PATH
    if os.path.exists(config_path):
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[get_local_mcp_config] MCP config file found at {config_path}", is_debug=True)
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
    with tracer.start_as_current_span("enkrypt_authenticate") as main_span:
        try:
            logger.info("Starting authentication")
            if IS_DEBUG_LOG_LEVEL:
                sys_print("[authenticate] Starting authentication", is_debug=True)
            
            custom_id = generate_custom_id()
            main_span.set_attribute("request_id", getattr(ctx, 'request_id', 'unknown'))
            main_span.set_attribute("custom_id", custom_id)

            # Gateway key validation
            with tracer.start_as_current_span("validate_gateway_key") as key_span:
                enkrypt_gateway_key = get_gateway_key(ctx)
                key_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                
                if not enkrypt_gateway_key:
                    # key_span.set_status(Status(StatusCode.ERROR))
                    key_span.set_attribute("error", "Gateway key required")
                    sys_print("Error: Gateway key is required. Please update your mcp client config and try again.")
                    logger.error("Error: Gateway key is required. Please update your mcp client config and try again.")
                    return {"status": "error", "error": "arg --gateway-key is required in MCP client config."}
                
                if enkrypt_gateway_key == "NULL":
                    key_span.set_attribute("using_header_key", True)
                    if ctx and ctx.request_context and ctx.request_context.request:
                        enkrypt_gateway_key = ctx.request_context.request.headers.get("apikey")
                        key_span.set_attribute("header_key_found", bool(enkrypt_gateway_key))
                        main_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                    else:
                        key_span.set_attribute("header_key_found", False)

                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[authenticate] Attempting auth for gateway key: {mask_key(enkrypt_gateway_key)}", is_debug=True)
                    logger.info(f"Attempting auth for gateway key: {mask_key(enkrypt_gateway_key)}")

            # Session check
            with tracer.start_as_current_span("check_session") as session_span:
                session_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                is_authenticated = enkrypt_gateway_key in SESSIONS and SESSIONS[enkrypt_gateway_key]["authenticated"]
                session_span.set_attribute("is_authenticated", is_authenticated)
                
                if is_authenticated:
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print("[authenticate] Already authenticated in session", is_debug=True)
                    
                    mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
                    session_span.set_attribute("has_mcp_config", bool(mcp_config))
                    session_span.set_attribute("config_count", len(mcp_config))
                    
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f'mcp_config: {mcp_config}', is_debug=True)
                    
                    main_span.set_attribute("auth_source", "session")
                    main_span.set_attribute("success", True)
                    
                    return {
                        "status": "success",
                        "message": "Already authenticated",
                        "id": SESSIONS[enkrypt_gateway_key]["gateway_config"].get("id"),
                        "mcp_config": mcp_config,
                        "available_servers": mcp_config_to_dict(mcp_config)
                    }
                else:
                    sys_print("[authenticate] Not authenticated yet in session", is_error=True)

            # Cache ID lookup
            with tracer.start_as_current_span("lookup_cached_id") as id_span:
                id_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                
                cached_id = get_id_from_key(cache_client, enkrypt_gateway_key)
                id_span.set_attribute("cache_hit", bool(cached_id))
                
                if cached_id:
                    id_span.set_attribute("cached_id", cached_id)
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[authenticate] Found cached gateway/user ID: {cached_id}", is_debug=True)
                else:
                    sys_print("[authenticate] No cached gateway/user ID found", is_error=True)

            # Cache config lookup
            with tracer.start_as_current_span("lookup_cached_config") as config_span:
                if cached_id:
                    config_span.set_attribute("id", cached_id)
                    cached_config = get_cached_gateway_config(cache_client, cached_id)
                    config_span.set_attribute("cache_hit", bool(cached_config))
                    
                    if cached_config:
                        cache_hit_counter.add(1)
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[authenticate] Found cached config for gateway/user: {cached_id}", is_debug=True)
                        
                        mcp_config = cached_config.get("mcp_config", [])
                        config_span.set_attribute("has_mcp_config", bool(mcp_config))
                        config_span.set_attribute("config_count", len(mcp_config))
                        
                        # Update session
                        if enkrypt_gateway_key not in SESSIONS:
                            SESSIONS[enkrypt_gateway_key] = {}
                        SESSIONS[enkrypt_gateway_key].update({
                            "authenticated": True,
                            "gateway_config": cached_config
                        })
                        
                        main_span.set_attribute("auth_source", "cache")
                        main_span.set_attribute("success", True)
                        
                        return {
                            "status": "success",
                            "message": "Authentication successful (from cache)",
                            "id": cached_config["id"],
                            "mcp_config": mcp_config,
                            "available_servers": mcp_config_to_dict(mcp_config)
                        }
                    else:
                        cache_miss_counter.add(1)
                        sys_print(f"[authenticate] No cached config found for gateway/user: {cached_id}")
                else:
                    config_span.set_attribute("cache_hit", False)

            # Config retrieval
            with tracer.start_as_current_span("retrieve_config") as retrieve_span:
                try:
                    if ENKRYPT_USE_REMOTE_MCP_CONFIG:
                        retrieve_span.set_attribute("config_source", "remote")
                        sys_print(f"[authenticate] No valid cache, contacting auth server with ENKRYPT_API_KEY: {mask_key(ENKRYPT_API_KEY)}")
                        
                        with tracer.start_as_current_span("remote_config_request") as remote_span:
                            remote_span.set_attribute("auth_server_url", AUTH_SERVER_VALIDATE_URL)
                            remote_span.set_attribute("gateway_name", ENKRYPT_REMOTE_MCP_GATEWAY_NAME)
                            remote_span.set_attribute("gateway_version", ENKRYPT_REMOTE_MCP_GATEWAY_VERSION)
                            
                            response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                                "apikey": ENKRYPT_API_KEY,
                                "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                                "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION
                            })
                            
                            remote_span.set_attribute("status_code", response.status_code)
                            remote_span.set_attribute("success", response.status_code == 200)
                            
                            if response.status_code != 200:
                                # remote_span.set_status(Status(StatusCode.ERROR))
                                remote_span.set_attribute("error", "Invalid API key")
                                sys_print("[authenticate] Invalid API key", is_error=True)
                                return {"status": "error", "error": "Invalid API key"}
                            
                            gateway_config = response.json()
                    else:
                        retrieve_span.set_attribute("config_source", "local")
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print("[authenticate] Using local MCP config", is_debug=True)
                        gateway_config = get_local_mcp_config(enkrypt_gateway_key)
                    
                    retrieve_span.set_attribute("config_found", bool(gateway_config))
                    
                    if not gateway_config:
                        # retrieve_span.set_status(Status(StatusCode.ERROR))
                        retrieve_span.set_attribute("error", "No gateway config found")
                        sys_print("[authenticate] No gateway config found", is_error=True)
                        return {"status": "error", "error": "No gateway config found. Probably the gateway key is invalid."}
                    
                    id = gateway_config.get("id")
                    retrieve_span.set_attribute("gateway_id", id)
                    main_span.set_attribute("gateway_id", id)
                    
                except Exception as e:
                    # retrieve_span.set_status(Status(StatusCode.ERROR))
                    retrieve_span.record_exception(e)
                    retrieve_span.set_attribute("error", str(e))
                    raise

            # Cache update
            with tracer.start_as_current_span("update_cache") as cache_span:
                try:
                    cache_span.set_attribute("gateway_id", id)
                    cache_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                    
                    # Cache key to ID mapping
                    cache_key_to_id(cache_client, enkrypt_gateway_key, id)
                    cache_span.set_attribute("key_mapping_cached", True)
                    
                    # Cache gateway config
                    cache_gateway_config(cache_client, id, gateway_config)
                    cache_span.set_attribute("config_cached", True)
                    
                except Exception as e:
                    # cache_span.set_status(Status(StatusCode.ERROR))
                    cache_span.record_exception(e)
                    cache_span.set_attribute("error", str(e))
                    # Don't raise here as caching is not critical for authentication

            # Session update
            with tracer.start_as_current_span("update_session") as session_span:
                session_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                session_span.set_attribute("gateway_id", id)
                
                if enkrypt_gateway_key not in SESSIONS:
                    SESSIONS[enkrypt_gateway_key] = {}
                SESSIONS[enkrypt_gateway_key].update({
                    "authenticated": True,
                    "gateway_config": gateway_config
                })
                
                mcp_config = gateway_config.get("mcp_config", [])
                session_span.set_attribute("has_mcp_config", bool(mcp_config))
                session_span.set_attribute("config_count", len(mcp_config))

            sys_print(f"[authenticate] Auth successful for gateway/user: {id}")
            
            main_span.set_attribute("auth_source", "remote" if ENKRYPT_USE_REMOTE_MCP_CONFIG else "local")
            main_span.set_attribute("success", True)
            main_span.set_attribute("server_count", len(mcp_config))
            
            return {
                "status": "success",
                "message": "Authentication successful",
                "id": id,
                "mcp_config": mcp_config,
                "available_servers": mcp_config_to_dict(mcp_config)
            }

        except Exception as e:
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
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
    custom_id = generate_custom_id()
    logger.info("Listing available servers", extra={
    "discover_tools": discover_tools,
    "custom_id": custom_id
    })
    
    with tracer.start_as_current_span("enkrypt_list_all_servers") as main_span:
        # Count total calls to this endpoint
        list_servers_call_count.add(1)
        sys_print("[list_available_servers] Request received")
        
        enkrypt_gateway_key = get_gateway_key(ctx)
        main_span.set_attribute("job", "enkrypt")
        main_span.set_attribute("env", "dev")
        main_span.set_attribute("custom_id", custom_id)
        main_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
        main_span.set_attribute("discover_tools", discover_tools)
        sys_print("[list_available_servers] Request received")
        logger.info("enkrypt_list_all_servers.started", extra={
            "request_id": ctx.request_id,
            "custom_id": custom_id,
            "gateway_key": mask_key(enkrypt_gateway_key)
        })
        try:
            # Authentication check
            with tracer.start_span("check_server_auth") as auth_span:
                auth_span.set_attribute("custom_id", custom_id)
                auth_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
                auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))

                if not enkrypt_gateway_key:
                    sys_print("[list_available_servers] No gateway key provided")
                    logger.warning("list_all_servers.no_gateway_key", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "gateway_key": mask_key(enkrypt_gateway_key)
                    })
                    return {"status": "error", "error": "No gateway key provided."}

                is_authenticated = enkrypt_gateway_key in SESSIONS and SESSIONS[enkrypt_gateway_key]["authenticated"]
                auth_span.set_attribute("is_authenticated", is_authenticated)

                if not is_authenticated:
                    result = enkrypt_authenticate(ctx)
                    if result.get("status") != "success":
                        if IS_DEBUG_LOG_LEVEL:
                            logger.warning("list_all_servers.auth_failed", extra={
                            "gateway_key": mask_key(enkrypt_gateway_key),
                            "request_id": ctx.request_id,
                            "custom_id": custom_id
                        })
                            sys_print("[list_available_servers] Not authenticated", is_error=True)
                        return {"status": "error", "error": "Not authenticated."}

            # Get server configuration
            with tracer.start_span("get_server_config") as config_span:
                id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]
                mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
                config_span.set_attribute("server_count", len(mcp_config))
                config_span.set_attribute("gateway_id", id)

            # Process servers
            with tracer.start_span("process_servers") as process_span:
                process_span.set_attribute("num_servers", len(mcp_config))
                process_span.set_attribute("total_servers", len(mcp_config))
                
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f'mcp_config: {mcp_config}', is_debug=True)
                
                servers_with_tools = {}
                servers_needing_discovery = []
                
                for server_info in mcp_config:
                    server_name = server_info["server_name"]
                    
                    # Check server cache
                    with tracer.start_span("check_server_cache") as cache_span:
                        cache_span.set_attribute("processing_server", server_name)
                        
                        if IS_DEBUG_LOG_LEVEL:
                            logger.info("list_all_servers.processing_server", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "server_name": server_name
                            })
                            sys_print(f"[list_available_servers] Processing server: {server_name}", is_debug=True)
                        
                        # server_info_copy = server_info.copy()
                        server_info_copy = get_latest_server_info(server_info, id, cache_client)
                        
                        if server_info_copy.get("tools_source") == "needs_discovery":
                            servers_needing_discovery.append(server_name)
                        
                        servers_with_tools[server_name] = server_info_copy
                
                # After the for loop that processes servers
                servers_discovered_count.add(len(servers_with_tools))
                process_span.set_attribute("servers_needing_discovery", len(servers_needing_discovery))
                
            if IS_DEBUG_LOG_LEVEL:
                logger.info("list_all_servers.returning_servers", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "num_servers": len(servers_with_tools)
                })
                sys_print(f"[list_available_servers] Returning {len(servers_with_tools)} servers with tools", is_debug=True)
            
            if not discover_tools:
                main_span.set_attribute("total_servers_processed", len(servers_with_tools))
                main_span.set_attribute("success", True)
                return {
                    "status": "success",
                    "available_servers": servers_with_tools,
                    "servers_needing_discovery": servers_needing_discovery
                }
            else:
                # Tool discovery
                with tracer.start_span("discover_tools") as discover_span:
                    discover_span.set_attribute("servers_to_discover", len(servers_needing_discovery))
                    
                    # Discover tools for all servers
                    status = "success"
                    message = "Tools discovery tried for all servers"
                    discovery_failed_servers = []
                    discovery_success_servers = []
                    
                    for server_name in servers_needing_discovery:
                        with tracer.start_span(f"discover_server_{server_name}") as server_span:
                            server_span.set_attribute("server_name", server_name)
                            
                            discover_server_result = await enkrypt_discover_all_tools(ctx, server_name)
                            
                            if discover_server_result.get("status") != "success":
                                status = "error"
                                discovery_failed_servers.append(server_name)
                                server_span.set_attribute("discovery_success", False)
                            else:
                                discovery_success_servers.append(server_name)
                                servers_with_tools[server_name] = discover_server_result
                                server_span.set_attribute("discovery_success", True)
                    
                    discover_span.set_attribute("failed_servers", len(discovery_failed_servers))
                    discover_span.set_attribute("success_servers", len(discovery_success_servers))
                    
                main_span.set_attribute("total_servers_processed", len(servers_with_tools))
                main_span.set_attribute("servers_discovered", len(servers_needing_discovery))
                main_span.set_attribute("success", True)
                
                return {
                    "status": status,
                    "message": message,
                    "discovery_failed_servers": discovery_failed_servers,
                    "discovery_success_servers": discovery_success_servers,
                    "available_servers": servers_with_tools
                }

        except Exception as e:
            main_span.set_attribute("error", "true")
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error_message", str(e))
            sys_print(f"[list_available_servers] Exception: {e}", is_error=True)
            logger.error("list_all_servers.exception", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "error": str(e)
            })
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
    custom_id = generate_custom_id()

    sys_print(f"[get_server_info] Requested for server: {server_name}")
    logger.info("enkrypt_get_server_info.started", extra={
        "request_id": ctx.request_id,
        "custom_id": custom_id,
    })
    enkrypt_gateway_key = get_gateway_key(ctx)
    
    with tracer.start_as_current_span("enkrypt_get_server_info") as main_span:
        main_span.set_attribute("server_name", server_name)
        main_span.set_attribute("job", "enkrypt")
        main_span.set_attribute("env", "dev")
        main_span.set_attribute("custom_id", custom_id)
        main_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
        
        try:
            # Authentication check
            with tracer.start_as_current_span("check_server_auth") as auth_span:
                auth_span.set_attribute("custom_id", custom_id)
                auth_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
                
                # Add authentication status tracking
                is_authenticated = enkrypt_gateway_key in SESSIONS and SESSIONS[enkrypt_gateway_key]["authenticated"]
                auth_span.set_attribute("is_authenticated", is_authenticated)
                
                if not is_authenticated:
                    result = enkrypt_authenticate(ctx)
                    auth_span.set_attribute("auth_result", result.get("status"))
                    if result.get("status") != "success":
                        # auth_span.set_status(Status(StatusCode.ERROR))
                        auth_span.set_attribute("error", "Authentication failed")
                        sys_print("[get_server_info] Not authenticated")
                        logger.warning("get_server_info.not_authenticated", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })
                        return {"status": "error", "error": "Not authenticated."}

            # Server info check
            with tracer.start_as_current_span("check_server_exists") as server_span:
                server_span.set_attribute("server_name", server_name)
                server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
                server_span.set_attribute("server_found", server_info is not None)
                
                if not server_info:
                    # server_span.set_status(Status(StatusCode.ERROR))
                    server_span.set_attribute("error", f"Server '{server_name}' not available")
                    sys_print(f"[get_server_info] Server '{server_name}' not available")
                    logger.warning("get_server_info.server_not_available", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    return {"status": "error", "error": f"Server '{server_name}' not available."}

            # Get latest server info
            with tracer.start_as_current_span("get_latest_server_info") as info_span:
                info_span.set_attribute("server_name", server_name)
                info_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
                info_span.set_attribute("gateway_id", SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"])
                
                server_info_copy = get_latest_server_info(
                    server_info, 
                    SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"], 
                    cache_client
                )
                
                info_span.set_attribute("has_tools", "tools" in server_info_copy)
                info_span.set_attribute("tools_discovered", server_info_copy.get("tools_discovered", False))

            # Success tracking
            main_span.set_attribute("success", True)
            
            return {
                "status": "success",
                "server_name": server_name,
                "server_info": server_info_copy
            }
            
        except Exception as e:
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
            sys_print(f"[get_server_info] Exception: {e}", is_error=True)
            logger.error("get_server_info.exception", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "error": str(e)
            })
            return {"status": "error", "error": f"Tool discovery failed: {e}"}
        
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
    custom_id = generate_custom_id()
    logger.info("enkrypt_discover_all_tools.started", extra={
        "request_id": ctx.request_id,
        "custom_id": custom_id,
        "server_name": server_name
    })
    
    with tracer.start_as_current_span("enkrypt_discover_all_tools") as main_span:
        main_span.set_attribute("server_name", server_name or "all")
        main_span.set_attribute("custom_id", custom_id)
        main_span.set_attribute("job", "enkrypt")
        main_span.set_attribute("env", "dev")
        main_span.set_attribute("discovery_mode", "single" if server_name else "all")
        
        sys_print(f"[discover_server_tools] Requested for server: {server_name}")
        logger.info("enkrypt_discover_all_tools.started", extra={
            "request_id": ctx.request_id,
            "custom_id": custom_id,
            "server_name": server_name
        })
        enkrypt_gateway_key = get_gateway_key(ctx)
        main_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
        
        try:
            # Authentication check
            if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
                with tracer.start_as_current_span("check_auth") as auth_span:
                    auth_span.set_attribute("custom_id", custom_id)
                    auth_span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
                    auth_span.set_attribute("is_authenticated", False)
                    result = enkrypt_authenticate(ctx)
                    auth_span.set_attribute("auth_result", result.get("status"))
                    if result.get("status") != "success":
                        # auth_span.set_status(Status(StatusCode.ERROR))
                        auth_span.set_attribute("error", "Authentication failed")
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print("[discover_server_tools] Not authenticated", is_error=True)
                        return {"status": "error", "error": "Not authenticated."}

            # If server_name is empty, then we discover all tools for all servers
            if not server_name:
                with tracer.start_as_current_span("discover_all_servers") as all_span:
                    all_span.set_attribute("custom_id", custom_id)
                    all_span.set_attribute("discovery_started", True)
                    
                    sys_print("[discover_server_tools] Discovering tools for all servers as server_name is empty")
                    logger.info("enkrypt_discover_all_tools.discovering_all_servers", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    list_servers_call_count.add(1)
                    all_servers = await enkrypt_list_all_servers(ctx, discover_tools=False)
                    all_servers_with_tools = all_servers.get("available_servers", {})
                    servers_needing_discovery = all_servers.get("servers_needing_discovery", [])

                    all_span.set_attribute("total_servers", len(servers_needing_discovery))

                    status = "success"
                    message = "Tools discovery tried for all servers"
                    discovery_failed_servers = []
                    discovery_success_servers = []
                    
                    for server_name in servers_needing_discovery:
                        with tracer.start_as_current_span(f"discover_server_{server_name}") as server_span:
                            server_span.set_attribute("server_name", server_name)
                            server_span.set_attribute("custom_id", custom_id)
                            start_time = time.time()
                            discover_server_result = await enkrypt_discover_all_tools(ctx, server_name)
                            end_time = time.time()
                            server_span.set_attribute("duration", end_time - start_time)
                            server_span.set_attribute("success", discover_server_result.get("status") == "success")
                            
                            tool_call_duration.record(end_time - start_time)
                            tool_call_counter.add(1)
                            if discover_server_result.get("status") != "success":
                                status = "error"
                                discovery_failed_servers.append(server_name)
                            else:
                                discovery_success_servers.append(server_name)
                                all_servers_with_tools[server_name] = discover_server_result
                    
                    servers_discovered_count.add(len(discovery_success_servers))
                    all_span.set_attribute("discovery_success_count", len(discovery_success_servers))
                    all_span.set_attribute("discovery_failed_count", len(discovery_failed_servers))
                    
                    main_span.set_attribute("success", True)
                    return {
                        "status": status,
                        "message": message,
                        "discovery_failed_servers": discovery_failed_servers,
                        "discovery_success_servers": discovery_success_servers,
                        "available_servers": all_servers_with_tools
                    }

            # Server info check
            with tracer.start_as_current_span("get_server_info") as info_span:
                info_span.set_attribute("server_name", server_name)
                
                server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
                info_span.set_attribute("server_found", server_info is not None)
                
                if not server_info:
                    # info_span.set_status(Status(StatusCode.ERROR))
                    info_span.set_attribute("error", f"Server '{server_name}' not available")
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[discover_server_tools] Server '{server_name}' not available", is_error=True)
                        logger.warning("enkrypt_discover_all_tools.server_not_available", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })
                    return {"status": "error", "error": f"Server '{server_name}' not available."}

                id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]
                info_span.set_attribute("gateway_id", id)

                # Check if server has configured tools in the gateway config
                config_tools = server_info.get("tools", {})
                info_span.set_attribute("has_config_tools", bool(config_tools))
                
                if config_tools:
                    sys_print(f"[discover_server_tools] Tools already defined in config for {server_name}")
                    logger.info("enkrypt_discover_all_tools.tools_already_defined_in_config", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    main_span.set_attribute("success", True)
                    return {
                        "status": "success",
                        "message": f"Tools already defined in config for {server_name}",
                        "tools": config_tools,
                        "source": "config"
                    }

            # Tool discovery
            with tracer.start_as_current_span("discover_tools") as discover_span:
                discover_span.set_attribute("server_name", server_name)
                
                # Cache check
                with tracer.start_as_current_span("check_tools_cache") as cache_span:
                    cached_tools = get_cached_tools(cache_client, id, server_name)
                    cache_span.set_attribute("cache_hit", cached_tools is not None)
                    
                    if cached_tools:
                        cache_hit_counter.add(1)
                        sys_print(f"[discover_server_tools] Tools already cached for {server_name}")
                        logger.info("enkrypt_discover_all_tools.tools_already_cached", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })
                        main_span.set_attribute("success", True)
                        return {
                            "status": "success",
                            "message": f"Tools retrieved from cache for {server_name}",
                            "tools": cached_tools,
                            "source": "cache"
                        }
                    else:
                        cache_miss_counter.add(1)
                        sys_print(f"[discover_server_tools] No cached tools found for {server_name}")
                        logger.info("enkrypt_discover_all_tools.no_cached_tools", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })

                # Forward tool call
                with tracer.start_as_current_span("forward_tool_call") as tool_span:
                    tool_call_counter.add(1)
                    start_time = time.time()
                    result = await forward_tool_call(server_name, None, None, SESSIONS[enkrypt_gateway_key]["gateway_config"])
                    end_time = time.time()
                    tool_call_duration.record(end_time - start_time)
                    tool_span.set_attribute("duration", end_time - start_time)
                    tools = result["tools"] if isinstance(result, dict) and "tools" in result else result
                    tool_span.set_attribute("tools_found", bool(tools))
                    
                    if tools:
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[discover_server_tools] Success: {server_name} tools discovered: {tools}", is_debug=True)
                            logger.info("enkrypt_discover_all_tools.tools_discovered", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "server_name": server_name
                            })
                        
                        # Cache write
                        with tracer.start_as_current_span("cache_tools") as cache_write_span:
                            cache_write_span.set_attribute("server_name", server_name)
                            cache_tools(cache_client, id, server_name, tools)
                            cache_write_span.set_attribute("cache_write_success", True)
                    else:
                        sys_print(f"[discover_server_tools] No tools discovered for {server_name}")
                        logger.warning("enkrypt_discover_all_tools.no_tools_discovered", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })

                main_span.set_attribute("success", True)
                return {
                    "status": "success",
                    "message": f"Tools discovered for {server_name}",
                    "tools": tools,
                    "source": "discovery"
                }
                
        except Exception as e:
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
            sys_print(f"[discover_server_tools] Exception: {e}", is_error=True)
            logger.error("enkrypt_discover_all_tools.exception", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "error": str(e)
            })
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
    custom_id = generate_custom_id()
    
    with tracer.start_as_current_span("enkrypt_secure_call_tools") as main_span:
        tool_calls = tool_calls or []
        num_tool_calls = len(tool_calls)
        
        # Set main span attributes
        main_span.set_attribute("server_name", server_name)
        main_span.set_attribute("num_tool_calls", num_tool_calls)
        main_span.set_attribute("request_id", ctx.request_id)
        main_span.set_attribute("custom_id", custom_id)
        
        sys_print(f"[secure_call_tools] Starting secure batch execution for {num_tool_calls} tools for server: {server_name}")
        logger.info("enkrypt_secure_call_tools.started", extra={
            "request_id": ctx.request_id,
            "custom_id": custom_id,
            "server_name": server_name
        })
        
        if num_tool_calls == 0:
            sys_print("[secure_call_tools] No tools provided. Treating this as a discovery call")
            logger.info("enkrypt_secure_call_tools.no_tools_provided", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name
            })
        
        try:
            # Authentication
            with tracer.start_as_current_span("authenticate_gateway") as auth_span:
                enkrypt_gateway_key = get_gateway_key(ctx)
                auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                
                if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
                    auth_span.set_attribute("required_new_auth", True)
                    result = enkrypt_authenticate(ctx)
                    if result.get("status") != "success":
                        # auth_span.set_status(Status(StatusCode.ERROR))
                        auth_span.set_attribute("error", "Authentication failed")
                        sys_print("[get_server_info] Not authenticated", is_error=True)
                        logger.error("enkrypt_secure_call_tools.not_authenticated", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name
                        })
                        return {"status": "error", "error": "Not authenticated."}
                else:
                    auth_span.set_attribute("required_new_auth", False)

            # Server info validation
            with tracer.start_as_current_span("validate_server_info") as server_span:
                server_span.set_attribute("server_name", server_name)
                
                server_info = get_server_info_by_name(SESSIONS[enkrypt_gateway_key]["gateway_config"], server_name)
                if not server_info:
                    # server_span.set_status(Status(StatusCode.ERROR))
                    server_span.set_attribute("error", f"Server '{server_name}' not available")
                    sys_print(f"[secure_call_tools] Server '{server_name}' not available", is_error=True)
                    logger.warning("enkrypt_secure_call_tools.server_not_available", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    return {"status": "error", "error": f"Server '{server_name}' not available."}

            # Get guardrails policies from server info
            input_guardrails_policy = server_info['input_guardrails_policy']
            output_guardrails_policy = server_info['output_guardrails_policy']
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"Input Guardrails Policy: {input_guardrails_policy}", is_debug=True)
                sys_print(f"Output Guardrails Policy: {output_guardrails_policy}", is_debug=True)
                logger.info("enkrypt_secure_call_tools.input_guardrails_policy", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "server_name": server_name,
                    "input_guardrails_policy": input_guardrails_policy,
                    "output_guardrails_policy": output_guardrails_policy
                })
            
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

            # Set guardrails attributes on main span
            main_span.set_attribute("input_guardrails_enabled", input_policy_enabled)
            main_span.set_attribute("output_guardrails_enabled", output_policy_enabled)
            main_span.set_attribute("pii_redaction_enabled", pii_redaction)
            main_span.set_attribute("relevancy_enabled", relevancy)
            main_span.set_attribute("adherence_enabled", adherence)
            main_span.set_attribute("hallucination_enabled", hallucination)

            server_config = server_info["config"]
            server_command = server_config["command"]
            server_args = server_config["args"]
            server_env = server_config.get("env", None)

            sys_print(f"[secure_call_tools] Starting secure batch call for {num_tool_calls} tools for server: {server_name}")
            logger.info("enkrypt_secure_call_tools.starting_secure_batch_call", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name,
                "num_tool_calls": num_tool_calls
            })
            
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[secure_call_tools] Using command: {server_command} with args: {server_args}", is_debug=True)
                logger.info("enkrypt_secure_call_tools.using_command", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "server_name": server_name,
                    "server_command": server_command,
                })
            
            results = []
            id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]

            # Tool discovery
            with tracer.start_as_current_span("tool_discovery") as discovery_span:
                discovery_span.set_attribute("server_name", server_name)
                
                server_config_tools = server_info.get("tools", {})
                discovery_span.set_attribute("has_cached_tools", bool(server_config_tools))

                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[secure_call_tools] Server config tools before discovery: {server_config_tools}", is_debug=True)
                    logger.info("enkrypt_secure_call_tools.server_config_tools_before_discovery", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name,
                        "server_config_tools": server_config_tools
                    })
                
                if not server_config_tools:
                    server_config_tools = get_cached_tools(cache_client, id, server_name)
                    discovery_span.set_attribute("cache_hit", bool(server_config_tools))
                    
                    if server_config_tools:
                        cache_hit_counter.add(1)
                        logger.info("enkrypt_secure_call_tools.server_config_tools_after_get_cached_tools", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name,
                            "server_config_tools": server_config_tools
                        })
                    if IS_DEBUG_LOG_LEVEL:
                        logger.info("enkrypt_secure_call_tools.server_config_tools_after_get_cached_tools", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "server_name": server_name,
                            "server_config_tools": server_config_tools
                        })
                        sys_print(f"[secure_call_tools] Server config tools after get_cached_tools: {server_config_tools}", is_debug=True)
                    if not server_config_tools:
                        cache_miss_counter.add(1)
                        try:
                            discovery_span.set_attribute("discovery_required", True)
                            list_servers_call_count.add(1)
                            discovery_result = await enkrypt_discover_all_tools(ctx, server_name)
                            discovery_span.set_attribute("discovery_success", discovery_result.get("status") == "success")
                            
                            if IS_DEBUG_LOG_LEVEL:
                                sys_print(f"[enkrypt_secure_call_tools] Discovery result: {discovery_result}", is_debug=True)
                                logger.info("enkrypt_secure_call_tools.discovery_result", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "discovery_result": discovery_result
                                })
                            
                            if discovery_result.get("status") != "success":
                                # discovery_span.set_status(Status(StatusCode.ERROR))
                                discovery_span.set_attribute("error", "Discovery failed")
                                logger.error("enkrypt_secure_call_tools.discovery_failed", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "discovery_result": discovery_result
                                })
                                return {"status": "error", "error": "Failed to discover tools for this server."}

                            if discovery_result.get("status") == "success":
                                server_config_tools = discovery_result.get("tools", {})
                                servers_discovered_count.add(1)
                                
                            if IS_DEBUG_LOG_LEVEL:
                                sys_print(f"[enkrypt_secure_call_tools] Discovered tools: {server_config_tools}", is_debug=True)
                                logger.info("enkrypt_secure_call_tools.discovered_tools", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "server_config_tools": server_config_tools
                                })
                        except Exception as e:
                            # discovery_span.set_status(Status(StatusCode.ERROR))
                            discovery_span.record_exception(e)
                            logger.error("enkrypt_secure_call_tools.exception", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "server_name": server_name,
                                "error": str(e)
                            })
                            sys_print(f"[enkrypt_secure_call_tools] Exception: {e}", is_error=True)
                            traceback.print_exc(file=sys.stderr)
                            return {"status": "error", "error": f"Failed to discover tools: {e}"}
                    else:
                        sys_print(f"[enkrypt_secure_call_tools] Found cached tools for {server_name}")

                if not server_config_tools:
                    discovery_span.set_status(Status(StatusCode.ERROR))
                    discovery_span.set_attribute("error", "No tools found")
                    logger.error("enkrypt_secure_call_tools.no_tools_found", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    sys_print(f"[enkrypt_secure_call_tools] No tools found for {server_name} even after discovery", is_error=True)
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
                    logger.info("enkrypt_secure_call_tools.session_initialized", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name
                    })
                    
                    # Tool execution loop
                    for i, tool_call in enumerate(tool_calls):
                        with tracer.start_as_current_span(f"tool_execution_{i}") as tool_span:
                            tool_name = tool_call.get("name") or tool_call.get("tool_name") or tool_call.get("tool") or tool_call.get("function") or tool_call.get("function_name") or tool_call.get("function_id")
                            tool_span.set_attribute("tool_name", tool_name or "unknown")
                            tool_span.set_attribute("call_index", i)
                            tool_span.set_attribute("server_name", server_name)
                            
                            try:
                                args = tool_call.get("args", {}) or tool_call.get("arguments", {}) or tool_call.get("parameters", {}) or tool_call.get("input", {}) or tool_call.get("params", {})

                                if not tool_name:
                                    # tool_span.set_status(Status(StatusCode.ERROR))
                                    tool_span.set_attribute("error", "No tool_name provided")
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
                                logger.info("enkrypt_secure_call_tools.processing_call", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "tool_name": tool_name,
                                    "tool_arguments": args
                                })

                                # Tool validation
                                with tracer.start_as_current_span("validate_tool") as validate_span:
                                    validate_span.set_attribute("tool_name", tool_name)
                                    tool_found = False
                                    
                                    if server_config_tools:
                                        # Handle tuple return from get_cached_tools() which returns (tools, expires_at)
                                        if isinstance(server_config_tools, tuple) and len(server_config_tools) == 2:
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f"[secure_call_tools] server_config_tools is a tuple from cache: {server_config_tools}", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_tuple_from_cache", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "server_config_tools": server_config_tools
                                                })
                                            server_config_tools = server_config_tools[0]  # Extract the tools, ignoring expires_at

                                        # Handles various formats of tools
                                        # like dictionary-style tools, ListToolsResult format, etc.
                                        if hasattr(server_config_tools, 'tools'):
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print("[secure_call_tools] server_config_tools is a class with tools", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_class_with_tools", extra={  
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "server_config_tools": server_config_tools
                                                })
                                            if isinstance(server_config_tools.tools, list):
                                                # ListToolsResult format
                                                if IS_DEBUG_LOG_LEVEL:
                                                    sys_print(f"[secure_call_tools] server_config_tools is ListToolsResult format: {server_config_tools}", is_debug=True)
                                                    logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_list_tools_result_format", extra={
                                                        "request_id": ctx.request_id,
                                                        "custom_id": custom_id,
                                                        "server_name": server_name,
                                                        "server_config_tools": server_config_tools
                                                    })
                                                for tool in server_config_tools.tools:
                                                    if hasattr(tool, 'name') and tool.name == tool_name:
                                                        tool_found = True
                                                        break
                                            elif isinstance(server_config_tools.tools, dict):
                                                if IS_DEBUG_LOG_LEVEL:
                                                    sys_print("[secure_call_tools] server_config_tools.tools is in Dictionary format", is_debug=True)
                                                    logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_dict_with_tools", extra={
                                                        "request_id": ctx.request_id,
                                                        "custom_id": custom_id,
                                                        "server_name": server_name,
                                                        "server_config_tools": server_config_tools
                                                    })
                                                # Dictionary format like {"echo": "Echo a message"}
                                                if tool_name in server_config_tools.tools:
                                                    tool_found = True
                                        elif isinstance(server_config_tools, dict):
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print("[secure_call_tools] server_config_tools is in Dictionary format", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_dict", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "server_config_tools": server_config_tools
                                                })
                                            if "tools" in server_config_tools:
                                                if IS_DEBUG_LOG_LEVEL:
                                                    sys_print("[secure_call_tools] server_config_tools is a dict and also has tools in Dictionary format", is_debug=True)
                                                    logger.info("enkrypt_secure_call_tools.server_config_tools_is_a_dict_and_also_has_tools_in_dict_format", extra={
                                                        "request_id": ctx.request_id,
                                                        "custom_id": custom_id,
                                                        "server_name": server_name,
                                                        "server_config_tools": server_config_tools
                                                    })
                                                if isinstance(server_config_tools.get("tools", {}), list):
                                                    for tool in server_config_tools.get("tools", []):
                                                        if isinstance(tool, dict):
                                                            # Handle the case where tools can be a list of dicts like [{"name": "echo", "description": "Echo a message"}]
                                                            if tool.get("name") == tool_name or tool_name in tool:
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
                                                    logger.info("enkrypt_secure_call_tools.tool_not_found_in_server_config_tools", extra={
                                                        "request_id": ctx.request_id,
                                                        "custom_id": custom_id,
                                                        "server_name": server_name,
                                                        "tool_name": tool_name
                                                    })
                                        
                                        else:
                                            sys_print(f"[secure_call_tools] Unknown tool format: {type(server_config_tools)}", is_error=True)
                                            logger.error("enkrypt_secure_call_tools.unknown_tool_format", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name,
                                                "server_config_tools": server_config_tools
                                            })
                                    validate_span.set_attribute("tool_found", tool_found)
                                    
                                    if not tool_found:
                                        # validate_span.set_status(Status(StatusCode.ERROR))
                                        validate_span.set_attribute("error", "Tool not found")
                                        sys_print(f"[enkrypt_secure_call_tools] Tool '{tool_name}' not found for this server.", is_error=True)
                                        logger.error("enkrypt_secure_call_tools.tool_not_found_for_this_server", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name
                                        })
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

                                # Input guardrails
                                if input_policy_enabled:
                                    with tracer.start_as_current_span("input_guardrails") as input_span:
                                        input_span.set_attribute("pii_redaction", pii_redaction)
                                        input_span.set_attribute("policy_name", input_policy_name)
                                        input_span.set_attribute("tool_name", tool_name)
                                        
                                        sys_print(f"[secure_call_tools] Call {i} : Input guardrails enabled for {tool_name} of server {server_name}")
                                        logger.info("enkrypt_secure_call_tools.input_guardrails_enabled", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name
                                        })
                                        
                                        # PII Redaction
                                        if pii_redaction:
                                            start_time = time.time()
                                            sys_print(f"[secure_call_tools] Call {i}: PII redaction enabled for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.pii_redaction_enabled", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            guardrail_api_request_counter.add(1)
                                            anonymized_text, redaction_key = anonymize_pii(input_json_string)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            input_span.set_attribute("pii_redaction_duration", end_time - start_time)
                                            
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f"[secure_call_tools] Call {i}: Anonymized text: {anonymized_text}", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.anonymized_text", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "anonymized_text": anonymized_text
                                                })
                                            # Using the anonymized text for input guardrails and tool call
                                            input_json_string = anonymized_text
                                            args = json.loads(anonymized_text)
                                        else:
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f"[secure_call_tools] Call {i}: PII redaction not enabled for {tool_name} of server {server_name}", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.pii_redaction_not_enabled", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name
                                                })
                                        # Input guardrail check
                                        if ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED:
                                            input_span.set_attribute("async_guardrails", True)
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            guardrail_task = asyncio.create_task(call_guardrail(input_json_string, input_blocks, input_policy_name))
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            
                                            tool_call_counter.add(1)
                                            start_time = time.time()
                                            tool_call_task = asyncio.create_task(session.call_tool(tool_name, arguments=args))
                                            end_time = time.time()
                                            tool_call_duration.record(end_time - start_time)

                                            input_violations_detected, input_violation_types, input_guardrail_response = await guardrail_task
                                        else:
                                            input_span.set_attribute("async_guardrails", False)
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            input_violations_detected, input_violation_types, input_guardrail_response = await call_guardrail(input_json_string, input_blocks, input_policy_name)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            input_span.set_attribute("guardrail_duration", end_time - start_time)

                                        input_span.set_attribute("violations_detected", input_violations_detected)
                                        input_span.set_attribute("violation_types", str(input_violation_types))
                                        
                                        sys_print(f"input_violations: {input_violations_detected}, {input_violation_types}")
                                        logger.info("enkrypt_secure_call_tools.input_violations", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "input_violations_detected": input_violations_detected,
                                            "input_violation_types": input_violation_types
                                        })
                            
                                        # Check for input violations
                                        if input_violations_detected:
                                            # input_span.set_status(Status(StatusCode.ERROR))
                                            input_span.set_attribute("error", f"Input violations: {input_violation_types}")
                                            for violation_type in input_violation_types:
                                                guardrail_violation_counter.add(1, {"violation_type": violation_type})
                                            
                                            sys_print(f"[secure_call_tools] Call {i}: Blocked due to input violations: {input_violation_types} for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.blocked_due_to_input_violations", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name,
                                                "input_violations_detected": input_violations_detected,
                                                "input_violation_types": input_violation_types
                                            })
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
                                            break

                                        # Get tool result if async was used
                                        if ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED:
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f"[secure_call_tools] Call {i}: Waiting for tool call to complete in async mode", is_debug=True)
                                            logger.info("enkrypt_secure_call_tools.waiting_for_tool_call_to_complete_in_async_mode", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            tool_call_counter.add(1)
                                            start_time = time.time()
                                            result = await tool_call_task
                                            end_time = time.time()
                                            tool_call_duration.record(end_time - start_time)
                                        else:
                                            # Tool execution
                                            with tracer.start_as_current_span("execute_tool") as exec_span:
                                                exec_span.set_attribute("tool_name", tool_name)
                                                exec_span.set_attribute("async_guardrails", False)
                                                tool_call_counter.add(1)
                                                start_time = time.time()
                                                result = await session.call_tool(tool_name, arguments=args)
                                                end_time = time.time()
                                                tool_call_duration.record(end_time - start_time)
                                                exec_span.set_attribute("execution_duration", end_time - start_time)
                                else:
                                    sys_print(f"[secure_call_tools] Call {i}: Input guardrails not enabled for {tool_name} of server {server_name}")
                                    logger.info("enkrypt_secure_call_tools.input_guardrails_not_enabled", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "server_name": server_name,
                                        "tool_name": tool_name
                                    })
                                    # Tool execution without input guardrails
                                    
                                    with tracer.start_as_current_span("execute_tool") as exec_span:
                                        exec_span.set_attribute("tool_name", tool_name)
                                        exec_span.set_attribute("async_guardrails", False)
                                        tool_call_counter.add(1)
                                        start_time = time.time()
                                        result = await session.call_tool(tool_name, arguments=args)
                                        end_time = time.time()
                                        tool_call_duration.record(end_time - start_time)
                                        exec_span.set_attribute("execution_duration", end_time - start_time)

                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[secure_call_tools] Call {i}: Success: {server_name}.{tool_name}", is_debug=True)
                                    sys_print(f"[secure_call_tools] Call {i}: type of result: {type(result)}", is_debug=True)
                                    sys_print(f"[secure_call_tools] Call {i}: Tool call result: {result}", is_debug=True)
                                    logger.info("enkrypt_secure_call_tools.tool_call_result", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "server_name": server_name,
                                        "tool_name": tool_name,
                                        "result": result
                                    })
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
                                        logger.info("enkrypt_secure_call_tools.tool_executed_and_is_text_checking_output_guardrails", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name
                                        })
                                    else:
                                        sys_print(f"[secure_call_tools] Call {i}: Tool result is not text, skipping output guardrails")
                                        logger.info("enkrypt_secure_call_tools.tool_result_is_not_text_skipping_output_guardrails", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name
                                        })
                  
                                if text_result:
                                    # OUTPUT GUARDRAILS PROCESSING
                                    with tracer.start_as_current_span("output_guardrails") as output_span:
                                        output_span.set_attribute("relevancy_enabled", relevancy)
                                        output_span.set_attribute("adherence_enabled", adherence)
                                        output_span.set_attribute("hallucination_enabled", hallucination)
                                        output_span.set_attribute("tool_name", tool_name)
                                        
                                        if output_policy_enabled:
                                            sys_print(f"[secure_call_tools] Call {i}: Output guardrails enabled for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.output_guardrails_enabled", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            output_violations_detected, output_violation_types, output_guardrail_response = await call_guardrail(text_result, output_blocks, output_policy_name)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            output_span.set_attribute("guardrail_duration", end_time - start_time)
                                            output_span.set_attribute("violations_detected", output_violations_detected)
                                            
                                            sys_print(f"output_violation_types: {output_violation_types}")
                                            logger.info("enkrypt_secure_call_tools.output_guardrails_processing", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name,
                                                "output_violations_detected": output_violations_detected,
                                                "output_violation_types": output_violation_types
                                            })
                                            if output_violations_detected:
                                                # output_span.set_status(Status(StatusCode.ERROR))
                                                output_span.set_attribute("error", f"Output violations: {output_violation_types}")
                                                for violation_type in output_violation_types:
                                                    guardrail_violation_counter.add(1, {"violation_type": violation_type})
                                                
                                                sys_print(f"[secure_call_tools] Call {i}: Blocked due to output violations: {output_violation_types}")
                                                logger.info("enkrypt_secure_call_tools.blocked_due_to_output_violations", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_violations_detected": output_violations_detected,
                                                    "output_violation_types": output_violation_types
                                                })
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
                                                logger.info("enkrypt_secure_call_tools.no_output_violations_detected", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name
                                                })
                                        # RELEVANCY CHECK
                                        if relevancy:
                                            sys_print(f"[secure_call_tools] Call {i}: Checking relevancy for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.checking_relevancy", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            output_relevancy_response = check_relevancy(input_json_string, text_result)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            output_span.set_attribute("relevancy_check_duration", end_time - start_time)
                                            
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f'relevancy response: {output_relevancy_response}', is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.relevancy_response", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_relevancy_response": output_relevancy_response
                                                })
                                            if "relevancy" in output_blocks and output_relevancy_response.get("summary", {}).get("relevancy_score") > RELEVANCY_THRESHOLD:
                                                output_span.set_attribute("relevancy_violation", True)
                                                guardrail_violation_counter.add(1, {"violation_type": "relevancy"})
                                                logger.info("enkrypt_secure_call_tools.blocked_due_to_relevancy_violations", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_relevancy_response": output_relevancy_response
                                                })
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
                                                output_span.set_attribute("relevancy_violation", False)
                                                sys_print(f"[secure_call_tools] Call {i}: No relevancy violations detected or relevancy is not in output_blocks for {tool_name} of server {server_name}")
                                                logger.info("enkrypt_secure_call_tools.no_relevancy_violations_detected", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name
                                                })
                                        
                                        # ADHERENCE CHECK
                                        if adherence:
                                            sys_print(f"[secure_call_tools] Call {i}: Checking adherence for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.checking_adherence", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            output_adherence_response = check_adherence(input_json_string, text_result)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            output_span.set_attribute("adherence_check_duration", end_time - start_time)
                                            
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f'adherence response: {output_adherence_response}', is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.adherence_response", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_adherence_response": output_adherence_response
                                                })
                                            if "adherence" in output_blocks and output_adherence_response.get("summary", {}).get("adherence_score") > ADHERENCE_THRESHOLD:
                                                output_span.set_attribute("adherence_violation", True)
                                                guardrail_violation_counter.add(1, {"violation_type": "adherence"})
                                                logger.info("enkrypt_secure_call_tools.blocked_due_to_adherence_violations", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_adherence_response": output_adherence_response
                                                })
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
                                                output_span.set_attribute("adherence_violation", False)
                                                sys_print(f"[secure_call_tools] Call {i}: No adherence violations detected or adherence is not in output_blocks for {tool_name} of server {server_name}")
                                                logger.info("enkrypt_secure_call_tools.no_adherence_violations_detected", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name
                                                })
                                        # HALLUCINATION CHECK
                                        if hallucination:
                                            sys_print(f"[secure_call_tools] Call {i}: Checking hallucination for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.checking_hallucination", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name
                                            })
                                            guardrail_api_request_counter.add(1)
                                            start_time = time.time()
                                            output_hallucination_response = check_hallucination(input_json_string, text_result)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            output_span.set_attribute("hallucination_check_duration", end_time - start_time)
                                            
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f'hallucination response: {output_hallucination_response}', is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.hallucination_response", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_hallucination_response": output_hallucination_response
                                                })
                                            if "hallucination" in output_blocks and output_hallucination_response.get("summary", {}).get("is_hallucination") > 0:
                                                output_span.set_attribute("hallucination_violation", True)
                                                guardrail_violation_counter.add(1, {"violation_type": "hallucination"})
                                                logger.info("enkrypt_secure_call_tools.blocked_due_to_hallucination_violations", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "output_hallucination_response": output_hallucination_response
                                                    })
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
                                                output_span.set_attribute("hallucination_violation", False)
                                                sys_print(f"[secure_call_tools] Call {i}: No hallucination violations detected or hallucination is not in output_blocks for {tool_name} of server {server_name}")
                                                logger.info("enkrypt_secure_call_tools.no_hallucination_violations_detected", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name
                                                })
                                        # PII DE-ANONYMIZATION
                                        if pii_redaction and redaction_key:
                                            start_time = time.time()
                                            sys_print(f"[secure_call_tools] Call {i}: De-anonymizing PII for {tool_name} of server {server_name} with redaction key: {redaction_key}")
                                            logger.info("enkrypt_secure_call_tools.deanonymizing_pii", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "server_name": server_name,
                                            "tool_name": tool_name,
                                            "redaction_key": redaction_key
                                        })
                                            guardrail_api_request_counter.add(1)
                                            deanonymized_text = deanonymize_pii(text_result, redaction_key)
                                            end_time = time.time()
                                            guardrail_api_request_duration.record(end_time - start_time)
                                            output_span.set_attribute("pii_deanonymization_duration", end_time - start_time)
                                            
                                            if IS_DEBUG_LOG_LEVEL:
                                                sys_print(f"[secure_call_tools] Call {i}: De-anonymized text for {tool_name} of server {server_name}: {deanonymized_text}", is_debug=True)
                                                logger.info("enkrypt_secure_call_tools.deanonymized_text", extra={
                                                    "request_id": ctx.request_id,
                                                    "custom_id": custom_id,
                                                    "server_name": server_name,
                                                    "tool_name": tool_name,
                                                    "deanonymized_text": deanonymized_text
                                                })
                                            text_result = deanonymized_text
                                        else:
                                            sys_print(f"[secure_call_tools] Call {i}: PII redaction not enabled or redaction key {redaction_key} not found for {tool_name} of server {server_name}")
                                            logger.info("enkrypt_secure_call_tools.pii_redaction_not_enabled", extra={
                                                "request_id": ctx.request_id,
                                                "custom_id": custom_id,
                                                "server_name": server_name,
                                                "tool_name": tool_name,
                                                "redaction_key": redaction_key
                                            })
                                sys_print(f"[secure_call_tools] Call {i}: Completed successfully for {tool_name} of server {server_name}")
                                tool_span.set_attribute("status", "success")
                                
                                logger.info("enkrypt_secure_call_tools.completed_successfully", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "tool_name": tool_name
                                })
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
                                # tool_span.set_status(Status(StatusCode.ERROR))
                                tool_span.record_exception(tool_error)
                                tool_span.set_attribute("error", str(tool_error))
                                sys_print(f"[secure_call_tools] Error in call {i} ({tool_name}): {tool_error}", is_error=True)
                                traceback.print_exc(file=sys.stderr)
                                logger.error("enkrypt_secure_call_tools.error_in_tool_call", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "server_name": server_name,
                                    "tool_name": tool_name,
                                    "error": str(tool_error)
                                })
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
            logger.info("enkrypt_secure_call_tools.batch_execution_completed", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name,
                "successful_calls": successful_calls,
                "blocked_calls": blocked_calls,
                "failed_calls": failed_calls
            })

            # Update main span with final status
            main_span.set_attribute("successful_calls", successful_calls)
            main_span.set_attribute("blocked_calls", blocked_calls)
            main_span.set_attribute("failed_calls", failed_calls)
            main_span.set_attribute("success", True)

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
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
            sys_print(f"[secure_call_tools] Critical error during batch execution: {e}", is_error=True)
            traceback.print_exc(file=sys.stderr)
            logger.error("enkrypt_secure_call_tools.critical_error_during_batch_execution", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name,
                "error": str(e)
            })
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
    with tracer.start_as_current_span("enkrypt_get_cache_status") as main_span:
        try:
            sys_print("[get_cache_status] Request received")
            custom_id = generate_custom_id()
            main_span.set_attribute("request_id", ctx.request_id)
            main_span.set_attribute("custom_id", custom_id)
            
            # Authentication
            with tracer.start_as_current_span("authenticate_gateway") as auth_span:
                enkrypt_gateway_key = get_gateway_key(ctx)
                auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                
                if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
                    auth_span.set_attribute("requires_auth", True)
                    result = enkrypt_authenticate(ctx)
                    if result.get("status") != "success":
                        # auth_span.set_status(Status(StatusCode.ERROR))
                        auth_span.set_attribute("error", "Authentication failed")
                        sys_print("[get_cache_status] Not authenticated", is_error=True)
                        logger.error("enkrypt_get_cache_status.not_authenticated", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "error": "Not authenticated."
                        })
                        return {"status": "error", "error": "Not authenticated."}
                else:
                    auth_span.set_attribute("requires_auth", False)

            id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]
            main_span.set_attribute("gateway_id", id)

            # Get cache statistics
            with tracer.start_as_current_span("get_cache_statistics") as stats_span:
                sys_print("[get_cache_status] Getting cache statistics")
                stats = get_cache_statistics(cache_client)
                stats_span.set_attribute("total_gateways", stats.get("total_gateways", 0))
                stats_span.set_attribute("total_tool_caches", stats.get("total_tool_caches", 0))
                stats_span.set_attribute("total_config_caches", stats.get("total_config_caches", 0))
                stats_span.set_attribute("cache_type", stats.get("cache_type", "unknown"))
                
                logger.info("enkrypt_get_cache_status.getting_cache_statistics", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "stats": stats
                })
                
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

            # Gateway config cache check
            with tracer.start_as_current_span("check_gateway_config_cache") as config_span:
                config_span.set_attribute("gateway_id", id)
                
                sys_print(f"[get_cache_status] Getting gateway config for Gateway or User {id}")
                logger.info("enkrypt_get_cache_status.getting_gateway_config", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "id": id
                })
                
                cached_result = get_cached_gateway_config(cache_client, id)
                if cached_result:
                    cache_hit_counter.add(1)
                    gateway_config, expires_at = cached_result
                    config_span.set_attribute("cache_hit", True)
                    config_span.set_attribute("expires_at", expires_at)
                    config_span.set_attribute("expires_in_hours", (expires_at - time.time()) / 3600)
                    
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[get_cache_status] Cached gateway config: {gateway_config}", is_debug=True)
                        logger.info("enkrypt_get_cache_status.cached_gateway_config", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "id": id,
                            "gateway_config": gateway_config
                        })
                    
                    cache_status["gateway_specific"]["config"] = {
                        "exists": True,
                        "expires_at": expires_at,
                        "expires_in_hours": (expires_at - time.time()) / 3600,
                        "is_expired": False
                    }
                else:
                    cache_miss_counter.add(1)
                    config_span.set_attribute("cache_hit", False)
                    
                    sys_print(f"[get_cache_status] No cached gateway config found for {id}", is_debug=True)
                    logger.info("enkrypt_get_cache_status.no_cached_gateway_config_found", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "id": id
                    })
                    
                    cache_status["gateway_specific"]["config"] = {
                        "exists": False,
                        "expires_at": None,
                        "expires_in_hours": None,
                        "is_expired": True
                    }

            # Server tools cache check
            with tracer.start_as_current_span("check_server_tools_cache") as servers_span:
                sys_print("[get_cache_status] Getting server cache status", is_debug=True)
                logger.info("enkrypt_get_cache_status.getting_server_cache_status", extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "id": id
                })
                
                mcp_config = SESSIONS[enkrypt_gateway_key]["gateway_config"].get("mcp_config", [])
                servers_span.set_attribute("total_servers", len(mcp_config))
                
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f'mcp_configs: {mcp_config}', is_debug=True)
                    logger.info("enkrypt_get_cache_status.mcp_configs", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "mcp_configs": mcp_config
                    })
                
                local_gateway_config = get_local_mcp_config(enkrypt_gateway_key)
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f'local gateway_config: {local_gateway_config}', is_debug=True)
                    logger.info("enkrypt_get_cache_status.local_gateway_config", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "local_gateway_config": local_gateway_config
                    })
                
                servers_cache = {}
                cached_servers = 0
                servers_need_discovery = 0
                
                for server_info in mcp_config:
                    server_name = server_info["server_name"]
                    
                    with tracer.start_as_current_span(f"check_server_cache_{server_name}") as server_span:
                        server_span.set_attribute("server_name", server_name)
                        server_span.set_attribute("gateway_id", id)
                        
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[get_cache_status] Getting tool cache for server: {server_name}", is_debug=True)
                            logger.info("enkrypt_get_cache_status.getting_tool_cache", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name
                            })
                        
                        cached_result = get_cached_tools(cache_client, id, server_name)
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[get_cache_status] Cached result: {cached_result}", is_debug=True)
                            logger.info("enkrypt_get_cache_status.cached_result", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name,
                                "cached_result": cached_result
                            })
                        
                        if cached_result:
                            cached_servers += 1
                            tools, expires_at = cached_result
                            server_span.set_attribute("cache_hit", True)
                            server_span.set_attribute("expires_at", expires_at)
                            server_span.set_attribute("expires_in_hours", (expires_at - time.time()) / 3600)
                            
                            if IS_DEBUG_LOG_LEVEL:
                                sys_print(f"[get_cache_status] Tools found for server: {server_name}", is_debug=True)
                                logger.info("enkrypt_get_cache_status.tools_found", extra={
                                    "request_id": ctx.request_id,
                                    "custom_id": custom_id,
                                    "id": id,
                                    "server_name": server_name,
                                    "tools": tools
                                })
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
                                    logger.error("enkrypt_get_cache_status.unknown_tool_format", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name,
                                        "tools": tools
                                    })
                                
                                server_span.set_attribute("tool_count", tool_count if tool_count is not None else 0)
                                
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
                            server_span.set_attribute("cache_hit", False)
                            needs_discovery = True
                            are_tools_explicitly_defined = False
                            
                            if local_gateway_config:
                                local_server_info = get_server_info_by_name(local_gateway_config, server_name)
                                if local_server_info and "tools" in local_server_info:
                                    if IS_DEBUG_LOG_LEVEL:
                                        sys_print(f"[get_cache_status] Server {server_name} tools are defined in the local gateway config", is_debug=True)
                                        logger.info("enkrypt_get_cache_status.server_tools_defined_in_local_gateway_config", extra={
                                            "request_id": ctx.request_id,
                                            "custom_id": custom_id,
                                            "id": id,
                                            "server_name": server_name
                                        })
                                    are_tools_explicitly_defined = True
                                    needs_discovery = False
                            else:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[get_cache_status] No tools found for server that needs discovery: {server_name}", is_debug=True)
                                    logger.info("enkrypt_get_cache_status.no_tools_found_for_server_that_needs_discovery", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name
                                    })
                            
                            if needs_discovery:
                                servers_need_discovery += 1
                            
                            server_span.set_attribute("explicitly_defined", are_tools_explicitly_defined)
                            server_span.set_attribute("needs_discovery", needs_discovery)
                            
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
                
                servers_span.set_attribute("cached_servers", cached_servers)
                servers_span.set_attribute("servers_need_discovery", servers_need_discovery)
                
                cache_status["gateway_specific"]["tools"] = {
                    "server_count": len(servers_cache),
                    "servers": servers_cache
                }

            # Set final span attributes
            main_span.set_attribute("total_servers", len(mcp_config))
            main_span.set_attribute("cached_servers", cached_servers)
            main_span.set_attribute("servers_need_discovery", servers_need_discovery)
            main_span.set_attribute("success", True)

            sys_print(f"[get_cache_status] Returning cache status for Gateway or User {id}", is_debug=True)
            return {
                "status": "success",
                "cache_status": cache_status
            }

        except Exception as e:
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
            sys_print(f"[get_cache_status] Critical error: {e}", is_error=True)
            logger.error("enkrypt_get_cache_status.critical_error", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "error": str(e)
            })
            raise

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
    with tracer.start_as_current_span("enkrypt_clear_cache") as main_span:
        try:
            sys_print(f"[clear_cache] Requested with id={id}, server_name={server_name}, cache_type={cache_type}")
            custom_id = generate_custom_id()
            
            # Set main span attributes
            main_span.set_attribute("request_id", ctx.request_id)
            main_span.set_attribute("custom_id", custom_id)
            main_span.set_attribute("id", id or "not_provided")
            main_span.set_attribute("server_name", server_name or "not_provided")
            main_span.set_attribute("cache_type", cache_type or "not_provided")
            
            # Authentication
            with tracer.start_as_current_span("authenticate_gateway") as auth_span:
                enkrypt_gateway_key = get_gateway_key(ctx)
                auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
                
                if enkrypt_gateway_key not in SESSIONS or not SESSIONS[enkrypt_gateway_key]["authenticated"]:
                    auth_span.set_attribute("requires_auth", True)
                    result = enkrypt_authenticate(ctx)
                    if result.get("status") != "success":
                        # auth_span.set_status(Status(StatusCode.ERROR))
                        auth_span.set_attribute("error", "Authentication failed")
                        sys_print("[clear_cache] Not authenticated", is_error=True)
                        logger.error("enkrypt_clear_cache.not_authenticated", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "error": "Not authenticated."
                        })
                        return {"status": "error", "error": "Not authenticated."}
                else:
                    auth_span.set_attribute("requires_auth", False)

            # Default id from session if not provided
            if not id:
                id = SESSIONS[enkrypt_gateway_key]["gateway_config"]["id"]
                main_span.set_attribute("id", id)

            sys_print(f"[clear_cache] Gateway/User ID: {id}, Server Name: {server_name}, Cache Type: {cache_type}")
            logger.info("enkrypt_clear_cache.requested", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "id": id,
                "server_name": server_name,
                "cache_type": cache_type
            })

            # Cache type determination
            with tracer.start_as_current_span("determine_cache_type") as type_span:
                if not cache_type:
                    type_span.set_attribute("default_type", True)
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print("[clear_cache] No cache type provided. Defaulting to 'all'")
                        logger.info("enkrypt_clear_cache.no_cache_type_provided", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "id": id,
                            "server_name": server_name,
                            "cache_type": cache_type
                        })
                    cache_type = "all"
                    main_span.set_attribute("cache_type", cache_type)
                else:
                    type_span.set_attribute("default_type", False)
                
                type_span.set_attribute("cache_type", cache_type)
                type_span.set_attribute("server_name", server_name or "not_provided")
                type_span.set_attribute("id", id)

            # Clear all caches (tool + gateway config)
            if cache_type == "all":
                with tracer.start_as_current_span("clear_all_caches") as all_span:
                    try:
                        all_span.set_attribute("id", id)
                        all_span.set_attribute("server_name", server_name or "all")
                        
                        sys_print("[clear_cache] Clearing all caches")
                        logger.info("enkrypt_clear_cache.clearing_all_caches", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "id": id,
                            "server_name": server_name,
                            "cache_type": cache_type
                        })
                        
                        cleared_servers = clear_cache_for_servers(cache_client, id)
                        cleared_gateway = clear_gateway_config_cache(cache_client, id, enkrypt_gateway_key)
                        
                        all_span.set_attribute("cleared_servers_count", cleared_servers)
                        all_span.set_attribute("gateway_config_cleared", cleared_gateway)
                        
                        if ENKRYPT_USE_REMOTE_MCP_CONFIG:
                            with tracer.start_as_current_span("refresh_remote_config") as refresh_span:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print("[clear_cache] Refreshing remote MCP config", is_debug=True)
                                    logger.info("enkrypt_clear_cache.refreshing_remote_mcp_config", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name,
                                        "cache_type": cache_type
                                    })
                                
                                refresh_response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                                    "apikey": ENKRYPT_API_KEY,
                                    "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                                    "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                                    "X-Enkrypt-Refresh-Cache": "true"
                                })
                                
                                refresh_span.set_attribute("status_code", refresh_response.status_code)
                                refresh_span.set_attribute("success", refresh_response.ok)
                                
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[clear_cache] Refresh response: {refresh_response}", is_debug=True)
                                    logger.info("enkrypt_clear_cache.refresh_response", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name,
                                        "cache_type": cache_type
                                    })
                        
                        main_span.set_attribute("success", True)
                        return {
                            "status": "success",
                            "message": f"Cache cleared for all servers ({cleared_servers} servers) and gateway config ({'cleared' if cleared_gateway else 'none'})"
                        }
                        
                    except Exception as e:
                        # all_span.set_status(Status(StatusCode.ERROR))
                        all_span.record_exception(e)
                        all_span.set_attribute("error", str(e))
                        raise

            # Clear gateway config cache
            if cache_type == "gateway_config" or cache_type == "gateway" or cache_type == "gateway_cache" or cache_type == "gateway_config_cache":
                with tracer.start_as_current_span("clear_gateway_config") as config_span:
                    try:
                        config_span.set_attribute("id", id)
                        config_span.set_attribute("cache_type", cache_type)
                        
                        sys_print("[clear_cache] Clearing gateway config cache")
                        logger.info("enkrypt_clear_cache.clearing_gateway_config_cache", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "id": id,
                            "server_name": server_name,
                            "cache_type": cache_type
                        })
                        
                        cleared = clear_gateway_config_cache(cache_client, id, enkrypt_gateway_key)
                        config_span.set_attribute("cache_cleared", cleared)
                        
                        if ENKRYPT_USE_REMOTE_MCP_CONFIG:
                            with tracer.start_as_current_span("refresh_remote_config") as refresh_span:
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print("[clear_cache] Refreshing remote MCP config", is_debug=True)
                                    logger.info("enkrypt_clear_cache.refreshing_remote_mcp_config", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name,
                                        "cache_type": cache_type
                                    })
                                
                                refresh_response = requests.get(AUTH_SERVER_VALIDATE_URL, headers={
                                    "apikey": ENKRYPT_API_KEY,
                                    "X-Enkrypt-MCP-Gateway": ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                                    "X-Enkrypt-MCP-Gateway-Version": ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                                    "X-Enkrypt-Refresh-Cache": "true"
                                })
                                
                                refresh_span.set_attribute("status_code", refresh_response.status_code)
                                refresh_span.set_attribute("success", refresh_response.ok)
                                
                                if IS_DEBUG_LOG_LEVEL:
                                    sys_print(f"[clear_cache] Refresh response: {refresh_response}", is_debug=True)
                                    logger.info("enkrypt_clear_cache.refresh_response", extra={
                                        "request_id": ctx.request_id,
                                        "custom_id": custom_id,
                                        "id": id,
                                        "server_name": server_name,
                                        "cache_type": cache_type
                                    })
                        
                        if cleared:
                            logger.info("enkrypt_clear_cache.gateway_config_cache_cleared", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name,
                                "cache_type": cache_type
                            })
                            main_span.set_attribute("success", True)
                            return {"status": "success", "message": f"Gateway config cache cleared for {id}"}
                        else:
                            logger.info("enkrypt_clear_cache.no_config_cache_found", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name,
                                "cache_type": cache_type
                            })
                            main_span.set_attribute("success", True)
                            return {"status": "info", "message": f"No config cache found for {id}"}
                            
                    except Exception as e:
                        # config_span.set_status(Status(StatusCode.ERROR))
                        config_span.record_exception(e)
                        config_span.set_attribute("error", str(e))
                        raise

            # Clear server config cache
            with tracer.start_as_current_span("clear_server_cache") as server_span:
                try:
                    server_span.set_attribute("id", id)
                    server_span.set_attribute("server_name", server_name or "all")
                    server_span.set_attribute("clear_specific_server", bool(server_name))
                    
                    sys_print("[clear_cache] Clearing server config cache")
                    logger.info("enkrypt_clear_cache.clearing_server_config_cache", extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "id": id,
                        "server_name": server_name,
                        "cache_type": cache_type
                    })
                    
                    # Clear tool cache for a specific server
                    if server_name:
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(f"[clear_cache] Clearing tool cache for server: {server_name}", is_debug=True)
                            logger.info("enkrypt_clear_cache.clearing_tool_cache_for_server", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name,
                                "cache_type": cache_type
                            })
                        
                        cleared = clear_cache_for_servers(cache_client, id, server_name)
                        server_span.set_attribute("cache_cleared", cleared)
                        server_span.set_attribute("target_server", server_name)
                        
                        if cleared:
                            logger.info("enkrypt_clear_cache.tool_cache_cleared", extra={
                                "request_id": ctx.request_id,
                                "custom_id": custom_id,
                                "id": id,
                                "server_name": server_name,
                                "cache_type": cache_type
                            })
                            main_span.set_attribute("success", True)
                            return {
                                "status": "success",
                                "message": f"Cache cleared for server: {server_name}"
                            }
                        else:
                            main_span.set_attribute("success", True)
                            return {
                                "status": "info",
                                "message": f"No cache found for server: {server_name}"
                            }
                    # Clear all server caches (tool cache)
                    else:
                        sys_print("[clear_cache] Clearing all server caches")
                        logger.info("enkrypt_clear_cache.clearing_all_server_caches", extra={
                            "request_id": ctx.request_id,
                            "custom_id": custom_id,
                            "id": id,
                            "server_name": server_name,
                            "cache_type": cache_type
                        })
                        
                        cleared = clear_cache_for_servers(cache_client, id)
                        server_span.set_attribute("cleared_servers_count", cleared)
                        
                        main_span.set_attribute("success", True)
                        return {
                            "status": "success",
                            "message": f"Cache cleared for all servers ({cleared} servers)"
                        }
                        
                except Exception as e:
                    # server_span.set_status(Status(StatusCode.ERROR))
                    server_span.record_exception(e)
                    server_span.set_attribute("error", str(e))
                    raise

        except Exception as e:
            # main_span.set_status(Status(StatusCode.ERROR))
            main_span.record_exception(e)
            main_span.set_attribute("error", str(e))
            sys_print(f"[clear_cache] Critical error: {e}", is_error=True)
            logger.error("enkrypt_clear_cache.critical_error", extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "error": str(e)
            })
            raise

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
        # NOTE:
        # Settings defined on top do not seem to work
        # But when we do it here, it works. Not sure why.
        # --------------------------------------------
        # Removing name, instructions due to the below error:
        # AttributeError: property 'name' of 'FastMCP' object has no setter
        # mcp.name = "Enkrypt Secure MCP Gateway"
        # mcp.instructions = "This is the Enkrypt Secure MCP Gateway. It is used to secure the MCP calls to the servers by authenticating with a gateway key and using guardrails to check both requests and responses."
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

