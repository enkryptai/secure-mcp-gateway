"""
Enkrypt Secure MCP Gateway Client Module

This module provides client-side functionality for the Enkrypt Secure MCP Gateway, handling:
1. Cache Management:
   - External Redis cache integration
   - Local in-memory cache fallback
   - Cache expiration and invalidation
   - Cache statistics and monitoring

2. Tool Management:
   - Tool discovery and caching
   - Tool invocation forwarding
   - Server configuration management

3. Gateway Configuration:
   - Gateway config caching
   - API key to gateway/user ID mapping
   - Server access control

The module supports both external Redis cache and local in-memory cache, with configurable
expiration times and automatic cache invalidation.

Configuration Variables:
    enkrypt_mcp_use_external_cache: Enable/disable external Redis cache
    enkrypt_cache_host: Redis host address
    enkrypt_cache_port: Redis port number
    enkrypt_cache_db: Redis database number
    enkrypt_cache_password: Redis password
    enkrypt_tool_cache_expiration: Tool cache expiration in hours
    enkrypt_gateway_cache_expiration: Gateway config cache expiration in hours

Cache Types:
    1. Tool Cache:
       - Stores discovered tools for each server
       - Key format: <id>-<server_name>-tools
       - Configurable expiration time

    2. Gateway Config Cache:
       - Stores gateway configuration and permissions
       - Key format: <id>-mcp-config
       - Configurable expiration time

    3. Gateway Key Cache:
       - Maps gateway keys to gateway/user IDs
       - Key format: gatewaykey-<gateway_key>
       - Expires with gateway config

Example Usage:
    ```python
    # Initialize cache
    cache_client = initialize_cache()

    # Cache tools for a server
    cache_tools(cache_client, "id123", "server1", tools_data)

    # Get cached tools
    tools = get_cached_tools(cache_client, "id123", "server1")

    # Forward tool call
    result = await forward_tool_call("server1", "tool1", args, gateway_config)

    # Get cache statistics
    stats = get_cache_statistics(cache_client)
    ```
"""

import sys
import time
import json
import hashlib
import threading
import asyncio
import aiohttp
from datetime import datetime
import redis as external_cache_server
# https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/stdio/__init__.py
from mcp.client.stdio import stdio_client
from mcp import ClientSession, StdioServerParameters

from secure_mcp_gateway.utils import (
    get_common_config,
    sys_print
)
from secure_mcp_gateway.version import __version__

sys_print(f"Initializing Enkrypt Secure MCP Gateway Client Module v{__version__}")

common_config = get_common_config()

ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"

# --- Cache Configuration ---
ENKRYPT_MCP_USE_EXTERNAL_CACHE = common_config.get("enkrypt_mcp_use_external_cache", False)
ENKRYPT_CACHE_HOST = common_config.get("enkrypt_cache_host", "localhost")
ENKRYPT_CACHE_PORT = int(common_config.get("enkrypt_cache_port", "6379"))
ENKRYPT_CACHE_DB = int(common_config.get("enkrypt_cache_db", "0"))
ENKRYPT_CACHE_PASSWORD = common_config.get("enkrypt_cache_password", None)

# Cache expiration times (in hours)
ENKRYPT_TOOL_CACHE_EXPIRATION = int(common_config.get("enkrypt_tool_cache_expiration", 4))  # 4 hours
ENKRYPT_GATEWAY_CACHE_EXPIRATION = int(common_config.get("enkrypt_gateway_cache_expiration", 24))  # 24 hours (1 day)

# HTTP client configuration
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
MAX_RETRIES = 3
RETRY_DELAY = 1.0

# Global HTTP session for authentication requests
_auth_http_session = None

local_cache = {}
local_cache_lock = threading.Lock()

# Add local registries for gateway config and servers
local_key_map = {}
local_server_registry = {}
local_gateway_config_registry = set()


async def get_auth_http_session() -> aiohttp.ClientSession:
    """Get or create a global HTTP session for authentication requests."""
    global _auth_http_session
    if _auth_http_session is None or _auth_http_session.closed:
        connector = aiohttp.TCPConnector(
            limit=50,  # Total connection pool size
            limit_per_host=20,  # Per-host connection limit
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        _auth_http_session = aiohttp.ClientSession(
            connector=connector,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": f"enkrypt-mcp-gateway/{__version__}"}
        )
    return _auth_http_session


async def close_auth_http_session():
    """Close the global authentication HTTP session."""
    global _auth_http_session
    if _auth_http_session and not _auth_http_session.closed:
        await _auth_http_session.close()
        _auth_http_session = None


async def make_auth_request(url: str, headers: dict) -> dict:
    """
    Make an async HTTP request for authentication with retry logic.
    
    Args:
        url: The URL to make the request to
        headers: HTTP headers to include
        
    Returns:
        Dict containing the response data or error information
    """
    session = await get_auth_http_session()
    
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:  # Rate limited
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)
                        sys_print(f"Auth request rate limited, waiting {wait_time}s before retry {attempt + 1}")
                        await asyncio.sleep(wait_time)
                        continue
                else:
                    response.raise_for_status()
                    
        except aiohttp.ClientError as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)
                sys_print(f"Auth request failed (attempt {attempt + 1}): {e}, retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
                continue
            else:
                sys_print(f"Auth request failed after {MAX_RETRIES} attempts: {e}")
                return {"error": str(e)}
        except Exception as e:
            sys_print(f"Unexpected error in auth request: {e}")
            return {"error": str(e)}
    
    return {"error": "Maximum retries exceeded"}


# --- Cache connection ---
def initialize_cache():
    """
    Initializes and tests the connection to the Redis cache server.

    This function creates a Redis client instance with the configured connection parameters
    and verifies the connection is working. If external cache is disabled, it returns None.

    Returns:
        Redis: A configured Redis client instance if external cache is enabled
        None: If external cache is disabled or connection fails

    Raises:
        ConnectionError: If unable to connect to the Redis server when external cache is enabled
    """
    # Initialize Cache client
    cache_client = external_cache_server.Redis(
        host=ENKRYPT_CACHE_HOST,
        port=ENKRYPT_CACHE_PORT,
        db=ENKRYPT_CACHE_DB,
        password=ENKRYPT_CACHE_PASSWORD,
        decode_responses=True,  # Automatically decode responses to strings
        socket_connect_timeout=5,  # Connection timeout
        socket_timeout=5,  # Socket timeout
        retry_on_timeout=True,  # Retry on timeout
        health_check_interval=30  # Health check interval
    )

    # Test Cache connection
    try:
        cache_client.ping()
        sys_print(f"[external_cache] Successfully connected to External Cache at {ENKRYPT_CACHE_HOST}:{ENKRYPT_CACHE_PORT}")
    except external_cache_server.ConnectionError as e:
        sys_print(f"[external_cache] Failed to connect to External Cache: {e}")
        sys_print("[external_cache] Exiting as External Cache is required for this gateway")
        sys.exit(1)  # Exit if External Cache is unavailable

    return cache_client


# --- Cache key patterns with hashing ---
def hash_key(key):
    """
    Creates an MD5 hash of the given key for secure cache storage.

    Args:
        key (str): The key to be hashed

    Returns:
        str: MD5 hash of the input key
    """
    return hashlib.md5(key.encode()).hexdigest()


def get_server_hashed_key(id, server_name):
    """
    Generates a hashed cache key for server tools.

    Args:
        id (str): The ID of the Gateway or User
        server_name (str): Name of the server

    Returns:
        str: Hashed cache key for the server tools
    """
    raw_key = f"{id}-{server_name}-tools"
    return hash_key(raw_key)


def get_gateway_config_hashed_key(id):
    """
    Generates a hashed cache key for gateway configuration.

    Args:
        id (str): The ID of the Gateway or User

    Returns:
        str: Hashed cache key for the gateway configuration
    """
    raw_key = f"{id}-mcp-config"
    return hash_key(raw_key)


def get_hashed_key(key):
    """
    Generates a hashed cache key for key to gateway/user ID mapping.

    Args:
        key (str): The Gateway/API key

    Returns:
        str: Hashed cache key for the API key mapping
    """
    raw_key = f"gatewaykey-{key}"
    return hash_key(raw_key)


def get_gateway_servers_registry_hashed_key(id):
    """
    Generates a hashed cache key for gateway servers registry.

    Args:
        id (str): The ID of the Gateway or User

    Returns:
        str: Hashed cache key for the gateway servers registry
    """
    raw_key = f"{id}-servers-registry"
    return hash_key(raw_key)


def get_gateway_registry_hashed_key():
    """
    Generates a hashed cache key for global gateway registry.

    Returns:
        str: Hashed cache key for the global gateway registry
    """
    raw_key = "gateways-registry"
    return hash_key(raw_key)


# --- Async cache operations ---
async def set_cache_async(cache_client, key: str, value: str, expires_in_seconds: int):
    """Set cache value asynchronously with proper error handling."""
    try:
        if ENKRYPT_MCP_USE_EXTERNAL_CACHE and cache_client:
            # Use Redis pipeline for better performance
            pipe = cache_client.pipeline()
            pipe.set(key, value, ex=expires_in_seconds)
            await asyncio.get_event_loop().run_in_executor(None, pipe.execute)
        else:
            set_local_cache(key, value, expires_in_seconds)
    except Exception as e:
        sys_print(f"Error setting cache key {key}: {e}")


async def get_cache_async(cache_client, key: str):
    """Get cache value asynchronously with proper error handling."""
    try:
        if ENKRYPT_MCP_USE_EXTERNAL_CACHE and cache_client:
            return await asyncio.get_event_loop().run_in_executor(None, cache_client.get, key)
        else:
            return get_local_cache(key)
    except Exception as e:
        sys_print(f"Error getting cache key {key}: {e}")
        return None


async def delete_cache_async(cache_client, key: str):
    """Delete cache value asynchronously with proper error handling."""
    try:
        if ENKRYPT_MCP_USE_EXTERNAL_CACHE and cache_client:
            await asyncio.get_event_loop().run_in_executor(None, cache_client.delete, key)
        else:
            with local_cache_lock:
                local_cache.pop(key, None)
    except Exception as e:
        sys_print(f"Error deleting cache key {key}: {e}")


# --- Tool forwarding ---
async def forward_tool_call(server_name, tool_name, args=None, gateway_config=None):
    """
    Forwards a tool call to the appropriate MCP server (async optimized).

    This function establishes a connection to the specified MCP server and forwards
    the tool call with the provided arguments. It handles server configuration,
    connection management, and error handling.

    Args:
        server_name (str): Name of the server to forward the call to
        tool_name (str): Name of the tool to call on the server
        args (dict, optional): Arguments to pass to the tool. Defaults to None.
        gateway_config (dict, optional): Gateway configuration containing server details.
                                       If None, will attempt to retrieve from cache.

    Returns:
        dict: Result from the tool call, or error information if the call fails

    Raises:
        Exception: If server configuration is invalid or connection fails

    Example:
        ```python
        result = await forward_tool_call(
            "github_server",
            "create_issue",
            {"title": "Bug report", "body": "Description"},
            gateway_config
        )
        ```
    """
    if args is None:
        args = {}

    if not gateway_config:
        sys_print("[forward_tool_call] No gateway config provided")
        return {"error": "No gateway config provided"}

    # Find server configuration
    server_config = None
    mcp_config = gateway_config.get("mcp_config", [])
    
    for server_info in mcp_config:
        if server_info["server_name"] == server_name:
            server_config = server_info["config"]
            break

    if not server_config:
        sys_print(f"[forward_tool_call] Server '{server_name}' not found in gateway config")
        return {"error": f"Server '{server_name}' not found"}

    # Extract server parameters
    command = server_config["command"]
    server_args = server_config["args"]
    env = server_config.get("env", None)

    sys_print(f"[forward_tool_call] Forwarding {tool_name} to {server_name}")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[forward_tool_call] Command: {command}, Args: {server_args}, Tool Args: {args}")

    try:
        # Create connection to MCP server
        async with stdio_client(StdioServerParameters(command=command, args=server_args, env=env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # Call the tool
                result = await session.call_tool(tool_name, arguments=args)
                
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[forward_tool_call] Tool result: {result}")
                
                return {"status": "success", "result": result}

    except Exception as e:
        sys_print(f"[forward_tool_call] Error calling {tool_name} on {server_name}: {e}")
        return {"error": str(e)}


# --- Local cache operations (optimized) ---
def set_local_cache(key, value, expires_in_seconds):
    """
    Sets a value in the local cache with expiration time (thread-safe).

    Args:
        key (str): Cache key
        value (any): Value to cache
        expires_in_seconds (int): Expiration time in seconds
    """
    expiration_time = time.time() + expires_in_seconds
    with local_cache_lock:
        local_cache[key] = {
            'value': value,
            'expires_at': expiration_time
        }


def get_local_cache(key):
    """
    Gets a value from the local cache, checking expiration (thread-safe).

    Args:
        key (str): Cache key

    Returns:
        any: Cached value if found and not expired, None otherwise
    """
    with local_cache_lock:
        cached_item = local_cache.get(key)
        if cached_item is None:
            return None
        
        if time.time() > cached_item['expires_at']:
            # Remove expired item
            del local_cache[key]
            return None
        
        return cached_item['value']


# --- Cache operations with improved error handling ---
def get_cached_tools(cache_client, id, server_name):
    """
    Retrieves cached tools for a specific server with improved error handling.

    Args:
        cache_client: Redis client instance or None for local cache
        id (str): The ID of the Gateway or User
        server_name (str): Name of the server

    Returns:
        tuple: (tools_data, expires_at) if found, (None, None) if not found or expired
    """
    cache_key = get_server_hashed_key(id, server_name)
    
    try:
        if ENKRYPT_MCP_USE_EXTERNAL_CACHE and cache_client:
            # Get value and TTL in a pipeline for efficiency
            pipe = cache_client.pipeline()
            pipe.get(cache_key)
            pipe.ttl(cache_key)
            cached_value, ttl = pipe.execute()
            
            if cached_value:
                expires_at = time.time() + ttl if ttl > 0 else None
                tools_data = json.loads(cached_value)
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[get_cached_tools] Found cached tools for {server_name}")
                return tools_data, expires_at
        else:
            cached_item = get_local_cache(cache_key)
            if cached_item:
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[get_cached_tools] Found local cached tools for {server_name}")
                return cached_item, None
                
    except Exception as e:
        sys_print(f"[get_cached_tools] Error retrieving cached tools for {server_name}: {e}")
    
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[get_cached_tools] No cached tools found for {server_name}")
    return None, None


def cache_tools(cache_client, id, server_name, tools):
    """
    Caches tools for a specific server with improved error handling.

    Args:
        cache_client: Redis client instance or None for local cache
        id (str): The ID of the Gateway or User
        server_name (str): Name of the server
        tools: Tools data to cache
    """
    cache_key = get_server_hashed_key(id, server_name)
    expires_in_seconds = ENKRYPT_TOOL_CACHE_EXPIRATION * 3600  # Convert hours to seconds
    
    try:
        if ENKRYPT_MCP_USE_EXTERNAL_CACHE and cache_client:
            tools_json = json.dumps(tools)
            cache_client.set(cache_key, tools_json, ex=expires_in_seconds)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[cache_tools] Cached tools for {server_name} (expires in {ENKRYPT_TOOL_CACHE_EXPIRATION}h)")
        else:
            set_local_cache(cache_key, tools, expires_in_seconds)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[cache_tools] Locally cached tools for {server_name}")
                
    except Exception as e:
        sys_print(f"[cache_tools] Error caching tools for {server_name}: {e}")


def get_cached_gateway_config(cache_client, id):
    """
    Retrieves cached gateway configuration.

    Args:
        cache_client: The cache client instance
        id (str): ID of the Gateway or User

    Returns:
        tuple: (config_data, expiration_time) if found and not expired, None otherwise
    """
    config_key = get_gateway_config_hashed_key(id)
    if not ENKRYPT_MCP_USE_EXTERNAL_CACHE:
        return get_local_cache(config_key)

    if cache_client is None:
        return None

    cached_data = cache_client.get(config_key)
    if not cached_data:
        return None
    try:
        config_data = json.loads(cached_data)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[external_cache] Using cached config for id '{id}' with key hash: {config_key}")
        return config_data
    except json.JSONDecodeError:
        sys_print(f"[external_cache] Error deserializing config cache for hash key: {config_key}")
        return None


def cache_gateway_config(cache_client, id, config):
    """
    Caches gateway configuration.

    Args:
        cache_client: The cache client instance
        id (str): ID of the Gateway or User
        config (dict): The gateway configuration to cache
    """
    expires_in_seconds = int(ENKRYPT_GATEWAY_CACHE_EXPIRATION * 3600)
    config_key = get_gateway_config_hashed_key(id)
    if not ENKRYPT_MCP_USE_EXTERNAL_CACHE:
        set_local_cache(config_key, config, expires_in_seconds)
        local_gateway_config_registry.add(id)
        return

    if cache_client is None:
        return
    serialized_data = json.dumps(config)
    cache_client.setex(config_key, expires_in_seconds, serialized_data)
    if IS_DEBUG_LOG_LEVEL:
        expiration_time = datetime.fromtimestamp(time.time() + expires_in_seconds).strftime('%Y-%m-%d %H:%M:%S')
        sys_print(f"[external_cache] Cached gateway config for '{id}' with key '{id}-mcp-config' (hash: {config_key}) until {expiration_time}")
    gateway_registry = get_gateway_registry_hashed_key()
    cache_client.sadd(gateway_registry, id)


def cache_key_to_id(cache_client, gateway_key, id):
    """
    Caches the mapping between a key and gateway/user ID.

    Args:
        cache_client: The cache client instance
        gateway_key (str): The key for gateway/user
        id (str): ID of the Gateway or User
    """
    expires_in_seconds = int(ENKRYPT_GATEWAY_CACHE_EXPIRATION * 3600)
    key = get_hashed_key(gateway_key)
    if not ENKRYPT_MCP_USE_EXTERNAL_CACHE:
        local_key_map[key] = id
        return

    if cache_client is None:
        return

    cache_client.setex(key, expires_in_seconds, id)
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[external_cache] Cached key mapping with key 'gateway_key-****{gateway_key[-4:]}' (hash: {key})")


def get_id_from_key(cache_client, gateway_key):
    """
    Retrieves the gateway/user ID associated with a key.

    Args:
        cache_client: The cache client instance
        gateway_key (str): The key for gateway/user

    Returns:
        str: The associated gateway/user ID if found, None otherwise
    """
    key = get_hashed_key(gateway_key)
    if not ENKRYPT_MCP_USE_EXTERNAL_CACHE:
        return local_key_map.get(key)

    if cache_client is None:
        return None

    id = cache_client.get(key)
    if id:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[external_cache] Found id for key with hash: {key}")
    return id


def clear_cache_for_servers(cache_client, id, server_name=None):
    """
    Clears tool cache for specific or all servers for a gateway/user.

    Args:
        cache_client: The cache client instance
        id (str): ID of the Gateway or User
        server_name (str, optional): Name of the server to clear cache for

    Returns:
        int: Number of cache entries cleared
    """
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[clear_cache_for_servers] Clearing cache for servers for gateway/user: {id} with current local_server_registry: {local_server_registry}")

    count = 0
    # Local cache clear
    if server_name:
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[clear_cache_for_servers] Clearing cache for server: {server_name}")
        key = get_server_hashed_key(id, server_name)
        if key in local_cache:
            del local_cache[key]
            count += 1
            if id in local_server_registry:
                local_server_registry[id].discard(server_name)
    else:
        if IS_DEBUG_LOG_LEVEL:
            sys_print("[clear_cache_for_servers] Clearing cache for all servers for gateway/user")
        # Clear all servers for a gateway/user
        if id in local_server_registry:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[clear_cache_for_servers] Clearing cache for all servers for gateway/user found in local_server_registry: {id}")
            for server_name in list(local_server_registry[id]):
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(f"[clear_cache_for_servers] Clearing cache for server: {server_name}")
                key = get_server_hashed_key(id, server_name)
                if key in local_cache:
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(f"[clear_cache_for_servers] Clearing cache for server: {server_name} found in local_cache")
                    del local_cache[key]
                    count += 1
            local_server_registry[id].clear()
        else:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f"[clear_cache_for_servers] Clearing cache for all servers for gateway/user not found in local_server_registry: {id}")

    if cache_client is None:
        return count

    # External cache clear
    count = 0  # Resetting as it is external cache
    if server_name:
        key = get_server_hashed_key(id, server_name)
        if cache_client.exists(key):
            cache_client.delete(key)
            registry_key = get_gateway_servers_registry_hashed_key(id)
            cache_client.srem(registry_key, server_name)
            count += 1
        return count
    else:
        registry_key = get_gateway_servers_registry_hashed_key(id)
        servers = cache_client.smembers(registry_key) if cache_client.exists(registry_key) else []
        for server_name in servers:
            key = get_server_hashed_key(id, server_name)
            if cache_client.exists(key):
                cache_client.delete(key)
                count += 1
        cache_client.delete(registry_key)
        return count


def clear_gateway_config_cache(cache_client, id, gateway_key):
    """
    Clears all cache entries for a gateway/user, including config, tools, and key mapping.

    Args:
        cache_client: The cache client instance
        id (str): ID of the Gateway or User
        gateway_key (str): The gateway/user's key

    Returns:
        bool: True if any cache entries were cleared
    """
    if IS_DEBUG_LOG_LEVEL:
        sys_print("[clear_gateway_config_cache] Clearing all cache entries for gateway/user")
    # 1. Clear all tool caches for the gateway/user
    registry_key = get_gateway_servers_registry_hashed_key(id)
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[clear_gateway_config_cache] Clearing all tool caches for gateway/user: {id} with registry key: {registry_key}")
    servers = cache_client.smembers(registry_key) if cache_client and cache_client.exists(registry_key) else []
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"[clear_gateway_config_cache] Clearing all tool caches for gateway/user: {id} with servers: {servers}")
    for server_name in servers:
        tool_key = get_server_hashed_key(id, server_name)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"[clear_gateway_config_cache] Clearing tool cache for server: {server_name} with tool_key: {tool_key}")
        if cache_client and cache_client.exists(tool_key):
            cache_client.delete(tool_key)
    if cache_client and cache_client.exists(registry_key):
        cache_client.delete(registry_key)

    # 2. Clear gateway config cache (local and external cache)
    config_key = get_gateway_config_hashed_key(id)
    if config_key in local_cache:
        del local_cache[config_key]
        local_gateway_config_registry.discard(id)
    if cache_client and cache_client.exists(config_key):
        cache_client.delete(config_key)

    # 3. Remove key mapping if gateway_key is provided
    if gateway_key:
        gateway_key_hash = get_hashed_key(gateway_key)
        if cache_client and cache_client.exists(gateway_key_hash):
            cache_client.delete(gateway_key_hash)
        if gateway_key_hash in local_key_map:
            del local_key_map[gateway_key_hash]

    # 4. Remove gateway/user from gateway/user registry (local and external cache)
    if cache_client:
        gateway_registry = get_gateway_registry_hashed_key()
        cache_client.srem(gateway_registry, id)
    local_server_registry.pop(id, None)

    return True


def get_cache_statistics(cache_client):
    """
    Retrieves statistics about the current cache state.

    Args:
        cache_client: The cache client instance

    Returns:
        dict: Cache statistics including:
            - total_gateways: Number of gateway/users in cache
            - total_tool_caches: Number of tool caches
            - total_config_caches: Number of config caches
            - cache_type: Type of cache being used
    """
    if not ENKRYPT_MCP_USE_EXTERNAL_CACHE:
        total_gateways = len(local_gateway_config_registry)
        total_tool_caches = sum(len(s) for s in local_server_registry.values())
        total_config_caches = len(local_gateway_config_registry)
        return {
            "total_gateways": total_gateways,
            "total_tool_caches": total_tool_caches,
            "total_config_caches": total_config_caches,
            "cache_type": "local"
        }

    if cache_client is None:
        return {
            "total_gateways": 0,
            "total_tool_caches": 0,
            "total_config_caches": 0,
            "cache_type": "none"
        }

    gateway_registry = get_gateway_registry_hashed_key()
    total_gateways = cache_client.scard(gateway_registry)
    total_tool_caches = 0
    total_config_caches = 0
    gateways = cache_client.smembers(gateway_registry)
    for id in gateways:
        config_key = get_gateway_config_hashed_key(id)
        if cache_client.exists(config_key):
            total_config_caches += 1
        servers_registry = get_gateway_servers_registry_hashed_key(id)
        if cache_client.exists(servers_registry):
            server_count = cache_client.scard(servers_registry)
            total_tool_caches += server_count
    return {
        "total_gateways": total_gateways,
        "total_tool_caches": total_tool_caches,
        "total_config_caches": total_config_caches,
        "cache_type": "external_cache"
    }

# Cleanup function for graceful shutdown
async def cleanup_client_module():
    """Clean up resources when shutting down."""
    await close_auth_http_session()
