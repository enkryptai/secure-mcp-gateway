# cache_service.py

import time
from typing import Any, Dict, List, Optional, Tuple, Union

from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager

# Get metrics from telemetry manager
telemetry_manager = get_telemetry_config_manager()
cache_hit_counter = telemetry_manager.cache_hit_counter
cache_miss_counter = telemetry_manager.cache_miss_counter
from secure_mcp_gateway.utils import (
    get_common_config,
    mask_key,
    sys_print,
)

# Get debug log level
common_config = get_common_config()
ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"


class CacheService:
    """
    Cache service for Enkrypt Secure MCP Gateway.
    Handles all caching operations including tool caching, gateway config caching, and cache management.
    """

    def __init__(self):
        """Initialize the cache service."""
        sys_print("Initializing Enkrypt Secure MCP Gateway Cache Service")

        # Get configuration
        self.common_config = get_common_config()

        # Cache configuration
        self.tool_cache_expiration = int(
            self.common_config.get("enkrypt_tool_cache_expiration", 4)
        )
        self.gateway_cache_expiration = int(
            self.common_config.get("enkrypt_gateway_cache_expiration", 24)
        )
        self.use_external_cache = self.common_config.get(
            "enkrypt_mcp_use_external_cache", False
        )

        # Initialize cache client
        self.cache_client = None
        self._initialize_cache()

        sys_print("Cache service initialized:")
        sys_print(f"  - Tool cache expiration: {self.tool_cache_expiration} hours")
        sys_print(
            f"  - Gateway cache expiration: {self.gateway_cache_expiration} hours"
        )
        sys_print(f"  - External cache enabled: {self.use_external_cache}")

    def _initialize_cache(self):
        """Initialize the cache client."""
        if self.use_external_cache:
            sys_print("Initializing External Cache connection")
            try:
                from secure_mcp_gateway.client import initialize_cache

                self.cache_client = initialize_cache()
                sys_print("[external_cache] Successfully connected to External Cache")
            except Exception as e:
                sys_print(
                    f"[external_cache] Failed to connect to External Cache: {e}",
                    is_error=True,
                )
                self.cache_client = None
        else:
            sys_print("External Cache is not enabled. Using local cache only.")
            self.cache_client = None

    def get_redis_ttl(self, key: str) -> tuple:
        """
        Get the TTL (Time To Live) for a Redis key.

        Args:
            key (str): Redis key to check

        Returns:
            tuple: (ttl_seconds, expires_at_timestamp) or (None, None) if key doesn't exist or no external cache
        """
        if not self.cache_client or not key:
            return None, None

        try:
            ttl_seconds = self.cache_client.ttl(key)
            if ttl_seconds == -1:
                # Key exists but has no expiration
                return None, None
            elif ttl_seconds == -2:
                # Key doesn't exist
                return None, None
            else:
                # Key exists and has expiration
                expires_at = time.time() + ttl_seconds
                return ttl_seconds, expires_at
        except Exception as e:
            sys_print(
                f"[get_redis_ttl] Error getting TTL for key {key}: {e}", is_error=True
            )
            return None, None

    def cache_tools(
        self, server_id: str, server_name: str, tools: List[Dict[str, Any]]
    ) -> bool:
        """
        Cache tools for a specific server.

        Args:
            server_id (str): Server ID
            server_name (str): Server name
            tools (List[Dict[str, Any]]): Tools to cache

        Returns:
            bool: True if caching was successful, False otherwise
        """
        try:
            from secure_mcp_gateway.client import cache_tools

            cache_tools(self.cache_client, server_id, server_name, tools)
            sys_print(f"[cache_tools] Successfully cached tools for {server_name}")
            return True
        except Exception as e:
            sys_print(
                f"[cache_tools] Failed to cache tools for {server_name}: {e}",
                is_error=True,
            )
            return False

    def get_cached_tools(
        self, server_id: str, server_name: str
    ) -> Optional[Union[List[Dict[str, Any]], Tuple[List[Dict[str, Any]], str]]]:
        """
        Get cached tools for a specific server.

        Args:
            server_id (str): Server ID
            server_name (str): Server name

        Returns:
            Optional[Union[List[Dict[str, Any]], Tuple[List[Dict[str, Any]], str]]]:
                Cached tools or tuple of (tools, expires_at), or None if not found
        """
        try:
            from secure_mcp_gateway.client import get_cached_tools

            return get_cached_tools(self.cache_client, server_id, server_name)
        except Exception as e:
            sys_print(
                f"[get_cached_tools] Failed to get cached tools for {server_name}: {e}",
                is_error=True,
            )
            return None

    def cache_gateway_config(self, gateway_id: str, config: Dict[str, Any]) -> bool:
        """
        Cache gateway configuration.

        Args:
            gateway_id (str): Gateway ID
            config (Dict[str, Any]): Configuration to cache

        Returns:
            bool: True if caching was successful, False otherwise
        """
        try:
            from secure_mcp_gateway.client import cache_gateway_config

            cache_gateway_config(self.cache_client, gateway_id, config)
            sys_print(
                f"[cache_gateway_config] Successfully cached gateway config for {gateway_id}"
            )
            return True
        except Exception as e:
            sys_print(
                f"[cache_gateway_config] Failed to cache gateway config for {gateway_id}: {e}",
                is_error=True,
            )
            return False

    def get_cached_gateway_config(
        self, gateway_id: str
    ) -> Optional[Union[Dict[str, Any], Tuple[Dict[str, Any], str]]]:
        """
        Get cached gateway configuration.

        Args:
            gateway_id (str): Gateway ID

        Returns:
            Optional[Union[Dict[str, Any], Tuple[Dict[str, Any], str]]]:
                Cached config or tuple of (config, expires_at), or None if not found
        """
        try:
            from secure_mcp_gateway.client import get_cached_gateway_config

            return get_cached_gateway_config(self.cache_client, gateway_id)
        except Exception as e:
            sys_print(
                f"[get_cached_gateway_config] Failed to get cached gateway config for {gateway_id}: {e}",
                is_error=True,
            )
            return None

    def clear_cache_for_servers(self, id: str, server_name: str = None) -> int:
        """
        Clear cache for specific servers.

        Args:
            id (str): Gateway/User ID
            server_name (str, optional): Name of the server to clear cache for. If None, clears all servers.

        Returns:
            int: Number of cache entries cleared
        """
        try:
            from secure_mcp_gateway.client import clear_cache_for_servers

            count = clear_cache_for_servers(self.cache_client, id, server_name)
            sys_print(
                f"[clear_cache_for_servers] Successfully cleared {count} cache entries for id={id}, server_name={server_name}"
            )
            return count
        except Exception as e:
            sys_print(
                f"[clear_cache_for_servers] Failed to clear cache for id={id}, server_name={server_name}: {e}",
                is_error=True,
            )
            return 0

    def clear_gateway_config_cache(self, id: str, gateway_key: str) -> bool:
        """
        Clear gateway configuration cache.

        Args:
            id (str): Gateway/User ID
            gateway_key (str): Gateway key to clear cache for

        Returns:
            bool: True if clearing was successful, False otherwise
        """
        try:
            from secure_mcp_gateway.client import clear_gateway_config_cache

            result = clear_gateway_config_cache(self.cache_client, id, gateway_key)
            sys_print(
                f"[clear_gateway_config_cache] Successfully cleared gateway config cache for id={id}, gateway_key={mask_key(gateway_key)}"
            )
            return result
        except Exception as e:
            sys_print(
                f"[clear_gateway_config_cache] Failed to clear gateway config cache for id={id}, gateway_key={mask_key(gateway_key)}: {e}",
                is_error=True,
            )
            return False

    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict[str, Any]: Cache statistics including total caches, cache type, etc.
        """
        try:
            from secure_mcp_gateway.client import get_cache_statistics

            return get_cache_statistics(self.cache_client)
        except Exception as e:
            sys_print(
                f"[get_cache_statistics] Failed to get cache statistics: {e}",
                is_error=True,
            )
            return {
                "total_tool_caches": 0,
                "total_config_caches": 0,
                "cache_type": "error",
                "error": str(e),
            }

    def get_server_hashed_key(self, id: str, server_name: str) -> str:
        """
        Get hashed key for a server.

        Args:
            id (str): Gateway/User ID
            server_name (str): Server name

        Returns:
            str: Hashed key for the server
        """
        try:
            from secure_mcp_gateway.client import get_server_hashed_key

            return get_server_hashed_key(id, server_name)
        except Exception as e:
            sys_print(
                f"[get_server_hashed_key] Failed to get hashed key for {server_name}: {e}",
                is_error=True,
            )
            return ""

    def get_gateway_config_hashed_key(self, gateway_key: str) -> str:
        """
        Get hashed key for gateway configuration.

        Args:
            gateway_key (str): Gateway key

        Returns:
            str: Hashed key for the gateway configuration
        """
        try:
            from secure_mcp_gateway.client import get_gateway_config_hashed_key

            return get_gateway_config_hashed_key(gateway_key)
        except Exception as e:
            sys_print(
                f"[get_gateway_config_hashed_key] Failed to get hashed key for gateway: {e}",
                is_error=True,
            )
            return ""

    def get_id_from_key(self, key: str) -> str:
        """
        Get ID from a cache key.

        Args:
            key (str): Cache key

        Returns:
            str: ID extracted from the key
        """
        try:
            from secure_mcp_gateway.client import get_id_from_key

            return get_id_from_key(key)
        except Exception as e:
            sys_print(
                f"[get_id_from_key] Failed to get ID from key: {e}", is_error=True
            )
            return ""

    def cache_key_to_id(self, key: str) -> str:
        """
        Convert cache key to ID.

        Args:
            key (str): Cache key

        Returns:
            str: ID from the cache key
        """
        try:
            from secure_mcp_gateway.client import cache_key_to_id

            return cache_key_to_id(key)
        except Exception as e:
            sys_print(
                f"[cache_key_to_id] Failed to convert key to ID: {e}", is_error=True
            )
            return ""

    def is_cache_available(self) -> bool:
        """
        Check if cache is available.

        Returns:
            bool: True if cache is available, False otherwise
        """
        return self.cache_client is not None

    def get_cache_type(self) -> str:
        """
        Get the type of cache being used.

        Returns:
            str: Cache type ('external', 'local', or 'none')
        """
        if self.use_external_cache and self.cache_client:
            return "external"
        elif not self.use_external_cache:
            return "local"
        else:
            return "none"

    def get_cache_config(self) -> Dict[str, Any]:
        """
        Get cache configuration.

        Returns:
            Dict[str, Any]: Cache configuration
        """
        return {
            "tool_cache_expiration_hours": self.tool_cache_expiration,
            "gateway_cache_expiration_hours": self.gateway_cache_expiration,
            "use_external_cache": self.use_external_cache,
            "cache_type": self.get_cache_type(),
            "cache_available": self.is_cache_available(),
        }

    def get_latest_server_info(self, server_info, id, cache_client):
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
            sys_print(
                f"[get_latest_server_info] Getting latest server info for {id}",
                is_debug=True,
            )
        server_info_copy = server_info.copy()
        config_tools = server_info_copy.get("tools", {})
        server_name = server_info_copy.get("server_name")
        sys_print(f"[get_latest_server_info] Server name: {server_name}")

        # If tools is empty {}, then we discover them
        if not config_tools:
            sys_print(
                f"[get_latest_server_info] No config tools found for {server_name}"
            )
            cached_tools = self.get_cached_tools(id, server_name)
            if cached_tools:
                cache_hit_counter.add(1)
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(
                        f"[get_latest_server_info] Found cached tools for {server_name}",
                        is_debug=True,
                    )
                server_info_copy["tools"] = cached_tools
                server_info_copy["has_cached_tools"] = True
                server_info_copy["tools_source"] = "cache"
            else:
                cache_miss_counter.add(1)
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(
                        f"[get_latest_server_info] No cached tools found for {server_name}. Need to discover them",
                        is_debug=True,
                    )
                server_info_copy["tools"] = {}
                server_info_copy["has_cached_tools"] = False
                server_info_copy["tools_source"] = "needs_discovery"
        else:
            if IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[get_latest_server_info] Tools defined in config already for {server_name}",
                    is_debug=True,
                )
            server_info_copy["tools_source"] = "config"
        return server_info_copy


# Global cache service instance
cache_service = CacheService()

# Export the cache client for backward compatibility
cache_client = cache_service.cache_client

# Export configuration constants for backward compatibility
ENKRYPT_TOOL_CACHE_EXPIRATION = cache_service.tool_cache_expiration
ENKRYPT_GATEWAY_CACHE_EXPIRATION = cache_service.gateway_cache_expiration
ENKRYPT_MCP_USE_EXTERNAL_CACHE = cache_service.use_external_cache
