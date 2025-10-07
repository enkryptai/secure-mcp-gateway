"""
Enkrypt Secure MCP Gateway Cache Module

This module contains caching services for the Enkrypt Secure MCP Gateway.
"""

# Only import the essentials at module level
from secure_mcp_gateway.services.cache.cache_service import (
    ENKRYPT_GATEWAY_CACHE_EXPIRATION,
    ENKRYPT_MCP_USE_EXTERNAL_CACHE,
    ENKRYPT_TOOL_CACHE_EXPIRATION,
    cache_client,
    cache_service,
)


# Use lazy imports for services that might cause circular dependencies
def get_cache_management_service():
    from secure_mcp_gateway.services.cache.cache_management_service import (
        CacheManagementService,
    )

    return CacheManagementService()


def get_cache_status_service():
    from secure_mcp_gateway.services.cache.cache_status_service import (
        CacheStatusService,
    )

    return CacheStatusService()


__all__ = [
    "cache_service",
    "cache_client",
    "ENKRYPT_TOOL_CACHE_EXPIRATION",
    "ENKRYPT_GATEWAY_CACHE_EXPIRATION",
    "ENKRYPT_MCP_USE_EXTERNAL_CACHE",
    "get_cache_management_service",
    "get_cache_status_service",
]
