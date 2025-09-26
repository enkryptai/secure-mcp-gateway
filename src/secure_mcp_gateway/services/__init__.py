"""
Enkrypt Secure MCP Gateway Services Module

This module contains all the service classes and utilities for the Enkrypt Secure MCP Gateway.
"""

# Import only the logger from telemetry_service to avoid circular imports
from secure_mcp_gateway.services.telemetry_service import logger


# Use lazy imports for other services to avoid circular dependencies
def get_auth_service():
    from secure_mcp_gateway.services.auth_service import auth_service

    return auth_service


def get_cache_service():
    from secure_mcp_gateway.services.cache_service import cache_service

    return cache_service


def get_cache_management_service():
    from secure_mcp_gateway.services.cache_management_service import (
        cache_management_service,
    )

    return cache_management_service


def get_cache_status_service():
    from secure_mcp_gateway.services.cache_status_service import cache_status_service

    return cache_status_service


def get_discovery_service():
    from secure_mcp_gateway.services.discovery_service import discovery_service

    return discovery_service


def get_guardrail_service():
    from secure_mcp_gateway.services.guardrail_service import guardrail_service

    return guardrail_service


def get_secure_tool_execution_service():
    from secure_mcp_gateway.services.secure_tool_execution_service import (
        secure_tool_execution_service,
    )

    return secure_tool_execution_service


def get_server_info_service():
    from secure_mcp_gateway.services.server_info_service import server_info_service

    return server_info_service


def get_server_listing_service():
    from secure_mcp_gateway.services.server_listing_service import (
        server_listing_service,
    )

    return server_listing_service


def get_telemetry_service():
    from secure_mcp_gateway.services.telemetry_service import telemetry_service

    return telemetry_service


def get_tool_execution_service():
    from secure_mcp_gateway.services.tool_execution_service import (
        tool_execution_service,
    )

    return tool_execution_service


__all__ = [
    "logger",
    "get_auth_service",
    "get_cache_service",
    "get_cache_management_service",
    "get_cache_status_service",
    "get_discovery_service",
    "get_guardrail_service",
    "get_secure_tool_execution_service",
    "get_server_info_service",
    "get_server_listing_service",
    "get_telemetry_service",
    "get_tool_execution_service",
]
