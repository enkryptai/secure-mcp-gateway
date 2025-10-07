"""
Enkrypt Secure MCP Gateway Services Module

This module contains all the service classes and utilities for the Enkrypt Secure MCP Gateway.
"""

# Import logger from telemetry plugin manager to avoid circular imports
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager

# Get logger from telemetry manager
try:
    _telemetry_manager = get_telemetry_config_manager()
    logger = _telemetry_manager.get_logger()
except Exception:
    # Fallback to no-op logger if telemetry manager is not available
    class NoOpLogger:
        def info(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def debug(self, *args, **kwargs):
            pass

    logger = NoOpLogger()


# Use lazy imports for other services to avoid circular dependencies
def get_cache_service():
    from secure_mcp_gateway.services.cache import cache_service

    return cache_service


def get_cache_management_service():
    from secure_mcp_gateway.services.cache import get_cache_management_service as _get

    return _get()


def get_cache_status_service():
    from secure_mcp_gateway.services.cache import get_cache_status_service as _get

    return _get()


def get_discovery_service():
    from secure_mcp_gateway.services.discovery import discovery_service

    return discovery_service


def get_secure_tool_execution_service():
    from secure_mcp_gateway.services.execution import SecureToolExecutionService

    return SecureToolExecutionService()


def get_server_info_service():
    from secure_mcp_gateway.services.server import ServerInfoService

    return ServerInfoService()


def get_server_listing_service():
    from secure_mcp_gateway.services.server import ServerListingService

    return ServerListingService()


def get_telemetry_service():
    from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager

    telemetry_manager = get_telemetry_config_manager()
    return {
        "logger": telemetry_manager.get_logger(),
        "tracer": telemetry_manager.get_tracer(),
        "meter": telemetry_manager.get_meter(),
    }


def get_tool_execution_service():
    from secure_mcp_gateway.services.execution import ToolExecutionService

    return ToolExecutionService()


__all__ = [
    "logger",
    "get_cache_service",
    "get_cache_management_service",
    "get_cache_status_service",
    "get_discovery_service",
    "get_secure_tool_execution_service",
    "get_server_info_service",
    "get_server_listing_service",
    "get_telemetry_service",
    "get_tool_execution_service",
]
