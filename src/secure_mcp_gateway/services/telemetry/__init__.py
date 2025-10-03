"""
Enkrypt Secure MCP Gateway Telemetry Module

DEPRECATED: This module is deprecated in favor of the plugin-based telemetry system.
Use: from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager

Legacy imports are maintained for backward compatibility but will be removed in a future version.
"""

# Legacy backward-compatible imports
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager

# Get telemetry components from plugin manager
telemetry_manager = get_telemetry_config_manager()

logger = telemetry_manager.get_logger()
tracer = telemetry_manager.get_tracer()
cache_hit_counter = telemetry_manager.cache_hit_counter
cache_miss_counter = telemetry_manager.cache_miss_counter
list_servers_call_count = telemetry_manager.list_servers_call_count
servers_discovered_count = telemetry_manager.servers_discovered_count

__all__ = [
    "logger",
    "tracer",
    "cache_hit_counter",
    "cache_miss_counter",
    "list_servers_call_count",
    "servers_discovered_count",
]
