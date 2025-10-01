from secure_mcp_gateway.services.discovery.discovery_service import DiscoveryService

# Module-level singleton instance (matches previous import expectations)
discovery_service = DiscoveryService()

__all__ = ["DiscoveryService", "discovery_service"]
