"""OAuth token lifecycle management with caching."""

import asyncio
from datetime import datetime
from typing import Dict, Optional

from secure_mcp_gateway.services.oauth.models import (
    OAuthConfig,
    OAuthToken,
    TokenStatus,
)
from secure_mcp_gateway.utils import logger


class TokenManager:
    """
    Manages OAuth token lifecycle with caching and refresh.

    Features:
    - Token caching per server
    - Automatic token refresh before expiry
    - Thread-safe token access
    - Token validation
    """

    def __init__(self):
        """Initialize token manager."""
        self._tokens: Dict[str, OAuthToken] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        logger.info("[TokenManager] Initialized")

    def _get_cache_key(
        self,
        server_name: str,
        config_id: str,
        project_id: str,
    ) -> str:
        """
        Generate cache key for token in format: project_id:mcp_config_id:server_name

        Args:
            server_name: Server name (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)

        Returns:
            Cache key in format project_id:mcp_config_id:server_name
        """
        return f"{project_id}:{config_id}:{server_name}"

    async def _get_lock(self, cache_key: str) -> asyncio.Lock:
        """
        Get or create lock for cache key.

        Args:
            cache_key: Cache key

        Returns:
            Lock instance
        """
        if cache_key not in self._locks:
            self._locks[cache_key] = asyncio.Lock()
        return self._locks[cache_key]

    async def get_token(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
        config_id: str,
        project_id: str,
    ) -> Optional[OAuthToken]:
        """
        Get cached token if valid.

        Args:
            server_name: Server name (required)
            oauth_config: OAuth configuration (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)

        Returns:
            Token if cached and valid, None otherwise
        """
        cache_key = self._get_cache_key(server_name, config_id, project_id)
        lock = await self._get_lock(cache_key)

        async with lock:
            token = self._tokens.get(cache_key)

            if not token:
                logger.debug(f"[TokenManager] No cached token for {cache_key}")
                return None

            # Check if expired
            if token.is_expired:
                logger.info(f"[TokenManager] Token expired for {cache_key}")
                del self._tokens[cache_key]
                return None

            # Check if expiring soon
            if token.is_expiring_soon(oauth_config.token_expiry_buffer):
                logger.info(
                    f"[TokenManager] Token expiring soon for {cache_key}, "
                    f"expires at {token.expires_at}"
                )
                return None

            logger.debug(f"[TokenManager] Using cached token for {cache_key}")
            return token

    async def store_token(
        self,
        server_name: str,
        token: OAuthToken,
        config_id: str,
        project_id: str,
    ) -> None:
        """
        Store token in cache.

        Args:
            server_name: Server name (required)
            token: OAuth token (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)
        """
        cache_key = self._get_cache_key(server_name, config_id, project_id)
        lock = await self._get_lock(cache_key)

        async with lock:
            token.server_name = server_name
            token.config_id = config_id
            self._tokens[cache_key] = token

            logger.info(
                f"[TokenManager] Stored token for {cache_key}, "
                f"expires at {token.expires_at}"
            )

    async def invalidate_token(
        self,
        server_name: str,
        config_id: str,
        project_id: str,
    ) -> None:
        """
        Invalidate cached token.

        Args:
            server_name: Server name (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)
        """
        cache_key = self._get_cache_key(server_name, config_id, project_id)
        lock = await self._get_lock(cache_key)

        async with lock:
            if cache_key in self._tokens:
                del self._tokens[cache_key]
                logger.info(f"[TokenManager] Invalidated token for {cache_key}")

    async def clear_all_tokens(self) -> int:
        """
        Clear all cached tokens.

        Returns:
            Number of tokens cleared
        """
        count = len(self._tokens)
        self._tokens.clear()
        self._locks.clear()
        logger.info(f"[TokenManager] Cleared {count} cached tokens")
        return count

    async def cleanup_expired_tokens(self) -> int:
        """
        Remove all expired tokens from cache.

        Returns:
            Number of tokens removed
        """
        expired_keys = []

        # Create a snapshot to avoid dictionary changed size during iteration
        for cache_key, token in list(self._tokens.items()):
            if token.is_expired:
                expired_keys.append(cache_key)

        for key in expired_keys:
            lock = await self._get_lock(key)
            async with lock:
                if key in self._tokens:
                    del self._tokens[key]

        logger.info(f"[TokenManager] Cleaned up {len(expired_keys)} expired tokens")
        return len(expired_keys)

    def get_token_info(
        self,
        server_name: str,
        config_id: str,
        project_id: str,
    ) -> Optional[Dict]:
        """
        Get token information without lock (for debugging).

        Args:
            server_name: Server name (required)
            config_id: MCP config ID (required)
            project_id: Project ID (required)

        Returns:
            Token info dictionary or None
        """
        cache_key = self._get_cache_key(server_name, config_id, project_id)
        token = self._tokens.get(cache_key)

        if not token:
            return None

        return token.to_dict()

    def get_all_tokens_info(self) -> Dict[str, Dict]:
        """
        Get information about all cached tokens.

        Returns:
            Dictionary of cache_key -> token_info
        """
        return {key: token.to_dict() for key, token in self._tokens.items()}

    @property
    def token_count(self) -> int:
        """Get number of cached tokens."""
        return len(self._tokens)


# Global token manager instance
_token_manager: Optional[TokenManager] = None


def get_token_manager() -> TokenManager:
    """
    Get global token manager instance.

    Returns:
        TokenManager instance
    """
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
    return _token_manager


def reset_token_manager() -> None:
    """Reset global token manager (for testing)."""
    global _token_manager
    _token_manager = None
