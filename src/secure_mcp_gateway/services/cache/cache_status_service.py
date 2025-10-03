from __future__ import annotations

import time
from typing import Any

from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import (
    ENKRYPT_GATEWAY_CACHE_EXPIRATION,
    ENKRYPT_MCP_USE_EXTERNAL_CACHE,
    ENKRYPT_TOOL_CACHE_EXPIRATION,
    cache_service,
)

# Get tracer from telemetry manager
telemetry_manager = get_telemetry_config_manager()
tracer = telemetry_manager.get_tracer()
from secure_mcp_gateway.utils import (
    IS_DEBUG_LOG_LEVEL,
    build_log_extra,
    generate_custom_id,
    get_server_info_by_name,
    mask_key,
    mask_sensitive_env_vars,
    sys_print,
)


class CacheStatusService:
    """
    Handles cache status retrieval operations.

    This service encapsulates the complex cache status logic from enkrypt_get_cache_status
    while maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        self.auth_manager = get_auth_config_manager()
        self.cache_service = cache_service

    async def get_cache_status(self, ctx, logger=None) -> dict[str, Any]:
        """
        Gets the current status of the tool cache for the servers whose tools are empty {}
        for which tools were discovered. This does not have the servers whose tools are
        explicitly defined in the MCP config in which case discovery is not needed.

        Args:
            ctx: The MCP context
            logger: Logger instance

        Returns:
            dict: Cache status containing:
                - status: Success/error status
                - cache_status: Detailed cache statistics and status
        """
        with tracer.start_as_current_span("cache_status.get_cache_status") as main_span:
            try:
                sys_print("[get_cache_status] Request received")
                custom_id = generate_custom_id()
                main_span.set_attribute("request_id", ctx.request_id)
                main_span.set_attribute("custom_id", custom_id)

                # Authentication and setup
                auth_result = await self._authenticate_and_setup(
                    ctx, custom_id, main_span, logger
                )
                if auth_result.get("status") != "success":
                    return auth_result

                session_key = auth_result["session_key"]
                id = auth_result["id"]

                # Get cache statistics
                cache_status = await self._get_cache_statistics(
                    ctx, custom_id, main_span, logger
                )

                # Check gateway config cache
                await self._check_gateway_config_cache(
                    ctx, custom_id, id, cache_status, main_span, logger
                )

                # Check server tools cache
                await self._check_server_tools_cache(
                    ctx, custom_id, id, session_key, cache_status, main_span, logger
                )

                # Set final span attributes
                main_span.set_attribute("success", True)

                sys_print(
                    f"[get_cache_status] Returning cache status for Gateway or User {id}",
                    is_debug=True,
                )
                return {"status": "success", "cache_status": cache_status}

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))
                sys_print(f"[get_cache_status] Critical error: {e}", is_error=True)
                logger.error(
                    "cache_status.get_cache_status.critical_error",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                raise

    async def _authenticate_and_setup(self, ctx, custom_id, main_span, logger):
        """Handle authentication and setup for cache status operations."""
        with tracer.start_as_current_span("cache_status.authenticate") as auth_span:
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            enkrypt_project_id = credentials.get("project_id", "not_provided")
            enkrypt_user_id = credentials.get("user_id", "not_provided")

            gateway_config = self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
            )

            if not gateway_config:
                sys_print(
                    f"[enkrypt_get_cache_status] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": "No MCP config found. Please check your credentials.",
                }

            enkrypt_project_name = gateway_config.get("project_name", "not_provided")
            enkrypt_email = gateway_config.get("email", "not_provided")
            enkrypt_mcp_config_id = gateway_config.get("mcp_config_id", "not_provided")

            # Set span attributes
            auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
            auth_span.set_attribute("enkrypt_project_id", enkrypt_project_id)
            auth_span.set_attribute("enkrypt_user_id", enkrypt_user_id)
            auth_span.set_attribute("enkrypt_mcp_config_id", enkrypt_mcp_config_id)
            auth_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            auth_span.set_attribute("enkrypt_email", enkrypt_email)

            session_key = f"{credentials.get('gateway_key')}_{credentials.get('project_id')}_{credentials.get('user_id')}_{enkrypt_mcp_config_id}"

            if not self.auth_manager.is_session_authenticated(session_key):
                auth_span.set_attribute("requires_auth", True)
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                if result.get("status") != "success":
                    auth_span.set_attribute("error", "Authentication failed")
                    sys_print("[get_cache_status] Not authenticated", is_error=True)
                    logger.error(
                        "cache_status.get_cache_status.not_authenticated",
                        extra=build_log_extra(
                            ctx, custom_id, error="Not authenticated."
                        ),
                    )
                    return {"status": "error", "error": "Not authenticated."}
            else:
                auth_span.set_attribute("requires_auth", False)

            id = self.auth_manager.get_session_gateway_config(session_key)["id"]
            main_span.set_attribute("gateway_id", id)

            return {
                "status": "success",
                "session_key": session_key,
                "id": id,
            }

    async def _get_cache_statistics(self, ctx, custom_id, main_span, logger):
        """Get global cache statistics."""
        with tracer.start_as_current_span(
            "cache_status.get_cache_statistics"
        ) as stats_span:
            sys_print("[get_cache_status] Getting cache statistics")
            stats = self.cache_service.get_cache_statistics()
            stats_span.set_attribute("total_gateways", stats.get("total_gateways", 0))
            stats_span.set_attribute(
                "total_tool_caches", stats.get("total_tool_caches", 0)
            )
            stats_span.set_attribute(
                "total_config_caches", stats.get("total_config_caches", 0)
            )
            stats_span.set_attribute("cache_type", stats.get("cache_type", "unknown"))

            logger.info(
                "cache_status.get_cache_status.getting_cache_statistics",
                extra=build_log_extra(ctx, custom_id, stats=stats),
            )

            return {
                "gateway_specific": {"config": {"exists": False}},
                "global": {
                    "total_gateways": stats.get("total_gateways", 0),
                    "total_tool_caches": stats.get("total_tool_caches", 0),
                    "total_config_caches": stats.get("total_config_caches", 0),
                    "tool_cache_expiration_hours": ENKRYPT_TOOL_CACHE_EXPIRATION,
                    "config_cache_expiration_hours": ENKRYPT_GATEWAY_CACHE_EXPIRATION,
                    "cache_type": stats.get("cache_type", "unknown"),
                },
            }

    async def _check_gateway_config_cache(
        self, ctx, custom_id, id, cache_status, main_span, logger
    ):
        """Check gateway config cache status."""
        with tracer.start_as_current_span(
            "cache_status.check_gateway_config_cache"
        ) as config_span:
            config_span.set_attribute("gateway_id", id)

            sys_print(
                f"[get_cache_status] Getting gateway config for Gateway or User {id}"
            )
            logger.info(
                "cache_status.get_cache_status.getting_gateway_config",
                extra=build_log_extra(ctx, custom_id, id=id),
            )

            cached_result = self.cache_service.get_cached_gateway_config(id)
            if cached_result:
                from secure_mcp_gateway.plugins.telemetry import (
                    get_telemetry_config_manager,
                )

                telemetry_mgr = get_telemetry_config_manager()
                telemetry_mgr.cache_hit_counter.add(
                    1, attributes=build_log_extra(ctx, custom_id)
                )

                # Handle both tuple (local cache) and non-tuple (external cache) returns
                if isinstance(cached_result, tuple) and len(cached_result) == 2:
                    gateway_config, expires_at = cached_result
                else:
                    # External cache returns just the config data - query TTL from Redis
                    gateway_config = cached_result
                    if ENKRYPT_MCP_USE_EXTERNAL_CACHE:
                        # Get the hashed key for the gateway config
                        config_key = self.cache_service.get_gateway_config_hashed_key(
                            id
                        )
                        ttl_seconds, expires_at = self.cache_service.get_redis_ttl(
                            config_key
                        )
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(
                                f"[get_cache_status] Redis TTL for gateway config: ttl_seconds={ttl_seconds}, expires_at={expires_at}",
                                is_debug=True,
                            )
                    else:
                        expires_at = None

                config_span.set_attribute("cache_hit", True)
                config_span.set_attribute("expires_at", expires_at)
                if expires_at:
                    config_span.set_attribute(
                        "expires_in_hours", (expires_at - time.time()) / 3600
                    )
                else:
                    config_span.set_attribute("expires_in_hours", None)

                if IS_DEBUG_LOG_LEVEL:
                    sys_print(
                        f"[get_cache_status] Cached gateway config: {gateway_config}",
                        is_debug=True,
                    )
                    logger.info(
                        "cache_status.get_cache_status.cached_gateway_config",
                        extra=build_log_extra(
                            ctx, custom_id, id=id, gateway_config=gateway_config
                        ),
                    )

                cache_status["gateway_specific"]["config"] = {
                    "exists": True,
                    "expires_at": expires_at,
                    "expires_in_hours": (expires_at - time.time()) / 3600
                    if expires_at
                    else None,
                    "is_expired": False,
                }
            else:
                from secure_mcp_gateway.plugins.telemetry import (
                    get_telemetry_config_manager,
                )

                telemetry_mgr = get_telemetry_config_manager()
                telemetry_mgr.cache_miss_counter.add(1, attributes=build_log_extra(ctx))
                config_span.set_attribute("cache_hit", False)

                sys_print(
                    f"[get_cache_status] No cached gateway config found for {id}",
                    is_debug=True,
                )
                logger.info(
                    "cache_status.get_cache_status.no_cached_gateway_config_found",
                    extra=build_log_extra(ctx, custom_id, id=id),
                )

                cache_status["gateway_specific"]["config"] = {
                    "exists": False,
                    "expires_at": None,
                    "expires_in_hours": None,
                    "is_expired": True,
                }

    async def _check_server_tools_cache(
        self, ctx, custom_id, id, session_key, cache_status, main_span, logger
    ):
        """Check server tools cache status."""
        with tracer.start_as_current_span(
            "cache_status.check_server_tools_cache"
        ) as servers_span:
            sys_print("[get_cache_status] Getting server cache status", is_debug=True)
            logger.info(
                "cache_status.get_cache_status.getting_server_cache_status",
                extra=build_log_extra(ctx, custom_id, id=id),
            )

            mcp_config = self.auth_manager.get_session_gateway_config(session_key).get(
                "mcp_config", []
            )
            servers_span.set_attribute("total_servers", len(mcp_config))

            if IS_DEBUG_LOG_LEVEL:
                # Mask sensitive data in debug logs
                masked_mcp_config = []
                for server in mcp_config:
                    masked_server = server.copy()
                    if "config" in masked_server and "env" in masked_server["config"]:
                        masked_server["config"] = masked_server["config"].copy()
                        masked_server["config"]["env"] = mask_sensitive_env_vars(
                            masked_server["config"]["env"]
                        )
                    masked_mcp_config.append(masked_server)
                sys_print(f"mcp_configs: {masked_mcp_config}", is_debug=True)
                logger.info(
                    "cache_status.get_cache_status.mcp_configs",
                    extra=build_log_extra(ctx, custom_id, mcp_configs=mcp_config),
                )

            # Get local gateway config for tool definitions
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            local_gateway_config = self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key
            )
            if not local_gateway_config:
                sys_print(
                    f"[enkrypt_get_cache_status] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": "No MCP config found. Please check your credentials.",
                }

            if IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"local gateway_config: {local_gateway_config}", is_debug=True
                )
                logger.info(
                    "cache_status.get_cache_status.local_gateway_config",
                    extra=build_log_extra(
                        ctx, custom_id, local_gateway_config=local_gateway_config
                    ),
                )

            servers_cache = {}
            cached_servers = 0
            servers_need_discovery = 0

            for server_info in mcp_config:
                server_name = server_info["server_name"]
                server_result = await self._check_single_server_cache(
                    ctx, custom_id, id, server_name, local_gateway_config, servers_span
                )

                servers_cache[server_name] = server_result
                if server_result["exists"]:
                    cached_servers += 1
                if server_result["needs_discovery"]:
                    servers_need_discovery += 1

            servers_span.set_attribute("cached_servers", cached_servers)
            servers_span.set_attribute("servers_need_discovery", servers_need_discovery)

            cache_status["gateway_specific"]["tools"] = {
                "server_count": len(servers_cache),
                "servers": servers_cache,
            }

            # Set final span attributes
            main_span.set_attribute("total_servers", len(mcp_config))
            main_span.set_attribute("cached_servers", cached_servers)
            main_span.set_attribute("servers_need_discovery", servers_need_discovery)

    async def _check_single_server_cache(
        self, ctx, custom_id, id, server_name, local_gateway_config, parent_span
    ):
        """Check cache status for a single server."""
        with tracer.start_as_current_span(
            f"cache_status.check_server_cache_{server_name}"
        ) as server_span:
            server_span.set_attribute("server_name", server_name)
            server_span.set_attribute("gateway_id", id)

            if IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[get_cache_status] Getting tool cache for server: {server_name}",
                    is_debug=True,
                )

            cached_result = self.cache_service.get_cached_tools(id, server_name)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[get_cache_status] Cached result: {cached_result}", is_debug=True
                )

            if cached_result:
                # Handle both tuple (local cache) and non-tuple (external cache) returns
                if isinstance(cached_result, tuple) and len(cached_result) == 2:
                    tools, expires_at = cached_result
                else:
                    # External cache returns just the tools data - query TTL from Redis
                    tools = cached_result
                    if ENKRYPT_MCP_USE_EXTERNAL_CACHE:
                        # Get the hashed key for the server tools
                        tools_key = self.cache_service.get_server_hashed_key(
                            id, server_name
                        )
                        ttl_seconds, expires_at = self.cache_service.get_redis_ttl(
                            tools_key
                        )
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(
                                f"[get_cache_status] Redis TTL for {server_name}: ttl_seconds={ttl_seconds}, expires_at={expires_at}",
                                is_debug=True,
                            )
                    else:
                        expires_at = None

                server_span.set_attribute("cache_hit", True)
                server_span.set_attribute("expires_at", expires_at)
                if expires_at:
                    server_span.set_attribute(
                        "expires_in_hours", (expires_at - time.time()) / 3600
                    )
                else:
                    server_span.set_attribute("expires_in_hours", None)

                tool_count = self._count_tools(tools, server_name)

                return {
                    "tool_count": tool_count if tool_count is not None else 0,
                    "error": "Unknown tool format" if tool_count is None else None,
                    "are_tools_explicitly_defined": False,
                    "needs_discovery": False,
                    "exists": True,
                    "expires_at": expires_at,
                    "expires_in_hours": (expires_at - time.time()) / 3600
                    if expires_at
                    else None,
                    "is_expired": False,
                }
            else:
                server_span.set_attribute("cache_hit", False)
                needs_discovery = True
                are_tools_explicitly_defined = False

                if local_gateway_config:
                    local_server_info = get_server_info_by_name(
                        local_gateway_config, server_name
                    )
                    if local_server_info and "tools" in local_server_info:
                        if IS_DEBUG_LOG_LEVEL:
                            sys_print(
                                f"[get_cache_status] Server {server_name} tools are defined in the local gateway config",
                                is_debug=True,
                            )
                        are_tools_explicitly_defined = True
                        needs_discovery = False

                server_span.set_attribute(
                    "explicitly_defined", are_tools_explicitly_defined
                )
                server_span.set_attribute("needs_discovery", needs_discovery)

                return {
                    "tool_count": 0,
                    "error": None,
                    "are_tools_explicitly_defined": are_tools_explicitly_defined,
                    "needs_discovery": needs_discovery,
                    "exists": False,
                    "expires_at": None,
                    "expires_in_hours": None,
                    "is_expired": True,
                }

    def _count_tools(self, tools, server_name):
        """Count tools in various formats."""
        if IS_DEBUG_LOG_LEVEL:
            sys_print(
                f"[get_cache_status] Tools found for server: {server_name}",
                is_debug=True,
            )

        # Handle ListToolsResult format
        if hasattr(tools, "tools") and isinstance(tools.tools, list):
            return len(tools.tools)
        # Handle dictionary with "tools" list
        elif (
            isinstance(tools, dict)
            and "tools" in tools
            and isinstance(tools["tools"], list)
        ):
            return len(tools["tools"])
        # Handle flat dictionary format
        elif isinstance(tools, dict):
            return len(tools)
        else:
            sys_print(
                f"[get_cache_status] ERROR: Unknown tool format for server: {server_name} - type: {type(tools)}",
                is_error=True,
            )
            return None
