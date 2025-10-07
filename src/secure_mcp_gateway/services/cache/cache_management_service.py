from __future__ import annotations

from typing import Any

import requests

from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import cache_service

# Get tracer from telemetry manager
telemetry_manager = get_telemetry_config_manager()
tracer = telemetry_manager.get_tracer()
from secure_mcp_gateway.utils import (
    build_log_extra,
    generate_custom_id,
    get_common_config,
    mask_key,
    sys_print,
)


class CacheManagementService:
    """
    Handles cache management operations including clearing various types of caches.

    This service encapsulates the complex cache clearing logic from enkrypt_clear_cache
    while maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        # Lazy import to avoid circular dependency
        from secure_mcp_gateway.plugins.auth import get_auth_config_manager

        self.auth_manager = get_auth_config_manager()
        self.cache_service = cache_service

        # Load configuration
        common_config = get_common_config()
        # Get API key and base URL from plugin configurations
        plugins_config = common_config.get("plugins", {})
        guardrails_config = plugins_config.get("guardrails", {}).get("config", {})
        auth_config = plugins_config.get("auth", {}).get("config", {})

        self.GUARDRAIL_API_KEY = guardrails_config.get(
            "api_key", auth_config.get("api_key", "null")
        )
        self.GUARDRAIL_URL = guardrails_config.get(
            "base_url", auth_config.get("base_url", "https://api.enkryptai.com")
        )
        self.ENKRYPT_USE_REMOTE_MCP_CONFIG = common_config.get(
            "enkrypt_use_remote_mcp_config", False
        )
        self.ENKRYPT_REMOTE_MCP_GATEWAY_NAME = common_config.get(
            "enkrypt_remote_mcp_gateway_name", "Test MCP Gateway"
        )
        self.ENKRYPT_REMOTE_MCP_GATEWAY_VERSION = common_config.get(
            "enkrypt_remote_mcp_gateway_version", "v1"
        )
        self.AUTH_SERVER_VALIDATE_URL = f"{self.GUARDRAIL_URL}/mcp-gateway/get-gateway"
        self.IS_DEBUG_LOG_LEVEL = (
            common_config.get("enkrypt_log_level", "INFO").lower() == "debug"
        )

    async def clear_cache(
        self,
        ctx,
        id: str | None = None,
        server_name: str | None = None,
        cache_type: str | None = None,
        logger=None,
    ) -> dict[str, Any]:
        """
        Clears various types of caches in the MCP Gateway.

        Args:
            ctx: The MCP context
            id: ID of the Gateway or User whose cache to clear
            server_name: Name of the server whose cache to clear
            cache_type: Type of cache to clear ('all', 'gateway_config', 'server_config')
            logger: Logger instance

        Returns:
            dict: Cache clearing result with status and message
        """
        with tracer.start_as_current_span("cache_management.clear_cache") as main_span:
            try:
                sys_print(
                    f"[clear_cache] Requested with id={id}, server_name={server_name}, cache_type={cache_type}"
                )
                custom_id = generate_custom_id()

                # Set main span attributes
                main_span.set_attribute("request_id", ctx.request_id)
                main_span.set_attribute("custom_id", custom_id)
                main_span.set_attribute("id", id or "not_provided")
                main_span.set_attribute("server_name", server_name or "not_provided")
                main_span.set_attribute("cache_type", cache_type or "not_provided")

                # Authentication and setup
                auth_result = await self._authenticate_and_setup(
                    ctx, custom_id, main_span, logger
                )
                if auth_result.get("status") != "success":
                    return auth_result

                session_key = auth_result["session_key"]
                enkrypt_gateway_key = auth_result["enkrypt_gateway_key"]
                id = auth_result["id"]

                # Determine cache type
                cache_type = self._determine_cache_type(cache_type, main_span)

                # Log the request
                sys_print(
                    f"[clear_cache] Gateway/User ID: {id}, Server Name: {server_name}, Cache Type: {cache_type}"
                )
                logger.info(
                    "cache_management.clear_cache.requested",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=id,
                        server_name=server_name,
                        cache_type=cache_type,
                    ),
                )

                # Route to appropriate cache clearing method
                if cache_type == "all":
                    return await self._clear_all_caches(
                        ctx,
                        custom_id,
                        id,
                        server_name,
                        enkrypt_gateway_key,
                        main_span,
                        logger,
                    )
                elif self._is_gateway_config_cache_type(cache_type):
                    return await self._clear_gateway_config_cache(
                        ctx,
                        custom_id,
                        id,
                        enkrypt_gateway_key,
                        cache_type,
                        main_span,
                        logger,
                    )
                else:
                    return await self._clear_server_cache(
                        ctx, custom_id, id, server_name, cache_type, main_span, logger
                    )

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))
                sys_print(f"[clear_cache] Critical error: {e}", is_error=True)
                logger.error(
                    "cache_management.clear_cache.critical_error",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                raise

    async def _authenticate_and_setup(self, ctx, custom_id, main_span, logger):
        """Handle authentication and setup for cache operations."""
        with tracer.start_as_current_span("cache_management.authenticate") as auth_span:
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            enkrypt_project_id = credentials.get("project_id", "not_provided")
            enkrypt_user_id = credentials.get("user_id", "not_provided")

            gateway_config = self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
            )

            if not gateway_config:
                sys_print(
                    f"[clear_cache] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}",
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
            auth_span.set_attribute("enkrypt_user_id", enkrypt_user_id)
            auth_span.set_attribute("enkrypt_mcp_config_id", enkrypt_mcp_config_id)
            auth_span.set_attribute("enkrypt_project_id", enkrypt_project_id)
            auth_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            auth_span.set_attribute("enkrypt_email", enkrypt_email)

            session_key = f"{credentials.get('gateway_key')}_{credentials.get('project_id')}_{credentials.get('user_id')}_{enkrypt_mcp_config_id}"

            if not self.auth_manager.is_session_authenticated(session_key):
                auth_span.set_attribute("requires_auth", True)
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                if result.get("status") != "success":
                    auth_span.set_attribute("error", "Authentication failed")
                    sys_print("[clear_cache] Not authenticated", is_error=True)
                    logger.error(
                        "cache_management.clear_cache.not_authenticated",
                        extra=build_log_extra(
                            ctx, custom_id, error="Not authenticated."
                        ),
                    )
                    return {"status": "error", "error": "Not authenticated."}
            else:
                auth_span.set_attribute("requires_auth", False)

            # Get default id from session if not provided
            id = self.auth_manager.get_session_gateway_config(session_key)["id"]
            main_span.set_attribute("id", id)

            return {
                "status": "success",
                "session_key": session_key,
                "enkrypt_gateway_key": enkrypt_gateway_key,
                "id": id,
            }

    def _determine_cache_type(self, cache_type, main_span):
        """Determine the cache type to clear."""
        with tracer.start_as_current_span(
            "cache_management.determine_cache_type"
        ) as type_span:
            if not cache_type:
                type_span.set_attribute("default_type", True)
                if self.IS_DEBUG_LOG_LEVEL:
                    sys_print(
                        "[clear_cache] No cache type provided. Defaulting to 'all'"
                    )
                cache_type = "all"
                main_span.set_attribute("cache_type", cache_type)
            else:
                type_span.set_attribute("default_type", False)

            type_span.set_attribute("cache_type", cache_type)
            return cache_type

    def _is_gateway_config_cache_type(self, cache_type):
        """Check if the cache type is for gateway config."""
        return cache_type in [
            "gateway_config",
            "gateway",
            "gateway_cache",
            "gateway_config_cache",
        ]

    async def _clear_all_caches(
        self, ctx, custom_id, id, server_name, enkrypt_gateway_key, main_span, logger
    ):
        """Clear all caches (tool + gateway config)."""
        with tracer.start_as_current_span(
            "cache_management.clear_all_caches"
        ) as all_span:
            try:
                all_span.set_attribute("id", id)
                all_span.set_attribute("server_name", server_name or "all")

                sys_print("[clear_cache] Clearing all caches")
                logger.info(
                    "cache_management.clear_cache.clearing_all_caches",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=id,
                        server_name=server_name,
                        cache_type="all",
                    ),
                )

                cleared_servers = self.cache_service.clear_cache_for_servers(id)
                cleared_gateway = self.cache_service.clear_gateway_config_cache(
                    id, enkrypt_gateway_key
                )

                all_span.set_attribute("cleared_servers_count", cleared_servers)
                all_span.set_attribute("gateway_config_cleared", cleared_gateway)

                # Refresh remote config if enabled
                if self.ENKRYPT_USE_REMOTE_MCP_CONFIG:
                    await self._refresh_remote_config(ctx, custom_id, all_span, logger)

                main_span.set_attribute("success", True)
                return {
                    "status": "success",
                    "message": f"Cache cleared for all servers ({cleared_servers} servers) and gateway config ({'cleared' if cleared_gateway else 'none'})",
                }

            except Exception as e:
                all_span.record_exception(e)
                all_span.set_attribute("error", str(e))
                raise

    async def _clear_gateway_config_cache(
        self, ctx, custom_id, id, enkrypt_gateway_key, cache_type, main_span, logger
    ):
        """Clear gateway config cache."""
        with tracer.start_as_current_span(
            "cache_management.clear_gateway_config"
        ) as config_span:
            try:
                config_span.set_attribute("id", id)
                config_span.set_attribute("cache_type", cache_type)

                sys_print("[clear_cache] Clearing gateway config cache")
                logger.info(
                    "cache_management.clear_cache.clearing_gateway_config_cache",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=id,
                        server_name=None,
                        cache_type=cache_type,
                    ),
                )

                cleared = self.cache_service.clear_gateway_config_cache(
                    id, enkrypt_gateway_key
                )
                config_span.set_attribute("cache_cleared", cleared)

                # Refresh remote config if enabled
                if self.ENKRYPT_USE_REMOTE_MCP_CONFIG:
                    await self._refresh_remote_config(
                        ctx, custom_id, config_span, logger
                    )

                if cleared:
                    logger.info(
                        "cache_management.clear_cache.gateway_config_cache_cleared",
                        extra=build_log_extra(
                            ctx,
                            custom_id,
                            id=id,
                            server_name=None,
                            cache_type=cache_type,
                        ),
                    )
                    main_span.set_attribute("success", True)
                    return {
                        "status": "success",
                        "message": f"Gateway config cache cleared for {id}",
                    }
                else:
                    logger.info(
                        "cache_management.clear_cache.no_config_cache_found",
                        extra=build_log_extra(
                            ctx,
                            custom_id,
                            id=id,
                            server_name=None,
                            cache_type=cache_type,
                        ),
                    )
                    main_span.set_attribute("success", True)
                    return {
                        "status": "info",
                        "message": f"No config cache found for {id}",
                    }

            except Exception as e:
                config_span.record_exception(e)
                config_span.set_attribute("error", str(e))
                raise

    async def _clear_server_cache(
        self, ctx, custom_id, id, server_name, cache_type, main_span, logger
    ):
        """Clear server cache (tool cache)."""
        with tracer.start_as_current_span(
            "cache_management.clear_server_cache"
        ) as server_span:
            try:
                server_span.set_attribute("id", id)
                server_span.set_attribute("server_name", server_name or "all")
                server_span.set_attribute("clear_specific_server", bool(server_name))

                sys_print("[clear_cache] Clearing server config cache")
                logger.info(
                    "cache_management.clear_cache.clearing_server_config_cache",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=id,
                        server_name=server_name,
                        cache_type=cache_type,
                    ),
                )

                # Clear tool cache for a specific server
                if server_name:
                    if self.IS_DEBUG_LOG_LEVEL:
                        sys_print(
                            f"[clear_cache] Clearing tool cache for server: {server_name}",
                            is_debug=True,
                        )
                        logger.info(
                            "cache_management.clear_cache.clearing_tool_cache_for_server",
                            extra=build_log_extra(
                                ctx,
                                custom_id,
                                id=id,
                                server_name=server_name,
                                cache_type=cache_type,
                            ),
                        )

                    cleared = self.cache_service.clear_cache_for_servers(
                        id, server_name
                    )
                    server_span.set_attribute("cache_cleared", cleared)
                    server_span.set_attribute("target_server", server_name)

                    if cleared:
                        logger.info(
                            "cache_management.clear_cache.tool_cache_cleared",
                            extra=build_log_extra(
                                ctx,
                                custom_id,
                                id=id,
                                server_name=server_name,
                                cache_type=cache_type,
                            ),
                        )
                        main_span.set_attribute("success", True)
                        return {
                            "status": "success",
                            "message": f"Cache cleared for server: {server_name}",
                        }
                    else:
                        main_span.set_attribute("success", True)
                        return {
                            "status": "info",
                            "message": f"No cache found for server: {server_name}",
                        }
                # Clear all server caches (tool cache)
                else:
                    sys_print("[clear_cache] Clearing all server caches")
                    logger.info(
                        "cache_management.clear_cache.clearing_all_server_caches",
                        extra=build_log_extra(
                            ctx,
                            custom_id,
                            id=id,
                            server_name=server_name,
                            cache_type=cache_type,
                        ),
                    )

                    cleared = self.cache_service.clear_cache_for_servers(id)
                    server_span.set_attribute("cleared_servers_count", cleared)

                    main_span.set_attribute("success", True)
                    return {
                        "status": "success",
                        "message": f"Cache cleared for all servers ({cleared} servers)",
                    }

            except Exception as e:
                server_span.record_exception(e)
                server_span.set_attribute("error", str(e))
                raise

    async def _refresh_remote_config(self, ctx, custom_id, parent_span, logger):
        """Refresh remote MCP config if enabled."""
        with tracer.start_as_current_span(
            "cache_management.refresh_remote_config"
        ) as refresh_span:
            if self.IS_DEBUG_LOG_LEVEL:
                sys_print(
                    "[clear_cache] Refreshing remote MCP config",
                    is_debug=True,
                )
                logger.info(
                    "cache_management.clear_cache.refreshing_remote_mcp_config",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=None,
                        server_name=None,
                        cache_type=None,
                    ),
                )

            refresh_response = requests.get(
                self.AUTH_SERVER_VALIDATE_URL,
                headers={
                    "apikey": self.GUARDRAIL_API_KEY,
                    "X-Enkrypt-MCP-Gateway": self.ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                    "X-Enkrypt-MCP-Gateway-Version": self.ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                    "X-Enkrypt-Refresh-Cache": "true",
                },
            )

            refresh_span.set_attribute("status_code", refresh_response.status_code)
            refresh_span.set_attribute("success", refresh_response.ok)

            if self.IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[clear_cache] Refresh response: {refresh_response}",
                    is_debug=True,
                )
                logger.info(
                    "cache_management.clear_cache.refresh_response",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        id=None,
                        server_name=None,
                        cache_type=None,
                    ),
                )
