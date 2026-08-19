from __future__ import annotations

from typing import Any

import requests

from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.plugins.telemetry.conventions import (
    SpanAttributes,
    set_span_attr_with_legacy,
)
from secure_mcp_gateway.services.cache.cache_service import cache_service

# Get tracer from telemetry manager
telemetry_manager = get_telemetry_config_manager()
tracer = telemetry_manager.get_tracer()
from secure_mcp_gateway.error_handling import create_error_response
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_auth_error,
    create_configuration_error,
)
from secure_mcp_gateway.utils import (
    build_log_extra,
    generate_custom_id,
    get_common_config,
    get_guardrail_api_key,
    get_guardrail_base_url,
    get_remote_gateway_name,
    get_remote_gateway_version,
    is_debug_log_level,
    logger,
    mask_key,
    use_remote_mcp_config,
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

    # All settings below resolve from the current common_config on every
    # access so config edits take effect without restart.
    @property
    def GUARDRAIL_API_KEY(self) -> str:
        return get_guardrail_api_key()

    @property
    def GUARDRAIL_URL(self) -> str:
        return get_guardrail_base_url()

    @property
    def ENKRYPT_USE_REMOTE_MCP_CONFIG(self) -> bool:
        return use_remote_mcp_config()

    @property
    def ENKRYPT_REMOTE_MCP_GATEWAY_NAME(self) -> str:
        return get_remote_gateway_name()

    @property
    def ENKRYPT_REMOTE_MCP_GATEWAY_VERSION(self) -> str:
        return get_remote_gateway_version()

    @property
    def AUTH_SERVER_VALIDATE_URL(self) -> str:
        return f"{self.GUARDRAIL_URL}/mcp-gateway/get-gateway"

    @property
    def IS_DEBUG_LOG_LEVEL(self) -> bool:
        return is_debug_log_level()

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
                logger.info(
                    f"[clear_cache] Requested with id={id}, server_name={server_name}, cache_type={cache_type}"
                )
                custom_id = generate_custom_id()

                # Set main span attributes
                # request_id / custom_id were previously emitted as snake_case
                # alongside the dotted SpanAttributes.* forms set elsewhere on
                # the same span. Use the canonical constants only.
                main_span.set_attribute(SpanAttributes.REQUEST_ID, ctx.request_id)
                main_span.set_attribute(SpanAttributes.CUSTOM_ID, custom_id)
                # ``id`` here is the cache-context gateway-config ID
                # (gateway_key + project_id + user_id + mcp_config_id), not a
                # standard SpanAttribute. Keep as snake_case for cache
                # debugging; gets dropped under dynamic:false unless added to
                # the trace template.
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
                logger.info(
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
                logger.error(f"[clear_cache] Critical error: {e}")
                logger.error(
                    "cache_management.clear_cache.critical_error",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                raise

    async def _authenticate_and_setup(self, ctx, custom_id, main_span, logger):
        """Handle authentication and setup for cache operations."""
        with tracer.start_as_current_span("cache_management.authenticate") as auth_span:
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            # See discovery_service.py for the rationale: ``or`` so a
            # ``None`` credential value is coerced to ``"not_provided"``
            # (cloud-auth MCP clients don't send project_id/user_id headers).
            enkrypt_gateway_key = credentials.get("gateway_key") or "not_provided"
            enkrypt_project_id = credentials.get("project_id") or "not_provided"
            enkrypt_user_id = credentials.get("user_id") or "not_provided"

            gateway_config = await self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key,
                enkrypt_project_id,
                enkrypt_user_id,
                gateway_name=credentials.get("gateway_name"),
                gateway_version=credentials.get("gateway_version"),
            )

            if not gateway_config:
                logger.error(
                    f"[clear_cache] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}"
                )
                context = ErrorContext(
                    operation="cache_management.init",
                    request_id=getattr(ctx, "request_id", None),
                )
                err = create_configuration_error(
                    code=ErrorCode.CONFIG_MISSING_REQUIRED,
                    message="No MCP config found. Please check your credentials.",
                    context=context,
                )
                return create_error_response(err)

            enkrypt_project_name = gateway_config.get("project_name", "not_provided")
            enkrypt_email = gateway_config.get("email", "not_provided")
            enkrypt_mcp_config_id = gateway_config.get("mcp_config_id", "not_provided")
            # Full request_context identity tuple from the cloud auth provider
            # (or "not_provided" for local-apikey / free-tier gateways).
            enkrypt_org_id = gateway_config.get("org_id") or "not_provided"
            enkrypt_project_registry = (
                gateway_config.get("registry_name") or "not_provided"
            )
            enkrypt_gateway_name = gateway_config.get("gateway_name") or "not_provided"
            enkrypt_gateway_version = (
                gateway_config.get("gateway_version") or "not_provided"
            )

            # Set span attributes
            auth_span.set_attribute(
                SpanAttributes.GATEWAY_KEY, mask_key(enkrypt_gateway_key)
            )
            set_span_attr_with_legacy(auth_span, SpanAttributes.ORG_ID, enkrypt_org_id)
            set_span_attr_with_legacy(
                auth_span, SpanAttributes.PROJECT_ID, enkrypt_project_id
            )
            set_span_attr_with_legacy(
                auth_span, SpanAttributes.PROJECT_NAME, enkrypt_project_name
            )
            auth_span.set_attribute(
                SpanAttributes.PROJECT_REGISTRY, enkrypt_project_registry
            )
            set_span_attr_with_legacy(
                auth_span, SpanAttributes.USER_ID, enkrypt_user_id
            )
            set_span_attr_with_legacy(
                auth_span, SpanAttributes.USER_EMAIL, enkrypt_email
            )
            auth_span.set_attribute(SpanAttributes.CONFIG_ID, enkrypt_mcp_config_id)
            set_span_attr_with_legacy(
                auth_span, SpanAttributes.GATEWAY_NAME, enkrypt_gateway_name
            )
            auth_span.set_attribute(
                SpanAttributes.GATEWAY_VERSION, enkrypt_gateway_version
            )

            # Build session key via the canonical helper so ``None``
            # credential components (cloud-auth requests don't send
            # project_id/user_id headers) get coerced consistently with the
            # store side in ``AuthConfigManager.authenticate``.
            session_key = self.auth_manager.create_session_key(
                credentials.get("gateway_key"),
                credentials.get("project_id"),
                credentials.get("user_id"),
                enkrypt_mcp_config_id,
            )

            if not self.auth_manager.is_session_authenticated(session_key):
                auth_span.set_attribute("requires_auth", True)
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                if result.get("status") != "success":
                    auth_msg = result.get("message", "Unknown auth error")
                    auth_err = result.get("error", "")
                    detail = f"Authentication failed: {auth_msg}"
                    if auth_err and auth_err != auth_msg:
                        detail += f" ({auth_err})"
                    auth_span.set_attribute("error", detail)
                    logger.error(f"[clear_cache] {detail}")
                    logger.error(
                        "cache_management.clear_cache.not_authenticated",
                        extra=build_log_extra(ctx, custom_id, error=detail),
                    )
                    context = ErrorContext(
                        operation="cache_management.auth",
                        request_id=getattr(ctx, "request_id", None),
                    )
                    err = create_auth_error(
                        code=ErrorCode.AUTH_INVALID_CREDENTIALS,
                        message=detail,
                        context=context,
                    )
                    return create_error_response(err)
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
                    logger.debug(
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

                logger.info("[clear_cache] Clearing all caches")
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

                logger.info("[clear_cache] Clearing gateway config cache")
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

                logger.info("[clear_cache] Clearing server config cache")
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
                        logger.debug(
                            f"[clear_cache] Clearing tool cache for server: {server_name}"
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
                    logger.info("[clear_cache] Clearing all server caches")
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
                logger.debug("[clear_cache] Refreshing remote MCP config")
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

            # Use aiohttp for async HTTP request with timeout management
            import aiohttp

            from secure_mcp_gateway.services.timeout import get_timeout_manager

            timeout_manager = get_timeout_manager()
            timeout_value = timeout_manager.get_timeout("cache")

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.AUTH_SERVER_VALIDATE_URL,
                    headers={
                        "apikey": self.GUARDRAIL_API_KEY,
                        "X-Enkrypt-MCP-Gateway": self.ENKRYPT_REMOTE_MCP_GATEWAY_NAME,
                        "X-Enkrypt-MCP-Gateway-Version": self.ENKRYPT_REMOTE_MCP_GATEWAY_VERSION,
                        "X-Enkrypt-Refresh-Cache": "true",
                    },
                    timeout=aiohttp.ClientTimeout(total=timeout_value),
                ) as refresh_response:
                    refresh_span.set_attribute("status_code", refresh_response.status)
                    refresh_span.set_attribute("success", refresh_response.ok)

                    if self.IS_DEBUG_LOG_LEVEL:
                        logger.debug(
                            f"[clear_cache] Refresh response: {refresh_response}"
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
