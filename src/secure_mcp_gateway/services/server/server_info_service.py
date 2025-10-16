from __future__ import annotations

from typing import Any

from secure_mcp_gateway.error_handling import create_error_response
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_discovery_error,
)
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.utils import (
    build_log_extra,
    get_server_info_by_name,
    logger,
    mask_key,
    mask_server_config_sensitive_data,
)


class ServerInfoService:
    """
    Handles server information retrieval with authentication and caching.

    This service encapsulates the logic from enkrypt_get_server_info while
    maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        self.auth_manager = get_auth_config_manager()

    async def get_server_info(
        self,
        ctx,
        server_name: str,
        tracer=None,
        cache_client=None,
    ) -> dict[str, Any]:
        """
        Gets detailed information about a server, including its tools.

        Args:
            ctx: The MCP context
            server_name: Name of the server
            tracer: OpenTelemetry tracer
            logger: Logger instance
            cache_client: Cache client instance

        Returns:
            dict: Server information with status, server_name, server_info
        """
        custom_id = self._generate_custom_id()

        logger.info(f"[get_server_info] Requested for server: {server_name}")
        logger.info(
            "enkrypt_get_server_info.started",
            extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name,
            },
        )

        # Get credentials and config
        credentials = self.auth_manager.get_gateway_credentials(ctx)
        enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
        enkrypt_project_id = credentials.get("project_id", "not_provided")
        enkrypt_user_id = credentials.get("user_id", "not_provided")
        gateway_config = await self.auth_manager.get_local_mcp_config(
            enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
        )

        if not gateway_config:
            logger.error(
                f"[get_server_info] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}"
            )
            context = ErrorContext(
                operation="server_info.init",
                request_id=getattr(ctx, "request_id", None),
            )
            err = create_discovery_error(
                code=ErrorCode.CONFIG_MISSING_REQUIRED,
                message="No MCP config found. Please check your credentials.",
                context=context,
            )
            return create_error_response(err)

        enkrypt_project_name = gateway_config.get("project_name", "not_provided")
        enkrypt_email = gateway_config.get("email", "not_provided")
        enkrypt_mcp_config_id = gateway_config.get("mcp_config_id", "not_provided")
        session_key = f"{enkrypt_gateway_key}_{enkrypt_project_id}_{enkrypt_user_id}_{enkrypt_mcp_config_id}"

        with tracer.start_as_current_span("enkrypt_get_server_info") as main_span:
            main_span.set_attribute("server_name", server_name)
            main_span.set_attribute("job", "enkrypt")
            main_span.set_attribute("env", "dev")
            main_span.set_attribute("custom_id", custom_id)
            main_span.set_attribute(
                "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
            )
            main_span.set_attribute("enkrypt_project_id", enkrypt_project_id)
            main_span.set_attribute("enkrypt_user_id", enkrypt_user_id)
            main_span.set_attribute("enkrypt_mcp_config_id", enkrypt_mcp_config_id)
            main_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            main_span.set_attribute("enkrypt_email", enkrypt_email)

            try:
                # Authentication check
                auth_result = await self._check_authentication(
                    ctx,
                    session_key,
                    enkrypt_gateway_key,
                    tracer,
                    custom_id,
                    server_name,
                )
                if auth_result:
                    return auth_result

                # Server info check
                server_info = await self._get_server_info(
                    session_key, server_name, tracer, custom_id, logger
                )
                if not server_info:
                    context = ErrorContext(
                        operation="server_info.lookup",
                        request_id=getattr(ctx, "request_id", None),
                        server_name=server_name,
                    )
                    err = create_discovery_error(
                        code=ErrorCode.DISCOVERY_SERVER_UNAVAILABLE,
                        message=f"Server '{server_name}' not available.",
                        context=context,
                    )
                    return create_error_response(err)

                # Get latest server info
                latest_server_info = await self._get_latest_server_info(
                    server_info,
                    session_key,
                    server_name,
                    tracer,
                    custom_id,
                    enkrypt_gateway_key,
                    enkrypt_project_id,
                    enkrypt_user_id,
                    enkrypt_mcp_config_id,
                    enkrypt_project_name,
                    enkrypt_email,
                    cache_client,
                )

                # Success tracking
                main_span.set_attribute("success", True)

                # Mask sensitive data before returning
                masked_server_info = mask_server_config_sensitive_data(
                    latest_server_info
                )

                return {
                    "status": "success",
                    "server_name": server_name,
                    "server_info": masked_server_info,
                }

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))
                logger.error(f"[get_server_info] Exception: {e}")
                logger.error(
                    "get_server_info.exception",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                context = ErrorContext(
                    operation="server_info.exception",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )
                err = create_discovery_error(
                    code=ErrorCode.DISCOVERY_FAILED,
                    message=f"Tool discovery failed: {e}",
                    context=context,
                    cause=e,
                )
                return create_error_response(err)

    def _generate_custom_id(self) -> str:
        """Generate a custom ID for tracking."""
        import uuid

        return str(uuid.uuid4())

    async def _check_authentication(
        self,
        ctx,
        session_key,
        enkrypt_gateway_key,
        tracer,
        custom_id,
        server_name,
    ):
        """Check authentication and return error if needed."""
        with tracer.start_as_current_span("check_server_auth") as auth_span:
            auth_span.set_attribute("custom_id", custom_id)
            auth_span.set_attribute(
                "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
            )

            # Add authentication status tracking
            is_authenticated = await self.auth_manager.is_authenticated(ctx)
            auth_span.set_attribute("is_authenticated", is_authenticated)

            if not is_authenticated:
                # Import here to avoid circular imports
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                auth_span.set_attribute("auth_result", result.get("status"))
                if result.get("status") != "success":
                    auth_span.set_attribute("error", "Authentication failed")
                    logger.warning("[get_server_info] Not authenticated")
                    logger.warning(
                        "get_server_info.not_authenticated",
                        extra=build_log_extra(
                            session_key,
                            custom_id,
                            server_name=server_name,
                        ),
                    )
                    context = ErrorContext(
                        operation="server_info.auth",
                        request_id=getattr(ctx, "request_id", None),
                        server_name=server_name,
                    )
                    err = create_discovery_error(
                        code=ErrorCode.AUTH_INVALID_CREDENTIALS,
                        message="Not authenticated.",
                        context=context,
                    )
                    return create_error_response(err)
        return None

    async def _get_server_info(
        self, session_key, server_name, tracer, custom_id, logger
    ):
        """Get server info and check if server exists."""
        with tracer.start_as_current_span("check_server_exists") as server_span:
            server_span.set_attribute("server_name", server_name)
            server_info = get_server_info_by_name(
                self.auth_manager.get_session_gateway_config(session_key), server_name
            )
            server_span.set_attribute("server_found", server_info is not None)

            if not server_info:
                server_span.set_attribute(
                    "error", f"Server '{server_name}' not available"
                )
                logger.warning(
                    f"[get_server_info] Server '{server_name}' not available"
                )
                logger.warning(
                    "get_server_info.server_not_available",
                    extra=build_log_extra(session_key, custom_id, server_name),
                )
                return None

            return server_info

    async def _get_latest_server_info(
        self,
        server_info,
        session_key,
        server_name,
        tracer,
        custom_id,
        enkrypt_gateway_key,
        enkrypt_project_id,
        enkrypt_user_id,
        enkrypt_mcp_config_id,
        enkrypt_project_name,
        enkrypt_email,
        cache_client,
    ):
        """Get latest server info with all attributes."""
        with tracer.start_as_current_span("get_latest_server_info") as info_span:
            info_span.set_attribute("server_name", server_name)
            info_span.set_attribute(
                "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
            )
            info_span.set_attribute(
                "gateway_id",
                self.auth_manager.get_session_gateway_config(session_key)["id"],
            )
            info_span.set_attribute("project_id", enkrypt_project_id)
            info_span.set_attribute("user_id", enkrypt_user_id)
            info_span.set_attribute("mcp_config_id", enkrypt_mcp_config_id)
            info_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            info_span.set_attribute("enkrypt_email", enkrypt_email)

            from secure_mcp_gateway.services.cache.cache_service import CacheService

            cache_service = CacheService()
            server_info_copy = cache_service.get_latest_server_info(
                server_info,
                self.auth_manager.get_session_gateway_config(session_key)["id"],
                cache_client,
            )

            info_span.set_attribute("has_tools", "tools" in server_info_copy)
            info_span.set_attribute(
                "tools_discovered", server_info_copy.get("tools_discovered", False)
            )

            return server_info_copy
