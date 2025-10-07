from __future__ import annotations

from typing import Any

from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import cache_service

# Get metrics from telemetry manager
telemetry_manager = get_telemetry_config_manager()
list_servers_call_count = telemetry_manager.list_servers_call_count
servers_discovered_count = telemetry_manager.servers_discovered_count
from secure_mcp_gateway.utils import (
    build_log_extra,
    mask_key,
    mask_server_config_sensitive_data,
    sys_print,
)


class ServerListingService:
    """
    Handles server listing operations with authentication, caching, and discovery.

    This service encapsulates the logic from enkrypt_list_all_servers while
    maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        self.auth_manager = get_auth_config_manager()
        self.cache_service = cache_service

    async def list_servers(
        self,
        ctx,
        discover_tools: bool = True,
        tracer=None,
        logger=None,
        IS_DEBUG_LOG_LEVEL: bool = False,
        cache_client=None,
    ) -> dict[str, Any]:
        """
        Lists available servers with their tool information.

        Args:
            ctx: The MCP context
            discover_tools: Whether to discover tools for servers that need it
            tracer: OpenTelemetry tracer
            logger: Logger instance
            IS_DEBUG_LOG_LEVEL: Debug logging flag
            cache_client: Cache client instance

        Returns:
            dict: Server listing with status, available_servers, etc.
        """
        custom_id = self._generate_custom_id()

        logger.info(
            "Listing available servers",
            extra={"discover_tools": discover_tools, "custom_id": custom_id},
        )

        with tracer.start_as_current_span("enkrypt_list_all_servers") as main_span:
            # Count total calls to this endpoint
            list_servers_call_count.add(1, attributes=build_log_extra(ctx, custom_id))
            sys_print("[list_available_servers] Request received")

            # Get credentials and config
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            enkrypt_project_id = credentials.get("project_id", "not_provided")
            enkrypt_user_id = credentials.get("user_id", "not_provided")
            gateway_config = self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
            )

            if not gateway_config:
                sys_print(
                    f"[list_available_servers] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}",
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
            self._set_span_attributes(
                main_span,
                custom_id,
                enkrypt_gateway_key,
                discover_tools,
                enkrypt_project_id,
                enkrypt_user_id,
                enkrypt_mcp_config_id,
                enkrypt_project_name,
                enkrypt_email,
            )

            try:
                # Authentication check
                session_key = f"{enkrypt_gateway_key}_{enkrypt_project_id}_{enkrypt_user_id}_{enkrypt_mcp_config_id}"
                auth_result = await self._check_authentication(
                    ctx, session_key, enkrypt_gateway_key, tracer, custom_id, logger
                )
                if auth_result:
                    return auth_result

                # Get server configuration
                gateway_config = self.auth_manager.get_session_gateway_config(
                    session_key
                )
                id = gateway_config["id"]
                mcp_config = gateway_config.get("mcp_config", [])

                # Process servers
                (
                    servers_with_tools,
                    servers_needing_discovery,
                ) = await self._process_servers(
                    mcp_config,
                    id,
                    cache_client,
                    ctx,
                    custom_id,
                    tracer,
                    logger,
                    IS_DEBUG_LOG_LEVEL,
                )

                # Update metrics
                servers_discovered_count.add(
                    len(servers_with_tools), attributes=build_log_extra(ctx, custom_id)
                )

                if not discover_tools:
                    return self._return_servers_without_discovery(
                        servers_with_tools, servers_needing_discovery, main_span
                    )
                else:
                    return await self._discover_and_return_servers(
                        servers_with_tools,
                        servers_needing_discovery,
                        ctx,
                        tracer,
                        main_span,
                    )

            except Exception as e:
                main_span.set_attribute("error", "true")
                main_span.record_exception(e)
                main_span.set_attribute("error_message", str(e))
                sys_print(f"[list_available_servers] Exception: {e}", is_error=True)
                logger.error(
                    "list_all_servers.exception",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                import traceback

                traceback.print_exc()
                return {"status": "error", "error": f"Tool discovery failed: {e}"}

    def _generate_custom_id(self) -> str:
        """Generate a custom ID for tracking."""
        import uuid

        return str(uuid.uuid4())

    def _set_span_attributes(
        self,
        span,
        custom_id,
        enkrypt_gateway_key,
        discover_tools,
        enkrypt_project_id,
        enkrypt_user_id,
        enkrypt_mcp_config_id,
        enkrypt_project_name,
        enkrypt_email,
    ):
        """Set attributes on the main span."""
        span.set_attribute("job", "enkrypt")
        span.set_attribute("env", "dev")
        span.set_attribute("custom_id", custom_id)
        span.set_attribute("enkrypt_gateway_key", mask_key(enkrypt_gateway_key))
        span.set_attribute("discover_tools", discover_tools)
        span.set_attribute("enkrypt_project_id", enkrypt_project_id)
        span.set_attribute("enkrypt_user_id", enkrypt_user_id)
        span.set_attribute("enkrypt_mcp_config_id", enkrypt_mcp_config_id)
        span.set_attribute("enkrypt_project_name", enkrypt_project_name)
        span.set_attribute("enkrypt_email", enkrypt_email)

    async def _check_authentication(
        self, ctx, session_key, enkrypt_gateway_key, tracer, custom_id, logger
    ):
        """Check authentication and return error if needed."""
        with tracer.start_span("check_server_auth") as auth_span:
            auth_span.set_attribute("custom_id", custom_id)
            auth_span.set_attribute(
                "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
            )
            auth_span.set_attribute("gateway_key", mask_key(enkrypt_gateway_key))
            # Get credentials for span attributes
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            auth_span.set_attribute(
                "project_id", credentials.get("project_id", "not_provided")
            )
            auth_span.set_attribute(
                "user_id", credentials.get("user_id", "not_provided")
            )
            auth_span.set_attribute(
                "mcp_config_id", credentials.get("mcp_config_id", "not_provided")
            )
            auth_span.set_attribute(
                "enkrypt_project_name", credentials.get("project_name", "not_provided")
            )
            auth_span.set_attribute(
                "enkrypt_email", credentials.get("email", "not_provided")
            )

            if not enkrypt_gateway_key:
                sys_print("[list_available_servers] No gateway key provided")
                logger.warning(
                    "list_all_servers.no_gateway_key",
                    extra=build_log_extra(ctx, custom_id),
                )
                return {"status": "error", "error": "No gateway key provided."}

            is_authenticated = self.auth_manager.is_session_authenticated(session_key)
            auth_span.set_attribute("is_authenticated", is_authenticated)

            if not is_authenticated:
                # Import here to avoid circular imports
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                if result.get("status") != "success":
                    if logger.level <= 10:  # DEBUG level
                        logger.warning(
                            "list_all_servers.auth_failed",
                            extra=build_log_extra(ctx, custom_id),
                        )
                        sys_print(
                            "[list_available_servers] Not authenticated",
                            is_error=True,
                        )
                    return {"status": "error", "error": "Not authenticated."}
        return None

    async def _process_servers(
        self,
        mcp_config,
        id,
        cache_client,
        ctx,
        custom_id,
        tracer,
        logger,
        IS_DEBUG_LOG_LEVEL,
    ):
        """Process servers and return servers with tools and those needing discovery."""
        with tracer.start_span("process_servers") as process_span:
            process_span.set_attribute("num_servers", len(mcp_config))
            process_span.set_attribute("total_servers", len(mcp_config))

            if IS_DEBUG_LOG_LEVEL:
                # Mask sensitive data in debug logs
                masked_mcp_config = []
                for server in mcp_config:
                    masked_server = server.copy()
                    if "config" in masked_server and "env" in masked_server["config"]:
                        masked_server["config"] = masked_server["config"].copy()
                        from secure_mcp_gateway.utils import mask_sensitive_env_vars

                        masked_server["config"]["env"] = mask_sensitive_env_vars(
                            masked_server["config"]["env"]
                        )
                    masked_mcp_config.append(masked_server)
                sys_print(f"mcp_config: {masked_mcp_config}", is_debug=True)

            servers_with_tools = {}
            servers_needing_discovery = []

            for server_info in mcp_config:
                server_name = server_info["server_name"]

                # Check server cache
                with tracer.start_span("check_server_cache") as cache_span:
                    cache_span.set_attribute("processing_server", server_name)

                    if IS_DEBUG_LOG_LEVEL:
                        logger.info(
                            "list_all_servers.processing_server",
                            extra=build_log_extra(ctx, custom_id, server_name),
                        )
                        sys_print(
                            f"[list_available_servers] Processing server: {server_name}",
                            is_debug=True,
                        )

                    server_info_copy = cache_service.get_latest_server_info(
                        server_info, id, cache_client
                    )

                    # Always send servers to discovery for guardrail validation
                    # regardless of whether tools are from config or need discovery or cached
                    # It then dynamically checks if the tools are needed and discovers them if needed
                    servers_needing_discovery.append(server_name)

                    servers_with_tools[server_name] = server_info_copy

            process_span.set_attribute(
                "servers_needing_discovery", len(servers_needing_discovery)
            )

            return servers_with_tools, servers_needing_discovery

    def _return_servers_without_discovery(
        self, servers_with_tools, servers_needing_discovery, main_span
    ):
        """Return servers without performing discovery."""
        main_span.set_attribute("total_servers_processed", len(servers_with_tools))
        main_span.set_attribute("success", True)

        # Mask sensitive data in all server configurations
        masked_servers = {}
        for server_name, server_info in servers_with_tools.items():
            masked_servers[server_name] = mask_server_config_sensitive_data(server_info)

        return {
            "status": "success",
            "available_servers": masked_servers,
            "servers_needing_discovery": servers_needing_discovery,
        }

    async def _discover_and_return_servers(
        self, servers_with_tools, servers_needing_discovery, ctx, tracer, main_span
    ):
        """Discover tools and return servers."""
        with tracer.start_span("discover_tools") as discover_span:
            discover_span.set_attribute(
                "servers_to_discover", len(servers_needing_discovery)
            )

            # Discover tools for all servers
            status = "success"
            message = "Tools discovery tried for all servers"
            discovery_failed_servers = []
            discovery_success_servers = []

            for server_name in servers_needing_discovery:
                with tracer.start_span(f"discover_server_{server_name}") as server_span:
                    server_span.set_attribute("server_name", server_name)

                    # Import here to avoid circular imports
                    from secure_mcp_gateway.gateway import (
                        enkrypt_discover_all_tools,
                    )

                    discover_server_result = await enkrypt_discover_all_tools(
                        ctx, server_name
                    )

                    if discover_server_result.get("status") != "success":
                        status = "error"
                        discovery_failed_servers.append(server_name)
                        server_span.set_attribute("discovery_success", False)
                    else:
                        discovery_success_servers.append(server_name)
                        servers_with_tools[server_name] = discover_server_result
                        server_span.set_attribute("discovery_success", True)

            discover_span.set_attribute("failed_servers", len(discovery_failed_servers))
            discover_span.set_attribute(
                "success_servers", len(discovery_success_servers)
            )

        main_span.set_attribute("total_servers_processed", len(servers_with_tools))
        main_span.set_attribute("servers_discovered", len(servers_needing_discovery))
        main_span.set_attribute("success", True)

        # Mask sensitive data in all server configurations
        masked_servers = {}
        for server_name, server_info in servers_with_tools.items():
            masked_servers[server_name] = mask_server_config_sensitive_data(server_info)

        return {
            "status": status,
            "message": message,
            "discovery_failed_servers": discovery_failed_servers,
            "discovery_success_servers": discovery_success_servers,
            "available_servers": masked_servers,
        }
