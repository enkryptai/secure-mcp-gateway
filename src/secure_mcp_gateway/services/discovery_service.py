from __future__ import annotations

import time
from typing import Any

from opentelemetry import trace

from secure_mcp_gateway.client import forward_tool_call
from secure_mcp_gateway.services.auth_service import auth_service
from secure_mcp_gateway.services.cache_service import cache_service
from secure_mcp_gateway.services.telemetry_service import (
    cache_hit_counter,
    cache_miss_counter,
    list_servers_call_count,
    servers_discovered_count,
    tool_call_counter,
    tool_call_duration,
    tracer,
)
from secure_mcp_gateway.utils import (
    build_log_extra,
    get_server_info_by_name,
    mask_key,
    sys_print,
)


class DiscoveryService:
    """
    Handles tool discovery operations with authentication, caching, and forwarding.

    This service encapsulates the logic from enkrypt_discover_all_tools while
    maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        self.auth_service = auth_service
        self.cache_service = cache_service

    async def discover_tools(
        self,
        ctx,
        server_name: str | None = None,
        tracer_obj=None,
        logger=None,
        IS_DEBUG_LOG_LEVEL: bool = False,
    ) -> dict[str, Any]:
        """
        Discovers and caches available tools for a specific server or all servers.

        Args:
            ctx: The MCP context
            server_name: Name of the server to discover tools for (None for all servers)
            tracer_obj: OpenTelemetry tracer
            logger: Logger instance
            IS_DEBUG_LOG_LEVEL: Debug logging flag

        Returns:
            dict: Discovery result with status, message, tools, source
        """
        sys_print(f"[discover_server_tools] Requested for server: {server_name}")
        custom_id = self._generate_custom_id()
        logger.info(
            "enkrypt_discover_all_tools.started",
            extra={
                "request_id": ctx.request_id,
                "custom_id": custom_id,
                "server_name": server_name,
            },
        )

        with tracer_obj.start_as_current_span(
            "enkrypt_discover_all_tools"
        ) as main_span:
            main_span.set_attribute("server_name", server_name or "all")
            main_span.set_attribute("custom_id", custom_id)
            main_span.set_attribute("job", "enkrypt")
            main_span.set_attribute("env", "dev")
            main_span.set_attribute(
                "discovery_mode", "single" if server_name else "all"
            )

            # Get credentials and config
            credentials = auth_service.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            enkrypt_project_id = credentials.get("project_id", "not_provided")
            enkrypt_user_id = credentials.get("user_id", "not_provided")
            gateway_config = auth_service.get_local_mcp_config(
                enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
            )

            if not gateway_config:
                sys_print(
                    f"[enkrypt_discover_all_tools] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}",
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
            main_span.set_attribute(
                "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
            )
            main_span.set_attribute("enkrypt_project_id", enkrypt_project_id)
            main_span.set_attribute("enkrypt_user_id", enkrypt_user_id)
            main_span.set_attribute("enkrypt_mcp_config_id", enkrypt_mcp_config_id)
            main_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            main_span.set_attribute("enkrypt_email", enkrypt_email)

            session_key = f"{credentials.get('gateway_key')}_{credentials.get('project_id')}_{credentials.get('user_id')}_{enkrypt_mcp_config_id}"

            try:
                # Authentication check
                auth_result = await self._check_authentication(
                    ctx,
                    session_key,
                    enkrypt_gateway_key,
                    tracer_obj,
                    custom_id,
                    logger,
                    server_name,
                )
                if auth_result:
                    return auth_result

                # Handle discovery for all servers if server_name is None
                if not server_name:
                    return await self._discover_all_servers(
                        ctx,
                        session_key,
                        tracer_obj,
                        custom_id,
                        logger,
                        IS_DEBUG_LOG_LEVEL,
                        enkrypt_project_id,
                        enkrypt_user_id,
                        enkrypt_mcp_config_id,
                        enkrypt_project_name,
                        enkrypt_email,
                    )

                # Single server discovery
                return await self._discover_single_server(
                    ctx,
                    server_name,
                    session_key,
                    tracer_obj,
                    custom_id,
                    logger,
                    IS_DEBUG_LOG_LEVEL,
                )

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))
                sys_print(f"[discover_server_tools] Exception: {e}", is_error=True)
                logger.error(
                    "enkrypt_discover_all_tools.exception",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                import traceback

                traceback.print_exc()
                return {"status": "error", "error": f"Tool discovery failed: {e}"}

    def _generate_custom_id(self) -> str:
        """Generate a custom ID for tracking."""
        import uuid

        return str(uuid.uuid4())

    async def _check_authentication(
        self,
        ctx,
        session_key,
        enkrypt_gateway_key,
        tracer_obj,
        custom_id,
        logger,
        server_name,
    ):
        """Check authentication and return error if needed."""
        if not self.auth_service.is_session_authenticated(session_key):
            with tracer_obj.start_as_current_span("check_auth") as auth_span:
                auth_span.set_attribute("custom_id", custom_id)
                auth_span.set_attribute(
                    "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
                )
                auth_span.set_attribute("is_authenticated", False)

                # Import here to avoid circular imports
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = enkrypt_authenticate(ctx)
                auth_span.set_attribute("auth_result", result.get("status"))
                if result.get("status") != "success":
                    auth_span.set_attribute("error", "Authentication failed")
                    logger.warning(
                        "enkrypt_discover_all_tools.not_authenticated",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )
                    if logger.level <= 10:  # DEBUG level
                        sys_print(
                            "[discover_server_tools] Not authenticated",
                            is_error=True,
                        )
                    return {"status": "error", "error": "Not authenticated."}
        return None

    async def _discover_all_servers(
        self,
        ctx,
        session_key,
        tracer_obj,
        custom_id,
        logger,
        IS_DEBUG_LOG_LEVEL,
        enkrypt_project_id,
        enkrypt_user_id,
        enkrypt_mcp_config_id,
        enkrypt_project_name,
        enkrypt_email,
    ):
        """Discover tools for all servers."""
        with tracer_obj.start_as_current_span("discover_all_servers") as all_span:
            all_span.set_attribute("custom_id", custom_id)
            all_span.set_attribute("discovery_started", True)
            all_span.set_attribute("project_id", enkrypt_project_id)
            all_span.set_attribute("user_id", enkrypt_user_id)
            all_span.set_attribute("mcp_config_id", enkrypt_mcp_config_id)
            all_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            all_span.set_attribute("enkrypt_email", enkrypt_email)

            sys_print(
                "[discover_server_tools] Discovering tools for all servers as server_name is empty"
            )
            logger.info(
                "enkrypt_discover_all_tools.discovering_all_servers",
                extra=build_log_extra(ctx, custom_id, server_name=None),
            )
            list_servers_call_count.add(1, attributes=build_log_extra(ctx, custom_id))

            # Import here to avoid circular imports
            from secure_mcp_gateway.gateway import enkrypt_list_all_servers

            all_servers = await enkrypt_list_all_servers(ctx, discover_tools=False)
            all_servers_with_tools = all_servers.get("available_servers", {})
            servers_needing_discovery = all_servers.get("servers_needing_discovery", [])

            all_span.set_attribute("total_servers", len(servers_needing_discovery))

            status = "success"
            message = "Tools discovery tried for all servers"
            discovery_failed_servers = []
            discovery_success_servers = []

            for server_name in servers_needing_discovery:
                with tracer_obj.start_as_current_span(
                    f"discover_server_{server_name}"
                ) as server_span:
                    server_span.set_attribute("server_name", server_name)
                    server_span.set_attribute("custom_id", custom_id)
                    start_time = time.time()
                    discover_server_result = await self.discover_tools(
                        ctx, server_name, tracer_obj, logger, IS_DEBUG_LOG_LEVEL
                    )
                    end_time = time.time()
                    server_span.set_attribute("duration", end_time - start_time)
                    server_span.set_attribute(
                        "success",
                        discover_server_result.get("status") == "success",
                    )

                    tool_call_duration.record(
                        end_time - start_time,
                        attributes=build_log_extra(ctx, custom_id),
                    )
                    tool_call_counter.add(1, attributes=build_log_extra(ctx))
                    servers_discovered_count.add(1, attributes=build_log_extra(ctx))

                    if discover_server_result.get("status") != "success":
                        status = "error"
                        discovery_failed_servers.append(server_name)
                    else:
                        discovery_success_servers.append(server_name)
                        all_servers_with_tools[server_name] = discover_server_result

            servers_discovered_count.add(
                len(discovery_success_servers), attributes=build_log_extra(ctx)
            )
            all_span.set_attribute(
                "discovery_success_count", len(discovery_success_servers)
            )
            all_span.set_attribute(
                "discovery_failed_count", len(discovery_failed_servers)
            )

            main_span = trace.get_current_span()
            main_span.set_attribute("success", True)
            return {
                "status": status,
                "message": message,
                "discovery_failed_servers": discovery_failed_servers,
                "discovery_success_servers": discovery_success_servers,
                "available_servers": all_servers_with_tools,
            }

    async def _discover_single_server(
        self,
        ctx,
        server_name,
        session_key,
        tracer_obj,
        custom_id,
        logger,
        IS_DEBUG_LOG_LEVEL,
    ):
        """Discover tools for a single server."""
        # Server info check
        with tracer_obj.start_as_current_span("get_server_info") as info_span:
            info_span.set_attribute("server_name", server_name)

            server_info = get_server_info_by_name(
                self.auth_service.get_session_gateway_config(session_key), server_name
            )
            info_span.set_attribute("server_found", server_info is not None)

            if not server_info:
                info_span.set_attribute(
                    "error", f"Server '{server_name}' not available"
                )
                if IS_DEBUG_LOG_LEVEL:
                    sys_print(
                        f"[discover_server_tools] Server '{server_name}' not available",
                        is_error=True,
                    )
                    logger.warning(
                        "enkrypt_discover_all_tools.server_not_available",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )
                return {
                    "status": "error",
                    "error": f"Server '{server_name}' not available.",
                }

            id = self.auth_service.get_session_gateway_config(session_key)["id"]
            info_span.set_attribute("gateway_id", id)

            # Check if server has configured tools in the gateway config
            config_tools = server_info.get("tools", {})
            info_span.set_attribute("has_config_tools", bool(config_tools))

            if config_tools:
                sys_print(
                    f"[discover_server_tools] Tools already defined in config for {server_name}"
                )
                logger.info(
                    "enkrypt_discover_all_tools.tools_already_defined_in_config",
                    extra=build_log_extra(ctx, custom_id, server_name),
                )
                main_span = trace.get_current_span()
                main_span.set_attribute("success", True)
                return {
                    "status": "success",
                    "message": f"Tools already defined in config for {server_name}",
                    "tools": config_tools,
                    "source": "config",
                }

        # Tool discovery
        with tracer_obj.start_as_current_span("discover_tools") as discover_span:
            discover_span.set_attribute("server_name", server_name)

            # Cache check
            with tracer_obj.start_as_current_span("check_tools_cache") as cache_span:
                cached_tools = self.cache_service.get_cached_tools(id, server_name)
                cache_span.set_attribute("cache_hit", cached_tools is not None)

                if cached_tools:
                    cache_hit_counter.add(1, attributes=build_log_extra(ctx))
                    sys_print(
                        f"[discover_server_tools] Tools already cached for {server_name}"
                    )
                    logger.info(
                        "enkrypt_discover_all_tools.tools_already_cached",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )
                    main_span = trace.get_current_span()
                    main_span.set_attribute("success", True)
                    return {
                        "status": "success",
                        "message": f"Tools retrieved from cache for {server_name}",
                        "tools": cached_tools,
                        "source": "cache",
                    }
                else:
                    cache_miss_counter.add(1, attributes=build_log_extra(ctx))
                    sys_print(
                        f"[discover_server_tools] No cached tools found for {server_name}"
                    )
                    logger.info(
                        "enkrypt_discover_all_tools.no_cached_tools",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )

            # Forward tool call
            with tracer_obj.start_as_current_span("forward_tool_call") as tool_span:
                tool_call_counter.add(1, attributes=build_log_extra(ctx, custom_id))
                start_time = time.time()
                result = await forward_tool_call(
                    server_name,
                    None,
                    None,
                    self.auth_service.get_session_gateway_config(session_key),
                )
                end_time = time.time()
                tool_call_duration.record(
                    end_time - start_time,
                    attributes=build_log_extra(ctx, custom_id),
                )
                tool_span.set_attribute("duration", end_time - start_time)
                tools = (
                    result["tools"]
                    if isinstance(result, dict) and "tools" in result
                    else result
                )
                tool_span.set_attribute("tools_found", bool(tools))

                if tools:
                    if IS_DEBUG_LOG_LEVEL:
                        sys_print(
                            f"[discover_server_tools] Success: {server_name} tools discovered: {tools}",
                            is_debug=True,
                        )
                        logger.info(
                            "enkrypt_discover_all_tools.tools_discovered",
                            extra=build_log_extra(ctx, custom_id, server_name),
                        )

                    # Cache write
                    with tracer_obj.start_as_current_span(
                        "cache_tools"
                    ) as cache_write_span:
                        cache_write_span.set_attribute("server_name", server_name)
                        self.cache_service.cache_tools(id, server_name, tools)
                        cache_write_span.set_attribute("cache_write_success", True)
                else:
                    sys_print(
                        f"[discover_server_tools] No tools discovered for {server_name}"
                    )
                    logger.warning(
                        "enkrypt_discover_all_tools.no_tools_discovered",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )

                main_span = trace.get_current_span()
                main_span.set_attribute("success", True)
                return {
                    "status": "success",
                    "message": f"Tools discovered for {server_name}",
                    "tools": tools,
                    "source": "discovery",
                }
