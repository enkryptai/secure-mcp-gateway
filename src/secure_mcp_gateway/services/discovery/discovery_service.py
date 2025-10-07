from __future__ import annotations

import time
from typing import Any

from opentelemetry import trace

from secure_mcp_gateway.client import forward_tool_call
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import cache_service

# Get telemetry components from manager
telemetry_manager = get_telemetry_config_manager()
cache_hit_counter = telemetry_manager.cache_hit_counter
cache_miss_counter = telemetry_manager.cache_miss_counter
list_servers_call_count = telemetry_manager.list_servers_call_count
servers_discovered_count = telemetry_manager.servers_discovered_count
tool_call_counter = telemetry_manager.tool_call_counter
tool_call_duration = telemetry_manager.tool_call_duration
tracer = telemetry_manager.get_tracer()
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
        self.auth_manager = get_auth_config_manager()
        self.cache_service = cache_service

        # Import guardrail manager for registration validation
        try:
            from secure_mcp_gateway.plugins.guardrails import (
                get_guardrail_config_manager,
            )

            self.guardrail_manager = get_guardrail_config_manager()
            self.registration_validation_enabled = True
        except Exception:
            self.guardrail_manager = None
            self.registration_validation_enabled = False

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
        if server_name and server_name.lower() == "null":
            server_name = None

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
            credentials = self.auth_manager.get_gateway_credentials(ctx)
            enkrypt_gateway_key = credentials.get("gateway_key", "not_provided")
            enkrypt_project_id = credentials.get("project_id", "not_provided")
            enkrypt_user_id = credentials.get("user_id", "not_provided")
            gateway_config = self.auth_manager.get_local_mcp_config(
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
        if not self.auth_manager.is_session_authenticated(session_key):
            with tracer_obj.start_as_current_span("check_auth") as auth_span:
                auth_span.set_attribute("custom_id", custom_id)
                auth_span.set_attribute(
                    "enkrypt_gateway_key", mask_key(enkrypt_gateway_key)
                )
                auth_span.set_attribute("is_authenticated", False)

                # Import here to avoid circular imports
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
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
                self.auth_manager.get_session_gateway_config(session_key), server_name
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

            id = self.auth_manager.get_session_gateway_config(session_key)["id"]
            info_span.set_attribute("gateway_id", id)

            # NEW: Validate server registration before proceeding
            if self.registration_validation_enabled and self.guardrail_manager:
                with tracer_obj.start_as_current_span(
                    "validate_server_registration"
                ) as server_validation_span:
                    server_validation_span.set_attribute("server_name", server_name)

                    sys_print(
                        f"[discover_server_tools] Validating server registration for {server_name}"
                    )

                    try:
                        server_validation_response = (
                            await self.guardrail_manager.validate_server_registration(
                                server_name=server_name, server_config=server_info
                            )
                        )

                        if (
                            server_validation_response
                            and not server_validation_response.is_safe
                        ):
                            # Server is unsafe - block it entirely
                            violations = server_validation_response.violations
                            violation_messages = [v.message for v in violations]

                            server_validation_span.set_attribute("server_blocked", True)
                            server_validation_span.set_attribute(
                                "violation_count", len(violations)
                            )

                            sys_print(
                                f"[discover_server_tools] ⚠️  BLOCKED UNSAFE SERVER: {server_name}",
                                is_error=True,
                            )
                            sys_print(
                                "[discover_server_tools] === SERVER BLOCKED ===",
                                is_error=True,
                            )
                            for violation in violations:
                                sys_print(
                                    f"[discover_server_tools]   ❌ {violation.message}",
                                    is_error=True,
                                )
                            sys_print(
                                "[discover_server_tools] ========================",
                                is_error=True,
                            )

                            logger.error(
                                "enkrypt_discover_all_tools.server_blocked_by_guardrails",
                                extra={
                                    **build_log_extra(ctx, custom_id, server_name),
                                    "violations": violation_messages,
                                },
                            )

                            return {
                                "status": "success",
                                "error": f"Server '{server_name}' blocked by security guardrails: {', '.join(violation_messages)}",
                                "blocked": True,
                                "violations": violation_messages,
                            }
                        else:
                            # Server is safe
                            sys_print(
                                f"[discover_server_tools] ✓ Server {server_name} passed validation"
                            )
                            server_validation_span.set_attribute("server_safe", True)

                    except Exception as server_validation_error:
                        # Fail open: if validation fails, allow the server
                        sys_print(
                            f"[discover_server_tools] Server validation error: {server_validation_error}",
                            is_error=True,
                        )
                        logger.error(
                            "enkrypt_discover_all_tools.server_validation_error",
                            extra={
                                **build_log_extra(ctx, custom_id, server_name),
                                "error": str(server_validation_error),
                            },
                        )
                        server_validation_span.set_attribute(
                            "validation_error", str(server_validation_error)
                        )

            # NOTE: Static description validation moved to after dynamic description capture
            # to ensure we can validate both static and dynamic descriptions together

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

                # Track blocked tools from config validation
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

                # NEW: Validate config tools with guardrails before returning
                enable_tool_guardrails = server_info.get("enable_tool_guardrails", True)
                sys_print(
                    f"[discover_server_tools] enable_tool_guardrails={enable_tool_guardrails} for {server_name}"
                )

                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_tool_guardrails
                ):
                    sys_print(
                        f"[discover_server_tools] Validating config tools for {server_name}"
                    )
                    with tracer_obj.start_as_current_span(
                        "validate_config_tool_registration"
                    ) as validation_span:
                        validation_span.set_attribute("server_name", server_name)

                        # Convert config tools to list format for validation
                        tool_list = []
                        for tool_name, tool_data in config_tools.items():
                            if isinstance(tool_data, dict):
                                tool_list.append(tool_data)
                            else:
                                # Convert to dict format if needed
                                tool_list.append(
                                    {
                                        "name": tool_name,
                                        "description": getattr(
                                            tool_data, "description", ""
                                        ),
                                        "inputSchema": getattr(
                                            tool_data, "inputSchema", {}
                                        ),
                                        "outputSchema": getattr(
                                            tool_data, "outputSchema", None
                                        ),
                                        "annotations": getattr(
                                            tool_data, "annotations", {}
                                        ),
                                    }
                                )

                        tool_count = len(tool_list)
                        validation_span.set_attribute("tool_count", tool_count)

                        sys_print(
                            f"[discover_server_tools] Validating {tool_count} config tools for {server_name}"
                        )

                        try:
                            validation_response = await self.guardrail_manager.validate_tool_registration(
                                server_name=server_name,
                                tools=tool_list,
                                mode="filter",  # Filter unsafe tools but allow safe ones
                            )

                            if validation_response and validation_response.metadata:
                                blocked_count = validation_response.metadata.get(
                                    "blocked_tools_count", 0
                                )
                                safe_count = validation_response.metadata.get(
                                    "safe_tools_count", 0
                                )

                                validation_span.set_attribute(
                                    "blocked_tools_count", blocked_count
                                )
                                validation_span.set_attribute(
                                    "safe_tools_count", safe_count
                                )

                                if blocked_count > 0:
                                    blocked_tools = validation_response.metadata.get(
                                        "blocked_tools", []
                                    )
                                    # Store for return value
                                    blocked_tools_list = blocked_tools
                                    blocked_tools_count = blocked_count

                                    # Extract all reasons from blocked tools
                                    for blocked_tool in blocked_tools:
                                        reasons = blocked_tool.get("reasons", [])
                                        blocked_reasons_list.extend(reasons)

                                    sys_print(
                                        f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe config tools from {server_name}",
                                        is_error=True,
                                    )
                                    sys_print(
                                        "[discover_server_tools] === BLOCKED CONFIG TOOLS DETAILS ===",
                                        is_error=True,
                                    )
                                    for blocked_tool in blocked_tools:
                                        tool_name = blocked_tool.get("name", "unknown")
                                        reasons = blocked_tool.get("reasons", [])
                                        sys_print(
                                            f"[discover_server_tools]   ❌ {tool_name}:",
                                            is_error=True,
                                        )
                                        for reason in reasons:
                                            sys_print(
                                                f"[discover_server_tools]      → {reason}",
                                                is_error=True,
                                            )
                                    sys_print(
                                        "[discover_server_tools] ==================================",
                                        is_error=True,
                                    )
                                    logger.warning(
                                        "enkrypt_discover_all_tools.config_tools_blocked_by_guardrails",
                                        extra={
                                            **build_log_extra(
                                                ctx, custom_id, server_name
                                            ),
                                            "blocked_count": blocked_count,
                                            "blocked_tools": blocked_tools,
                                        },
                                    )

                                # Filter out blocked tools from config_tools
                                if blocked_count > 0:
                                    blocked_tool_names = {
                                        tool.get("name") for tool in blocked_tools
                                    }
                                    config_tools = {
                                        name: tool
                                        for name, tool in config_tools.items()
                                        if name not in blocked_tool_names
                                    }

                                sys_print(
                                    f"[discover_server_tools] ✓ {safe_count} safe config tools approved for {server_name}"
                                )

                        except Exception as validation_error:
                            # Fail open: if validation fails, allow the tools
                            sys_print(
                                f"[discover_server_tools] Config tool validation error: {validation_error}",
                                is_error=True,
                            )
                            logger.error(
                                "enkrypt_discover_all_tools.config_tool_validation_error",
                                extra={
                                    **build_log_extra(ctx, custom_id, server_name),
                                    "error": str(validation_error),
                                },
                            )
                            validation_span.set_attribute(
                                "validation_error", str(validation_error)
                            )
                else:
                    sys_print(
                        f"[discover_server_tools] Skipping config tool validation for {server_name} (enable_tool_guardrails={enable_tool_guardrails})"
                    )

                main_span = trace.get_current_span()
                main_span.set_attribute("success", True)

                return {
                    "status": "success",
                    "message": f"Tools already defined in config for {server_name}",
                    "tools": config_tools,
                    "source": "config",
                    "blocked_tools": blocked_tools_list,
                    "blocked_count": blocked_tools_count,
                    "blocked_reasons": blocked_reasons_list,
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
                        "blocked_tools": [],  # Cached tools already passed validation
                        "blocked_count": 0,
                        "blocked_reasons": [],
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
                    self.auth_manager.get_session_gateway_config(session_key),
                )
                end_time = time.time()
                tool_call_duration.record(
                    end_time - start_time,
                    attributes=build_log_extra(ctx, custom_id),
                )
                tool_span.set_attribute("duration", end_time - start_time)

                # Print result
                # sys_print(f"[discover_server_tools] Result: {result}")

                # Handle new return format with server metadata
                if isinstance(result, dict) and "tools" in result:
                    tools = result["tools"]
                    server_metadata = result.get("server_metadata", {})
                    dynamic_description = server_metadata.get("description")
                    dynamic_name = server_metadata.get("name")
                    dynamic_version = server_metadata.get("version")

                    # Print dynamic server information
                    sys_print(
                        f"[discover_server_tools] 🔍 Dynamic Server Info for {server_name}:"
                    )
                    sys_print(
                        f"[discover_server_tools]   📝 Description: '{dynamic_description}'"
                    )
                    sys_print(f"[discover_server_tools]   🏷️  Name: '{dynamic_name}'")
                    sys_print(
                        f"[discover_server_tools]   📦 Version: '{dynamic_version}'"
                    )
                else:
                    tools = result
                    server_metadata = {}
                    dynamic_description = None
                    dynamic_name = None
                    dynamic_version = None
                    sys_print(
                        f"[discover_server_tools] ⚠️  No dynamic metadata available for {server_name}"
                    )

                tool_span.set_attribute("tools_found", bool(tools))

                # NEW: Validate dynamic server description if available
                if (
                    dynamic_description
                    and self.registration_validation_enabled
                    and self.guardrail_manager
                ):
                    with tracer_obj.start_as_current_span(
                        "validate_dynamic_server_description"
                    ) as dynamic_desc_span:
                        dynamic_desc_span.set_attribute("server_name", server_name)
                        dynamic_desc_span.set_attribute("description_source", "dynamic")

                        sys_print(
                            f"[discover_server_tools] Validating dynamic server description: '{dynamic_description}'"
                        )

                        try:
                            # Create a mock tool object with the dynamic description for validation
                            dynamic_description_tool = {
                                "name": f"{server_name}",
                                "description": dynamic_description,
                                "inputSchema": {},
                                "outputSchema": None,
                                "annotations": {},
                            }

                            validation_response = (
                                await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name,
                                    tools=[dynamic_description_tool],
                                    mode="block",  # Block if description is harmful
                                )
                            )

                            if validation_response and validation_response.metadata:
                                blocked_count = validation_response.metadata.get(
                                    "blocked_tools_count", 0
                                )

                                if blocked_count > 0:
                                    blocked_tools = validation_response.metadata.get(
                                        "blocked_tools", []
                                    )
                                    violation_messages = []

                                    for blocked_tool in blocked_tools:
                                        reasons = blocked_tool.get("reasons", [])
                                        violation_messages.extend(reasons)

                                    dynamic_desc_span.set_attribute(
                                        "description_blocked", True
                                    )
                                    dynamic_desc_span.set_attribute(
                                        "violation_count", len(violation_messages)
                                    )

                                    sys_print(
                                        f"[discover_server_tools] ⚠️  BLOCKED UNSAFE DYNAMIC SERVER DESCRIPTION: {server_name}",
                                        is_error=True,
                                    )
                                    sys_print(
                                        "[discover_server_tools] === DYNAMIC SERVER DESCRIPTION BLOCKED ===",
                                        is_error=True,
                                    )
                                    for violation in violation_messages:
                                        sys_print(
                                            f"[discover_server_tools]   ❌ {violation}",
                                            is_error=True,
                                        )
                                    sys_print(
                                        "[discover_server_tools] ========================================",
                                        is_error=True,
                                    )

                                    logger.error(
                                        "enkrypt_discover_all_tools.dynamic_server_description_blocked_by_guardrails",
                                        extra={
                                            **build_log_extra(
                                                ctx, custom_id, server_name
                                            ),
                                            "violations": violation_messages,
                                            "description": dynamic_description,
                                        },
                                    )

                                    return {
                                        "status": "success",
                                        "error": f"Server '{server_name}' blocked by security guardrails: Harmful content detected in dynamic server description",
                                        "blocked": True,
                                        "violations": violation_messages,
                                    }
                                else:
                                    # Dynamic description is safe
                                    sys_print(
                                        f"[discover_server_tools] ✓ Dynamic server description for {server_name} passed validation"
                                    )
                                    dynamic_desc_span.set_attribute(
                                        "description_safe", True
                                    )

                        except Exception as dynamic_desc_validation_error:
                            # Fail open: if validation fails, allow the server
                            sys_print(
                                f"[discover_server_tools] Dynamic server description validation error: {dynamic_desc_validation_error}",
                                is_error=True,
                            )
                            logger.error(
                                "enkrypt_discover_all_tools.dynamic_server_description_validation_error",
                                extra={
                                    **build_log_extra(ctx, custom_id, server_name),
                                    "error": str(dynamic_desc_validation_error),
                                },
                            )
                            dynamic_desc_span.set_attribute(
                                "validation_error", str(dynamic_desc_validation_error)
                            )

                # NEW: Validate static server description with guardrails (after dynamic capture)
                if self.registration_validation_enabled and self.guardrail_manager:
                    with tracer_obj.start_as_current_span(
                        "validate_static_server_description"
                    ) as static_desc_span:
                        static_desc_span.set_attribute("server_name", server_name)

                        # Get server description from config (static)
                        static_server_description = server_info.get("description", "")
                        static_desc_span.set_attribute("description_source", "static")

                        sys_print(
                            f"[discover_server_tools] Validating static server description: '{static_server_description}'"
                        )

                        try:
                            # Create a mock tool object with the static description for validation
                            static_description_tool = {
                                "name": f"{server_name}",
                                "description": static_server_description,
                                "inputSchema": {},
                                "outputSchema": None,
                                "annotations": {},
                            }

                            validation_response = (
                                await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name,
                                    tools=[static_description_tool],
                                    mode="block",  # Block if description is harmful
                                )
                            )

                            if validation_response and validation_response.metadata:
                                blocked_count = validation_response.metadata.get(
                                    "blocked_tools_count", 0
                                )

                                if blocked_count > 0:
                                    blocked_tools = validation_response.metadata.get(
                                        "blocked_tools", []
                                    )
                                    violation_messages = []

                                    for blocked_tool in blocked_tools:
                                        reasons = blocked_tool.get("reasons", [])
                                        violation_messages.extend(reasons)

                                    static_desc_span.set_attribute(
                                        "description_blocked", True
                                    )
                                    static_desc_span.set_attribute(
                                        "violation_count", len(violation_messages)
                                    )

                                    sys_print(
                                        f"[discover_server_tools] ⚠️  BLOCKED UNSAFE STATIC SERVER DESCRIPTION: {server_name}",
                                        is_error=True,
                                    )
                                    sys_print(
                                        "[discover_server_tools] === STATIC SERVER DESCRIPTION BLOCKED ===",
                                        is_error=True,
                                    )
                                    for violation in violation_messages:
                                        sys_print(
                                            f"[discover_server_tools]   ❌ {violation}",
                                            is_error=True,
                                        )
                                    sys_print(
                                        "[discover_server_tools] ======================================",
                                        is_error=True,
                                    )

                                    logger.error(
                                        "enkrypt_discover_all_tools.static_server_description_blocked_by_guardrails",
                                        extra={
                                            **build_log_extra(
                                                ctx, custom_id, server_name
                                            ),
                                            "violations": violation_messages,
                                            "description": static_server_description,
                                        },
                                    )

                                    return {
                                        "status": "success",
                                        "error": f"Server '{server_name}' blocked by security guardrails: Harmful content detected in static server description",
                                        "blocked": True,
                                        "violations": violation_messages,
                                    }
                                else:
                                    # Static description is safe
                                    sys_print(
                                        f"[discover_server_tools] ✓ Static server description for {server_name} passed validation"
                                    )
                                    static_desc_span.set_attribute(
                                        "description_safe", True
                                    )

                        except Exception as static_desc_validation_error:
                            # Fail open: if validation fails, allow the server
                            sys_print(
                                f"[discover_server_tools] Static server description validation error: {static_desc_validation_error}",
                                is_error=True,
                            )
                            logger.error(
                                "enkrypt_discover_all_tools.static_server_description_validation_error",
                                extra={
                                    **build_log_extra(ctx, custom_id, server_name),
                                    "error": str(static_desc_validation_error),
                                },
                            )
                            static_desc_span.set_attribute(
                                "validation_error", str(static_desc_validation_error)
                            )

                # Track blocked tools information
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

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

                    # NEW: Validate tools with guardrails before caching
                    enable_tool_guardrails = server_info.get(
                        "enable_tool_guardrails", True
                    )
                    sys_print(
                        f"[discover_server_tools] enable_tool_guardrails={enable_tool_guardrails} for {server_name}"
                    )

                    if (
                        self.registration_validation_enabled
                        and self.guardrail_manager
                        and enable_tool_guardrails
                    ):
                        sys_print(
                            f"[discover_server_tools] Validating discovered tools for {server_name}"
                        )
                        with tracer_obj.start_as_current_span(
                            "validate_tool_registration"
                        ) as validation_span:
                            validation_span.set_attribute("server_name", server_name)

                            # Extract tool list from ListToolsResult or dict
                            if hasattr(tools, "tools"):
                                # ListToolsResult object
                                tool_list = list(tools.tools)
                            elif isinstance(tools, dict):
                                tool_list = tools.get("tools", [])
                            else:
                                tool_list = list(tools) if tools else []

                            tool_count = len(tool_list)
                            validation_span.set_attribute("tool_count", tool_count)

                            sys_print(
                                f"[discover_server_tools] Validating {tool_count} tools for {server_name}"
                            )

                            try:
                                validation_response = await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name,
                                    tools=tool_list,
                                    mode="filter",  # Filter unsafe tools but allow safe ones
                                )

                                if validation_response and validation_response.metadata:
                                    blocked_count = validation_response.metadata.get(
                                        "blocked_tools_count", 0
                                    )
                                    safe_count = validation_response.metadata.get(
                                        "safe_tools_count", 0
                                    )

                                    validation_span.set_attribute(
                                        "blocked_tools_count", blocked_count
                                    )
                                    validation_span.set_attribute(
                                        "safe_tools_count", safe_count
                                    )

                                    if blocked_count > 0:
                                        blocked_tools = (
                                            validation_response.metadata.get(
                                                "blocked_tools", []
                                            )
                                        )
                                        # Store for return value
                                        blocked_tools_list = blocked_tools
                                        blocked_tools_count = blocked_count

                                        # Extract all reasons from blocked tools
                                        for blocked_tool in blocked_tools:
                                            reasons = blocked_tool.get("reasons", [])
                                            blocked_reasons_list.extend(reasons)

                                        sys_print(
                                            f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe tools from {server_name}",
                                            is_error=True,
                                        )
                                        sys_print(
                                            "[discover_server_tools] === BLOCKED TOOLS DETAILS ===",
                                            is_error=True,
                                        )
                                        for blocked_tool in blocked_tools:
                                            tool_name = blocked_tool.get(
                                                "name", "unknown"
                                            )
                                            reasons = blocked_tool.get("reasons", [])
                                            sys_print(
                                                f"[discover_server_tools]   ❌ {tool_name}:",
                                                is_error=True,
                                            )
                                            for reason in reasons:
                                                sys_print(
                                                    f"[discover_server_tools]      → {reason}",
                                                    is_error=True,
                                                )
                                        sys_print(
                                            "[discover_server_tools] ==============================",
                                            is_error=True,
                                        )
                                        logger.warning(
                                            "enkrypt_discover_all_tools.tools_blocked_by_guardrails",
                                            extra={
                                                **build_log_extra(
                                                    ctx, custom_id, server_name
                                                ),
                                                "blocked_count": blocked_count,
                                                "blocked_tools": blocked_tools,
                                            },
                                        )

                                    # Update tools with filtered list
                                    filtered_tools = validation_response.metadata.get(
                                        "filtered_tools", tool_list
                                    )
                                    if isinstance(tools, dict):
                                        tools["tools"] = filtered_tools
                                    else:
                                        tools = filtered_tools

                                    sys_print(
                                        f"[discover_server_tools] ✓ {safe_count} safe tools approved for {server_name}"
                                    )
                                    validation_span.set_attribute(
                                        "validation_success", True
                                    )

                            except Exception as validation_error:
                                # Fail open: if validation fails, allow all tools
                                sys_print(
                                    f"[discover_server_tools] Tool validation error: {validation_error}",
                                    is_error=True,
                                )
                                logger.error(
                                    "enkrypt_discover_all_tools.tool_validation_error",
                                    extra={
                                        **build_log_extra(ctx, custom_id, server_name),
                                        "error": str(validation_error),
                                    },
                                )
                                validation_span.set_attribute(
                                    "validation_error", str(validation_error)
                                )
                    else:
                        sys_print(
                            f"[discover_server_tools] Skipping discovered tool validation for {server_name} (enable_tool_guardrails={enable_tool_guardrails})"
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
                    "blocked_tools": blocked_tools_list,
                    "blocked_count": blocked_tools_count,
                    "blocked_reasons": blocked_reasons_list,
                }
