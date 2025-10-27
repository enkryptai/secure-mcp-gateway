from __future__ import annotations

import time
from typing import Any

from opentelemetry import trace

from secure_mcp_gateway.client import forward_tool_call

# Telemetry components will be obtained lazily when needed
from secure_mcp_gateway.error_handling import create_error_response
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_discovery_error,
)
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import cache_service
from secure_mcp_gateway.utils import (
    build_log_extra,
    get_server_info_by_name,
    logger,
    mask_key,
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
        logger_instance=None,
        IS_DEBUG_LOG_LEVEL: bool = False,
        session_key: str = None,
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

        logger.info(f"[discover_server_tools] Requested for server: {server_name}")
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
            gateway_config = await self.auth_manager.get_local_mcp_config(
                enkrypt_gateway_key, enkrypt_project_id, enkrypt_user_id
            )

            # Generate session key if not provided (for backward compatibility)
            if session_key is None:
                mcp_config_id = (
                    gateway_config.get("mcp_config_id", "not_provided")
                    if gateway_config
                    else "not_provided"
                )
                session_key = f"{enkrypt_gateway_key}_{enkrypt_project_id}_{enkrypt_user_id}_{mcp_config_id}"

            if not gateway_config:
                logger.error(
                    f"[enkrypt_discover_all_tools] No local MCP config found for gateway_key={mask_key(enkrypt_gateway_key)}, project_id={enkrypt_project_id}, user_id={enkrypt_user_id}"
                )
                context = ErrorContext(
                    operation="discover.init",
                    request_id=getattr(ctx, "request_id", None),
                )
                error = create_discovery_error(
                    code=ErrorCode.CONFIG_MISSING_REQUIRED,
                    message="No MCP config found. Please check your credentials.",
                    context=context,
                )
                return create_error_response(error)

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
                    logger_instance,
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
                        logger_instance,
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
                    logger_instance,
                    IS_DEBUG_LOG_LEVEL,
                )

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))

                # Use standardized error handling
                from secure_mcp_gateway.error_handling import error_logger

                context = ErrorContext(
                    operation="discovery.server_tools_discovery",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )

                error = create_discovery_error(
                    code=ErrorCode.DISCOVERY_FAILED,
                    message=f"Server tools discovery failed: {e}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)

                logger.error(f"[discover_server_tools] Exception: {e}")
                logger.error(
                    "enkrypt_discover_all_tools.exception",
                    extra=build_log_extra(ctx, custom_id, error=str(e)),
                )
                import traceback

                traceback.print_exc()
                context = ErrorContext(
                    operation="discover.exception",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )
                error = create_discovery_error(
                    code=ErrorCode.DISCOVERY_FAILED,
                    message=f"Tool discovery failed: {e}",
                    context=context,
                    cause=e,
                )
                return create_error_response(error)

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
        logger_instance,
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
                    if logger_instance and logger_instance.level <= 10:  # DEBUG level
                        logger_instance.error(
                            "[discover_server_tools] Not authenticated"
                        )
                    context = ErrorContext(
                        operation="discover.auth",
                        request_id=getattr(ctx, "request_id", None),
                        server_name=server_name,
                    )
                    error = create_discovery_error(
                        code=ErrorCode.AUTH_INVALID_CREDENTIALS,
                        message="Not authenticated.",
                        context=context,
                    )
                    return create_error_response(error)
        return None

    async def _discover_all_servers(
        self,
        ctx,
        session_key,
        tracer_obj,
        custom_id,
        logger_instance,
        IS_DEBUG_LOG_LEVEL,
        enkrypt_project_id,
        enkrypt_user_id,
        enkrypt_mcp_config_id,
        enkrypt_project_name,
        enkrypt_email,
    ):
        """Discover tools for all servers using three-phase parallel approach."""
        with tracer_obj.start_as_current_span("discover_all_servers") as all_span:
            all_span.set_attribute("custom_id", custom_id)
            all_span.set_attribute("discovery_started", True)
            all_span.set_attribute("project_id", enkrypt_project_id)
            all_span.set_attribute("user_id", enkrypt_user_id)
            all_span.set_attribute("mcp_config_id", enkrypt_mcp_config_id)
            all_span.set_attribute("enkrypt_project_name", enkrypt_project_name)
            all_span.set_attribute("enkrypt_email", enkrypt_email)

            logger.info(
                "[discover_server_tools] Discovering tools for all servers using three-phase parallel approach"
            )
            logger.info(
                "enkrypt_discover_all_tools.discovering_all_servers",
                extra=build_log_extra(ctx, custom_id, server_name=None),
            )
            # Get telemetry metrics lazily
            telemetry_manager = get_telemetry_config_manager()
            if (
                hasattr(telemetry_manager, "list_servers_call_count")
                and telemetry_manager.list_servers_call_count
            ):
                telemetry_manager.list_servers_call_count.add(
                    1, attributes=build_log_extra(ctx, custom_id)
                )

            # Import here to avoid circular imports
            from secure_mcp_gateway.gateway import enkrypt_list_all_servers

            all_servers = await enkrypt_list_all_servers(ctx, discover_tools=True)
            all_servers_with_tools = all_servers.get("available_servers", {})
            servers_needing_discovery = all_servers.get("servers_needing_discovery", [])

            all_span.set_attribute("total_servers", len(servers_needing_discovery))

            status = "success"
            message = "Tools discovery tried for all servers"
            discovery_failed_servers = []
            discovery_success_servers = []

            import asyncio

            # PHASE 1: Validate all servers in parallel
            logger.info(
                "[discover_server_tools] 🔄 Phase 1: Validating all servers in parallel"
            )
            server_validation_results = await self._validate_all_servers_parallel(
                ctx,
                servers_needing_discovery,
                tracer_obj,
                custom_id,
                logger_instance,
                session_key,
            )

            # PHASE 2: Separate servers by config tool availability
            logger.info(
                "[discover_server_tools] 🔄 Phase 2: Separating servers by config tool availability"
            )
            servers_with_config_tools = []
            servers_needing_discovery_phase3 = []

            for server_name, validation_result in server_validation_results.items():
                if validation_result.get("status") == "success":
                    server_info = get_server_info_by_name(
                        self.auth_manager.get_session_gateway_config(session_key),
                        server_name,
                    )
                    config_tools = server_info.get("tools", {}) if server_info else {}

                    if config_tools:
                        servers_with_config_tools.append(server_name)
                        logger.info(
                            f"[discover_server_tools]   📋 {server_name} has config tools"
                        )
                    else:
                        servers_needing_discovery_phase3.append(server_name)
                        logger.info(
                            f"[discover_server_tools]   🔍 {server_name} needs discovery"
                        )
                else:
                    discovery_failed_servers.append(server_name)
                    all_servers_with_tools[server_name] = validation_result

            # PHASE 3: Parallel execution of config tool validation and discovery+validation
            logger.info(
                "[discover_server_tools] 🔄 Phase 3: Parallel config tool validation and discovery+validation"
            )

            # Create tasks for both phases
            config_tool_tasks = []
            discovery_tasks = []

            # Config tool validation tasks
            for server_name in servers_with_config_tools:
                config_tool_tasks.append(
                    self._validate_config_tools_parallel(
                        ctx, server_name, session_key, tracer_obj, custom_id, logger
                    )
                )

            # Discovery+validation tasks
            for server_name in servers_needing_discovery_phase3:
                discovery_tasks.append(
                    self._discover_and_validate_tools_parallel(
                        ctx,
                        server_name,
                        session_key,
                        tracer_obj,
                        custom_id,
                        logger_instance,
                        IS_DEBUG_LOG_LEVEL,
                    )
                )

            # Execute both phases in parallel with timeout management
            from secure_mcp_gateway.services.timeout import get_timeout_manager

            timeout_manager = get_timeout_manager()

            all_tasks = config_tool_tasks + discovery_tasks

            # Create a proper async function for timeout manager
            async def _parallel_discovery():
                return await asyncio.gather(*all_tasks, return_exceptions=True)

            results = await timeout_manager.execute_with_timeout(
                _parallel_discovery,
                "discovery",
                f"parallel_discovery_{len(all_tasks)}_tasks",
            )

            # Extract results from timeout result
            if hasattr(results, "result"):
                results = results.result

            # Process results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    status = "error"
                    continue

                server_name = result.get("server_name")
                if not server_name:
                    continue

                if result.get("status") == "success":
                    discovery_success_servers.append(server_name)
                    all_servers_with_tools[server_name] = result
                else:
                    status = "error"
                    discovery_failed_servers.append(server_name)
                    all_servers_with_tools[server_name] = result

            # Update metrics lazily
            telemetry_manager = get_telemetry_config_manager()
            if (
                hasattr(telemetry_manager, "servers_discovered_count")
                and telemetry_manager.servers_discovered_count
            ):
                telemetry_manager.servers_discovered_count.add(
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

    async def _validate_all_servers_parallel(
        self,
        ctx,
        servers,
        tracer_obj,
        custom_id,
        logger_instance,
        session_key,
    ):
        """Phase 1: Validate all servers in parallel."""
        import asyncio

        async def _validate_single_server(server_name: str):
            with tracer_obj.start_as_current_span(
                f"validate_server_{server_name}"
            ) as server_span:
                server_span.set_attribute("server_name", server_name)
                server_span.set_attribute("custom_id", custom_id)

                try:
                    # Get server info
                    server_info = get_server_info_by_name(
                        self.auth_manager.get_session_gateway_config(session_key),
                        server_name,
                    )

                    if not server_info:
                        return {
                            "server_name": server_name,
                            "status": "error",
                            "message": f"Server '{server_name}' not available",
                        }

                    # Validate server registration
                    # Check per-server flag (defaults to True for backward compatibility)
                    enable_server_info_validation = server_info.get(
                        "enable_server_info_validation", True
                    )
                    if (
                        self.registration_validation_enabled
                        and self.guardrail_manager
                        and enable_server_info_validation
                    ):
                        server_validation_response = (
                            await self.guardrail_manager.validate_server_registration(
                                server_name=server_name, server_config=server_info
                            )
                        )

                        if (
                            server_validation_response
                            and not server_validation_response.is_safe
                        ):
                            violations = server_validation_response.violations
                            violation_messages = [v.message for v in violations]

                            server_span.set_attribute("server_blocked", True)
                            server_span.set_attribute(
                                "violation_count", len(violations)
                            )

                            logger.error(
                                f"[discover_server_tools] ⚠️  BLOCKED UNSAFE SERVER: {server_name}"
                            )

                            return {
                                "server_name": server_name,
                                "status": "error",
                                "message": f"Server '{server_name}' blocked by security guardrails: {', '.join(violation_messages)}",
                                "blocked": True,
                                "violations": violation_messages,
                            }
                        else:
                            logger.info(
                                f"[discover_server_tools] ✓ Server {server_name} passed validation"
                            )
                            server_span.set_attribute("server_safe", True)

                    return {
                        "server_name": server_name,
                        "status": "success",
                        "message": f"Server {server_name} validation successful",
                    }

                except Exception as e:
                    server_span.set_attribute("validation_error", str(e))

                    # Use standardized error handling
                    from secure_mcp_gateway.error_handling import error_logger

                    context = ErrorContext(
                        operation="discovery.server_validation",
                        request_id=getattr(ctx, "request_id", None),
                        server_name=server_name,
                    )

                    error = create_discovery_error(
                        code=ErrorCode.DISCOVERY_FAILED,
                        message=f"Server validation failed for {server_name}: {e}",
                        context=context,
                        cause=e,
                    )
                    error_logger.log_error(error)

                    return {
                        "server_name": server_name,
                        "status": "error",
                        "message": f"Server validation failed: {e}",
                        "error": str(e),
                    }

        # Execute all server validations in parallel with timeout management
        from secure_mcp_gateway.services.timeout import get_timeout_manager

        timeout_manager = get_timeout_manager()

        tasks = [_validate_single_server(server_name) for server_name in servers]

        # Create a proper async function for timeout manager
        async def _parallel_server_validation():
            return await asyncio.gather(*tasks, return_exceptions=True)

        results = await timeout_manager.execute_with_timeout(
            _parallel_server_validation,
            "discovery",
            f"server_validation_{len(servers)}_servers",
        )

        # Extract results from timeout result
        if hasattr(results, "result"):
            results = results.result

        # Convert results to dictionary
        validation_results = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            validation_results[result["server_name"]] = result

        return validation_results

    async def _validate_config_tools_parallel(
        self,
        ctx,
        server_name,
        session_key,
        tracer_obj,
        custom_id,
        logger_instance,
    ):
        """Phase 3a: Validate config tools for a single server."""
        with tracer_obj.start_as_current_span(
            f"validate_config_tools_{server_name}"
        ) as span:
            span.set_attribute("server_name", server_name)
            span.set_attribute("custom_id", custom_id)

            try:
                # Get server info and config tools
                server_info = get_server_info_by_name(
                    self.auth_manager.get_session_gateway_config(session_key),
                    server_name,
                )
                config_tools = server_info.get("tools", {}) if server_info else {}

                if not config_tools:
                    return {
                        "server_name": server_name,
                        "status": "error",
                        "message": f"No config tools found for {server_name}",
                    }

                logger.info(
                    f"[discover_server_tools] Validating config tools for {server_name}"
                )

                # Track blocked tools information
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

                # Validate config tools with guardrails
                enable_tool_guardrails = server_info.get("enable_tool_guardrails", True)

                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_tool_guardrails
                ):
                    # Convert config tools to list format for validation
                    tool_list = []
                    for tool_name, tool_data in config_tools.items():
                        if isinstance(tool_data, dict):
                            tool_list.append(tool_data)
                        else:
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

                    validation_response = (
                        await self.guardrail_manager.validate_tool_registration(
                            server_name=server_name,
                            tools=tool_list,
                            mode="filter",
                        )
                    )

                    if validation_response and validation_response.metadata:
                        blocked_count = validation_response.metadata.get(
                            "blocked_tools_count", 0
                        )
                        safe_count = validation_response.metadata.get(
                            "safe_tools_count", 0
                        )

                        if blocked_count > 0:
                            blocked_tools = validation_response.metadata.get(
                                "blocked_tools", []
                            )
                            blocked_tools_list = blocked_tools
                            blocked_tools_count = blocked_count

                            for blocked_tool in blocked_tools:
                                reasons = blocked_tool.get("reasons", [])
                                blocked_reasons_list.extend(reasons)

                            logger.info(
                                f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe config tools from {server_name}"
                            )

                        # Filter out blocked tools
                        if blocked_count > 0:
                            blocked_tool_names = {
                                tool.get("name") for tool in blocked_tools
                            }
                            config_tools = {
                                name: tool
                                for name, tool in config_tools.items()
                                if name not in blocked_tool_names
                            }

                        logger.info(
                            f"[discover_server_tools] ✓ {safe_count} safe config tools approved for {server_name}"
                        )

                span.set_attribute("success", True)
                return {
                    "server_name": server_name,
                    "status": "success",
                    "message": f"Tools already defined in config for {server_name}",
                    "tools": config_tools,
                    "source": "config",
                    "blocked_tools": blocked_tools_list,
                    "blocked_count": blocked_tools_count,
                    "blocked_reasons": blocked_reasons_list,
                }

            except Exception as e:
                span.set_attribute("error", str(e))

                # Use standardized error handling
                from secure_mcp_gateway.error_handling import error_logger

                context = ErrorContext(
                    operation="discovery.config_tools_validation",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )

                error = create_discovery_error(
                    code=ErrorCode.DISCOVERY_FAILED,
                    message=f"Config tools validation failed for {server_name}: {e}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)

                return {
                    "server_name": server_name,
                    "status": "error",
                    "message": f"Config tool validation failed: {e}",
                    "error": str(e),
                }

    async def _discover_and_validate_tools_parallel(
        self,
        ctx,
        server_name,
        session_key,
        tracer_obj,
        custom_id,
        logger_instance,
        IS_DEBUG_LOG_LEVEL,
    ):
        """Phase 3b: Discover and validate tools for a single server."""
        with tracer_obj.start_as_current_span(
            f"discover_and_validate_{server_name}"
        ) as span:
            span.set_attribute("server_name", server_name)
            span.set_attribute("custom_id", custom_id)

            try:
                # Get server info
                server_info = get_server_info_by_name(
                    self.auth_manager.get_session_gateway_config(session_key),
                    server_name,
                )

                if not server_info:
                    return {
                        "server_name": server_name,
                        "status": "error",
                        "message": f"Server '{server_name}' not available",
                    }

                # Check cache first
                id = self.auth_manager.get_session_gateway_config(session_key)["id"]
                cached_tools = self.cache_service.get_cached_tools(id, server_name)

                if cached_tools:
                    logger.info(
                        f"[discover_server_tools] Tools already cached for {server_name}"
                    )
                    return {
                        "server_name": server_name,
                        "status": "success",
                        "message": f"Tools retrieved from cache for {server_name}",
                        "tools": cached_tools,
                        "source": "cache",
                        "blocked_tools": [],
                        "blocked_count": 0,
                        "blocked_reasons": [],
                    }

                # Forward tool call to discover tools
                logger.info(
                    f"[discover_server_tools] Discovering tools for {server_name}"
                )
                result = await forward_tool_call(
                    server_name,
                    None,
                    None,
                    self.auth_manager.get_session_gateway_config(session_key),
                )

                # Handle result format
                if isinstance(result, dict) and "tools" in result:
                    tools = result["tools"]
                    server_metadata = result.get("server_metadata", {})
                else:
                    tools = result
                    server_metadata = {}

                if not tools:
                    return {
                        "server_name": server_name,
                        "status": "error",
                        "message": f"No tools discovered for {server_name}",
                    }

                # Validate discovered tools
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

                enable_tool_guardrails = server_info.get("enable_tool_guardrails", True)

                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_tool_guardrails
                ):
                    # Extract tool list
                    if hasattr(tools, "tools"):
                        tool_list = list(tools.tools)
                    elif isinstance(tools, dict):
                        tool_list = tools.get("tools", [])
                    else:
                        tool_list = list(tools) if tools else []

                    validation_response = (
                        await self.guardrail_manager.validate_tool_registration(
                            server_name=server_name,
                            tools=tool_list,
                            mode="filter",
                        )
                    )

                    if validation_response and validation_response.metadata:
                        blocked_count = validation_response.metadata.get(
                            "blocked_tools_count", 0
                        )
                        safe_count = validation_response.metadata.get(
                            "safe_tools_count", 0
                        )

                        if blocked_count > 0:
                            blocked_tools = validation_response.metadata.get(
                                "blocked_tools", []
                            )
                            blocked_tools_list = blocked_tools
                            blocked_tools_count = blocked_count

                            for blocked_tool in blocked_tools:
                                reasons = blocked_tool.get("reasons", [])
                                blocked_reasons_list.extend(reasons)

                            logger.info(
                                f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe tools from {server_name}"
                            )

                        # Update tools with filtered list
                        filtered_tools = validation_response.metadata.get(
                            "filtered_tools", tool_list
                        )
                        if isinstance(tools, dict):
                            tools["tools"] = filtered_tools
                        else:
                            tools = filtered_tools

                        logger.info(
                            f"[discover_server_tools] ✓ {safe_count} safe tools approved for {server_name}"
                        )

                # Cache the tools
                self.cache_service.cache_tools(id, server_name, tools)

                span.set_attribute("success", True)
                return {
                    "server_name": server_name,
                    "status": "success",
                    "message": f"Tools discovered for {server_name}",
                    "tools": tools,
                    "source": "discovery",
                    "blocked_tools": blocked_tools_list,
                    "blocked_count": blocked_tools_count,
                    "blocked_reasons": blocked_reasons_list,
                }

            except Exception as e:
                span.set_attribute("error", str(e))

                # Use standardized error handling
                from secure_mcp_gateway.error_handling import error_logger

                context = ErrorContext(
                    operation="discovery.tool_discovery",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )

                error = create_discovery_error(
                    code=ErrorCode.DISCOVERY_FAILED,
                    message=f"Tool discovery failed for {server_name}: {e}",
                    context=context,
                    cause=e,
                )
                error_logger.log_error(error)

                return {
                    "server_name": server_name,
                    "status": "error",
                    "message": f"Tool discovery failed: {e}",
                    "error": str(e),
                }

    async def _discover_single_server(
        self,
        ctx,
        server_name,
        session_key,
        tracer_obj,
        custom_id,
        logger_instance,
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
                    logger.error(
                        f"[discover_server_tools] Server '{server_name}' not available"
                    )
                    logger.warning(
                        "enkrypt_discover_all_tools.server_not_available",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )
                context = ErrorContext(
                    operation="discover.server_info",
                    request_id=getattr(ctx, "request_id", None),
                    server_name=server_name,
                )
                error = create_discovery_error(
                    code=ErrorCode.DISCOVERY_SERVER_UNAVAILABLE,
                    message=f"Server '{server_name}' not available.",
                    context=context,
                )
                return create_error_response(error)

            id = self.auth_manager.get_session_gateway_config(session_key)["id"]
            info_span.set_attribute("gateway_id", id)

            # NEW: Validate server registration before proceeding
            # Check per-server flag (defaults to True for backward compatibility)
            enable_server_info_validation = server_info.get(
                "enable_server_info_validation", True
            )
            if (
                self.registration_validation_enabled
                and self.guardrail_manager
                and enable_server_info_validation
            ):
                with tracer_obj.start_as_current_span(
                    "validate_server_registration"
                ) as server_validation_span:
                    server_validation_span.set_attribute("server_name", server_name)

                    logger.info(
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

                            logger.error(
                                f"[discover_server_tools] ⚠️  BLOCKED UNSAFE SERVER: {server_name}"
                            )
                            logger.error(
                                "[discover_server_tools] === SERVER BLOCKED ==="
                            )
                            for violation in violations:
                                logger.error(
                                    f"[discover_server_tools]   ❌ {violation.message}"
                                )
                            logger.error(
                                "[discover_server_tools] ========================"
                            )

                            logger.error(
                                "enkrypt_discover_all_tools.server_blocked_by_guardrails",
                                extra={
                                    **build_log_extra(ctx, custom_id, server_name),
                                    "violations": violation_messages,
                                },
                            )

                            # Return standardized error response
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )
                            from secure_mcp_gateway.exceptions import (
                                create_guardrail_error,
                            )

                            context = ErrorContext(
                                operation="discover.server_blocked_by_guardrails",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )

                            error = create_guardrail_error(
                                code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                                message=f"Server '{server_name}' blocked by security guardrails: {', '.join(violation_messages)}",
                                context=context,
                            )
                            error_logger.log_error(error)

                            error_response = create_error_response(error)
                            error_response.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": violation_messages,
                                }
                            )
                            return error_response
                        else:
                            # Server is safe
                            logger.info(
                                f"[discover_server_tools] ✓ Server {server_name} passed validation"
                            )
                            server_validation_span.set_attribute("server_safe", True)

                    except Exception as server_validation_error:
                        # Check if this is a timeout error - fail closed for timeouts
                        from secure_mcp_gateway.exceptions import (
                            TimeoutError as MCPTimeoutError,
                        )

                        is_timeout_error = (
                            isinstance(server_validation_error, MCPTimeoutError)
                            or "GUARDRAIL_TIMEOUT:" in str(server_validation_error)
                            or "timed out" in str(server_validation_error).lower()
                        )

                        if is_timeout_error:
                            # Timeout occurred - block the server (fail closed)
                            logger.error(
                                f"[discover_server_tools] ⚠️  Timeout occurred during server validation for {server_name} - blocking server"
                            )

                            # Log timeout error with proper error handling
                            from secure_mcp_gateway.error_handling import error_logger

                            context = ErrorContext(
                                operation="discover.server_validation_timeout",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )

                            error = create_discovery_error(
                                code=ErrorCode.DISCOVERY_FAILED,
                                message=f"Server validation timed out for {server_name}",
                                context=context,
                            )
                            error_logger.log_error(error)

                            server_validation_span.set_attribute("server_blocked", True)
                            server_validation_span.set_attribute("timeout_error", True)

                            # Return standardized error response
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                            )

                            error_response = create_error_response(error)
                            error_response.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": ["Server validation timed out"],
                                }
                            )
                            return error_response
                        else:
                            # Other errors - FAIL CLOSED: if validation fails, block the server
                            logger.error(
                                f"[discover_server_tools] ⚠️  Server validation error for {server_name} - blocking server (fail-closed)"
                            )

                            # Log with standardized error handling
                            from secure_mcp_gateway.error_handling import error_logger
                            from secure_mcp_gateway.exceptions import (
                                create_guardrail_error,
                            )

                            context = ErrorContext(
                                operation="discover.server_validation_error",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )

                            error = create_guardrail_error(
                                code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                                message=f"Server validation failed for {server_name}",
                                context=context,
                                cause=server_validation_error,
                            )
                            error_logger.log_error(error)

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
                        server_validation_span.set_attribute("server_blocked", True)

                        # Return standardized error response
                        from secure_mcp_gateway.error_handling import (
                            create_error_response,
                        )

                        error_response = create_error_response(error)
                        # Add discovery-specific context
                        error_response.update(
                            {
                                "server_name": server_name,
                                "blocked": True,
                                "violations": [str(server_validation_error)],
                            }
                        )
                        return error_response

            # NOTE: Static description validation moved to after dynamic description capture
            # to ensure we can validate both static and dynamic descriptions together

            # Check if server has configured tools in the gateway config
            config_tools = server_info.get("tools", {})
            info_span.set_attribute("has_config_tools", bool(config_tools))

            # PHASE 2: Server description validation for ALL servers (parallel)
            # This happens regardless of whether server has config tools or not
            # Check per-server flag (defaults to True for backward compatibility)
            enable_server_info_validation = server_info.get(
                "enable_server_info_validation", True
            )
            if (
                self.registration_validation_enabled
                and self.guardrail_manager
                and enable_server_info_validation
            ):
                logger.info(
                    f"[discover_server_tools] 🔄 Starting server description validation for {server_name}"
                )

                # Get static description from config
                static_desc = server_info.get("description", "")
                logger.info(
                    f"[discover_server_tools]   Static description: '{static_desc}'"
                )

                # ALL servers get both static and dynamic description validation
                # This happens regardless of whether server has config tools or not
                logger.info(
                    f"[discover_server_tools] 🔄 Starting server description validation for {server_name}"
                )
                logger.info(
                    f"[discover_server_tools]   Static description: '{static_desc}'"
                )
            else:
                logger.info(
                    f"[discover_server_tools] ⏭️  Skipping server description validation for {server_name} (enable_server_info_validation={enable_server_info_validation})"
                )

                # For servers with config tools, we'll get dynamic description during discovery
                # For servers without config tools, we'll also get dynamic description during discovery
                # Both will be validated in the discovery path below

            if config_tools:
                logger.info(
                    f"[discover_server_tools] Tools already defined in config for {server_name}"
                )
                logger.info(
                    "enkrypt_discover_all_tools.tools_already_defined_in_config",
                    extra=build_log_extra(ctx, custom_id, server_name),
                )

                # For config servers, we still need to get dynamic description for validation
                # This ensures ALL servers get both static and dynamic description validation
                logger.info(
                    f"[discover_server_tools] 🔄 Getting dynamic description for config server {server_name}"
                )

                # Get dynamic description by getting server metadata ONLY (no tool discovery)
                try:
                    from secure_mcp_gateway.client import get_server_metadata_only

                    result = await get_server_metadata_only(
                        server_name,
                        self.auth_manager.get_session_gateway_config(session_key),
                    )

                    # Extract dynamic description from result
                    if isinstance(result, dict) and "server_metadata" in result:
                        server_metadata = result.get("server_metadata", {})
                        dynamic_description = server_metadata.get("description", "")
                        dynamic_name = server_metadata.get("name", "")
                        dynamic_version = server_metadata.get("version", "")

                        logger.info(
                            f"[discover_server_tools] 🔍 Dynamic Server Info for {server_name}:"
                        )
                        logger.info(
                            f"[discover_server_tools]   📝 Description: '{dynamic_description}'"
                        )
                        logger.info(
                            f"[discover_server_tools]   🏷️  Name: '{dynamic_name}'"
                        )
                        logger.info(
                            f"[discover_server_tools]   📦 Version: '{dynamic_version}'"
                        )
                    else:
                        dynamic_description = ""
                        logger.info(
                            f"[discover_server_tools] ⚠️  No dynamic metadata available for {server_name}"
                        )

                except Exception as e:
                    logger.error(
                        f"[discover_server_tools] Error getting dynamic description for {server_name}: {e}"
                    )
                    dynamic_description = ""

                # Track blocked tools from config validation
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

                # NEW: Validate config tools with guardrails before returning
                enable_tool_guardrails = server_info.get("enable_tool_guardrails", True)
                logger.info(
                    f"[discover_server_tools] enable_tool_guardrails={enable_tool_guardrails} for {server_name}"
                )

                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_tool_guardrails
                ):
                    logger.info(
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

                        logger.info(
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

                                # Check if validation failed due to error (all tools blocked with error metadata)
                                is_validation_error = (
                                    validation_response.metadata.get("error")
                                    is not None
                                )
                                if (
                                    is_validation_error
                                    and safe_count == 0
                                    and tool_count > 0
                                ):
                                    # Validation failed - treat as error
                                    error_msg = validation_response.metadata.get(
                                        "error", "Config tool validation failed"
                                    )

                                    logger.error(
                                        f"[discover_server_tools] ⚠️  Config tool validation failed for {server_name}: {error_msg}"
                                    )

                                    # Log with standardized error handling
                                    from secure_mcp_gateway.error_handling import (
                                        create_error_response,
                                        error_logger,
                                    )

                                    context = ErrorContext(
                                        operation="discover.config_tool_validation_failed",
                                        request_id=getattr(ctx, "request_id", None),
                                        server_name=server_name,
                                    )

                                    error = create_discovery_error(
                                        code=ErrorCode.DISCOVERY_TOOL_VALIDATION_FAILED,
                                        message=f"Config tool validation failed for {server_name}: {error_msg}",
                                        context=context,
                                    )
                                    error_logger.log_error(error)

                                    # Return standardized error response
                                    error_response = create_error_response(error)
                                    error_response.update(
                                        {
                                            "server_name": server_name,
                                            "blocked": True,
                                            "tools": {},
                                            "source": "config",
                                            "blocked_tools": [],
                                            "blocked_count": 0,
                                            "blocked_reasons": [error_msg],
                                        }
                                    )
                                    return error_response

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

                                    logger.error(
                                        f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe config tools from {server_name}"
                                    )
                                    logger.error(
                                        "[discover_server_tools] === BLOCKED CONFIG TOOLS DETAILS ==="
                                    )
                                    for blocked_tool in blocked_tools:
                                        tool_name = blocked_tool.get("name", "unknown")
                                        reasons = blocked_tool.get("reasons", [])
                                        logger.error(
                                            f"[discover_server_tools]   ❌ {tool_name}:"
                                        )
                                        for reason in reasons:
                                            logger.error(
                                                f"[discover_server_tools]      → {reason}"
                                            )
                                    logger.error(
                                        "[discover_server_tools] =================================="
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
                                # Check if validation failed due to timeout
                                is_timeout_error = validation_response.metadata.get(
                                    "timeout", False
                                )

                                if is_timeout_error:
                                    # Timeout occurred - block all tools and return error response
                                    logger.error(
                                        f"[discover_server_tools] ⚠️  Timeout occurred during config tool validation for {server_name} - blocking all tools"
                                    )

                                    # Log timeout error with proper error handling
                                    from secure_mcp_gateway.error_handling import (
                                        create_error_response,
                                        error_logger,
                                    )
                                    from secure_mcp_gateway.exceptions import (
                                        create_guardrail_timeout_error,
                                    )

                                    context = ErrorContext(
                                        operation="discover.config_tool_validation_timeout",
                                        request_id=getattr(ctx, "request_id", None),
                                        server_name=server_name,
                                    )

                                    error = create_guardrail_timeout_error(
                                        timeout_duration=1.0,  # Will be updated with actual duration
                                        context=context,
                                    )
                                    error_logger.log_error(error)

                                    # Return standardized error response with discovery structure
                                    timeout_duration = validation_response.metadata.get(
                                        "timeout_duration", "unknown"
                                    )
                                    error_response = create_error_response(error)
                                    # Return error in discovery response format
                                    return {
                                        "status": "error",
                                        "message": f"Config tool validation timed out for {server_name}",
                                        "error": error_response.get("error"),
                                        "error_code": error.code.value,
                                        "timeout_duration": timeout_duration,
                                        "tools": {},
                                        "source": "config",
                                        "blocked": True,
                                        "blocked_tools": [],
                                        "blocked_count": 0,
                                        "blocked_reasons": [
                                            f"Guardrail validation timed out after {timeout_duration}s"
                                        ],
                                    }
                                elif blocked_count > 0:
                                    blocked_tool_names = {
                                        tool.get("name") for tool in blocked_tools
                                    }
                                    config_tools = {
                                        name: tool
                                        for name, tool in config_tools.items()
                                        if name not in blocked_tool_names
                                    }

                                logger.info(
                                    f"[discover_server_tools] ✓ {safe_count} safe config tools approved for {server_name}"
                                )

                        except Exception as validation_error:
                            # Check if it's a timeout error - fail closed for timeouts
                            if (
                                "timeout" in str(validation_error).lower()
                                or "timed out" in str(validation_error).lower()
                            ):
                                logger.error(
                                    f"[discover_server_tools] Config tool validation timeout - blocking all tools: {validation_error}"
                                )
                                logger.error(
                                    "enkrypt_discover_all_tools.config_tool_validation_timeout",
                                    extra={
                                        **build_log_extra(ctx, custom_id, server_name),
                                        "error": str(validation_error),
                                    },
                                )
                                validation_span.set_attribute(
                                    "validation_timeout", True
                                )

                                # Return standardized error response for timeout
                                from secure_mcp_gateway.error_handling import (
                                    create_error_response,
                                    error_logger,
                                )
                                from secure_mcp_gateway.exceptions import (
                                    create_guardrail_timeout_error,
                                )

                                context = ErrorContext(
                                    operation="discover.config_tool_validation_timeout",
                                    request_id=getattr(ctx, "request_id", None),
                                    server_name=server_name,
                                )

                                error = create_guardrail_timeout_error(
                                    timeout_duration=1.0,  # Will be extracted from error if available
                                    context=context,
                                    cause=validation_error,
                                )
                                error_logger.log_error(error)

                                error_response = create_error_response(error)
                                error_response.update(
                                    {
                                        "server_name": server_name,
                                        "blocked": True,
                                        "tools": {},
                                        "source": "config",
                                        "blocked_tools": [],
                                        "blocked_count": 0,
                                        "blocked_reasons": [
                                            "Config tool validation timed out"
                                        ],
                                    }
                                )
                                return error_response
                            else:
                                # FAIL CLOSED: if validation fails for other reasons, block all tools
                                logger.error(
                                    f"[discover_server_tools] ⚠️  Config tool validation error for {server_name} - blocking all tools (fail-closed)"
                                )

                                # Log with standardized error handling
                                from secure_mcp_gateway.error_handling import (
                                    create_error_response,
                                    error_logger,
                                )

                                context = ErrorContext(
                                    operation="discover.config_tool_validation_error",
                                    request_id=getattr(ctx, "request_id", None),
                                    server_name=server_name,
                                )

                                error = create_discovery_error(
                                    code=ErrorCode.DISCOVERY_TOOL_VALIDATION_FAILED,
                                    message=f"Config tool validation failed for {server_name}",
                                    context=context,
                                    cause=validation_error,
                                )
                                error_logger.log_error(error)

                                validation_span.set_attribute(
                                    "validation_blocked", True
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

                            # Return standardized error response
                            error_response = create_error_response(error)
                            error_response.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "tools": {},
                                    "source": "config",
                                    "blocked_tools": [],
                                    "blocked_count": 0,
                                    "blocked_reasons": [
                                        "Config tool validation failed"
                                    ],
                                }
                            )
                            return error_response
                else:
                    logger.info(
                        f"[discover_server_tools] Skipping config tool validation for {server_name} (enable_tool_guardrails={enable_tool_guardrails})"
                    )

                # NEW: Parallel validation for config servers (static + dynamic descriptions)
                # Check per-server flag (defaults to True for backward compatibility)
                enable_server_info_validation = server_info.get(
                    "enable_server_info_validation", True
                )
                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_server_info_validation
                ):
                    logger.info(
                        f"[discover_server_tools] 🔄 Starting parallel validation for config server {server_name}"
                    )
                    logger.info(
                        f"[discover_server_tools]   Dynamic description: '{dynamic_description}'"
                    )
                    logger.info(
                        f"[discover_server_tools]   Static description: '{static_desc}'"
                    )

                    async def _validate_dynamic_config():
                        if not dynamic_description:
                            logger.info(
                                "[discover_server_tools] ⏭️  Skipping dynamic validation (empty description)"
                            )
                            return {"status": "skip"}
                        with tracer_obj.start_as_current_span(
                            "validate_dynamic_server_description_config"
                        ) as dynamic_desc_span:
                            dynamic_desc_span.set_attribute("server_name", server_name)
                            dynamic_desc_span.set_attribute(
                                "description_source", "dynamic"
                            )
                            logger.info(
                                f"[discover_server_tools] Validating dynamic server description: '{dynamic_description}'"
                            )
                            try:
                                tool = {
                                    "name": f"{server_name}",
                                    "description": dynamic_description,
                                    "inputSchema": {},
                                    "outputSchema": None,
                                    "annotations": {},
                                }
                                resp = await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name, tools=[tool], mode="block"
                                )
                                if resp and resp.metadata:
                                    blocked = resp.metadata.get(
                                        "blocked_tools_count", 0
                                    )
                                    if blocked > 0:
                                        violations = []
                                        for b in resp.metadata.get("blocked_tools", []):
                                            violations.extend(b.get("reasons", []))
                                        dynamic_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        dynamic_desc_span.set_attribute(
                                            "violation_count", len(violations)
                                        )
                                        return {
                                            "status": "blocked",
                                            "violations": violations,
                                            "source": "dynamic",
                                        }
                                dynamic_desc_span.set_attribute(
                                    "description_safe", True
                                )
                                return {"status": "ok"}
                            except Exception as e:
                                return {
                                    "status": "error",
                                    "error": e,
                                    "source": "dynamic",
                                }

                    async def _validate_static_config():
                        if not static_desc:
                            return {"status": "skip"}
                        with tracer_obj.start_as_current_span(
                            "validate_static_server_description_config"
                        ) as static_desc_span:
                            static_desc_span.set_attribute("server_name", server_name)
                            static_desc_span.set_attribute(
                                "description_source", "static"
                            )
                            logger.info(
                                f"[discover_server_tools] Validating static server description: '{static_desc}'"
                            )
                            try:
                                tool = {
                                    "name": f"{server_name}",
                                    "description": static_desc,
                                    "inputSchema": {},
                                    "outputSchema": None,
                                    "annotations": {},
                                }
                                resp = await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name, tools=[tool], mode="block"
                                )
                                if resp and resp.metadata:
                                    if resp.metadata.get("timeout", False):
                                        static_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        static_desc_span.set_attribute(
                                            "timeout_error", True
                                        )
                                        return {
                                            "status": "timeout",
                                            "violations": [
                                                "Static server description validation timed out"
                                            ],
                                            "source": "static",
                                        }
                                    blocked = resp.metadata.get(
                                        "blocked_tools_count", 0
                                    )
                                    if blocked > 0:
                                        violations = []
                                        for b in resp.metadata.get("blocked_tools", []):
                                            violations.extend(b.get("reasons", []))
                                        static_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        static_desc_span.set_attribute(
                                            "violation_count", len(violations)
                                        )
                                        return {
                                            "status": "blocked",
                                            "violations": violations,
                                            "source": "static",
                                        }
                                static_desc_span.set_attribute("description_safe", True)
                                return {"status": "ok"}
                            except Exception as e:
                                return {
                                    "status": "error",
                                    "error": e,
                                    "source": "static",
                                }

                    logger.info(
                        f"[discover_server_tools] 🚀 Executing parallel validation for config server {server_name}"
                    )
                    import asyncio

                    # Use timeout management for parallel validation
                    from secure_mcp_gateway.services.timeout import get_timeout_manager

                    timeout_manager = get_timeout_manager()

                    dyn_task = _validate_dynamic_config()
                    stat_task = _validate_static_config()

                    # Create a proper async function for timeout manager
                    async def _parallel_validation():
                        return await asyncio.gather(dyn_task, stat_task)

                    results = await timeout_manager.execute_with_timeout(
                        _parallel_validation,
                        "discovery",
                        f"config_server_validation_{server_name}",
                    )

                    # Extract results from timeout result
                    if hasattr(results, "result"):
                        dyn_result, stat_result = results.result
                    else:
                        dyn_result, stat_result = results
                    logger.info(
                        f"[discover_server_tools] ✅ Parallel validation completed for config server {server_name}"
                    )

                    # Fail-closed prioritization: error/timeout/blocked wins over ok/skip
                    for res in (dyn_result, stat_result):
                        if res.get("status") == "timeout":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )

                            context = ErrorContext(
                                operation="discover.description_validation_timeout_parallel_config",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_discovery_error(
                                code=ErrorCode.DISCOVERY_FAILED,
                                message=f"{res.get('source').capitalize()} server description validation timed out for {server_name}",
                                context=context,
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": res.get("violations", []),
                                }
                            )
                            return er

                    for res in (dyn_result, stat_result):
                        if res.get("status") == "blocked":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )
                            from secure_mcp_gateway.exceptions import (
                                create_guardrail_error,
                            )

                            context = ErrorContext(
                                operation="discover.description_blocked_parallel_config",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_guardrail_error(
                                code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                                message=f"Server '{server_name}' blocked: Harmful content in {res.get('source')} description",
                                context=context,
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": res.get("violations", []),
                                }
                            )
                            return er

                    for res in (dyn_result, stat_result):
                        if res.get("status") == "error":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )

                            context = ErrorContext(
                                operation="discover.description_validation_error_parallel_config",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_discovery_error(
                                code=ErrorCode.DISCOVERY_FAILED,
                                message=f"{res.get('source').capitalize()} server description validation failed for {server_name}: {res.get('error')}",
                                context=context,
                                cause=res.get("error"),
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": [str(res.get("error"))],
                                }
                            )
                            return er
                else:
                    logger.info(
                        f"[discover_server_tools] ⏭️  Skipping description validation for config server {server_name} (enable_server_info_validation={enable_server_info_validation})"
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
                    # Update metrics lazily
                    telemetry_manager = get_telemetry_config_manager()
                    if (
                        hasattr(telemetry_manager, "cache_hit_counter")
                        and telemetry_manager.cache_hit_counter
                    ):
                        telemetry_manager.cache_hit_counter.add(
                            1, attributes=build_log_extra(ctx)
                        )
                    logger.info(
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
                    # Update metrics lazily
                    telemetry_manager = get_telemetry_config_manager()
                    if (
                        hasattr(telemetry_manager, "cache_miss_counter")
                        and telemetry_manager.cache_miss_counter
                    ):
                        telemetry_manager.cache_miss_counter.add(
                            1, attributes=build_log_extra(ctx)
                        )
                    logger.info(
                        f"[discover_server_tools] No cached tools found for {server_name}"
                    )
                    logger.info(
                        "enkrypt_discover_all_tools.no_cached_tools",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )

            # Forward tool call
            with tracer_obj.start_as_current_span("forward_tool_call") as tool_span:
                # Update metrics lazily
                telemetry_manager = get_telemetry_config_manager()
                if (
                    hasattr(telemetry_manager, "tool_call_counter")
                    and telemetry_manager.tool_call_counter
                ):
                    telemetry_manager.tool_call_counter.add(
                        1, attributes=build_log_extra(ctx, custom_id)
                    )
                start_time = time.time()
                result = await forward_tool_call(
                    server_name,
                    None,
                    None,
                    self.auth_manager.get_session_gateway_config(session_key),
                )
                end_time = time.time()
                # Update metrics lazily
                telemetry_manager = get_telemetry_config_manager()
                if (
                    hasattr(telemetry_manager, "tool_call_duration")
                    and telemetry_manager.tool_call_duration
                ):
                    telemetry_manager.tool_call_duration.record(
                        end_time - start_time,
                        attributes=build_log_extra(ctx, custom_id),
                    )
                tool_span.set_attribute("duration", end_time - start_time)

                # Print result
                # logger.info(f"[discover_server_tools] Result: {result}")

                # Handle new return format with server metadata
                if isinstance(result, dict) and "tools" in result:
                    tools = result["tools"]
                    server_metadata = result.get("server_metadata", {})
                    dynamic_description = server_metadata.get("description")
                    dynamic_name = server_metadata.get("name")
                    dynamic_version = server_metadata.get("version")

                    # Print dynamic server information
                    logger.info(
                        f"[discover_server_tools] 🔍 Dynamic Server Info for {server_name}:"
                    )
                    logger.info(
                        f"[discover_server_tools]   📝 Description: '{dynamic_description}'"
                    )
                    logger.info(f"[discover_server_tools]   🏷️  Name: '{dynamic_name}'")
                    logger.info(
                        f"[discover_server_tools]   📦 Version: '{dynamic_version}'"
                    )
                else:
                    tools = result
                    server_metadata = {}
                    dynamic_description = None
                    dynamic_name = None
                    dynamic_version = None
                    logger.info(
                        f"[discover_server_tools] ⚠️  No dynamic metadata available for {server_name}"
                    )

                tool_span.set_attribute("tools_found", bool(tools))

                # Parallel validation: dynamic and static descriptions
                # Check per-server flag (defaults to True for backward compatibility)
                enable_server_info_validation = server_info.get(
                    "enable_server_info_validation", True
                )
                if (
                    self.registration_validation_enabled
                    and self.guardrail_manager
                    and enable_server_info_validation
                ):
                    import asyncio

                    logger.info(
                        f"[discover_server_tools] 🔄 Starting parallel validation for {server_name}"
                    )
                    logger.info(
                        f"[discover_server_tools]   Dynamic description: '{dynamic_description}'"
                    )
                    logger.error(
                        f"[discover_server_tools]   Static description: '{server_info.get('description', '')}'"
                    )

                    async def _validate_dynamic():
                        if not dynamic_description:
                            logger.info(
                                "[discover_server_tools] ⏭️  Skipping dynamic validation (empty description)"
                            )
                            return {"status": "skip"}
                        with tracer_obj.start_as_current_span(
                            "validate_dynamic_server_description"
                        ) as dynamic_desc_span:
                            dynamic_desc_span.set_attribute("server_name", server_name)
                            logger.info(
                                f"[discover_server_tools] Validating dynamic server description: '{dynamic_description}'"
                            )
                            try:
                                tool = {
                                    "name": f"{server_name}",
                                    "description": dynamic_description,
                                    "inputSchema": {},
                                    "outputSchema": None,
                                    "annotations": {},
                                }
                                resp = await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name, tools=[tool], mode="block"
                                )
                                if resp and resp.metadata:
                                    blocked = resp.metadata.get(
                                        "blocked_tools_count", 0
                                    )
                                    if blocked > 0:
                                        violations = []
                                        for b in resp.metadata.get("blocked_tools", []):
                                            violations.extend(b.get("reasons", []))
                                        dynamic_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        dynamic_desc_span.set_attribute(
                                            "violation_count", len(violations)
                                        )
                                        return {
                                            "status": "blocked",
                                            "violations": violations,
                                            "source": "dynamic",
                                        }
                                dynamic_desc_span.set_attribute(
                                    "description_safe", True
                                )
                                return {"status": "ok"}
                            except Exception as e:
                                return {
                                    "status": "error",
                                    "error": e,
                                    "source": "dynamic",
                                }

                    async def _validate_static():
                        static_desc = server_info.get("description", "")
                        if not static_desc:
                            return {"status": "skip"}
                        with tracer_obj.start_as_current_span(
                            "validate_static_server_description"
                        ) as static_desc_span:
                            static_desc_span.set_attribute("server_name", server_name)
                            static_desc_span.set_attribute(
                                "description_source", "static"
                            )
                            logger.info(
                                f"[discover_server_tools] Validating static server description: '{static_desc}'"
                            )
                            try:
                                tool = {
                                    "name": f"{server_name}",
                                    "description": static_desc,
                                    "inputSchema": {},
                                    "outputSchema": None,
                                    "annotations": {},
                                }
                                resp = await self.guardrail_manager.validate_tool_registration(
                                    server_name=server_name, tools=[tool], mode="block"
                                )
                                if resp and resp.metadata:
                                    if resp.metadata.get("timeout", False):
                                        static_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        static_desc_span.set_attribute(
                                            "timeout_error", True
                                        )
                                        return {
                                            "status": "timeout",
                                            "violations": [
                                                "Static server description validation timed out"
                                            ],
                                            "source": "static",
                                        }
                                    blocked = resp.metadata.get(
                                        "blocked_tools_count", 0
                                    )
                                    if blocked > 0:
                                        violations = []
                                        for b in resp.metadata.get("blocked_tools", []):
                                            violations.extend(b.get("reasons", []))
                                        static_desc_span.set_attribute(
                                            "description_blocked", True
                                        )
                                        static_desc_span.set_attribute(
                                            "violation_count", len(violations)
                                        )
                                        return {
                                            "status": "blocked",
                                            "violations": violations,
                                            "source": "static",
                                        }
                                static_desc_span.set_attribute("description_safe", True)
                                return {"status": "ok"}
                            except Exception as e:
                                return {
                                    "status": "error",
                                    "error": e,
                                    "source": "static",
                                }

                    logger.info(
                        f"[discover_server_tools] 🚀 Executing parallel validation for {server_name}"
                    )
                    # Use timeout management for parallel validation
                    from secure_mcp_gateway.services.timeout import get_timeout_manager

                    timeout_manager = get_timeout_manager()

                    dyn_task = _validate_dynamic()
                    stat_task = _validate_static()

                    # Create a proper async function for timeout manager
                    async def _parallel_validation():
                        return await asyncio.gather(dyn_task, stat_task)

                    results = await timeout_manager.execute_with_timeout(
                        _parallel_validation,
                        "discovery",
                        f"server_validation_{server_name}",
                    )

                    # Extract results from timeout result
                    if hasattr(results, "result"):
                        dyn_result, stat_result = results.result
                    else:
                        dyn_result, stat_result = results
                    logger.info(
                        f"[discover_server_tools] ✅ Parallel validation completed for {server_name}"
                    )

                    # Fail-closed prioritization: error/timeout/blocked wins over ok/skip
                    for res in (dyn_result, stat_result):
                        if res.get("status") == "timeout":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )

                            context = ErrorContext(
                                operation="discover.description_validation_timeout_parallel",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_discovery_error(
                                code=ErrorCode.DISCOVERY_FAILED,
                                message=f"{res.get('source').capitalize()} server description validation timed out for {server_name}",
                                context=context,
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": res.get("violations", []),
                                }
                            )
                            return er

                    for res in (dyn_result, stat_result):
                        if res.get("status") == "blocked":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )
                            from secure_mcp_gateway.exceptions import (
                                create_guardrail_error,
                            )

                            context = ErrorContext(
                                operation="discover.description_blocked_parallel",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_guardrail_error(
                                code=ErrorCode.GUARDRAIL_VALIDATION_FAILED,
                                message=f"Server '{server_name}' blocked: Harmful content in {res.get('source')} description",
                                context=context,
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": res.get("violations", []),
                                }
                            )
                            return er

                    for res in (dyn_result, stat_result):
                        if res.get("status") == "error":
                            from secure_mcp_gateway.error_handling import (
                                create_error_response,
                                error_logger,
                            )

                            context = ErrorContext(
                                operation="discover.description_validation_error_parallel",
                                request_id=getattr(ctx, "request_id", None),
                                server_name=server_name,
                            )
                            error = create_discovery_error(
                                code=ErrorCode.DISCOVERY_FAILED,
                                message=f"{res.get('source').capitalize()} server description validation failed for {server_name}: {res.get('error')}",
                                context=context,
                                cause=res.get("error"),
                            )
                            error_logger.log_error(error)
                            er = create_error_response(error)
                            er.update(
                                {
                                    "server_name": server_name,
                                    "blocked": True,
                                    "violations": [str(res.get("error"))],
                                }
                            )
                            return er
                else:
                    logger.info(
                        f"[discover_server_tools] ⏭️  Skipping description validation for {server_name} (enable_server_info_validation={enable_server_info_validation})"
                    )

                # Track blocked tools information
                blocked_tools_list = []
                blocked_tools_count = 0
                blocked_reasons_list = []

                if tools:
                    if IS_DEBUG_LOG_LEVEL:
                        logger.debug(
                            f"[discover_server_tools] Success: {server_name} tools discovered: {tools}"
                        )
                        logger.info(
                            "enkrypt_discover_all_tools.tools_discovered",
                            extra=build_log_extra(ctx, custom_id, server_name),
                        )

                    # NEW: Validate tools with guardrails before caching
                    enable_tool_guardrails = server_info.get(
                        "enable_tool_guardrails", True
                    )
                    logger.info(
                        f"[discover_server_tools] enable_tool_guardrails={enable_tool_guardrails} for {server_name}"
                    )

                    if (
                        self.registration_validation_enabled
                        and self.guardrail_manager
                        and enable_tool_guardrails
                    ):
                        logger.info(
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

                            logger.info(
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

                                    # Check if validation failed due to error (all tools blocked with error metadata)
                                    is_validation_error = (
                                        validation_response.metadata.get("error")
                                        is not None
                                    )
                                    if (
                                        is_validation_error
                                        and safe_count == 0
                                        and tool_count > 0
                                    ):
                                        # Validation failed - treat as error
                                        error_msg = validation_response.metadata.get(
                                            "error", "Tool validation failed"
                                        )

                                        logger.info(
                                            f"[discover_server_tools] ⚠️  Tool validation failed for {server_name}: {error_msg}"
                                        )

                                        # Log with standardized error handling
                                        from secure_mcp_gateway.error_handling import (
                                            create_error_response,
                                            error_logger,
                                        )

                                        context = ErrorContext(
                                            operation="discover.tool_validation_failed",
                                            request_id=getattr(ctx, "request_id", None),
                                            server_name=server_name,
                                        )

                                        error = create_discovery_error(
                                            code=ErrorCode.DISCOVERY_TOOL_VALIDATION_FAILED,
                                            message=f"Tool validation failed for {server_name}: {error_msg}",
                                            context=context,
                                        )
                                        error_logger.log_error(error)

                                        # Return standardized error response
                                        error_response = create_error_response(error)
                                        error_response.update(
                                            {
                                                "server_name": server_name,
                                                "blocked": True,
                                                "tools": [],
                                                "source": "discovery",
                                                "blocked_tools": [],
                                                "blocked_count": 0,
                                                "blocked_reasons": [error_msg],
                                            }
                                        )
                                        return error_response

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

                                        logger.error(
                                            f"[discover_server_tools] ⚠️  Blocked {blocked_count} unsafe tools from {server_name}"
                                        )
                                        logger.error(
                                            "[discover_server_tools] === BLOCKED TOOLS DETAILS ==="
                                        )
                                        for blocked_tool in blocked_tools:
                                            tool_name = blocked_tool.get(
                                                "name", "unknown"
                                            )
                                            reasons = blocked_tool.get("reasons", [])
                                            logger.error(
                                                f"[discover_server_tools]   ❌ {tool_name}:"
                                            )
                                            for reason in reasons:
                                                logger.error(
                                                    f"[discover_server_tools]      → {reason}"
                                                )
                                        logger.error(
                                            "[discover_server_tools] =============================="
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
                                    # Check if validation failed due to timeout
                                    is_timeout_error = validation_response.metadata.get(
                                        "timeout", False
                                    )

                                    if is_timeout_error:
                                        # Timeout occurred - block all tools and return error response
                                        logger.error(
                                            f"[discover_server_tools] ⚠️  Timeout occurred during tool validation for {server_name} - blocking all tools"
                                        )

                                        # Log timeout error with proper error handling
                                        from secure_mcp_gateway.error_handling import (
                                            create_error_response,
                                            error_logger,
                                        )
                                        from secure_mcp_gateway.exceptions import (
                                            create_guardrail_timeout_error,
                                        )

                                        context = ErrorContext(
                                            operation="discover.tool_validation_timeout",
                                            request_id=getattr(ctx, "request_id", None),
                                            server_name=server_name,
                                        )

                                        error = create_guardrail_timeout_error(
                                            timeout_duration=1.0,  # Will be updated with actual duration
                                            context=context,
                                        )
                                        error_logger.log_error(error)

                                        # Return standardized error response with discovery structure
                                        timeout_duration = (
                                            validation_response.metadata.get(
                                                "timeout_duration", "unknown"
                                            )
                                        )
                                        error_response = create_error_response(error)
                                        # Return error in discovery response format
                                        return {
                                            "status": "error",
                                            "message": f"Tool validation timed out for {server_name}",
                                            "error": error_response.get("error"),
                                            "error_code": error.code.value,
                                            "timeout_duration": timeout_duration,
                                            "tools": [],
                                            "source": "discovery",
                                            "blocked": True,
                                            "blocked_tools": [],
                                            "blocked_count": 0,
                                            "blocked_reasons": [
                                                f"Guardrail validation timed out after {timeout_duration}s"
                                            ],
                                        }
                                    else:
                                        # Normal validation - use filtered tools or fallback to original
                                        filtered_tools = (
                                            validation_response.metadata.get(
                                                "filtered_tools", tool_list
                                            )
                                        )

                                    if isinstance(tools, dict):
                                        tools["tools"] = filtered_tools
                                    else:
                                        tools = filtered_tools

                                    logger.info(
                                        f"[discover_server_tools] ✓ {safe_count} safe tools approved for {server_name}"
                                    )
                                    validation_span.set_attribute(
                                        "validation_success", True
                                    )

                            except Exception as validation_error:
                                # FAIL CLOSED: if validation fails, block all tools
                                logger.error(
                                    f"[discover_server_tools] ⚠️  Tool validation error for {server_name} - blocking all tools (fail-closed)"
                                )

                                # Log with standardized error handling
                                from secure_mcp_gateway.error_handling import (
                                    create_error_response,
                                    error_logger,
                                )

                                context = ErrorContext(
                                    operation="discover.tool_validation_error",
                                    request_id=getattr(ctx, "request_id", None),
                                    server_name=server_name,
                                )

                                error = create_discovery_error(
                                    code=ErrorCode.DISCOVERY_TOOL_VALIDATION_FAILED,
                                    message=f"Tool validation failed for {server_name}",
                                    context=context,
                                    cause=validation_error,
                                )
                                error_logger.log_error(error)

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
                                validation_span.set_attribute(
                                    "validation_blocked", True
                                )

                                # Return standardized error response
                                error_response = create_error_response(error)
                                error_response.update(
                                    {
                                        "server_name": server_name,
                                        "blocked": True,
                                        "tools": [],
                                        "source": "discovery",
                                        "blocked_tools": [],
                                        "blocked_count": 0,
                                        "blocked_reasons": ["Tool validation failed"],
                                    }
                                )
                                return error_response
                    else:
                        logger.info(
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
                    logger.info(
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
