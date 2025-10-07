from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Any

from secure_mcp_gateway.plugins.auth import AuthCredentials, get_auth_config_manager
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailAction,
    GuardrailRequest,
    get_guardrail_config_manager,
)
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.cache.cache_service import cache_service
from secure_mcp_gateway.services.execution.execution_utils import (
    extract_input_text_from_args,
)
from secure_mcp_gateway.services.execution.tool_execution_service import (
    ToolExecutionService,
)

# Get tracer from telemetry manager
telemetry_manager = get_telemetry_config_manager()
tracer = telemetry_manager.get_tracer()
from secure_mcp_gateway.utils import (
    build_log_extra,
    generate_custom_id,
    get_common_config,
    get_server_info_by_name,
    mask_key,
    sys_print,
)


class SecureToolExecutionService:
    """
    Handles secure tool execution with comprehensive guardrail checks.

    This service encapsulates the complex secure tool execution logic from
    enkrypt_secure_call_tools while maintaining the same behavior, telemetry, and error handling.
    """

    def __init__(self):
        self.auth_manager = get_auth_config_manager()
        self.cache_service = cache_service
        self.guardrail_manager = get_guardrail_config_manager()
        self.tool_execution_service = ToolExecutionService()

        # Load constants from common config
        common_config = get_common_config()
        self.ADHERENCE_THRESHOLD = common_config.get("adherence_threshold", 0.8)
        self.ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED = common_config.get(
            "enkrypt_async_input_guardrails_enabled", True
        )
        self.ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED = common_config.get(
            "enkrypt_async_output_guardrails_enabled", True
        )
        self.IS_DEBUG_LOG_LEVEL = (
            common_config.get("enkrypt_log_level", "INFO").lower() == "debug"
        )
        self.RELEVANCY_THRESHOLD = common_config.get("relevancy_threshold", 0.7)

    async def execute_secure_tools(
        self,
        ctx,
        server_name: str,
        tool_calls: list[dict[str, Any]] = None,
        logger=None,
    ) -> dict[str, Any]:
        """
        Execute multiple tool calls securely with comprehensive guardrail checks.

        Args:
            ctx: The MCP context
            server_name: Name of the server containing the tools
            tool_calls: List of tool call objects
            logger: Logger instance

        Returns:
            dict: Batch execution results with guardrails responses
        """
        tool_calls = tool_calls or []
        num_tool_calls = len(tool_calls)
        custom_id = generate_custom_id()

        with tracer.start_as_current_span(
            "secure_tool_execution.execute_secure_tools"
        ) as main_span:
            # Set main span attributes
            main_span.set_attribute("server_name", server_name)
            main_span.set_attribute("num_tool_calls", num_tool_calls)
            main_span.set_attribute("request_id", ctx.request_id)
            main_span.set_attribute("custom_id", custom_id)

            sys_print(
                f"[secure_call_tools] Starting secure batch execution for {num_tool_calls} tools for server: {server_name}"
            )
            logger.info(
                "secure_tool_execution.execute_secure_tools.started",
                extra={
                    "request_id": ctx.request_id,
                    "custom_id": custom_id,
                    "server_name": server_name,
                },
            )

            if num_tool_calls == 0:
                sys_print(
                    "[secure_call_tools] No tools provided. Treating this as a discovery call"
                )
                logger.info(
                    "secure_tool_execution.execute_secure_tools.no_tools_provided",
                    extra={
                        "request_id": ctx.request_id,
                        "custom_id": custom_id,
                        "server_name": server_name,
                    },
                )

            try:
                # Authentication and setup
                auth_result = await self._authenticate_and_setup(
                    ctx, custom_id, server_name, main_span, logger
                )
                if auth_result.get("status") != "success":
                    return auth_result

                session_key = auth_result["session_key"]
                server_info = auth_result["server_info"]

                # Get guardrails policies
                guardrails_config = self._extract_guardrails_config(
                    server_info, main_span
                )

                # Tool discovery
                server_config_tools = await self._handle_tool_discovery(
                    ctx,
                    custom_id,
                    server_name,
                    server_info,
                    session_key,
                    main_span,
                    logger,
                )
                if not server_config_tools:
                    return {
                        "status": "error",
                        "error": f"No tools found for {server_name} even after discovery",
                    }

                # Handle discovery-only call
                if num_tool_calls == 0:
                    return {
                        "status": "success",
                        "message": f"Successfully discovered tools for {server_name}",
                        "tools": server_config_tools,
                    }

                # Execute tools with guardrails
                results = await self._execute_tools_with_guardrails(
                    ctx,
                    custom_id,
                    server_name,
                    tool_calls,
                    server_config_tools,
                    guardrails_config,
                    session_key,
                    main_span,
                    logger,
                )

                # Calculate and return summary
                return self._build_execution_summary(
                    ctx,
                    custom_id,
                    server_name,
                    num_tool_calls,
                    results,
                    guardrails_config,
                    logger,
                )

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute("error", str(e))
                sys_print(
                    f"[secure_call_tools] Critical error during batch execution: {e}",
                    is_error=True,
                )
                traceback.print_exc(file=sys.stderr)
                logger.error(
                    "secure_tool_execution.execute_secure_tools.critical_error",
                    extra=build_log_extra(ctx, custom_id, server_name, error=str(e)),
                )
                return {
                    "status": "error",
                    "error": f"Secure batch tool call failed: {e}",
                }

    async def _authenticate_and_setup(
        self, ctx, custom_id, server_name, main_span, logger
    ):
        """Handle authentication and setup for secure tool execution."""
        with tracer.start_as_current_span(
            "secure_tool_execution.authenticate"
        ) as auth_span:
            # Gather credentials
            creds = self.auth_manager.get_gateway_credentials(ctx)

            # Decide whether to use auth plugins
            common_config = get_common_config()
            auth_plugins = common_config.get("auth_plugins", {})
            use_plugins = bool(auth_plugins.get("enabled", False))

            if use_plugins:
                # Authenticate via plugin manager
                manager = get_auth_config_manager()
                auth_result = await manager.authenticate(
                    ctx,
                    credentials=AuthCredentials(
                        gateway_key=creds.get("gateway_key"),
                        project_id=creds.get("project_id"),
                        user_id=creds.get("user_id"),
                    ),
                    provider_name=auth_plugins.get("default_provider"),
                )
                if not auth_result.is_success:
                    return {
                        "status": "error",
                        "error": f"Authentication failed: {auth_result.message}",
                    }

                # Build session and resolve server info from returned gateway_config
                mcp_config_id = (auth_result.gateway_config or {}).get(
                    "mcp_config_id", "not_provided"
                )
                session_key = f"{creds.get('gateway_key')}_{creds.get('project_id')}_{creds.get('user_id')}_{mcp_config_id}"
                server_info = get_server_info_by_name(
                    auth_result.gateway_config, server_name
                )
            else:
                # Fallback to legacy authentication path
                # First, get the local config to build the proper session key
                local_config = self.auth_manager.get_local_mcp_config(
                    creds.get("gateway_key"),
                    creds.get("project_id"),
                    creds.get("user_id"),
                )

                if not local_config:
                    auth_span.set_attribute("error", "No local config found")
                    return {"status": "error", "error": "Configuration not found."}

                mcp_config_id = local_config.get("mcp_config_id", "not_provided")
                session_key = f"{creds.get('gateway_key')}_{creds.get('project_id')}_{creds.get('user_id')}_{mcp_config_id}"

                if not self.auth_manager.is_session_authenticated(session_key):
                    auth_span.set_attribute("required_new_auth", True)
                    from secure_mcp_gateway.gateway import enkrypt_authenticate

                    result = await enkrypt_authenticate(ctx)
                    if result.get("status") != "success":
                        auth_span.set_attribute("error", "Authentication failed")
                        sys_print("[get_server_info] Not authenticated", is_error=True)
                        logger.error(
                            "secure_tool_execution.execute_secure_tools.not_authenticated",
                            extra=build_log_extra(ctx, custom_id, server_name),
                        )
                        return {"status": "error", "error": "Not authenticated."}
                else:
                    auth_span.set_attribute("required_new_auth", False)

                server_info = get_server_info_by_name(
                    self.auth_manager.get_session_gateway_config(session_key),
                    server_name,
                )

            # Validate server availability
            if not server_info:
                auth_span.set_attribute(
                    "error", f"Server '{server_name}' not available"
                )
                sys_print(
                    f"[secure_call_tools] Server '{server_name}' not available",
                    is_error=True,
                )
                logger.warning(
                    "secure_tool_execution.execute_secure_tools.server_not_available",
                    extra=build_log_extra(ctx, custom_id, server_name),
                )
                return {
                    "status": "error",
                    "error": f"Server '{server_name}' not available.",
                }

            return {
                "status": "success",
                "session_key": session_key,
                "server_info": server_info,
            }

    def _extract_guardrails_config(self, server_info, main_span):
        """Extract guardrails configuration from server info."""
        input_guardrails_policy = server_info["input_guardrails_policy"]
        output_guardrails_policy = server_info["output_guardrails_policy"]

        if self.IS_DEBUG_LOG_LEVEL:
            sys_print(
                f"Input Guardrails Policy: {input_guardrails_policy}", is_debug=True
            )
            sys_print(
                f"Output Guardrails Policy: {output_guardrails_policy}", is_debug=True
            )

        input_policy_enabled = input_guardrails_policy["enabled"]
        output_policy_enabled = output_guardrails_policy["enabled"]
        input_policy_name = input_guardrails_policy["policy_name"]
        output_policy_name = output_guardrails_policy["policy_name"]
        input_blocks = input_guardrails_policy["block"]
        output_blocks = output_guardrails_policy["block"]
        pii_redaction = input_guardrails_policy["additional_config"].get(
            "pii_redaction", False
        )
        relevancy = output_guardrails_policy["additional_config"].get(
            "relevancy", False
        )
        adherence = output_guardrails_policy["additional_config"].get(
            "adherence", False
        )
        hallucination = output_guardrails_policy["additional_config"].get(
            "hallucination", False
        )

        # Set guardrails attributes on main span
        main_span.set_attribute("input_guardrails_enabled", input_policy_enabled)
        main_span.set_attribute("output_guardrails_enabled", output_policy_enabled)
        main_span.set_attribute("pii_redaction_enabled", pii_redaction)
        main_span.set_attribute("relevancy_enabled", relevancy)
        main_span.set_attribute("adherence_enabled", adherence)
        main_span.set_attribute("hallucination_enabled", hallucination)

        return {
            "input_guardrails_policy": input_guardrails_policy,
            "output_guardrails_policy": output_guardrails_policy,
            "input_policy_enabled": input_policy_enabled,
            "output_policy_enabled": output_policy_enabled,
            "input_policy_name": input_policy_name,
            "output_policy_name": output_policy_name,
            "input_blocks": input_blocks,
            "output_blocks": output_blocks,
            "pii_redaction": pii_redaction,
            "relevancy": relevancy,
            "adherence": adherence,
            "hallucination": hallucination,
        }

    async def _handle_tool_discovery(
        self, ctx, custom_id, server_name, server_info, session_key, main_span, logger
    ):
        """Handle tool discovery for the server."""
        with tracer.start_as_current_span(
            "secure_tool_execution.tool_discovery"
        ) as discovery_span:
            discovery_span.set_attribute("server_name", server_name)

            server_config_tools = server_info.get("tools", {})
            discovery_span.set_attribute("has_cached_tools", bool(server_config_tools))

            if self.IS_DEBUG_LOG_LEVEL:
                sys_print(
                    f"[secure_call_tools] Server config tools before discovery: {server_config_tools}",
                    is_debug=True,
                )

            if not server_config_tools:
                id = self.auth_manager.get_session_gateway_config(session_key)["id"]
                server_config_tools = self.cache_service.get_cached_tools(
                    id, server_name
                )
                discovery_span.set_attribute("cache_hit", bool(server_config_tools))

                if server_config_tools:
                    from secure_mcp_gateway.plugins.telemetry import (
                        get_telemetry_config_manager,
                    )

                    telemetry_mgr = get_telemetry_config_manager()
                    telemetry_mgr.cache_hit_counter.add(
                        1, attributes=build_log_extra(ctx)
                    )
                    logger.info(
                        "secure_tool_execution.execute_secure_tools.server_config_tools_after_get_cached_tools",
                        extra=build_log_extra(ctx, custom_id, server_name),
                    )
                    sys_print(
                        f"[enkrypt_secure_call_tools] Found cached tools for {server_name}"
                    )
                else:
                    from secure_mcp_gateway.plugins.telemetry import (
                        get_telemetry_config_manager,
                    )

                    telemetry_mgr = get_telemetry_config_manager()
                    telemetry_mgr.cache_miss_counter.add(
                        1, attributes=build_log_extra(ctx)
                    )
                    try:
                        discovery_span.set_attribute("discovery_required", True)

                        telemetry_mgr.list_servers_call_count.add(
                            1, attributes=build_log_extra(ctx, custom_id)
                        )

                        from secure_mcp_gateway.gateway import (
                            enkrypt_discover_all_tools,
                        )

                        discovery_result = await enkrypt_discover_all_tools(
                            ctx, server_name
                        )
                        discovery_span.set_attribute(
                            "discovery_success",
                            discovery_result.get("status") == "success",
                        )

                        if discovery_result.get("status") != "success":
                            discovery_span.set_attribute("error", "Discovery failed")
                            logger.error(
                                "secure_tool_execution.execute_secure_tools.discovery_failed",
                                extra=build_log_extra(
                                    ctx,
                                    custom_id,
                                    server_name,
                                    discovery_result=discovery_result,
                                ),
                            )
                            return None

                        if discovery_result.get("status") == "success":
                            server_config_tools = discovery_result.get("tools", {})

                            telemetry_mgr.servers_discovered_count.add(
                                1, attributes=build_log_extra(ctx)
                            )

                        if self.IS_DEBUG_LOG_LEVEL:
                            sys_print(
                                f"[enkrypt_secure_call_tools] Discovered tools: {server_config_tools}",
                                is_debug=True,
                            )
                            logger.info(
                                "secure_tool_execution.execute_secure_tools.discovered_tools",
                                extra=build_log_extra(
                                    ctx,
                                    custom_id,
                                    server_name,
                                    server_config_tools=server_config_tools,
                                ),
                            )
                    except Exception as e:
                        discovery_span.record_exception(e)
                        logger.error(
                            "secure_tool_execution.execute_secure_tools.exception",
                            extra=build_log_extra(
                                ctx, custom_id, server_name, error=str(e)
                            ),
                        )
                        sys_print(
                            f"[enkrypt_secure_call_tools] Exception: {e}", is_error=True
                        )
                        traceback.print_exc(file=sys.stderr)
                        return None

            return server_config_tools

    async def _execute_tools_with_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        tool_calls,
        server_config_tools,
        guardrails_config,
        session_key,
        main_span,
        logger,
    ):
        """Execute tools with comprehensive guardrail checks."""
        server_config = get_server_info_by_name(
            self.auth_manager.get_session_gateway_config(session_key), server_name
        )["config"]

        server_command = server_config["command"]
        server_args = server_config["args"]
        server_env = server_config.get("env", None)

        sys_print(
            f"[secure_call_tools] Starting secure batch call for {len(tool_calls)} tools for server: {server_name}"
        )
        logger.info(
            "secure_tool_execution.execute_secure_tools.starting_secure_batch_call",
            extra=build_log_extra(
                ctx, custom_id, server_name, num_tool_calls=len(tool_calls)
            ),
        )

        if self.IS_DEBUG_LOG_LEVEL:
            sys_print(
                f"[secure_call_tools] Using command: {server_command} with args: {server_args}",
                is_debug=True,
            )
            logger.info(
                "secure_tool_execution.execute_secure_tools.using_command",
                extra=build_log_extra(
                    ctx, custom_id, server_name, server_command=server_command
                ),
            )

        results = []

        # Single session for all calls (managed by ToolExecutionService)
        async with self.tool_execution_service.open_session(
            {"command": server_command, "args": server_args, "env": server_env}
        ) as session:
            sys_print(
                f"[secure_call_tools] Session initialized successfully for {server_name}"
            )
            logger.info(
                "secure_tool_execution.execute_secure_tools.session_initialized",
                extra=build_log_extra(ctx, custom_id, server_name),
            )

            # Tool execution loop
            for i, tool_call in enumerate(tool_calls):
                result = await self._execute_single_tool(
                    ctx,
                    custom_id,
                    server_name,
                    i,
                    tool_call,
                    server_config_tools,
                    guardrails_config,
                    session,
                    main_span,
                    logger,
                )
                results.append(result)

                # Break if tool execution failed or was blocked
                if result["status"] in [
                    "error",
                    "blocked_input",
                    "blocked_output",
                    "blocked_output_relevancy",
                    "blocked_output_adherence",
                    "blocked_output_hallucination",
                ]:
                    break

        return results

    async def _execute_single_tool(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_call,
        server_config_tools,
        guardrails_config,
        session,
        main_span,
        logger,
    ):
        """Execute a single tool with all guardrail checks."""
        with tracer.start_as_current_span(
            f"secure_tool_execution.tool_execution_{i}"
        ) as tool_span:
            tool_name = (
                tool_call.get("name")
                or tool_call.get("tool_name")
                or tool_call.get("tool")
                or tool_call.get("function")
                or tool_call.get("function_name")
                or tool_call.get("function_id")
            )
            tool_span.set_attribute("tool_name", tool_name or "unknown")
            tool_span.set_attribute("call_index", i)
            tool_span.set_attribute("server_name", server_name)

            try:
                args = (
                    tool_call.get("args", {})
                    or tool_call.get("arguments", {})
                    or tool_call.get("tool_arguments", {})
                    or tool_call.get("tool_input_arguments", {})
                    or tool_call.get("tool_args", {})
                    or tool_call.get("tool_input_args", {})
                    or tool_call.get("parameters", {})
                    or tool_call.get("input", {})
                    or tool_call.get("params", {})
                )

                if not tool_name:
                    tool_span.set_attribute("error", "No tool_name provided")
                    return {
                        "status": "error",
                        "error": "No tool_name provided",
                        "message": "No tool_name provided",
                        "enkrypt_mcp_data": {
                            "call_index": i,
                            "server_name": server_name,
                            "tool_name": tool_name,
                            "args": args,
                        },
                    }

                sys_print(
                    f"[secure_call_tools] Processing call {i}: {tool_name} with args: {args}"
                )
                logger.info(
                    "secure_tool_execution.execute_secure_tools.processing_call",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        server_name,
                        tool_name=tool_name,
                        tool_arguments=args,
                    ),
                )

                # Tool validation
                validation_result = self._validate_tool(
                    tool_name, server_config_tools, tool_span
                )
                if validation_result:
                    return validation_result

                # Initialize guardrail responses
                redaction_key = None
                input_guardrail_response = {}
                output_guardrail_response = {}
                output_relevancy_response = {}
                output_adherence_response = {}
                output_hallucination_response = {}

                # Prepare input for guardrails
                input_text_content, input_json_string = extract_input_text_from_args(
                    args
                )

                # Execute tool with input guardrails
                if guardrails_config["input_policy_enabled"]:
                    result = await self._execute_with_input_guardrails(
                        ctx,
                        custom_id,
                        server_name,
                        i,
                        tool_name,
                        args,
                        input_text_content,
                        input_json_string,
                        guardrails_config,
                        session,
                        tool_span,
                        logger,
                    )
                    # Extract input guardrail response from result
                    input_guardrail_response = result.get(
                        "input_guardrail_response", {}
                    )
                else:
                    result = await self._execute_without_input_guardrails(
                        ctx,
                        custom_id,
                        server_name,
                        i,
                        tool_name,
                        args,
                        session,
                        tool_span,
                        logger,
                    )

                if result.get("status") in ["blocked_input", "error"]:
                    return result

                # Process output with guardrails
                if result.get("text_result"):
                    output_result = await self._process_output_guardrails(
                        ctx,
                        custom_id,
                        server_name,
                        i,
                        tool_name,
                        args,
                        result["text_result"],
                        input_json_string,
                        guardrails_config,
                        tool_span,
                        logger,
                    )
                    if output_result:
                        # Check if it's a blocking result
                        if output_result.get("status") in ["blocked_output", "error"]:
                            return output_result
                        # Extract guardrail responses
                        output_guardrail_response = output_result.get(
                            "output_guardrail_response", {}
                        )
                        output_relevancy_response = output_result.get(
                            "output_relevancy_response", {}
                        )
                        output_adherence_response = output_result.get(
                            "output_adherence_response", {}
                        )
                        output_hallucination_response = output_result.get(
                            "output_hallucination_response", {}
                        )

                # Build successful result
                return self._build_successful_result(
                    ctx,
                    custom_id,
                    i,
                    server_name,
                    tool_name,
                    args,
                    result["text_result"],
                    guardrails_config,
                    input_guardrail_response,
                    output_guardrail_response,
                    output_relevancy_response,
                    output_adherence_response,
                    output_hallucination_response,
                    logger,
                )

            except Exception as tool_error:
                tool_span.record_exception(tool_error)
                tool_span.set_attribute("error", str(tool_error))
                sys_print(
                    f"[secure_call_tools] Error in call {i} ({tool_name}): {tool_error}",
                    is_error=True,
                )
                traceback.print_exc(file=sys.stderr)
                logger.error(
                    "secure_tool_execution.execute_secure_tools.error_in_tool_call",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        server_name,
                        tool_name=tool_name,
                        error=str(tool_error),
                    ),
                )
                return {
                    "status": "error",
                    "error": str(tool_error),
                    "message": "Error while processing tool call",
                    "enkrypt_mcp_data": {
                        "call_index": i,
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "args": args,
                    },
                }

    def _validate_tool(self, tool_name, server_config_tools, tool_span):
        """Validate that the tool exists and is available."""
        with tracer.start_as_current_span(
            "secure_tool_execution.validate_tool"
        ) as validate_span:
            validate_span.set_attribute("tool_name", tool_name)

            # Normalize possible formats and check membership
            if isinstance(server_config_tools, tuple) and len(server_config_tools) == 2:
                server_config_tools = server_config_tools[0]

            valid_format, names = self.tool_execution_service.get_available_tool_names(
                server_config_tools
            )
            if not valid_format:
                validate_span.set_attribute("error", "Unknown tool format")
                sys_print(
                    f"[secure_call_tools] Unknown tool format: {type(server_config_tools)}",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": "Unknown tool format for server tools.",
                }

            tool_found = tool_name in names
            validate_span.set_attribute("tool_found", tool_found)
            if not tool_found:
                validate_span.set_attribute("error", "Tool not found")
                sys_print(
                    f"[enkrypt_secure_call_tools] Tool '{tool_name}' not found for this server.",
                    is_error=True,
                )
                return {
                    "status": "error",
                    "error": f"Tool '{tool_name}' not found for this server.",
                }

        return None

    async def _execute_with_input_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_name,
        args,
        input_text_content,
        input_json_string,
        guardrails_config,
        session,
        tool_span,
        logger,
    ):
        """Execute tool with input guardrails enabled."""
        with tracer.start_as_current_span(
            "secure_tool_execution.input_guardrails"
        ) as input_span:
            input_span.set_attribute(
                "pii_redaction", guardrails_config["pii_redaction"]
            )
            input_span.set_attribute(
                "policy_name", guardrails_config["input_policy_name"]
            )
            input_span.set_attribute("tool_name", tool_name)

            sys_print(
                f"[secure_call_tools] Call {i} : Input guardrails enabled for {tool_name} of server {server_name}"
            )
            logger.info(
                "secure_tool_execution.execute_secure_tools.input_guardrails_enabled",
                extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),
            )

            # Get input guardrail from manager
            input_guardrail = self.guardrail_manager.get_input_guardrail(
                server_config={
                    "input_guardrails_policy": guardrails_config[
                        "input_guardrails_policy"
                    ]
                }
            )

            if input_guardrail is None:
                # Guardrails not enabled, proceed directly
                result = await self.tool_execution_service.call_tool(
                    session, tool_name, args
                )
                text_result = self._extract_text_result(result)
                return {
                    "text_result": text_result,
                    "result": result,
                    "input_guardrail_response": {"is_safe": True, "enabled": False},
                }

            # Create guardrail request
            request = GuardrailRequest(
                content=input_text_content,
                tool_name=tool_name,
                tool_args=args,
                server_name=server_name,
                context={"call_index": i},
            )

            # Validate with plugin
            if self.ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED:
                input_span.set_attribute("async_guardrails", True)
                # Start both guardrail and tool call tasks concurrently
                guardrail_task = asyncio.create_task(input_guardrail.validate(request))
                tool_call_task = asyncio.create_task(
                    self.tool_execution_service.call_tool(session, tool_name, args)
                )
                guardrail_response, result = await asyncio.gather(
                    guardrail_task, tool_call_task
                )
            else:
                input_span.set_attribute("async_guardrails", False)
                guardrail_response = await input_guardrail.validate(request)
                result = await self.tool_execution_service.call_tool(
                    session, tool_name, args
                )

            # Check if blocked
            if not guardrail_response.is_safe:
                violation_types = [
                    v.violation_type.value for v in guardrail_response.violations
                ]
                input_span.set_attribute(
                    "error", f"Input violations: {violation_types}"
                )
                sys_print(
                    f"[secure_call_tools] Call {i}: Blocked due to input guardrail violations: {violation_types} for {tool_name} of server {server_name}"
                )
                logger.info(
                    "secure_tool_execution.execute_secure_tools.blocked_due_to_input_violations",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        server_name,
                        tool_name=tool_name,
                        input_violations_detected=True,
                        input_violation_types=violation_types,
                    ),
                )
                return {
                    "status": "blocked_input",
                    "message": f"Request blocked due to input guardrail violations: {', '.join(violation_types)}",
                    "response": "",
                    "enkrypt_mcp_data": {
                        "call_index": i,
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "args": args,
                    },
                    "input_guardrail_response": {
                        "is_safe": False,
                        "violations": [
                            {
                                "type": v.violation_type.value,
                                "severity": v.severity,
                                "message": v.message,
                                "action": v.action.value,
                                "metadata": v.metadata,
                            }
                            for v in guardrail_response.violations
                        ],
                        "processing_time_ms": guardrail_response.processing_time_ms,
                        "metadata": guardrail_response.metadata,
                    },
                }

            # Success
            text_result = self._extract_text_result(result)
            return {
                "text_result": text_result,
                "result": result,
                "input_guardrail_response": {
                    "is_safe": True,
                    "processing_time_ms": guardrail_response.processing_time_ms,
                    "metadata": guardrail_response.metadata,
                },
            }

    async def _execute_without_input_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_name,
        args,
        session,
        tool_span,
        logger,
    ):
        """Execute tool without input guardrails."""
        with tracer.start_as_current_span(
            "secure_tool_execution.execute_tool"
        ) as exec_span:
            exec_span.set_attribute("tool_name", tool_name)
            exec_span.set_attribute("async_guardrails", False)

            sys_print(
                f"[secure_call_tools] Call {i}: Input guardrails not enabled for {tool_name} of server {server_name}"
            )
            logger.info(
                "secure_tool_execution.execute_secure_tools.input_guardrails_not_enabled",
                extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),
            )

            result = await self.tool_execution_service.call_tool(
                session, tool_name, args
            )
            text_result = self._extract_text_result(result)
            return {"text_result": text_result, "result": result}

    def _extract_text_result(self, result):
        """Extract text content from tool result."""
        text_result = ""
        if (
            result
            and hasattr(result, "content")
            and result.content
            and len(result.content) > 0
        ):
            result_type = result.content[0].type
            if result_type == "text":
                text_result = result.content[0].text
        return text_result

    async def _process_output_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_name,
        args,
        text_result,
        input_json_string,
        guardrails_config,
        tool_span,
        logger,
    ):
        """Process output with guardrails."""
        with tracer.start_as_current_span(
            "secure_tool_execution.output_guardrails"
        ) as output_span:
            output_span.set_attribute(
                "relevancy_enabled", guardrails_config["relevancy"]
            )
            output_span.set_attribute(
                "adherence_enabled", guardrails_config["adherence"]
            )
            output_span.set_attribute(
                "hallucination_enabled", guardrails_config["hallucination"]
            )
            output_span.set_attribute("tool_name", tool_name)

            if not self.ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED:
                # Sync output guardrails
                return await self._process_sync_output_guardrails(
                    ctx,
                    custom_id,
                    server_name,
                    i,
                    tool_name,
                    args,
                    text_result,
                    input_json_string,
                    guardrails_config,
                    output_span,
                    logger,
                )
            else:
                # Async output guardrails
                return await self._process_async_output_guardrails(
                    ctx,
                    custom_id,
                    server_name,
                    i,
                    tool_name,
                    args,
                    text_result,
                    input_json_string,
                    guardrails_config,
                    output_span,
                    logger,
                )

    async def _process_sync_output_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_name,
        args,
        text_result,
        input_json_string,
        guardrails_config,
        output_span,
        logger,
    ):
        """Process output guardrails synchronously."""
        sys_print(
            f"[secure_call_tools] Call {i}: Starting sync output guardrails for {tool_name} of server {server_name}"
        )
        logger.info(
            "secure_tool_execution.execute_secure_tools.starting_sync_output_guardrails",
            extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),
        )

        # Initialize guardrail responses
        output_guardrail_response = {}
        output_relevancy_response = {}
        output_adherence_response = {}
        output_hallucination_response = {}

        # Debug: Check if output policy is enabled
        sys_print(
            f"[DEBUG] output_policy_enabled: {guardrails_config.get('output_policy_enabled', 'NOT_SET')}",
            is_debug=True,
        )
        sys_print(
            f"[DEBUG] guardrails_config keys: {list(guardrails_config.keys())}",
            is_debug=True,
        )
        sys_print(
            f"[DEBUG] relevancy: {guardrails_config.get('relevancy', 'NOT_SET')}",
            is_debug=True,
        )
        sys_print(
            f"[DEBUG] adherence: {guardrails_config.get('adherence', 'NOT_SET')}",
            is_debug=True,
        )
        sys_print(
            f"[DEBUG] hallucination: {guardrails_config.get('hallucination', 'NOT_SET')}",
            is_debug=True,
        )

        # Get output guardrail from manager
        output_guardrail = self.guardrail_manager.get_output_guardrail(
            server_config={
                "output_guardrails_policy": guardrails_config[
                    "output_guardrails_policy"
                ]
            }
        )

        if output_guardrail is None:
            # No output guardrails enabled
            return {
                "output_guardrail_response": {},
                "output_relevancy_response": {},
                "output_adherence_response": {},
                "output_hallucination_response": {},
            }

        # Create request for context
        original_request = GuardrailRequest(
            content=input_json_string,
            tool_name=tool_name,
            tool_args=args,
            server_name=server_name,
        )

        # Validate output (includes ALL checks: policy, relevancy, adherence, hallucination)
        guardrail_response = await output_guardrail.validate(
            response_content=text_result, original_request=original_request
        )

        # Check if blocked
        if not guardrail_response.is_safe:
            violation_types = [
                v.violation_type.value for v in guardrail_response.violations
            ]

            # Check if any are blocking violations
            has_blocking = any(
                v.action == GuardrailAction.BLOCK for v in guardrail_response.violations
            )

            if has_blocking:
                output_span.set_attribute(
                    "error", f"Output violations: {violation_types}"
                )
                sys_print(
                    f"[secure_call_tools] Call {i}: Blocked due to output violations: {violation_types}"
                )
                logger.info(
                    "secure_tool_execution.execute_secure_tools.blocked_due_to_output_violations",
                    extra=build_log_extra(
                        ctx,
                        custom_id,
                        server_name,
                        tool_name=tool_name,
                        output_violations_detected=True,
                        output_violation_types=violation_types,
                    ),
                )
                return self._build_blocked_result(
                    "blocked_output",
                    f"Request blocked due to output guardrail violations: {', '.join(violation_types)}",
                    i,
                    server_name,
                    tool_name,
                    args,
                    text_result,
                    guardrails_config,
                    {
                        "is_safe": False,
                        "violations": [
                            {
                                "type": v.violation_type.value,
                                "severity": v.severity,
                                "message": v.message,
                                "action": v.action.value,
                            }
                            for v in guardrail_response.violations
                        ],
                        "processing_time_ms": guardrail_response.processing_time_ms,
                    },
                    guardrail_response.metadata.get("relevancy", {}),
                    guardrail_response.metadata.get("adherence", {}),
                    guardrail_response.metadata.get("hallucination", {}),
                )

        # Extract individual check results from metadata
        # (EnkryptOutputGuardrail includes these in metadata)
        metadata = guardrail_response.metadata or {}

        output_guardrail_response = {
            "is_safe": True,
            "processing_time_ms": guardrail_response.processing_time_ms,
            "warnings": [
                {
                    "type": v.violation_type.value,
                    "severity": v.severity,
                    "message": v.message,
                }
                for v in guardrail_response.violations
                if v.action == GuardrailAction.WARN
            ],
        }
        output_relevancy_response = metadata.get("relevancy", {})
        output_adherence_response = metadata.get("adherence", {})
        output_hallucination_response = metadata.get("hallucination", {})

        # Return guardrail responses even when no violations
        return {
            "output_guardrail_response": output_guardrail_response,
            "output_relevancy_response": output_relevancy_response,
            "output_adherence_response": output_adherence_response,
            "output_hallucination_response": output_hallucination_response,
        }

    async def _process_async_output_guardrails(
        self,
        ctx,
        custom_id,
        server_name,
        i,
        tool_name,
        args,
        text_result,
        input_json_string,
        guardrails_config,
        output_span,
        logger,
    ):
        """Process output guardrails asynchronously."""
        sys_print(
            f"[secure_call_tools] Call {i}: Starting async output guardrails for {tool_name} of server {server_name}"
        )
        logger.info(
            "secure_tool_execution.execute_secure_tools.starting_async_output_guardrails",
            extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),
        )

        tasks = {}

        # Initialize guardrail responses
        output_guardrail_response = {}
        output_relevancy_response = {}
        output_adherence_response = {}
        output_hallucination_response = {}

        # Get output guardrail from manager
        output_guardrail = self.guardrail_manager.get_output_guardrail(
            server_config={
                "output_guardrails_policy": guardrails_config[
                    "output_guardrails_policy"
                ]
            }
        )

        if output_guardrail is None:
            # No output guardrails enabled
            return {
                "output_guardrail_response": {},
                "output_relevancy_response": {},
                "output_adherence_response": {},
                "output_hallucination_response": {},
            }

        # Create request for context
        original_request = GuardrailRequest(
            content=input_json_string,
            tool_name=tool_name,
            tool_args=args,
            server_name=server_name,
        )

        # Single call - provider handles async internally
        guardrail_response = await output_guardrail.validate(
            response_content=text_result, original_request=original_request
        )

        # Check if blocked
        if not guardrail_response.is_safe:
            violation_types = [
                v.violation_type.value for v in guardrail_response.violations
            ]

            # Check if any are blocking violations
            has_blocking = any(
                v.action == GuardrailAction.BLOCK for v in guardrail_response.violations
            )

            if has_blocking:
                return self._build_blocked_result(
                    "blocked_output",
                    f"Request blocked due to output guardrail violations: {', '.join(violation_types)}",
                    i,
                    server_name,
                    tool_name,
                    args,
                    text_result,
                    guardrails_config,
                    {
                        "is_safe": False,
                        "violations": [
                            {
                                "type": v.violation_type.value,
                                "severity": v.severity,
                                "message": v.message,
                                "action": v.action.value,
                            }
                            for v in guardrail_response.violations
                        ],
                        "processing_time_ms": guardrail_response.processing_time_ms,
                    },
                    guardrail_response.metadata.get("relevancy", {}),
                    guardrail_response.metadata.get("adherence", {}),
                    guardrail_response.metadata.get("hallucination", {}),
                )

        # Extract individual check results from metadata
        metadata = guardrail_response.metadata or {}

        output_guardrail_response = {
            "is_safe": True,
            "processing_time_ms": guardrail_response.processing_time_ms,
            "warnings": [
                {
                    "type": v.violation_type.value,
                    "severity": v.severity,
                    "message": v.message,
                }
                for v in guardrail_response.violations
                if v.action == GuardrailAction.WARN
            ],
        }
        output_relevancy_response = metadata.get("relevancy", {})
        output_adherence_response = metadata.get("adherence", {})
        output_hallucination_response = metadata.get("hallucination", {})

        # Return guardrail responses even when no violations
        return {
            "output_guardrail_response": output_guardrail_response,
            "output_relevancy_response": output_relevancy_response,
            "output_adherence_response": output_adherence_response,
            "output_hallucination_response": output_hallucination_response,
        }

    def _build_blocked_result(
        self,
        status,
        message,
        i,
        server_name,
        tool_name,
        args,
        text_result,
        guardrails_config,
        output_guardrail_response,
        output_relevancy_response,
        output_adherence_response,
        output_hallucination_response,
    ):
        """Build a blocked result."""
        return {
            "status": status,
            "message": message,
            "response": text_result,
            "enkrypt_mcp_data": {
                "call_index": i,
                "server_name": server_name,
                "tool_name": tool_name,
                "args": args,
            },
            "enkrypt_policy_detections": {
                "input_guardrail_policy": guardrails_config["input_guardrails_policy"],
                "input_guardrail_response": {},
                "output_guardrail_policy": guardrails_config[
                    "output_guardrails_policy"
                ],
                "output_guardrail_response": output_guardrail_response,
                "output_relevancy_response": output_relevancy_response,
                "output_adherence_response": output_adherence_response,
                "output_hallucination_response": output_hallucination_response,
            },
        }

    def _build_successful_result(
        self,
        ctx,
        custom_id,
        i,
        server_name,
        tool_name,
        args,
        text_result,
        guardrails_config,
        input_guardrail_response,
        output_guardrail_response,
        output_relevancy_response,
        output_adherence_response,
        output_hallucination_response,
        logger,
    ):
        """Build a successful result."""
        sys_print(
            f"[secure_call_tools] Call {i}: Completed successfully for {tool_name} of server {server_name}"
        )
        logger.info(
            "secure_tool_execution.execute_secure_tools.completed_successfully",
            extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),
        )

        return {
            "status": "success",
            "message": "Request processed successfully",
            "response": text_result,
            "enkrypt_mcp_data": {
                "call_index": i,
                "server_name": server_name,
                "tool_name": tool_name,
                "args": args,
            },
            "enkrypt_policy_detections": {
                "input_guardrail_policy": guardrails_config["input_guardrails_policy"],
                "input_guardrail_response": input_guardrail_response,
                "output_guardrail_policy": guardrails_config[
                    "output_guardrails_policy"
                ],
                "output_guardrail_response": output_guardrail_response,
                "output_relevancy_response": output_relevancy_response,
                "output_adherence_response": output_adherence_response,
                "output_hallucination_response": output_hallucination_response,
            },
        }

    def _build_execution_summary(
        self,
        ctx,
        custom_id,
        server_name,
        num_tool_calls,
        results,
        guardrails_config,
        logger,
    ):
        """Build the final execution summary."""
        successful_calls = len([r for r in results if r["status"] == "success"])
        blocked_calls = len([r for r in results if r["status"].startswith("blocked")])
        failed_calls = len([r for r in results if r["status"] == "error"])

        sys_print(
            f"[secure_call_tools] Batch execution completed: {successful_calls} successful, {blocked_calls} blocked, {failed_calls} failed"
        )
        logger.info(
            "secure_tool_execution.execute_secure_tools.batch_execution_completed",
            extra=build_log_extra(
                ctx,
                custom_id,
                server_name,
                successful_calls=successful_calls,
                blocked_calls=blocked_calls,
                failed_calls=failed_calls,
            ),
        )

        return {
            "server_name": server_name,
            "status": "success",
            "summary": {
                "total_calls": num_tool_calls,
                "successful_calls": successful_calls,
                "blocked_calls": blocked_calls,
                "failed_calls": failed_calls,
            },
            "guardrails_applied": {
                "input_guardrails_enabled": guardrails_config["input_policy_enabled"],
                "output_guardrails_enabled": guardrails_config["output_policy_enabled"],
                "pii_redaction_enabled": guardrails_config["pii_redaction"],
                "relevancy_check_enabled": guardrails_config["relevancy"],
                "adherence_check_enabled": guardrails_config["adherence"],
                "hallucination_check_enabled": guardrails_config["hallucination"],
            },
            "results": results,
        }
