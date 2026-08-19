from __future__ import annotations

from typing import Any

from secure_mcp_gateway.error_handling import create_error_response
from secure_mcp_gateway.exceptions import (
    ErrorCode,
    ErrorContext,
    create_discovery_error,
)
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.plugins.telemetry.conventions import (
    SpanAttributes,
    SpanNames,
    set_span_attr_with_legacy,
)
from secure_mcp_gateway.utils import (
    build_log_extra,
    clear_request_identity_context,
    get_server_info_by_name,
    logger,
    mask_key,
    mask_server_config_sensitive_data,
    set_request_identity_context,
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
        # Cloud auth may return ``None`` for any identity field (free-tier
        # or personal-account gateways, apikeys not bound to a registry,
        # local-apikey provider). Coerce to the placeholder so OTel
        # doesn't reject the attribute and so dashboards filtering by
        # ``enkrypt.org.id`` etc. see a stable token. (Note: cloud does
        # NOT return org_name -- only org_id.)
        enkrypt_org_id = gateway_config.get("org_id") or "not_provided"
        enkrypt_project_registry = gateway_config.get("registry_name") or "not_provided"
        # Mirrors the ``X-Enkrypt-MCP-Gateway`` /
        # ``X-Enkrypt-MCP-Gateway-Version`` headers we send to the cloud
        # when fetching this config -- same coercion rationale.
        enkrypt_gateway_name = gateway_config.get("gateway_name") or "not_provided"
        enkrypt_gateway_version = (
            gateway_config.get("gateway_version") or "not_provided"
        )
        session_key = f"{enkrypt_gateway_key}_{enkrypt_project_id}_{enkrypt_user_id}_{enkrypt_mcp_config_id}"

        with tracer.start_as_current_span(SpanNames.SERVER_INFO) as main_span:
            set_span_attr_with_legacy(
                main_span, SpanAttributes.SERVER_NAME, server_name
            )
            main_span.set_attribute(SpanAttributes.JOB, "enkrypt")
            main_span.set_attribute(SpanAttributes.ENV, "dev")
            main_span.set_attribute(SpanAttributes.CUSTOM_ID, custom_id)
            main_span.set_attribute(
                SpanAttributes.GATEWAY_KEY, mask_key(enkrypt_gateway_key)
            )
            set_span_attr_with_legacy(main_span, SpanAttributes.ORG_ID, enkrypt_org_id)
            set_span_attr_with_legacy(
                main_span, SpanAttributes.GATEWAY_NAME, enkrypt_gateway_name
            )
            main_span.set_attribute(
                SpanAttributes.GATEWAY_VERSION, enkrypt_gateway_version
            )
            set_span_attr_with_legacy(
                main_span, SpanAttributes.PROJECT_ID, enkrypt_project_id
            )
            set_span_attr_with_legacy(
                main_span, SpanAttributes.USER_ID, enkrypt_user_id
            )
            main_span.set_attribute(SpanAttributes.CONFIG_ID, enkrypt_mcp_config_id)
            set_span_attr_with_legacy(
                main_span, SpanAttributes.PROJECT_NAME, enkrypt_project_name
            )
            main_span.set_attribute(
                SpanAttributes.PROJECT_REGISTRY, enkrypt_project_registry
            )
            set_span_attr_with_legacy(
                main_span, SpanAttributes.USER_EMAIL, enkrypt_email
            )

            # Publish identity on the request-scoped ContextVar so every
            # downstream metric / log emitted under this request inherits
            # the rich identity tags (cache.hits/misses, etc.).
            #
            # Cloud-auth MCP clients only send ``apikey`` (no project_id /
            # user_id headers), so prefer the values resolved from the cloud
            # response (``gateway_config``) over the raw header credentials.
            set_request_identity_context(
                {
                    "user_id": gateway_config.get("user_id") or enkrypt_user_id,
                    "user_email": enkrypt_email,
                    "project_id": gateway_config.get("project_id")
                    or enkrypt_project_id,
                    "project_name": enkrypt_project_name,
                    "project_registry": enkrypt_project_registry,
                    "org_id": enkrypt_org_id,
                    "gateway_name": enkrypt_gateway_name,
                    "gateway_version": enkrypt_gateway_version,
                    "mcp_config_id": enkrypt_mcp_config_id,
                }
            )

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
                main_span.set_attribute(SpanAttributes.SUCCESS, True)

                # Mask sensitive data before returning
                masked_server_info = mask_server_config_sensitive_data(
                    latest_server_info
                )

                # Apply deny-list filter to the tools payload so the response
                # is consistent with what ``enkrypt_discover_all_tools`` shows.
                # ``policy_denied_tools`` / ``policy_denied_count`` are always
                # emitted (empty list / zero when nothing matched) so callers
                # have a stable contract.
                policy_denied, policy_count = self._apply_deny_list(
                    masked_server_info, latest_server_info
                )

                return {
                    "status": "success",
                    "server_name": server_name,
                    "server_info": masked_server_info,
                    "policy_denied_tools": policy_denied,
                    "policy_denied_count": policy_count,
                }

            except Exception as e:
                main_span.record_exception(e)
                main_span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(e))
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
            finally:
                clear_request_identity_context()

    def _generate_custom_id(self) -> str:
        """Generate a custom ID for tracking."""
        import uuid

        return str(uuid.uuid4())

    def _apply_deny_list(self, masked_server_info, source_server_info):
        """
        Filter the masked server-info ``tools`` field through the deny list
        configured on the *unmasked* source. The deny rules and configured
        allow list come from the source because masking may rewrite tool
        names or metadata.

        Mutates ``masked_server_info["tools"]`` in place and returns
        ``(decisions, count)``. Always returns a list (possibly empty)
        and an int so the response shape is stable.
        """
        from secure_mcp_gateway.gateway import _filter_tools_payload

        denied = source_server_info.get("denied_tools", []) or []
        configured_allowed = source_server_info.get("tools", {}) or {}

        # Mask may have replaced tools with a marker dict. If the masked
        # value isn't a recognisable shape, we still want to report what
        # the policy *would* have denied based on the unmasked tool names.
        if not denied:
            return [], 0

        target = masked_server_info.get("tools")
        new_target, decisions = _filter_tools_payload(
            target, denied, configured_allowed
        )
        if new_target is not target:
            masked_server_info["tools"] = new_target
        return decisions, len(decisions)

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
        with tracer.start_as_current_span(SpanNames.SERVER_INFO_AUTH) as auth_span:
            auth_span.set_attribute(SpanAttributes.CUSTOM_ID, custom_id)
            auth_span.set_attribute(
                SpanAttributes.GATEWAY_KEY, mask_key(enkrypt_gateway_key)
            )

            # Add authentication status tracking
            is_authenticated = await self.auth_manager.is_authenticated(ctx)
            auth_span.set_attribute(SpanAttributes.IS_AUTHENTICATED, is_authenticated)

            if not is_authenticated:
                # Import here to avoid circular imports
                from secure_mcp_gateway.gateway import enkrypt_authenticate

                result = await enkrypt_authenticate(ctx)
                auth_span.set_attribute(
                    SpanAttributes.AUTH_RESULT, result.get("status")
                )
                if result.get("status") != "success":
                    auth_msg = result.get("message", "Unknown auth error")
                    auth_err = result.get("error", "")
                    detail = f"Authentication failed: {auth_msg}"
                    if auth_err and auth_err != auth_msg:
                        detail += f" ({auth_err})"
                    auth_span.set_attribute(SpanAttributes.ERROR_MESSAGE, detail)
                    logger.warning(f"[get_server_info] {detail}")
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
                        message=detail,
                        context=context,
                    )
                    return create_error_response(err)
        return None

    async def _get_server_info(
        self, session_key, server_name, tracer, custom_id, logger
    ):
        """Get server info and check if server exists."""
        with tracer.start_as_current_span(SpanNames.SERVER_INFO_CHECK) as server_span:
            set_span_attr_with_legacy(
                server_span, SpanAttributes.SERVER_NAME, server_name
            )
            server_info = get_server_info_by_name(
                self.auth_manager.get_session_gateway_config(session_key), server_name
            )
            server_span.set_attribute(
                SpanAttributes.TOOL_FOUND, server_info is not None
            )

            if not server_info:
                server_span.set_attribute(
                    SpanAttributes.ERROR_MESSAGE,
                    f"Server '{server_name}' not available",
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
        with tracer.start_as_current_span(SpanNames.SERVER_INFO_LATEST) as info_span:
            set_span_attr_with_legacy(
                info_span, SpanAttributes.SERVER_NAME, server_name
            )
            info_span.set_attribute(
                SpanAttributes.GATEWAY_KEY, mask_key(enkrypt_gateway_key)
            )
            info_span.set_attribute(
                "gateway_id",
                self.auth_manager.get_session_gateway_config(session_key)["id"],
            )
            set_span_attr_with_legacy(
                info_span, SpanAttributes.PROJECT_ID, enkrypt_project_id
            )
            set_span_attr_with_legacy(
                info_span, SpanAttributes.USER_ID, enkrypt_user_id
            )
            info_span.set_attribute(SpanAttributes.CONFIG_ID, enkrypt_mcp_config_id)
            set_span_attr_with_legacy(
                info_span, SpanAttributes.PROJECT_NAME, enkrypt_project_name
            )
            set_span_attr_with_legacy(
                info_span, SpanAttributes.USER_EMAIL, enkrypt_email
            )

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
