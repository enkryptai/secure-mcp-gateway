"""Main MCP Gateway module."""

import os
import subprocess
import sys

# ENKRYPT_ENVIRONMENT = os.environ.get("ENKRYPT_ENVIRONMENT", "production")
# IS_LOCAL_ENVIRONMENT = ENKRYPT_ENVIRONMENT == "local"

# Printing system info before importing other modules
# As MCP Clients like Claude Desktop use their own Python interpreter, it may not have the modules installed
# So, we can use this debug system info to identify that python interpreter to install the missing modules using that specific interpreter
# So, debugging this in gateway module as this info can be used for fixing such issues in other modules
# TODO: Fix error and use stdout
# print("Initializing Enkrypt Secure MCP Gateway Module", file=sys.stderr)
# print("--------------------------------", file=sys.stderr)
# print("SYSTEM INFO: ", file=sys.stderr)
# print(f"Using Python interpreter: {sys.executable}", file=sys.stderr)
# print(f"Python version: {sys.version}", file=sys.stderr)
# print(f"Current working directory: {os.getcwd()}", file=sys.stderr)
# print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}", file=sys.stderr)
# print(f"ENKRYPT_ENVIRONMENT: {ENKRYPT_ENVIRONMENT}", file=sys.stderr)
# print(f"IS_LOCAL_ENVIRONMENT: {IS_LOCAL_ENVIRONMENT}", file=sys.stderr)
# print("--------------------------------", file=sys.stderr)

# Error: Can't find secure_mcp_gateway
# import importlib
# # Force module initialization to resolve pip installation issues
# try:
#     importlib.import_module("secure_mcp_gateway")
# except ImportError as e:
#     sys.stderr.write(f"Error importing secure_mcp_gateway: {e}\n")
#     sys.exit(1)

# Error: Can't find secure_mcp_gateway
# Add src directory to Python path
# from importlib.resources import files
# BASE_DIR = files('secure_mcp_gateway')
# if BASE_DIR not in sys.path:
#     sys.path.insert(0, BASE_DIR)

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, ".."))
# Go up one more level to reach project root
root_dir = os.path.abspath(os.path.join(src_dir, ".."))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# print("--------------------------------", file=sys.stderr)
# print("PATHS: ", file=sys.stderr)
# print(f"src_dir: {src_dir}", file=sys.stderr)
# print(f"root_dir: {root_dir}", file=sys.stderr)
# print("--------------------------------", file=sys.stderr)
# --- Logging must be configured BEFORE any module that uses `logger` ---
from secure_mcp_gateway.log import configure_logging, get_logger

configure_logging(
    level=os.environ.get("ENKRYPT_LOG_LEVEL", "INFO"),
    json_output=os.environ.get("ENKRYPT_LOG_FORMAT", "").lower() == "json",
)
_boot_logger = get_logger("secure_mcp_gateway.gateway")

from secure_mcp_gateway.dependencies import __dependencies__
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.utils import (
    async_input_guardrails_enabled,
    async_output_guardrails_enabled,
    get_common_config,
    get_fastmcp_log_level,
    get_guardrail_api_key,
    get_guardrail_base_url,
    get_log_level,
    get_remote_gateway_name,
    get_remote_gateway_version,
    get_telemetry_endpoint,
    is_debug_log_level,
    is_docker,
    is_telemetry_enabled,
    use_external_cache,
    use_remote_mcp_config,
)
from secure_mcp_gateway.version import __version__

_boot_logger.info("imported secure_mcp_gateway", version=__version__)

# Initialize telemetry system with plugin-based architecture
from secure_mcp_gateway.plugins.telemetry import (
    get_telemetry_config_manager,
    initialize_telemetry_system,
)

# Default to skipping dependency install in Docker (dependencies pre-installed in image)
skip_dep_install_env = os.environ.get("SKIP_DEPENDENCY_INSTALL")
skip_dependency_install = skip_dep_install_env == "true" or (
    skip_dep_install_env is None and is_docker()
)

if not skip_dependency_install:
    try:
        _boot_logger.info("installing dependencies")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", *__dependencies__],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _boot_logger.info("dependencies installed successfully")
    except Exception as e:
        _boot_logger.error("error installing dependencies", error=str(e))
else:
    reason = (
        "SKIP_DEPENDENCY_INSTALL=true"
        if skip_dep_install_env == "true"
        else "Docker environment detected"
    )
    _boot_logger.info("skipping dependency installation", reason=reason)

from mcp.server.fastmcp import Context, FastMCP

# from starlette.requests import Request # This is the class of ctx.request_context.request
from mcp.server.fastmcp.tools import Tool

from secure_mcp_gateway.plugins.auth import initialize_auth_system
from secure_mcp_gateway.plugins.guardrails import (
    get_guardrail_config_manager,
    initialize_guardrail_system,
)
from secure_mcp_gateway.plugins.guardrails.example_providers import (
    CustomKeywordProvider,
    OpenAIGuardrailProvider,
)
from secure_mcp_gateway.services.cache.cache_service import (
    cache_client,
    cache_service,
)
from secure_mcp_gateway.services.discovery import DiscoveryService
from secure_mcp_gateway.services.server.server_info_service import ServerInfoService
from secure_mcp_gateway.services.server.server_listing_service import (
    ServerListingService,
)

common_config = get_common_config()  # Pass True to print debug info

# Initialize guardrail system and get manager
initialize_guardrail_system(common_config)
guardrail_manager = get_guardrail_config_manager()

# Initialize auth system
initialize_auth_system(common_config)

# Initialize telemetry system based on plugin configuration
telemetry_manager = initialize_telemetry_system(common_config)
logger = get_logger("secure_mcp_gateway.gateway")
tracer = telemetry_manager.get_tracer()
logger.info("telemetry providers loaded", providers=telemetry_manager.list_providers())

# Initialize timeout management system
from secure_mcp_gateway.services.timeout import initialize_timeout_manager

timeout_manager = initialize_timeout_manager(common_config)
logger.info(
    f"Timeout management system initialized with {len(timeout_manager.get_active_operations())} active operations"
)

# Initialize sandbox system
from secure_mcp_gateway.plugins.sandbox import (
    get_sandbox_config_manager,
    initialize_sandbox_system,
)

sandbox_manager = initialize_sandbox_system(common_config)
logger.info(f"Registered sandbox providers: {sandbox_manager.list_providers()}")

# Initialize session pool for reusing MCP server processes across calls
from secure_mcp_gateway.services.session.session_pool import initialize_session_pool

session_pool = initialize_session_pool(common_config)
logger.info(
    f"Session pool initialized (enabled={session_pool.enabled}, ttl={session_pool.ttl}s)"
)

# Plugin loading is now handled by the initialization functions above
logger.info(f"Registered guardrail providers: {guardrail_manager.list_providers()}")

# Start config-file watcher so edits to enkrypt_mcp_config.json take effect
# without restarting the process. The watcher is a daemon thread so it does
# not block process shutdown. Disabled when poll_seconds <= 0.
try:
    from secure_mcp_gateway.config_watcher import start_config_watcher

    start_config_watcher()
except Exception as e:
    logger.warning(f"[gateway] config watcher startup failed: {e}")


# NOTE: gateway runtime settings are now resolved lazily via accessors in
# secure_mcp_gateway.utils so changes to enkrypt_mcp_config.json take effect
# on the next request without restarting the gateway. The module-level
# globals that used to live here have been removed. See:
#   - get_log_level / is_debug_log_level / get_fastmcp_log_level
#   - get_guardrail_base_url / get_guardrail_api_key
#   - use_remote_mcp_config / get_remote_gateway_name / get_remote_gateway_version
#   - async_input_guardrails_enabled / async_output_guardrails_enabled
#   - is_telemetry_enabled / get_telemetry_endpoint
#   - use_external_cache / get_tool_cache_ttl_hours / get_gateway_cache_ttl_seconds

logger.info("--------------------------------")
logger.info(f"enkrypt_log_level: {get_log_level()}")
logger.info(f"is_debug_log_level: {is_debug_log_level()}")
logger.info(f"guardrail_url: {get_guardrail_base_url()}")
logger.info(f"enkrypt_use_remote_mcp_config: {use_remote_mcp_config()}")
if use_remote_mcp_config():
    logger.info(f"enkrypt_remote_mcp_gateway_name: {get_remote_gateway_name()}")
    logger.info(f"enkrypt_remote_mcp_gateway_version: {get_remote_gateway_version()}")
_gk = get_guardrail_api_key()
logger.info(f"guardrail_api_key: {'****' + (_gk[-4:] if len(_gk) >= 4 else _gk)}")
logger.info(f"enkrypt_tool_cache_expiration: {cache_service.tool_cache_expiration}")
logger.info(
    f"enkrypt_gateway_cache_expiration: {cache_service.gateway_cache_expiration}"
)
logger.info(f"enkrypt_mcp_use_external_cache: {use_external_cache()}")
logger.info(
    f"enkrypt_async_input_guardrails_enabled: {async_input_guardrails_enabled()}"
)
if is_debug_log_level():
    logger.debug(
        f"enkrypt_async_output_guardrails_enabled: {async_output_guardrails_enabled()}"
    )
logger.info(f"telemetry_enabled: {is_telemetry_enabled()}")
logger.info(f"telemetry_endpoint: {get_telemetry_endpoint()}")
logger.info("--------------------------------")

# TODO


def get_auth_server_validate_url() -> str:
    """Return the upstream cloud auth validate URL using the latest config."""
    return f"{get_guardrail_base_url()}/mcp-gateway/get-gateway"


# For Output Checks if they are enabled in output_guardrails_config['additional_config']
RELEVANCY_THRESHOLD = 0.75
ADHERENCE_THRESHOLD = 0.75


# --- Session data (for current session only, not persistent) ---
SESSIONS = {
    # "sample_gateway_key_1": {
    #     "authenticated": False,
    #     "gateway_config": None
    # }
}

# --- Helper functions ---


def mask_key(key):
    """
    Masks the last 4 characters of the key.
    """
    if not key or len(key) < 4:
        return "****"
    return "****" + key[-4:]


# Getting gateway key per request instead of global variable
# As we can support multuple gateway configs in the same Secure MCP Gateway server
def get_gateway_credentials(ctx: Context):
    """Wrapper for getting credentials using the auth manager."""
    auth_manager = get_auth_config_manager()
    return auth_manager.get_gateway_credentials(ctx)


# Read from local MCP config file
async def get_local_mcp_config(
    gateway_key, project_id=None, user_id=None, gateway_name=None, gateway_version=None
):
    """Wrapper for getting local MCP config using the auth manager."""
    auth_manager = get_auth_config_manager()
    return await auth_manager.get_local_mcp_config(
        gateway_key,
        project_id,
        user_id,
        gateway_name=gateway_name,
        gateway_version=gateway_version,
    )


async def enkrypt_authenticate(ctx: Context):
    """Wrapper for authentication using the auth manager."""
    auth_manager = get_auth_config_manager()
    auth_result = await auth_manager.authenticate(ctx)

    # Convert to legacy format for backward compatibility
    from secure_mcp_gateway.plugins.auth.config_manager import (
        convert_auth_result_to_legacy_format,
    )

    return convert_auth_result_to_legacy_format(auth_result)


# --- MCP Tools ---


# NOTE: inputSchema is not supported here if we explicitly define it.
# But it is defined in the SDK - https://modelcontextprotocol.io/docs/concepts/tools#python
# As FastMCP automatically generates an input schema based on the function's parameters and type annotations.
# See: https://gofastmcp.com/servers/tools#the-%40tool-decorator
# Annotations can be explicitly defined - https://gofastmcp.com/servers/tools#annotations-2


# NOTE: If we use the name "enkrypt_list_available_servers", for some reason claude-desktop throws internal server error.
# So we use a different name as it doesn't even print any logs for us to troubleshoot the issue.
async def enkrypt_list_all_servers(ctx: Context, discover_tools: bool = True):
    """
    Lists available servers with their tool information.

    This function provides a comprehensive list of available servers,
    including their tools and configuration status.

    Args:
        ctx (Context): The MCP context
        discover_tools (bool): Whether to discover tools for servers that need it

    Returns:
        dict: Server listing containing:
            - status: Success/error status
            - available_servers: Dictionary of available servers
            - servers_needing_discovery: List of servers requiring tool discovery
    """
    service = ServerListingService()
    return await service.list_servers(
        ctx=ctx,
        discover_tools=discover_tools,
        tracer=tracer,
        logger=logger,
        IS_DEBUG_LOG_LEVEL=is_debug_log_level(),
        cache_client=cache_client,
    )


async def enkrypt_get_server_info(ctx: Context, server_name: str):
    """
    Gets detailed information about a server, including its tools.

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server

    Returns:
        dict: Server information containing:
            - status: Success/error status
            - server_name: Name of the server
            - server_info: Detailed server configuration
    """
    service = ServerInfoService()
    return await service.get_server_info(
        ctx=ctx,
        server_name=server_name,
        tracer=tracer,
        cache_client=cache_client,
    )


def _get_tool_name(item):
    """Extract a tool's name from any of the supported shapes."""
    if isinstance(item, dict):
        return item.get("name") or item.get("tool_name") or ""
    return getattr(item, "name", "") or ""


def _collect_deny_decisions(names, denied, allowed):
    """
    Run the deny matcher over each tool name and return a tuple of
    (visible_names_set, denied_decisions_list) where each decision is
    ``{"name", "pattern", "reason"}``.
    """
    from secure_mcp_gateway.services.execution.deny_matcher import is_tool_denied

    visible = set()
    denied_decisions = []
    for name in names:
        match = is_tool_denied(name, denied, allowed)
        if match is None:
            visible.add(name)
        else:
            denied_decisions.append(match)
    return visible, denied_decisions


def _filter_tools_payload(tools, denied, allowed):
    """
    Filter denied tools from any of the formats the gateway uses:

    - ``ListToolsResult`` (Pydantic) with ``.tools`` list
    - ``{"tools": [...]}`` wrapper dict (cached form)
    - Flat dict keyed by tool name
    - Plain list of Tool objects / dicts

    Returns ``(filtered_payload, denied_decisions)`` where ``denied_decisions``
    is a list of ``{"name", "pattern", "reason"}`` dicts describing every tool
    that was removed.
    """
    if not denied or tools is None:
        return tools, []

    # Flat dict: {name: metadata}
    if isinstance(tools, dict) and "tools" not in tools:
        visible, decisions = _collect_deny_decisions(
            list(tools.keys()), denied, allowed
        )
        return {k: v for k, v in tools.items() if k in visible}, decisions

    # Wrapper dict: {"tools": [...]} (and possibly other keys)
    if isinstance(tools, dict) and isinstance(tools.get("tools"), list):
        names = [_get_tool_name(t) for t in tools["tools"]]
        visible, decisions = _collect_deny_decisions(names, denied, allowed)
        new_list = [t for t in tools["tools"] if _get_tool_name(t) in visible]
        new_payload = dict(tools)
        new_payload["tools"] = new_list
        return new_payload, decisions

    # Plain list
    if isinstance(tools, list):
        names = [_get_tool_name(t) for t in tools]
        visible, decisions = _collect_deny_decisions(names, denied, allowed)
        return [t for t in tools if _get_tool_name(t) in visible], decisions

    # Pydantic ListToolsResult: has .tools attribute that is a list.
    #
    # CRITICAL: do NOT mutate ``tools`` in place. The same object may also be
    # held by the local in-process cache (same Python reference), and mutating
    # it would silently corrupt the cache so subsequent cache hits return the
    # already-filtered list with no record of the deny decision. Always
    # construct a *new* model instance via ``model_copy`` (Pydantic v2) or
    # ``copy(update=...)`` (v1); fall back to a plain list if neither is
    # available.
    inner = getattr(tools, "tools", None)
    if isinstance(inner, list):
        names = [_get_tool_name(t) for t in inner]
        visible, decisions = _collect_deny_decisions(names, denied, allowed)
        new_inner = [t for t in inner if _get_tool_name(t) in visible]

        if hasattr(tools, "model_copy"):
            try:
                return tools.model_copy(update={"tools": new_inner}), decisions
            except Exception:
                pass
        copy_method = getattr(tools, "copy", None)
        if callable(copy_method):
            try:
                return copy_method(update={"tools": new_inner}), decisions
            except TypeError:
                pass
        return new_inner, decisions

    return tools, []


def _filter_denied_from_discovery(
    result, local_config, server_name, filter_denied_tools
):
    """
    Remove denied tools from discovery results in-place and **always** attach
    ``policy_denied_tools`` (list) and ``policy_denied_count`` (int) so callers
    have a stable contract — empty list / zero when nothing matched.

    ``filter_denied_tools`` is kept in the signature for backward compatibility
    but is no longer used; deny decisions go through ``is_tool_denied`` so we
    can capture per-tool reasons.
    """
    del filter_denied_tools  # unused

    mcp_config = local_config.get("mcp_config", []) if local_config else []
    server_deny_map = {
        s.get("server_name"): (s.get("denied_tools", []), s.get("tools", {}))
        for s in mcp_config
    }

    if server_name:
        denied, allowed = server_deny_map.get(server_name, ([], {}))
        decisions: list = []
        if denied:
            new_tools, decisions = _filter_tools_payload(
                result.get("tools"), denied, allowed
            )
            result["tools"] = new_tools
        result["policy_denied_tools"] = decisions
        result["policy_denied_count"] = len(decisions)
    else:
        available = result.get("available_servers", {})
        for sname, sdata in available.items():
            if not isinstance(sdata, dict):
                continue

            # If a previous pass (the per-server enkrypt_discover_all_tools
            # invoked by enkrypt_list_all_servers) already attached deny
            # metadata, preserve it. Re-running the filter here would always
            # produce zero decisions because ``sdata["tools"]`` has already
            # been filtered, which would silently clobber the original
            # attribution. Only normalise the keys if they're missing.
            if "policy_denied_tools" in sdata:
                sdata.setdefault(
                    "policy_denied_count",
                    len(sdata.get("policy_denied_tools") or []),
                )
                continue

            denied, allowed = server_deny_map.get(sname, ([], {}))
            decisions = []
            if denied:
                new_tools, decisions = _filter_tools_payload(
                    sdata.get("tools"), denied, allowed
                )
                sdata["tools"] = new_tools
            sdata["policy_denied_tools"] = decisions
            sdata["policy_denied_count"] = len(decisions)


# NOTE: Using name "enkrypt_discover_server_tools" is not working in Cursor for some reason.
# So using a different name "enkrypt_discover_all_tools" which works.
async def enkrypt_discover_all_tools(ctx: Context, server_name: str = None):
    """
    Discovers and caches available tools for a specific server or all servers if server_name is None.

    This function handles tool discovery for a server, with support for
    caching discovered tools and fallback to configured tools.

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server to discover tools for

    Returns:
        dict: Discovery result containing:
            - status: Success/error status
            - message: Discovery result message
            - tools: Dictionary of discovered tools
            - source: Source of the tools (config/cache/discovery)
    """
    # Get proper session key to match the one used for caching
    creds = get_gateway_credentials(ctx)
    gateway_key = creds.get("gateway_key")
    project_id = creds.get("project_id")
    user_id = creds.get("user_id")
    gateway_name = creds.get("gateway_name")
    gateway_version = creds.get("gateway_version")

    # Get mcp_config_id from local config
    auth_manager = get_auth_config_manager()
    local_config = await auth_manager.get_local_mcp_config(
        gateway_key,
        project_id,
        user_id,
        gateway_name=gateway_name,
        gateway_version=gateway_version,
    )
    mcp_config_id = (
        local_config.get("mcp_config_id", "not_provided")
        if local_config
        else "not_provided"
    )

    # Create the same session key format used by SecureToolExecutionService
    session_key = f"{gateway_key}_{project_id}_{user_id}_{mcp_config_id}"

    service = DiscoveryService()
    result = await service.discover_tools(
        ctx=ctx,
        server_name=server_name,
        tracer_obj=tracer,
        logger_instance=logger,
        IS_DEBUG_LOG_LEVEL=is_debug_log_level(),
        session_key=session_key,
    )

    # Filter out denied tools so the LLM never sees them
    from secure_mcp_gateway.services.execution.deny_matcher import (
        filter_denied_tools,
    )

    if result.get("status") == "success":
        _filter_denied_from_discovery(
            result, local_config, server_name, filter_denied_tools
        )

    return result


async def enkrypt_secure_call_tools(
    ctx: Context, server_name: str, tool_calls: list = []
):
    """
    If there are multiple tool calls to be made, please pass all of them in a single list. If there is only one tool call, pass it as a single object in the list.

    First check the number of tools needed for the prompt and then pass all of them in a single list. Because if tools are multiple and we pass one by one, it will create a new session for each tool call and that may fail.

    This has the ability to execute multiple tool calls in sequence within the same session, with guardrails and PII handling.

    This function provides secure batch execution with comprehensive guardrail checks for each tool call:
    - Input guardrails (PII, policy violations)
    - Output guardrails (relevancy, adherence, hallucination)
    - PII handling (anonymization/de-anonymization)

    Args:
        ctx (Context): The MCP context
        server_name (str): Name of the server containing the tools
        tool_calls (list): List of {"name": str, "args": dict, "env": dict} objects
            - name: Name of the tool to call
            - args: Arguments to pass to the tool
            # env is not supported by MCP protocol used by Claude Desktop for some reason
            # But it is defined in the SDK
            # https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/stdio/__init__.py
            # - env: Optional environment variables to pass to the tool

    Example:
        tool_calls = [
            {"name": "navigate", "args": {"url": "https://enkryptai.com"}},
            {"name": "screenshot", "args": {"filename": "enkryptai-homepage.png"}}
        ]

    Returns:
        dict: Batch execution results with guardrails responses
            - status: Success/error status
            - message: Response message
            - Additional response data or error details
    """
    from secure_mcp_gateway.services.execution.secure_tool_execution_service import (
        SecureToolExecutionService,
    )

    secure_tool_execution_service = SecureToolExecutionService()
    return await secure_tool_execution_service.execute_secure_tools(
        ctx, server_name, tool_calls, logger
    )


# # Using GATEWAY_TOOLS instead of @mcp.tool decorator
# @mcp.tool(
#     name="enkrypt_get_cache_status",
#     description="Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered. This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed. Use this only if you need to debug cache issues or asked specifically for cache status.",
#     annotations={
#         "title": "Get Cache Status",
#         "readOnlyHint": True,
#         "destructiveHint": False,
#         "idempotentHint": True,
#         "openWorldHint": False
#     }
#     # inputSchema={
#     #     "type": "object",
#     #     "properties": {},
#     #     "required": []
#     # }
# )
async def enkrypt_get_cache_status(ctx: Context):
    """
    Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered.
    This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed.
    Use this only if you need to debug cache issues or asked specifically for cache status.

    This function provides detailed information about the cache state,
    including gateway/user-specific and global cache statistics.

    Args:
        ctx (Context): The MCP context

    Returns:
        dict: Cache status containing:
            - status: Success/error status
            - cache_status: Detailed cache statistics and status
    """
    from secure_mcp_gateway.services.cache.cache_status_service import (
        CacheStatusService,
    )

    cache_status_service = CacheStatusService()
    return await cache_status_service.get_cache_status(ctx, logger)


# # Using GATEWAY_TOOLS instead of @mcp.tool decorator
# @mcp.tool(
#     name="enkrypt_clear_cache",
#     description="Clear the gateway cache for all/specific servers/gateway config. Use this only if you need to debug cache issues or asked specifically to clear cache.",
#     annotations={
#         "title": "Clear Cache",
#         "readOnlyHint": False,
#         "destructiveHint": True,
#         "idempotentHint": False,
#         "openWorldHint": True
#     }
#     # inputSchema={
#     #     "type": "object",
#     #     "properties": {
#     #         "id": {
#     #             "type": "string",
#     #             "description": "The ID of the Gateway or User to clear cache for"
#     #         },
#     #         "server_name": {
#     #             "type": "string",
#     #             "description": "The name of the server to clear cache for"
#     #         },
#     #         "cache_type": {
#     #             "type": "string",
#     #             "description": "The type of cache to clear"
#     #         }
#     #     },
#     #     "required": []
#     # }
# )
async def enkrypt_clear_cache(
    ctx: Context, id: str = None, server_name: str = None, cache_type: str = None
):
    """
    Clears various types of caches in the MCP Gateway.
    Use this only if you need to debug cache issues or asked specifically to clear cache.

    This function can clear:
    - Tool cache for a specific server
    - Tool cache for all servers
    - Gateway config cache
    - All caches

    Args:
        ctx (Context): The MCP context
        id (str, optional): ID of the Gateway or User whose cache to clear
        server_name (str, optional): Name of the server whose cache to clear
        cache_type (str, optional): Type of cache to clear ('all', 'gateway_config', 'server_config')

    Returns:
        dict: Cache clearing result containing:
            - status: Success/error status
            - message: Cache clearing result message
    """
    from secure_mcp_gateway.services.cache.cache_management_service import (
        CacheManagementService,
    )

    cache_management_service = CacheManagementService()
    return await cache_management_service.clear_cache(
        ctx, id, server_name, cache_type, logger
    )


async def enkrypt_get_timeout_metrics(ctx: Context):
    """
    Get timeout management metrics including active operations, success rates, and escalation counts.

    Use this to monitor timeout performance and identify potential issues.
    """
    from secure_mcp_gateway.services.timeout import get_timeout_manager

    timeout_manager = get_timeout_manager()
    metrics = timeout_manager.get_metrics()
    active_operations = timeout_manager.get_active_operations()

    return {
        "timeout_metrics": metrics,
        "active_operations": active_operations,
        "timeout_config": {
            "default_timeout": timeout_manager.get_timeout("default"),
            "guardrail_timeout": timeout_manager.get_timeout("guardrail"),
            "auth_timeout": timeout_manager.get_timeout("auth"),
            "tool_execution_timeout": timeout_manager.get_timeout("tool_execution"),
            "discovery_timeout": timeout_manager.get_timeout("discovery"),
            "cache_timeout": timeout_manager.get_timeout("cache"),
            "connectivity_timeout": timeout_manager.get_timeout("connectivity"),
        },
    }


async def enkrypt_oauth_authorize(ctx: Context, server_name: str):
    """Begin gateway-managed OAuth for a server that needs a one-time browser sign-in.

    Use this for local servers whose OAuth is delivered via a credentials file
    (e.g. a Google Sheets MCP) BEFORE calling their tools. The gateway builds a
    Google/OAuth authorization URL (PKCE + offline access), reading the OAuth
    client id/secret and the registered redirect from the server's mounted
    gcp-oauth.keys.json when available, so no secrets need to be supplied.

    Returns ``auth_url`` -- present it to the user to open and approve. If the
    gateway runs on a host with a browser, it also auto-opens it. After approval
    the gateway exchanges the code, writes the credentials file, and the
    server's tools work normally. If a tool errors with "OAuth not completed",
    call this first.
    """
    from secure_mcp_gateway.gateway_oauth_routes import begin_authorization
    from secure_mcp_gateway.plugins.auth import get_auth_config_manager

    manager = get_auth_config_manager()
    auth_result = await manager.authenticate(ctx)
    if not getattr(auth_result, "is_success", False):
        return {
            "status": "error",
            "error": f"Authentication failed: {getattr(auth_result, 'message', 'unknown')}",
        }

    gateway_config = getattr(auth_result, "gateway_config", None) or {}
    mcp_config = (
        getattr(auth_result, "mcp_config", None)
        or gateway_config.get("mcp_config", [])
        or []
    )
    server_entry = next(
        (s for s in mcp_config if s.get("server_name") == server_name), None
    )
    if not server_entry:
        return {
            "status": "error",
            "error": f"Server '{server_name}' not found for this gateway",
        }

    result = await begin_authorization(server_name, server_entry, gateway_config)
    result.pop("status_code", None)
    return result


# --- MCP Gateway Server ---

GATEWAY_TOOLS = [
    Tool.from_function(
        fn=enkrypt_list_all_servers,
        name="enkrypt_list_all_servers",
        description="Get detailed information about all available servers, including their tools and configuration status.",
        annotations={
            "title": "List Available Servers",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {},
        #     "required": []
        # }
    ),
    Tool.from_function(
        fn=enkrypt_get_server_info,
        name="enkrypt_get_server_info",
        description="Get detailed information about a server, including its tools.",
        annotations={
            "title": "Get Server Info",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to get info for"
        #         }
        #     },
        #     "required": ["server_name"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_discover_all_tools,
        name="enkrypt_discover_all_tools",
        description="Discover available tools for a specific server or all servers if server_name is None",
        annotations={
            "title": "Discover Server Tools",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to discover tools for"
        #         }
        #     },
        #     "required": ["server_name"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_secure_call_tools,
        name="enkrypt_secure_call_tools",
        description="Securely call tools for a specific server. If there are multiple tool calls to be made, please pass all of them in a single list. If there is only one tool call, pass it as a single object in the list. First check the number of tools needed for the prompt and then pass all of them in a single list. Because if tools are multiple and we pass one by one, it will create a new session for each tool call and that may fail. If tools need to be discovered, pass empty list for tool_calls.",
        annotations={
            "title": "Securely Call Tools",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to call tools for"
        #         },
        #         "tool_calls": {
        #             "type": "array",
        #             "description": "The list of tool calls to make",
        #             "items": {
        #                 "type": "object",
        #                 "properties": {
        #                     "name": {
        #                         "type": "string",
        #                         "description": "The name of the tool to call"
        #                     },
        #                     "args": {
        #                         "type": "object",
        #                         "description": "The arguments to pass to the tool"
        #                     }
        # #                     "env": {
        # #                         "type": "object",
        # #                         "description": "The environment variables to pass to the tool"
        # #                     }
        #                 }
        #             }
        #         }
        #     },
        #     "required": ["server_name", "tool_calls"]
        # }
    ),
    Tool.from_function(
        fn=enkrypt_get_cache_status,
        name="enkrypt_get_cache_status",
        description="Gets the current status of the tool cache for the servers whose tools are empty {} for which tools were discovered. This does not have the servers whose tools are explicitly defined in the MCP config in which case discovery is not needed. Use this only if you need to debug cache issues or asked specifically for cache status.",
        annotations={
            "title": "Get Cache Status",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {},
        #     "required": []
        # }
    ),
    Tool.from_function(
        fn=enkrypt_clear_cache,
        name="enkrypt_clear_cache",
        description="Clear the gateway cache for all/specific servers/gateway config. Use this only if you need to debug cache issues or asked specifically to clear cache.",
        annotations={
            "title": "Clear Cache",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        # inputSchema={
        #     "type": "object",
        #     "properties": {
        #         "id": {
        #             "type": "string",
        #             "description": "The ID of the Gateway or User to clear cache for"
        #         },
        #         "server_name": {
        #             "type": "string",
        #             "description": "The name of the server to clear cache for"
        #         },
        #         "cache_type": {
        #             "type": "string",
        #             "description": "The type of cache to clear"
        #         }
        #     },
        #     "required": []
        # }
    ),
    Tool.from_function(
        fn=enkrypt_get_timeout_metrics,
        name="enkrypt_get_timeout_metrics",
        description="Gets timeout management metrics including active operations, success rates, and escalation counts. Use this to monitor timeout performance and identify potential issues.",
        annotations={
            "title": "Get Timeout Metrics",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    Tool.from_function(
        fn=enkrypt_oauth_authorize,
        name="enkrypt_oauth_authorize",
        description=(
            "Begin gateway-managed OAuth for a server that needs a one-time browser "
            "sign-in (e.g. a Google Sheets MCP using a credentials file). Returns an "
            "auth_url to present to the user; after they approve, the gateway stores the "
            "credentials and the server's tools work. Call this first if a tool errors "
            "with 'OAuth not completed'."
        ),
        annotations={
            "title": "Authorize Server OAuth",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    ),
]


# NOTE: Settings defined directly do not seem to work
# But when we do it later in main, it works. Not sure why.
mcp = FastMCP(
    name="Enkrypt Secure MCP Gateway",
    instructions="This is the Enkrypt Secure MCP Gateway. It is used to secure the MCP calls to the servers by authenticating with a gateway key and using guardrails to check both requests and responses.",
    # auth_server_provider=None,
    # event_store=None,
    # TODO: Not sure if we need to specify tools as it discovers them automatically
    tools=GATEWAY_TOOLS,
    debug=True if get_fastmcp_log_level() == "DEBUG" else False,
    log_level=get_fastmcp_log_level(),
    host="0.0.0.0",
    port=8000,
    mount_path="/",
    # sse_path="/sse/",
    # message_path="/messages/",
    streamable_http_path="/mcp/",
    json_response=True,
    stateless_http=False,
    dependencies=__dependencies__,
)

# Mount admin HTTP routes onto the gateway so a single REST call can flush
# this process's in-memory caches (mirrors api_cache_routes on the REST API
# server). See gateway_cache_routes.py for the full rationale.
try:
    from secure_mcp_gateway.gateway_cache_routes import (
        register_gateway_cache_routes,
    )

    register_gateway_cache_routes(mcp)
except Exception as e:
    logger.error(
        "[gateway] failed to register gateway cache routes",
        error=str(e),
        exc_info=True,
    )

# Mount the gateway-owned OAuth authorization-code routes so the gateway can
# drive a user browser sign-in for downstream servers and deliver the token
# (e.g. materialize the credentials file for google-sheets-mcp). The callback
# rides on this same port (already published, already bound 0.0.0.0), so no
# extra ports are needed. See gateway_oauth_routes.py for the full rationale.
try:
    from secure_mcp_gateway.gateway_oauth_routes import (
        register_gateway_oauth_routes,
    )

    register_gateway_oauth_routes(mcp)
except Exception as e:
    logger.error(
        "[gateway] failed to register gateway oauth routes",
        error=str(e),
        exc_info=True,
    )


# --- Run ---
if __name__ == "__main__":
    logger.info("Starting Enkrypt Secure MCP Gateway")
    try:
        # --------------------------------------------
        # NOTE:
        # Settings defined on top do not seem to work
        # But when we do it here, it works. Not sure why.
        # --------------------------------------------
        # Removing name, instructions due to the below error:
        # AttributeError: property 'name' of 'FastMCP' object has no setter
        # mcp.name = "Enkrypt Secure MCP Gateway"
        # mcp.instructions = "This is the Enkrypt Secure MCP Gateway. It is used to secure the MCP calls to the servers by authenticating with a gateway key and using guardrails to check both requests and responses."
        mcp.tools = GATEWAY_TOOLS
        # --------------------------------------------
        _fastmcp_log_level = get_fastmcp_log_level()
        mcp.settings.debug = True if _fastmcp_log_level == "DEBUG" else False
        mcp.settings.log_level = _fastmcp_log_level
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8000
        mcp.settings.mount_path = "/"
        mcp.settings.streamable_http_path = "/mcp/"
        mcp.settings.json_response = True
        mcp.settings.stateless_http = False
        mcp.settings.dependencies = __dependencies__
        # --------------------------------------------
        # Mount the playground HTTP routes (/mcp-playground/test-server,
        # /mcp-playground/get-tools, /mcp-playground/call-tool) onto the
        # FastMCP gateway so the playground UI works without needing
        # api_server.py to run in a separate process / container.  Same
        # pattern as gateway_cache_routes -- the routes are added via
        # FastMCP.custom_route inside the registration function and so
        # they MUST be attached before mcp.run() builds the ASGI app.
        try:
            from secure_mcp_gateway.gateway_playground_routes import (
                register_gateway_playground_routes,
            )

            register_gateway_playground_routes(mcp)
        except Exception as _exc:
            logger.warning(f"[gateway] failed to register playground routes: {_exc}")
        # --------------------------------------------
        # Transport mode: "streamable-http" (default) or "stdio"
        # Use MCP_TRANSPORT=stdio env var for stdio mode
        transport_mode = os.environ.get("MCP_TRANSPORT", "streamable-http").lower()
        if transport_mode == "stdio":
            logger.info("Running in stdio mode")
            mcp.run()
        else:
            logger.info("Running in streamable-http mode on port 8000")
            mcp.run(transport="streamable-http", mount_path="/mcp/")
        logger.info("Enkrypt Secure MCP Gateway is running")
    except Exception as e:
        logger.error("fatal error in mcp.run()", error=str(e), exc_info=True)
        sys.exit(1)
