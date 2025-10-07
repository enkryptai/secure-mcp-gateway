"""
Enkrypt Secure MCP Gateway Module

This module provides the main gateway functionality for the Enkrypt Secure MCP Gateway, handling:
1. Authentication and Authorization:
   - API key validation
   - Gateway configuration management
   - Server access control

2. Tool Management:
   - Tool discovery and caching
   - Secure tool invocation
   - Server configuration management

3. Guardrail Integration:
   - Input/output guardrails
   - PII handling
   - Content quality checks

4. Cache Management:
   - Tool caching
   - Gateway config caching
   - Cache invalidation

Configuration Variables:
    enkrypt_base_url: Base URL for EnkryptAI API
    enkrypt_use_remote_mcp_config: Enable/disable remote MCP config
    enkrypt_remote_mcp_gateway_name: Name of the MCP gateway
    enkrypt_remote_mcp_gateway_version: Version of the MCP gateway
    enkrypt_tool_cache_expiration: Tool cache expiration in hours
    enkrypt_gateway_cache_expiration: Gateway config cache expiration in hours
    enkrypt_mcp_use_external_cache: Enable/disable external cache
    enkrypt_async_input_guardrails_enabled: Enable/disable async input guardrails

Example Usage:
    ```python
    # Authenticate gateway/user
    auth_result = enkrypt_authenticate(ctx)

    # Discover server tools
    tools = await enkrypt_discover_all_tools(ctx, "server1")

    # Call a tool securely
    result = await enkrypt_secure_call_tool(ctx, "server1", "tool1", args)

    # Get server information
    info = await enkrypt_get_server_info(ctx, "server1")
    ```
"""

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
print("Initializing Enkrypt Secure MCP Gateway Module", file=sys.stderr)
print("--------------------------------", file=sys.stderr)
print("SYSTEM INFO: ", file=sys.stderr)
print(f"Using Python interpreter: {sys.executable}", file=sys.stderr)
print(f"Python version: {sys.version}", file=sys.stderr)
print(f"Current working directory: {os.getcwd()}", file=sys.stderr)
print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}", file=sys.stderr)
# print(f"ENKRYPT_ENVIRONMENT: {ENKRYPT_ENVIRONMENT}", file=sys.stderr)
# print(f"IS_LOCAL_ENVIRONMENT: {IS_LOCAL_ENVIRONMENT}", file=sys.stderr)
print("--------------------------------", file=sys.stderr)

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

print("--------------------------------", file=sys.stderr)
print("PATHS: ", file=sys.stderr)
print(f"src_dir: {src_dir}", file=sys.stderr)
print(f"root_dir: {root_dir}", file=sys.stderr)
print("--------------------------------", file=sys.stderr)

# Try to install the package if not found to cater for clients like Claude Desktop who use a separate python interpreter
try:
    import secure_mcp_gateway
except ImportError:
    # What if user is intalling a specific version of the package?
    # package_name = src_dir if IS_LOCAL_ENVIRONMENT else "secure_mcp_gateway"

    # TODO: Fix error and use stdout
    print("Installing secure_mcp_gateway package...", file=sys.stderr)
    print(f"src_dir: {src_dir}", file=sys.stderr)
    print(f"src_dir: {src_dir}", file=sys.stderr)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", src_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

from secure_mcp_gateway.dependencies import __dependencies__
from secure_mcp_gateway.plugins.auth import get_auth_config_manager
from secure_mcp_gateway.utils import (
    get_common_config,
    sys_print,
)
from secure_mcp_gateway.version import __version__

sys_print(f"Successfully imported secure_mcp_gateway v{__version__} in gateway module")

# Initialize telemetry system with plugin-based architecture
from secure_mcp_gateway.plugins.telemetry import (
    get_telemetry_config_manager,
    initialize_telemetry_system,
)

# Initialize the telemetry system
try:
    telemetry_manager = initialize_telemetry_system()
    logger = telemetry_manager.get_logger()
    tracer = telemetry_manager.get_tracer()
except Exception as e:
    sys_print(f"Telemetry initialization failed: {e}", is_error=True)

    # Fallback to no-op logger/tracer if initialization fails
    class NoOpLogger:
        def info(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def debug(self, *args, **kwargs):
            pass

    class NoOpTracer:
        def start_as_current_span(self, *args, **kwargs):
            class NoOpSpan:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    pass

                def set_attribute(self, *args):
                    pass

            return NoOpSpan()

    logger = NoOpLogger()
    tracer = NoOpTracer()

try:
    sys_print("Installing dependencies...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", *__dependencies__],
        stdout=subprocess.DEVNULL,  # Suppress output
        stderr=subprocess.DEVNULL,
    )
    sys_print("All dependencies installed successfully.")
except Exception as e:
    sys_print(f"Error installing dependencies: {e}", is_error=True)

import traceback

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
    ENKRYPT_GATEWAY_CACHE_EXPIRATION,
    ENKRYPT_MCP_USE_EXTERNAL_CACHE,
    ENKRYPT_TOOL_CACHE_EXPIRATION,
    cache_client,
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

# Initialize telemetry system (already imported at top) based on new flag
if common_config.get("enkrypt_telemetry_enabled", False):
    initialize_telemetry_system(common_config)
    telemetry_manager = get_telemetry_config_manager()
    sys_print(f"Telemetry providers: {telemetry_manager.list_providers()}")
else:
    telemetry_manager = get_telemetry_config_manager()
    sys_print("Telemetry disabled by configuration (enkrypt_telemetry_enabled=false)")

# Plugin loading is now handled by the initialization functions above
sys_print(f"Registered guardrail providers: {guardrail_manager.list_providers()}")


ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"
FASTMCP_LOG_LEVEL = ENKRYPT_LOG_LEVEL.upper()

# Get API key and base URL from plugin configurations
plugins_config = common_config.get("plugins", {})
guardrails_config = plugins_config.get("guardrails", {}).get("config", {})
auth_config = plugins_config.get("auth", {}).get("config", {})

GUARDRAIL_URL = guardrails_config.get(
    "base_url", auth_config.get("base_url", "https://api.enkryptai.com")
)
ENKRYPT_USE_REMOTE_MCP_CONFIG = common_config.get(
    "enkrypt_use_remote_mcp_config", False
)
ENKRYPT_REMOTE_MCP_GATEWAY_NAME = common_config.get(
    "enkrypt_remote_mcp_gateway_name", "Test MCP Gateway"
)
ENKRYPT_REMOTE_MCP_GATEWAY_VERSION = common_config.get(
    "enkrypt_remote_mcp_gateway_version", "v1"
)
ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED = common_config.get(
    "enkrypt_async_input_guardrails_enabled", False
)
ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED = common_config.get(
    "enkrypt_async_output_guardrails_enabled", False
)
ENKRYPT_TELEMETRY_ENABLED = common_config.get("enkrypt_telemetry_enabled", False)
ENKRYPT_TELEMETRY_ENDPOINT = common_config.get("enkrypt_telemetry", {}).get(
    "endpoint", "http://localhost:4317"
)

GUARDRAIL_API_KEY = guardrails_config.get("api_key", auth_config.get("api_key", "null"))


sys_print("--------------------------------")
sys_print(f"enkrypt_log_level: {ENKRYPT_LOG_LEVEL}")
sys_print(f"is_debug_log_level: {IS_DEBUG_LOG_LEVEL}")
sys_print(f"guardrail_url: {GUARDRAIL_URL}")
sys_print(f"enkrypt_use_remote_mcp_config: {ENKRYPT_USE_REMOTE_MCP_CONFIG}")
if ENKRYPT_USE_REMOTE_MCP_CONFIG:
    sys_print(f"enkrypt_remote_mcp_gateway_name: {ENKRYPT_REMOTE_MCP_GATEWAY_NAME}")
    sys_print(
        f"enkrypt_remote_mcp_gateway_version: {ENKRYPT_REMOTE_MCP_GATEWAY_VERSION}"
    )
sys_print(f'guardrail_api_key: {"****" + GUARDRAIL_API_KEY[-4:]}')
sys_print(f"enkrypt_tool_cache_expiration: {ENKRYPT_TOOL_CACHE_EXPIRATION}")
sys_print(f"enkrypt_gateway_cache_expiration: {ENKRYPT_GATEWAY_CACHE_EXPIRATION}")
sys_print(f"enkrypt_mcp_use_external_cache: {ENKRYPT_MCP_USE_EXTERNAL_CACHE}")
sys_print(
    f"enkrypt_async_input_guardrails_enabled: {ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED}"
)
if IS_DEBUG_LOG_LEVEL:
    sys_print(
        f"enkrypt_async_output_guardrails_enabled: {ENKRYPT_ASYNC_OUTPUT_GUARDRAILS_ENABLED}",
        is_debug=True,
    )
sys_print(f"enkrypt_telemetry_enabled: {ENKRYPT_TELEMETRY_ENABLED}")
sys_print(f"enkrypt_telemetry_endpoint: {ENKRYPT_TELEMETRY_ENDPOINT}")
sys_print("--------------------------------")

# TODO
AUTH_SERVER_VALIDATE_URL = f"{GUARDRAIL_URL}/mcp-gateway/get-gateway"

# For Output Checks if they are enabled in output_guardrails_policy['additional_config']
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
def get_local_mcp_config(gateway_key, project_id=None, user_id=None):
    """Wrapper for getting local MCP config using the auth manager."""
    auth_manager = get_auth_config_manager()
    return auth_manager.get_local_mcp_config(gateway_key, project_id, user_id)


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
        IS_DEBUG_LOG_LEVEL=IS_DEBUG_LOG_LEVEL,
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
        logger=logger,
        cache_client=cache_client,
    )


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
    service = DiscoveryService()
    return await service.discover_tools(
        ctx=ctx,
        server_name=server_name,
        tracer_obj=tracer,
        logger=logger,
        IS_DEBUG_LOG_LEVEL=IS_DEBUG_LOG_LEVEL,
    )


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
    debug=True if FASTMCP_LOG_LEVEL == "DEBUG" else False,
    log_level=FASTMCP_LOG_LEVEL,
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


# --- Run ---
if __name__ == "__main__":
    sys_print("Starting Enkrypt Secure MCP Gateway")
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
        mcp.settings.debug = True if FASTMCP_LOG_LEVEL == "DEBUG" else False
        mcp.settings.log_level = FASTMCP_LOG_LEVEL
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8000
        mcp.settings.mount_path = "/"
        mcp.settings.streamable_http_path = "/mcp/"
        mcp.settings.json_response = True
        mcp.settings.stateless_http = False
        mcp.settings.dependencies = __dependencies__
        # --------------------------------------------
        mcp.run(transport="streamable-http", mount_path="/mcp/")
        sys_print("Enkrypt Secure MCP Gateway is running")
    except Exception as e:
        sys_print(f"Exception in mcp.run(): {e}", is_error=True)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
