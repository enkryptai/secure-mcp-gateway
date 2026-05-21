"""Common utilities for MCP Gateway."""

import json
import os
import secrets
import socket
import string
import sys
import threading
import time
from typing import Any
from urllib.parse import urlparse

from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DEFAULT_COMMON_CONFIG,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    EXAMPLE_CONFIG_PATH,
)
from secure_mcp_gateway.log import get_logger
from secure_mcp_gateway.version import __version__

logger = get_logger("secure_mcp_gateway")


# Get debug log level (lazy-loaded to avoid circular imports)
def _get_debug_log_level():
    return get_common_config().get("enkrypt_log_level", "INFO").lower() == "debug"


# Use a property-like approach to avoid circular imports
class _DebugLevel:
    def __bool__(self):
        return _get_debug_log_level()


IS_DEBUG_LOG_LEVEL = _DebugLevel()

IS_TELEMETRY_ENABLED = None


def get_file_from_root(file_name):
    """
    Get the absolute path of a file from the root directory (two levels up from current script)
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
    return os.path.join(root_dir, file_name)


def get_absolute_path(file_name):
    """
    Get the absolute path of a file
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, file_name)


def does_file_exist(file_name_or_path, is_absolute_path=None):
    """
    Check if a file exists in the current directory
    """
    if is_absolute_path is None:
        # Try to determine if it's an absolute path
        is_absolute_path = os.path.isabs(file_name_or_path)

    if is_absolute_path:
        return os.path.exists(file_name_or_path)
    else:
        return os.path.exists(get_absolute_path(file_name_or_path))


def is_docker():
    """Return True if the process is running inside any container.

    Historically named ``is_docker`` for backwards compatibility — it really
    answers "am I in a container?", covering Docker, containerd, podman, and
    Kubernetes pods regardless of which CRI runtime they use.

    Detection order (cheap → expensive, most reliable → fallback):

    1. ``KUBERNETES_SERVICE_HOST`` env var — kubelet injects this into every
       pod and it is never set on a real host. Highest-confidence signal for
       the K8s + containerd + cgroups v2 stack that ships in modern EKS / GKE
       / AKS / kind / k3s clusters.
    2. ``/.dockerenv`` — file dropped by the Docker daemon at container start.
       ``/run/.containerenv`` — equivalent marker used by podman / CRI-O.
    3. ``/proc/1/cgroup`` keyword sniff — works for cgroups v1 hierarchies
       (``docker``, ``kubepods``, ``containerd``, ``lxc`` appear in paths).
    4. ``/proc/1/cgroup`` cgroups-v2 heuristic — on the unified hierarchy a
       container's PID 1 sees a single ``0::/`` line with an empty path,
       whereas a host's PID 1 typically reports ``0::/init.scope`` or
       ``0::/system.slice/...``. This catches plain containerd / nerdctl /
       k3d that don't set any of the markers above.
    """
    # 1. Kubernetes — definitive, zero false positives outside K8s.
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True

    # 2. Runtime-dropped marker files.
    for indicator in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(indicator):
            return True

    # 3 + 4. cgroup inspection (covers v1 + v2; absent on macOS / Windows).
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as f:
            cgroup_text = f.read()
    except FileNotFoundError:
        return False

    container_identifiers = ("docker", "kubepods", "containerd", "lxc")
    if any(keyword in cgroup_text for keyword in container_identifiers):
        return True

    # cgroups v2 unified hierarchy: container PID 1 shows "0::/" with empty
    # path; host PID 1 shows a non-empty scope/slice path.
    if cgroup_text.strip() == "0::/":
        return True

    return False


# Config cache with file modification time tracking for hot-reload support
# Thread-safe implementation for async/concurrent access
_config_cache = {}
_config_mtime = 0
_config_path_cached = None
_config_lock = threading.RLock()

# Tracks the last "config missing" warning so a repeatedly-failing hot-reload
# poll doesn't flood logs with the same INFO line every few seconds. Keyed by
# (picked_config_path, example_path_exists) so a recovery-then-loss cycle still
# logs the second loss. Reset to ``None`` whenever a real config is loaded.
_missing_config_warned_for: tuple[str, bool] | None = None


def get_common_config(print_debug=False):
    """
    Get the common configuration for the Enkrypt Secure MCP Gateway.

    Uses file modification time to detect config changes and reload automatically.
    This enables hot-reload when config files are updated (e.g., in Docker volumes).
    Thread-safe for concurrent access.
    """
    global _config_cache, _config_mtime, _config_path_cached, _missing_config_warned_for

    if print_debug:
        logger.debug(f"[utils] config_path: {CONFIG_PATH}")
        logger.debug(f"[utils] docker_config_path: {DOCKER_CONFIG_PATH}")
        logger.debug(f"[utils] example_config_path: {EXAMPLE_CONFIG_PATH}")

    is_running_in_docker = is_docker()
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH

    with _config_lock:
        # Check if config file has been modified since last read
        if does_file_exist(picked_config_path):
            try:
                current_mtime = os.path.getmtime(picked_config_path)
            except OSError as e:
                logger.warning(
                    f"[utils] Error getting mtime for {picked_config_path}: {e}"
                )
                # Return cached config if available, otherwise use defaults
                if _config_cache:
                    return _config_cache
                return {**DEFAULT_COMMON_CONFIG, "plugins": {}}

            # Return cached config if file hasn't changed
            if (
                _config_cache
                and _config_path_cached == picked_config_path
                and current_mtime == _config_mtime
            ):
                return _config_cache

            # File changed or first load - reload config
            try:
                logger.info("loading config", path=picked_config_path)
                with open(picked_config_path, encoding="utf-8") as f:
                    config = json.load(f)
                _config_mtime = current_mtime
                _config_path_cached = picked_config_path
                # Real config loaded — clear the missing-config latch so a
                # later loss (e.g. volume unmount) re-emits the warning once.
                _missing_config_warned_for = None
            except (OSError, json.JSONDecodeError) as e:
                logger.error(
                    f"[utils] Error loading config from {picked_config_path}: {e}"
                )
                # Return cached config if available, otherwise use defaults
                if _config_cache:
                    return _config_cache
                return {**DEFAULT_COMMON_CONFIG, "plugins": {}}
        else:
            example_exists = does_file_exist(EXAMPLE_CONFIG_PATH)
            # Hot-reload polls this function frequently; only log the
            # missing-config warning once per (path, fallback-state) pair so
            # we don't flood OpenSearch/stdout when the operator's deployment
            # still hasn't materialised the config file.
            warn_key = (picked_config_path, example_exists)
            if _missing_config_warned_for != warn_key:
                logger.warning(
                    "[utils] No config file found at %s. Falling back to %s.",
                    picked_config_path,
                    "bundled example config"
                    if example_exists
                    else "hardcoded default common config",
                )
                _missing_config_warned_for = warn_key
            if example_exists:
                if print_debug:
                    logger.debug(f"[utils] Loading {EXAMPLE_CONFIG_NAME} file...")
                try:
                    with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                        config = json.load(f)
                except (OSError, json.JSONDecodeError) as e:
                    logger.error(f"[utils] Error loading example config: {e}")
                    config = {}
            else:
                config = {}

        if print_debug and config:
            logger.debug(f"[utils] config: {config}")

        common_config = config.get("common_mcp_gateway_config", {})
        plugins_config = config.get("plugins", {})
        enkrypt_config = config.get("enkrypt_config", {})
        # Merge with defaults to ensure all required fields exist
        _config_cache = {
            **DEFAULT_COMMON_CONFIG,
            **common_config,
            "plugins": plugins_config,
            "enkrypt_config": enkrypt_config,
        }
        return _config_cache


def clear_config_cache():
    """Clear the config cache to force reload on next get_common_config() call."""
    global _config_cache, _config_mtime, _config_path_cached, IS_TELEMETRY_ENABLED
    global _missing_config_warned_for
    with _config_lock:
        _config_cache = {}
        _missing_config_warned_for = None
        _config_mtime = 0
        _config_path_cached = None
    IS_TELEMETRY_ENABLED = None


def get_active_config_path() -> str:
    """Return the config file path currently in use (docker-aware)."""
    return DOCKER_CONFIG_PATH if is_docker() else CONFIG_PATH


# ---------------------------------------------------------------------------
# Lazy config accessors
#
# These all read get_common_config() on every call so the underlying mtime-
# based hot-reload picks up file changes without restart. Avoid storing the
# returned values in module-level globals.
# ---------------------------------------------------------------------------


def _enkrypt_cfg() -> dict:
    return get_common_config().get("enkrypt_config", {}) or {}


def _plugin_cfg(plugin: str) -> dict:
    return (
        get_common_config().get("plugins", {}).get(plugin, {}).get("config", {}) or {}
    )


def get_log_level() -> str:
    return get_common_config().get("enkrypt_log_level", "INFO").lower()


def is_debug_log_level() -> bool:
    return get_log_level() == "debug"


def get_fastmcp_log_level() -> str:
    return get_log_level().upper()


def get_guardrail_base_url() -> str:
    return (
        _plugin_cfg("guardrails").get("base_url")
        or _enkrypt_cfg().get("base_url")
        or _plugin_cfg("auth").get("base_url")
        or "https://api.enkryptai.com"
    )


def get_guardrail_api_key() -> str:
    return (
        _plugin_cfg("guardrails").get("api_key")
        or _enkrypt_cfg().get("api_key")
        or _plugin_cfg("auth").get("api_key")
        or "null"
    )


def use_remote_mcp_config() -> bool:
    """DEPRECATED. Reads ``common_mcp_gateway_config.enkrypt_use_remote_mcp_config``.

    Only meaningful for the legacy ``LocalApiKeyProvider`` "fetch config
    from Enkrypt cloud" fallback path. New deployments should switch to
    ``plugins.auth.provider = "enkrypt"`` instead, which has its own
    cloud-config flow that does not consult this flag.

    Defaults to ``False`` when the key is absent (which is now the case
    for newly-generated configs), so this accessor stays safe to call
    from any code path.
    """
    return bool(get_common_config().get("enkrypt_use_remote_mcp_config", False))


def get_remote_gateway_name() -> str:
    """DEPRECATED. Reads ``common_mcp_gateway_config.enkrypt_remote_mcp_gateway_name``.

    Only consulted by the legacy ``LocalApiKeyProvider``'s remote-fetch
    path and the legacy ``cache_management_service._refresh_remote_config``
    flow. The canonical "what gateway name should we identify ourselves
    as" is ``plugins.auth.config.gateway_name`` for the
    ``EnkryptAuthProvider``.
    """
    return get_common_config().get(
        "enkrypt_remote_mcp_gateway_name", "Test MCP Gateway"
    )


def get_remote_gateway_version() -> str:
    """DEPRECATED. Reads ``common_mcp_gateway_config.enkrypt_remote_mcp_gateway_version``.

    See :func:`get_remote_gateway_name` — same caveats. The canonical
    location is ``plugins.auth.config.gateway_version``.
    """
    return get_common_config().get("enkrypt_remote_mcp_gateway_version", "v1")


def async_input_guardrails_enabled() -> bool:
    return bool(
        get_common_config().get("enkrypt_async_input_guardrails_enabled", False)
    )


def async_output_guardrails_enabled() -> bool:
    return bool(
        get_common_config().get("enkrypt_async_output_guardrails_enabled", False)
    )


def get_telemetry_endpoint() -> str:
    return _plugin_cfg("telemetry").get("url", "http://localhost:4317")


def get_tool_cache_ttl_hours() -> float:
    return float(get_common_config().get("enkrypt_tool_cache_expiration", 4))


def get_gateway_cache_ttl_seconds() -> float:
    """Resolve gateway-config cache TTL with minutes-first preference.

    Order: enkrypt_gateway_cache_expiration_minutes (minutes) ->
    enkrypt_gateway_cache_expiration (hours) -> default 300s (5 min).
    """
    cfg = get_common_config()
    minutes = cfg.get("enkrypt_gateway_cache_expiration_minutes")
    if minutes is not None:
        try:
            return float(minutes) * 60.0
        except (TypeError, ValueError):
            pass
    hours = cfg.get("enkrypt_gateway_cache_expiration")
    if hours is not None:
        try:
            return float(hours) * 3600.0
        except (TypeError, ValueError):
            pass
    return 300.0


def get_config_watcher_poll_seconds() -> float:
    """Polling interval for the config-file watcher. 0 disables the watcher."""
    try:
        return float(
            get_common_config().get("enkrypt_config_watcher_poll_seconds", 2.0)
        )
    except (TypeError, ValueError):
        return 2.0


def use_external_cache() -> bool:
    return bool(get_common_config().get("enkrypt_mcp_use_external_cache", False))


def get_cache_host() -> str:
    return get_common_config().get("enkrypt_cache_host", "localhost")


def get_cache_port() -> int:
    return int(get_common_config().get("enkrypt_cache_port", 6379))


def get_cache_db() -> int:
    return int(get_common_config().get("enkrypt_cache_db", 0))


def get_cache_password():
    return get_common_config().get("enkrypt_cache_password", None)


def is_telemetry_enabled():
    """
    Check if telemetry is enabled
    """
    global IS_TELEMETRY_ENABLED
    if IS_TELEMETRY_ENABLED:
        return True
    elif IS_TELEMETRY_ENABLED is not None:
        return False

    config = get_common_config()
    telemetry_plugin_config = config.get("plugins", {}).get("telemetry", {})
    telemetry_config = telemetry_plugin_config.get("config", {})
    if not telemetry_config.get("enabled", False):
        IS_TELEMETRY_ENABLED = False
        return False

    endpoint = telemetry_config.get("url", "http://localhost:4317")

    try:
        parsed_url = urlparse(endpoint)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if not hostname or not port:
            logger.error(f"[utils] Invalid OTLP endpoint URL: {endpoint}")
            IS_TELEMETRY_ENABLED = False
            return False

        # Get configurable timeout from TimeoutManager
        from secure_mcp_gateway.services.timeout import get_timeout_manager

        timeout_manager = get_timeout_manager()
        timeout_value = timeout_manager.get_timeout("connectivity")

        with socket.create_connection((hostname, port), timeout=timeout_value):
            IS_TELEMETRY_ENABLED = True
            return True
    except (OSError, AttributeError, TypeError, ValueError) as e:
        logger.error(
            f"[utils] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}"
        )
        IS_TELEMETRY_ENABLED = False
        return False


def generate_custom_id():
    """
    Generate a unique identifier consisting of 34 random characters followed by current timestamp.

    Returns:
        str: A string in format '{random_chars}_{timestamp_ms}' that can be used as a unique identifier
    """
    try:
        # Generate 34 random characters (letters + digits)
        charset = string.ascii_letters + string.digits
        random_part = "".join(secrets.choice(charset) for _ in range(34))

        # Get current epoch time in milliseconds
        timestamp_ms = int(time.time() * 1000)

        return f"{random_part}_{timestamp_ms}"
    except Exception as e:
        logger.error(f"[utils] Error generating custom ID: {e}")
        # Fallback to a simpler ID if there's an error
        return f"fallback_{int(time.time())}"


def mask_key(key):
    """
    Masks the last 4 characters of the key.
    """
    if not key or len(key) < 4:
        return "****"
    return "****" + key[-4:]


def build_log_extra(ctx, custom_id=None, server_name=None, error=None, **kwargs):
    """Build structured log extras. Tolerates missing/invalid ctx.

    Falls back to 'not_provided' values if ctx is not an MCP Context or
    if credentials/config cannot be resolved.
    """
    project_id = "not_provided"
    user_id = "not_provided"
    project_name = "not_provided"
    email = "not_provided"
    mcp_config_id = "not_provided"
    org_id = "not_provided"
    registry_name = "not_provided"
    gateway_name = "not_provided"
    gateway_version = "not_provided"

    try:
        # Only attempt auth lookups when ctx looks like an MCP Context
        has_ctx_attrs = hasattr(ctx, "request_context") or hasattr(ctx, "__dict__")
        if has_ctx_attrs:
            from secure_mcp_gateway.plugins.auth import get_auth_config_manager

            auth_manager = get_auth_config_manager()
            credentials = auth_manager.get_gateway_credentials(ctx)
            gateway_key = credentials.get("gateway_key")
            project_id = credentials.get("project_id", project_id)
            user_id = credentials.get("user_id", user_id)
            gateway_name = credentials.get("gateway_name")

            if gateway_key:
                try:
                    import asyncio

                    # Check if we're already in an async context
                    try:
                        # Try to get the current event loop
                        loop = asyncio.get_running_loop()
                        # If we get here, we're in an async context, skip the call
                        # to avoid creating unawaited coroutines
                        pass
                    except RuntimeError:
                        # No event loop running, safe to use asyncio.run()
                        try:
                            gateway_config = (
                                asyncio.run(
                                    auth_manager.get_local_mcp_config(
                                        gateway_key,
                                        project_id,
                                        user_id,
                                        gateway_name=gateway_name,
                                    )
                                )
                                or {}
                            )
                            project_name = gateway_config.get(
                                "project_name", project_name
                            )
                            email = gateway_config.get("email", email)
                            mcp_config_id = gateway_config.get(
                                "mcp_config_id", mcp_config_id
                            )
                            # Cloud may return ``None`` for org_id / registry_name
                            # (free-tier / personal-account gateways, or apikeys
                            # not bound to a registry). Keep the "not_provided"
                            # placeholder in that case so log output stays uniform.
                            # (The cloud does NOT return ``org_name`` -- only
                            # ``org_id`` -- so there is intentionally no org_name
                            # read here.)
                            org_id = gateway_config.get("org_id") or org_id
                            registry_name = (
                                gateway_config.get("registry_name") or registry_name
                            )
                            # Mirrors the values sent on the
                            # ``X-Enkrypt-MCP-Gateway`` /
                            # ``X-Enkrypt-MCP-Gateway-Version`` headers of the
                            # cloud's ``get-gateway-config`` call. Lets log
                            # queries pivot per deployed gateway revision.
                            gateway_name = (
                                gateway_config.get("gateway_name") or gateway_name
                            )
                            gateway_version = (
                                gateway_config.get("gateway_version") or gateway_version
                            )
                        except Exception:
                            # If anything fails, just use defaults
                            pass
                except Exception:
                    # If anything fails, just use defaults
                    pass
    except Exception:
        # Swallow errors and use defaults to avoid breaking logging
        pass

    # Filter out None values from kwargs
    filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}

    return {
        "custom_id": custom_id or "",
        "server_name": server_name or "",
        "org_id": org_id or "",
        "project_id": project_id or "",
        "project_name": project_name or "",
        "registry_name": registry_name or "",
        "user_id": user_id or "",
        "email": email or "",
        "mcp_config_id": mcp_config_id or "",
        "gateway_name": gateway_name or "",
        "gateway_version": gateway_version or "",
        "error": error or "",
        **filtered_kwargs,
    }


def mask_server_config_sensitive_data(server_info):
    """
    Masks sensitive data in server configuration before returning to client.

    Args:
        server_info (dict): Server configuration dictionary

    Returns:
        dict: Server configuration with sensitive data masked
    """
    if not server_info:
        return server_info

    # Create a deep copy to avoid modifying the original
    import copy

    masked_server_info = copy.deepcopy(server_info)

    # Mask environment variables in config
    if "config" in masked_server_info and "env" in masked_server_info["config"]:
        masked_server_info["config"]["env"] = mask_sensitive_env_vars(
            masked_server_info["config"]["env"]
        )

    return masked_server_info


def mask_sensitive_env_vars(env_vars):
    """
    Masks sensitive environment variables that may contain tokens, keys, or secrets.

    Args:
        env_vars (dict): Dictionary of environment variables

    Returns:
        dict: Environment variables with sensitive values masked
    """
    if not env_vars:
        return env_vars

    sensitive_keys = [
        "token",
        "key",
        "secret",
        "password",
        "pass",
        "auth",
        "credential",
        "api_key",
        "access_token",
        "refresh_token",
        "bearer",
        "jwt",
        "github_token",
        "github_key",
        "gitlab_token",
        "bitbucket_token",
        "aws_key",
        "aws_secret",
        "azure_key",
        "gcp_key",
        "database_url",
        "connection_string",
        "uri",
        "url",
    ]

    masked_env = {}
    for key, value in env_vars.items():
        key_lower = key.lower()
        is_sensitive = any(
            sensitive_key in key_lower for sensitive_key in sensitive_keys
        )

        if is_sensitive and value:
            # Mask the value, showing only first 4 and last 4 characters
            if len(value) <= 8:
                masked_env[key] = "****"
            else:
                masked_env[key] = value[:4] + "****" + value[-4:]
        else:
            masked_env[key] = value

    return masked_env


def get_server_info_by_name(gateway_config, server_name):
    """
    Retrieves server configuration by server name from gateway config.

    Args:
        gateway_config (dict): Gateway/user's configuration containing server details
        server_name (str): Name of the server to look up

    Returns:
        dict: Server configuration if found, None otherwise
    """
    if IS_DEBUG_LOG_LEVEL:
        logger.debug(f"[get_server_info_by_name] Getting server info for {server_name}")
    mcp_config = gateway_config.get("mcp_config", [])
    if IS_DEBUG_LOG_LEVEL:
        # Mask sensitive data in debug logs
        masked_mcp_config = []
        for server in mcp_config:
            masked_server = server.copy()
            if "config" in masked_server and "env" in masked_server["config"]:
                masked_server["config"] = masked_server["config"].copy()
                masked_server["config"]["env"] = mask_sensitive_env_vars(
                    masked_server["config"]["env"]
                )
            masked_mcp_config.append(masked_server)
        logger.debug(f"[get_server_info_by_name] mcp_config: {masked_mcp_config}")
    return next((s for s in mcp_config if s.get("server_name") == server_name), None)


def mask_sensitive_headers(
    headers: dict[str, str] | dict[str, Any],
) -> dict[str, str]:
    """
    Mask sensitive information in HTTP headers for logging purposes.

    Args:
        headers: Dictionary of HTTP headers

    Returns:
        Dictionary with sensitive headers masked
    """
    if not headers:
        return {}

    # Define sensitive header patterns (case-insensitive)
    sensitive_patterns = [
        # Authentication headers
        "authorization",
        "auth",
        "bearer",
        "token",
        "apikey",
        "api-key",
        "api_key",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-auth",
        "x-token",
        "x-enkrypt-api-key",
        "x-enkrypt-gateway-key",
        # Security headers
        "cookie",
        "set-cookie",
        "x-csrf-token",
        "x-csrf",
        "csrf-token",
        "x-requested-with",
        "x-forwarded-for",
        "x-real-ip",
        # Sensitive data headers
        "password",
        "passwd",
        "pwd",
        "secret",
        "private",
        "key",
        "session",
        "sessionid",
        "session-id",
        "sess",
        # Custom sensitive headers
        "x-session",
        "x-user",
        "x-tenant",
        "x-org",
        "x-organization",
        "x-client",
        "x-device",
        "x-device-id",
        "x-deviceid",
        # OAuth and JWT
        "oauth",
        "jwt",
        "access-token",
        "refresh-token",
        "id-token",
        "x-oauth",
        "x-jwt",
        "x-access",
        "x-refresh",
    ]

    masked_headers = {}

    for key, value in headers.items():
        key_lower = key.lower()

        # Check if this header should be masked
        should_mask = any(pattern in key_lower for pattern in sensitive_patterns)

        if should_mask:
            # Mask the value but preserve the structure
            if isinstance(value, str) and len(value) > 0:
                if len(value) <= 4:
                    masked_headers[key] = "***"
                else:
                    # Show first 2 and last 2 characters for longer values
                    masked_headers[key] = f"{value[:2]}***{value[-2:]}"
            else:
                masked_headers[key] = "***"
        else:
            # Keep non-sensitive headers as-is
            masked_headers[key] = value

    return masked_headers


def mask_sensitive_data(
    data: dict[str, Any], sensitive_keys: list = None
) -> dict[str, Any]:
    """
    Recursively mask sensitive information in a dictionary.

    Args:
        data: Dictionary to mask
        sensitive_keys: List of keys to mask (defaults to common sensitive keys)

    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "private",
            "key",
            "token",
            "apikey",
            "api_key",
            "api-key",
            "auth",
            "authorization",
            "bearer",
            "session",
            "sessionid",
            "session-id",
            "cookie",
            "csrf",
            "oauth",
            "jwt",
            "access-token",
            "refresh-token",
            "id-token",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-csrf-token",
            "x-enkrypt-api-key",
            "x-enkrypt-gateway-key",
        ]

    if not isinstance(data, dict):
        return data

    masked_data = {}

    for key, value in data.items():
        key_lower = key.lower()

        # Check if this key should be masked
        should_mask = any(pattern in key_lower for pattern in sensitive_keys)

        if should_mask:
            if isinstance(value, str) and len(value) > 0:
                if len(value) <= 4:
                    masked_data[key] = "***"
                else:
                    masked_data[key] = f"{value[:2]}***{value[-2:]}"
            else:
                masked_data[key] = "***"
        elif isinstance(value, dict):
            # Recursively mask nested dictionaries
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
        elif isinstance(value, list):
            # Mask items in lists
            masked_data[key] = [
                mask_sensitive_data(item, sensitive_keys)
                if isinstance(item, dict)
                else item
                for item in value
            ]
        else:
            masked_data[key] = value

    return masked_data
