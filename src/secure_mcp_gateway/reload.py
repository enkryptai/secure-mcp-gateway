"""Zero-restart hot-reload orchestrator.

Coordinates reloading every in-memory binding to ``enkrypt_mcp_config.json``
so config edits take effect on the next request without restarting the
gateway process.

Reload order is intentional:

1. ``utils.clear_config_cache()`` -- forces ``get_common_config()`` to re-read
   the file on next access.
2. ``get_common_config()`` -- pulls the fresh dict so we pass a consistent
   snapshot to every reload step below.
3. Manager ``reload(config)`` calls -- rebuild auth/guardrail/telemetry
   provider instances with the new credentials.
4. Singleton ``reset_*`` calls -- replace timeout manager + session pool.
5. ``flush_all_gateway_config_cache()`` -- drop the per-gateway mapped
   config so the next request re-fetches via the (now reloaded) auth
   provider. ``AuthConfigManager.sessions`` is already cleared by step 3.
6. Optional: clear tool cache so per-server tool lists are re-discovered.

The whole sequence runs under ``_reload_lock`` so concurrent flush API
calls / watcher fires do not race.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict

from secure_mcp_gateway.utils import clear_config_cache, get_common_config, logger

_reload_lock = threading.Lock()
_last_reload_ts: float = 0.0
_last_reload_summary: Dict[str, Any] = {}


def get_last_reload_info() -> Dict[str, Any]:
    """Return the timestamp + summary of the most recent reload, if any."""
    return {
        "last_reload_ts": _last_reload_ts,
        "last_reload_summary": dict(_last_reload_summary),
    }


def trigger_full_reload(include_tool_cache: bool = False) -> Dict[str, Any]:
    """Reload every cached/bound config layer.

    Args:
        include_tool_cache: When True, also clears the per-server tool cache.
            Defaults to False because re-discovery is comparatively expensive
            and tools rarely change in normal config edits.

    Returns:
        A dict summarising what was reloaded. Keys reflect best-effort
        success so partial failures still surface useful info.
    """
    global _last_reload_ts, _last_reload_summary

    summary: Dict[str, Any] = {
        "started_at": time.time(),
        "include_tool_cache": include_tool_cache,
    }

    if not _reload_lock.acquire(timeout=10.0):
        summary["status"] = "skipped_busy"
        return summary

    try:
        clear_config_cache()
        summary["config_cache_cleared"] = True

        config = get_common_config()
        summary["config_loaded"] = True

        try:
            from secure_mcp_gateway.plugins.auth import get_auth_config_manager

            get_auth_config_manager().reload(config)
            summary["auth_reloaded"] = True
        except Exception as e:
            logger.error(f"[reload] auth reload failed: {e}")
            summary["auth_reloaded"] = False
            summary["auth_error"] = str(e)

        try:
            from secure_mcp_gateway.plugins.guardrails import (
                get_guardrail_config_manager,
            )

            get_guardrail_config_manager().reload(config)
            summary["guardrails_reloaded"] = True
        except Exception as e:
            logger.error(f"[reload] guardrails reload failed: {e}")
            summary["guardrails_reloaded"] = False
            summary["guardrails_error"] = str(e)

        try:
            from secure_mcp_gateway.plugins.telemetry import (
                get_telemetry_config_manager,
            )

            get_telemetry_config_manager().reload(config)
            summary["telemetry_reloaded"] = True
        except Exception as e:
            logger.error(f"[reload] telemetry reload failed: {e}")
            summary["telemetry_reloaded"] = False
            summary["telemetry_error"] = str(e)

        try:
            from secure_mcp_gateway.services.timeout.timeout_manager import (
                reset_timeout_manager,
            )

            reset_timeout_manager(config)
            summary["timeout_manager_reset"] = True
        except Exception as e:
            logger.error(f"[reload] timeout reset failed: {e}")
            summary["timeout_manager_reset"] = False
            summary["timeout_error"] = str(e)

        try:
            from secure_mcp_gateway.services.session.session_pool import (
                reset_session_pool,
            )

            reset_session_pool(config)
            summary["session_pool_reset"] = True
        except Exception as e:
            logger.error(f"[reload] session pool reset failed: {e}")
            summary["session_pool_reset"] = False
            summary["session_pool_error"] = str(e)

        try:
            from secure_mcp_gateway.services.cache.cache_service import (
                flush_all_gateway_config_cache,
            )

            cleared = flush_all_gateway_config_cache(
                include_tool_cache=include_tool_cache,
            )
            summary["cache_flushed"] = True
            summary["cache_cleared"] = cleared
        except Exception as e:
            logger.error(f"[reload] cache flush failed: {e}")
            summary["cache_flushed"] = False
            summary["cache_error"] = str(e)

        summary["status"] = "ok"
        summary["completed_at"] = time.time()
        summary["duration_seconds"] = summary["completed_at"] - summary["started_at"]
        logger.info(f"[reload] trigger_full_reload complete: {summary}")
        _last_reload_ts = summary["completed_at"]
        _last_reload_summary = summary
        return summary
    finally:
        _reload_lock.release()


__all__ = [
    "trigger_full_reload",
    "get_last_reload_info",
]
