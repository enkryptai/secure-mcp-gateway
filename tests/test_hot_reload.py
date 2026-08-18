"""Integration tests for zero-restart hot-reload of gateway config.

Covers the contracts that make hot-reload work end-to-end:

* mtime-based ``get_common_config()`` re-reads the file when it changes.
* ``trigger_full_reload()`` rebuilds the auth / guardrail / telemetry
  managers from the latest credentials.
* Session entries beyond the gateway-cache TTL are evicted by
  ``AuthConfigManager.is_session_authenticated()``.
* Concurrent ``flush_all_gateway_config_cache()`` calls do not corrupt the
  in-memory ``local_gateway_config_registry``.

These tests run fully in-process; no Docker / real HTTP is involved.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict

import pytest


@pytest.fixture
def tmp_config(tmp_path: Path, monkeypatch) -> Path:
    """Write a minimal config file and point the gateway at it."""
    cfg_path = tmp_path / "enkrypt_mcp_config.json"
    initial: Dict[str, Any] = {
        "enkrypt_config": {
            "api_key": "INITIAL_API_KEY",
            "base_url": "https://initial.example.com",
            "admin_apikey": "INITIAL_ADMIN",
        },
        "common_mcp_gateway_config": {
            "enkrypt_log_level": "INFO",
            "enkrypt_mcp_use_external_cache": False,
            "enkrypt_gateway_cache_expiration_minutes": 1,
            "enkrypt_config_watcher_poll_seconds": 0,
        },
        "plugins": {
            "auth": {"provider": "local_apikey", "config": {}},
            "guardrails": {"provider": "enkrypt", "config": {}},
            "telemetry": {"provider": "stdout", "config": {}},
        },
        "mcp_configs": {},
        "projects": {},
        "users": {},
        "apikeys": {},
    }
    cfg_path.write_text(json.dumps(initial), encoding="utf-8")

    from secure_mcp_gateway import consts, utils

    monkeypatch.setattr(consts, "CONFIG_PATH", str(cfg_path), raising=False)
    monkeypatch.setattr(utils, "CONFIG_PATH", str(cfg_path), raising=False)
    utils.clear_config_cache()
    return cfg_path


def _update_config(path: Path, mutator) -> None:
    """Helper: load, mutate, save, and bump mtime to guarantee detection."""
    data = json.loads(path.read_text(encoding="utf-8"))
    mutator(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    new_mtime = time.time() + 2.0
    os.utime(str(path), (new_mtime, new_mtime))


def test_mtime_based_hot_reload_picks_up_log_level(tmp_config: Path) -> None:
    """Changing log level on disk is visible on the next get_common_config()."""
    from secure_mcp_gateway.utils import get_common_config, get_log_level

    assert get_log_level() == "info"

    _update_config(
        tmp_config,
        lambda d: d["common_mcp_gateway_config"].__setitem__(
            "enkrypt_log_level", "DEBUG"
        ),
    )

    fresh = get_common_config()
    assert fresh.get("enkrypt_log_level") == "DEBUG"
    assert get_log_level() == "debug"


def test_full_reload_rebuilds_guardrail_provider_with_new_credentials(
    tmp_config: Path,
) -> None:
    """A reload swaps in the updated Enkrypt credentials end-to-end."""
    from secure_mcp_gateway.plugins.guardrails import (
        get_guardrail_config_manager,
        initialize_guardrail_system,
    )
    from secure_mcp_gateway.utils import get_common_config

    initialize_guardrail_system(get_common_config())
    manager_before = get_guardrail_config_manager()
    providers_before = list(manager_before.list_providers())

    _update_config(
        tmp_config,
        lambda d: d["enkrypt_config"].__setitem__("api_key", "ROTATED_KEY"),
    )

    from secure_mcp_gateway.reload import trigger_full_reload

    summary = trigger_full_reload(include_tool_cache=False)
    assert summary["status"] == "ok"
    assert summary["guardrails_reloaded"] is True

    manager_after = get_guardrail_config_manager()
    assert manager_after is manager_before, "Manager singleton must survive reload"
    assert list(manager_after.list_providers()) == providers_before

    from secure_mcp_gateway.utils import get_guardrail_api_key

    assert get_guardrail_api_key() == "ROTATED_KEY"


def test_session_expires_after_gateway_cache_ttl(tmp_config: Path) -> None:
    """Sessions older than the TTL fail authentication and get evicted."""
    from secure_mcp_gateway.plugins.auth.base import SessionData
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    _update_config(
        tmp_config,
        lambda d: d["common_mcp_gateway_config"].__setitem__(
            "enkrypt_gateway_cache_expiration_minutes", 0.0001
        ),
    )

    mgr = AuthConfigManager()
    mgr.sessions["sk"] = SessionData(
        session_id="sk",
        user_id="u1",
        authenticated=True,
        created_at=time.time() - 60,
        last_accessed=time.time(),
    )

    assert mgr.is_session_authenticated("sk") is False
    assert "sk" not in mgr.sessions


def test_concurrent_flush_does_not_corrupt_registry(tmp_config: Path) -> None:
    """Many concurrent flush_all calls must not raise mid-iteration."""
    from secure_mcp_gateway import client as client_mod

    for i in range(50):
        gateway_id = f"gw-{i}"
        client_mod.local_gateway_config_registry.add(gateway_id)
        client_mod.local_cache[
            client_mod.get_gateway_config_hashed_key(gateway_id)
        ] = ({"id": gateway_id}, time.time() + 60)
        client_mod.local_key_map[f"hash-{i}"] = gateway_id

    errors: list[Exception] = []

    def flush_worker() -> None:
        try:
            for _ in range(5):
                client_mod.flush_all_gateway_config_cache(
                    cache_client=None, include_tool_cache=False
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=flush_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"flush corrupted state: {errors}"
    assert len(client_mod.local_gateway_config_registry) == 0
    assert len(client_mod.local_key_map) == 0
