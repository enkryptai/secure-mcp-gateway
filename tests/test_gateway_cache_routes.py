"""Regression tests for the gateway-side cache flush HTTP routes.

These run fully in-process via Starlette's ``TestClient`` -- no uvicorn,
no FastMCP transport. They cover:

* ``register_gateway_cache_routes`` actually attaches both routes
* ``apikey`` header is required (401)
* invalid ``apikey`` is rejected (401)
* missing admin key in config returns a clear 500 (fail-closed)
* valid admin key returns 200 with the full reload summary
* ``last-reload`` mirrors ``trigger_full_reload``'s output

Both processes (the FastAPI REST API on port 8001 and the FastMCP gateway
on port 8000) share ``trigger_full_reload`` + ``resolve_admin_keys``, so
these tests also implicitly cover the contract used by ``api_cache_routes``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

RouteSpec = tuple[str, list[str], Callable[[Request], Awaitable[Response]]]


class _FakeMCP:
    """Minimal stand-in for FastMCP that just captures custom_route calls."""

    def __init__(self) -> None:
        self.captured: list[RouteSpec] = []

    def custom_route(
        self,
        path: str,
        methods: list[str],
        name: str | None = None,
        include_in_schema: bool = True,
    ):
        def decorator(
            func: Callable[[Request], Awaitable[Response]],
        ) -> Callable[[Request], Awaitable[Response]]:
            self.captured.append((path, methods, func))
            return func

        return decorator


@pytest.fixture
def cfg_path(tmp_path: Path, monkeypatch) -> Path:
    """Write a minimal config file with a static admin-key flow.

    Uses ``provider=local_apikey`` so the static-admin-key path stays
    valid: under strict mode (commit ``84e5b83`` and later), the
    ``provider=enkrypt`` path always rounds-trips Enkrypt cloud's
    ``/consumer-info`` and refuses to short-circuit on the static key.
    The enkrypt-strict path is covered separately in
    :mod:`tests.test_auth_policy_cache_flush`.
    """
    path = tmp_path / "enkrypt_mcp_config.json"
    cfg: dict[str, Any] = {
        "enkrypt_config": {
            "api_key": "CLOUD_API_KEY",
            "base_url": "https://example.invalid",
        },
        "admin_apikey": "ROOT_ADMIN_KEY",
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
    path.write_text(json.dumps(cfg), encoding="utf-8")

    from secure_mcp_gateway import consts, gateway_cache_routes, utils

    monkeypatch.setattr(consts, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(utils, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(
        gateway_cache_routes, "CONFIG_PATH", str(path), raising=False
    )
    utils.clear_config_cache()
    return path


def _build_test_app() -> tuple[Starlette, _FakeMCP]:
    """Register the cache routes via the public API and wrap them in a Starlette app."""
    from secure_mcp_gateway.gateway_cache_routes import (
        register_gateway_cache_routes,
    )

    fake = _FakeMCP()
    register_gateway_cache_routes(fake)  # type: ignore[arg-type]

    routes = [Route(path, endpoint=fn, methods=methods) for path, methods, fn in fake.captured]
    return Starlette(routes=routes), fake


def test_register_attaches_both_routes() -> None:
    """register_gateway_cache_routes must register flush + last-reload."""
    _, fake = _build_test_app()

    paths = {p for p, _, _ in fake.captured}
    methods_by_path = {p: set(m) for p, m, _ in fake.captured}

    assert paths == {
        "/api/v1/cache/flush-gateway-config",
        "/api/v1/cache/last-reload",
    }
    assert methods_by_path["/api/v1/cache/flush-gateway-config"] == {"POST"}
    assert methods_by_path["/api/v1/cache/last-reload"] == {"GET"}


def test_flush_requires_apikey_header(cfg_path: Path) -> None:
    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post("/api/v1/cache/flush-gateway-config", json={})
    assert r.status_code == 401
    body = r.json()
    assert body["status"] == "error"
    assert "apikey" in body["error"].lower()


def test_flush_rejects_invalid_apikey(cfg_path: Path) -> None:
    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            json={},
            headers={"apikey": "totally-wrong-key"},
        )
    assert r.status_code == 401
    body = r.json()
    assert body["status"] == "error"
    assert "invalid" in body["error"].lower()


def test_flush_returns_500_when_no_admin_key_configured(
    tmp_path: Path, monkeypatch
) -> None:
    """Fail-closed if neither admin_apikey nor an enkrypt cloud api_key is set."""
    path = tmp_path / "enkrypt_mcp_config.json"
    cfg = {
        "common_mcp_gateway_config": {},
        "plugins": {"auth": {"provider": "local_apikey", "config": {}}},
    }
    path.write_text(json.dumps(cfg), encoding="utf-8")

    from secure_mcp_gateway import consts, gateway_cache_routes, utils

    monkeypatch.setattr(consts, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(utils, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(
        gateway_cache_routes, "CONFIG_PATH", str(path), raising=False
    )
    utils.clear_config_cache()

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            json={},
            headers={"apikey": "anything"},
        )
    assert r.status_code == 500
    assert "Admin API key not configured" in r.json()["error"]


def test_flush_success_returns_full_reload_summary(
    cfg_path: Path, monkeypatch
) -> None:
    """Valid admin apikey -> 200 + summary from trigger_full_reload."""
    fake_summary = {
        "status": "ok",
        "auth_reloaded": True,
        "guardrails_reloaded": True,
        "telemetry_reloaded": True,
        "cache_flushed": True,
        "include_tool_cache": True,
    }
    captured: dict[str, Any] = {}

    def fake_reload(include_tool_cache: bool = False) -> dict[str, Any]:
        captured["include_tool_cache"] = include_tool_cache
        return fake_summary

    from secure_mcp_gateway import reload as reload_mod

    monkeypatch.setattr(reload_mod, "trigger_full_reload", fake_reload)

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            json={"include_tool_cache": True},
            headers={"apikey": "ROOT_ADMIN_KEY"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["summary"] == fake_summary
    assert captured["include_tool_cache"] is True


def test_flush_returns_409_when_reload_busy(cfg_path: Path, monkeypatch) -> None:
    """trigger_full_reload returning skipped_busy must surface as a 409."""
    from secure_mcp_gateway import reload as reload_mod

    monkeypatch.setattr(
        reload_mod,
        "trigger_full_reload",
        lambda include_tool_cache=False: {"status": "skipped_busy"},
    )

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            json={},
            headers={"apikey": "ROOT_ADMIN_KEY"},
        )
    assert r.status_code == 409
    assert "in progress" in r.json()["error"].lower()


def test_flush_tolerates_empty_body(cfg_path: Path, monkeypatch) -> None:
    """No body / no content-length must default include_tool_cache=False."""
    captured: dict[str, Any] = {}

    def fake_reload(include_tool_cache: bool = False) -> dict[str, Any]:
        captured["include_tool_cache"] = include_tool_cache
        return {"status": "ok"}

    from secure_mcp_gateway import reload as reload_mod

    monkeypatch.setattr(reload_mod, "trigger_full_reload", fake_reload)

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            headers={"apikey": "ROOT_ADMIN_KEY"},
        )
    assert r.status_code == 200
    assert captured["include_tool_cache"] is False


def test_last_reload_returns_metadata(cfg_path: Path, monkeypatch) -> None:
    """GET /last-reload must mirror reload.get_last_reload_info output."""
    expected = {
        "last_reload_ts": 1234567890.5,
        "last_reload_summary": {"status": "ok", "auth_reloaded": True},
    }
    from secure_mcp_gateway import reload as reload_mod

    monkeypatch.setattr(reload_mod, "get_last_reload_info", lambda: expected)

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.get(
            "/api/v1/cache/last-reload",
            headers={"apikey": "ROOT_ADMIN_KEY"},
        )
    assert r.status_code == 200
    assert r.json() == expected


def test_last_reload_requires_apikey(cfg_path: Path) -> None:
    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.get("/api/v1/cache/last-reload")
    assert r.status_code == 401


def test_enkrypt_provider_strict_requires_org_id_configured(
    tmp_path: Path, monkeypatch
) -> None:
    """Strict mode: under provider=enkrypt, ``enkrypt_config.org_id`` is
    MANDATORY. Without it, every flush returns 500 -- even with the
    operator's own cloud apikey -- because there is no static
    short-circuit and no org to compare against."""
    path = tmp_path / "enkrypt_mcp_config.json"
    cfg = {
        "enkrypt_config": {
            "api_key": "CLOUD_KEY_AS_ADMIN",
            "base_url": "https://example.invalid",
            # org_id intentionally absent
        },
        "common_mcp_gateway_config": {},
        "plugins": {"auth": {"provider": "enkrypt", "config": {}}},
    }
    path.write_text(json.dumps(cfg), encoding="utf-8")

    from secure_mcp_gateway import (
        consts,
        gateway_cache_routes,
        utils,
    )

    monkeypatch.setattr(consts, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(utils, "CONFIG_PATH", str(path), raising=False)
    monkeypatch.setattr(
        gateway_cache_routes, "CONFIG_PATH", str(path), raising=False
    )
    utils.clear_config_cache()

    app, _ = _build_test_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/cache/flush-gateway-config",
            json={},
            headers={"apikey": "CLOUD_KEY_AS_ADMIN"},
        )
    assert r.status_code == 500
    body = r.json()
    assert body["status"] == "error"
    assert body["reason"] == "no_org_gating_configured"
    assert "org_id" in body["error"].lower()
