"""Regression tests for the gateway-side /mcp-playground/* HTTP routes.

These mirror the FastAPI ``api_health_routes`` contract (covered by
``tests/test_playground_registry_mode.py``) but for the routes mounted onto
the FastMCP gateway process (port 8000) via ``FastMCP.custom_route``. They
run fully in-process via Starlette's ``TestClient`` -- no uvicorn, no
FastMCP transport.

The headline regression: a **registry-mode** request carries the
``X-Enkrypt-MCP-Registry-Server`` header and NO body. Before the fix the
gateway handler called ``await request.json()`` first and 400'd every
bodyless request with ``"invalid JSON body: Expecting value: line 1
column 1 (char 0)"`` -- registry mode was simply unimplemented on the
gateway surface (it only existed on the REST API server, which most
deployments don't run).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from secure_mcp_gateway import gateway_playground_routes as gpr
from secure_mcp_gateway.services.health.consumer_info_client import ConsumerInfo
from secure_mcp_gateway.services.health.registry_client import RegistryServerLookup

RouteSpec = tuple[str, list[str], Callable[[Request], Awaitable[Response]]]

ADMIN_APIKEY = "test-admin-apikey"
CLOUD_APIKEY = "cloud-user-apikey"

LOCAL_PROVIDER_CONFIG: Dict[str, Any] = {
    "admin_apikey": ADMIN_APIKEY,
    "plugins": {"auth": {"provider": "local_apikey"}},
}
ENKRYPT_PROVIDER_CONFIG: Dict[str, Any] = {
    "enkrypt_config": {
        "api_key": ADMIN_APIKEY,
        "base_url": "https://api.cloud.test",
    },
    "plugins": {"auth": {"provider": "enkrypt"}},
}


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
        def decorator(func):
            self.captured.append((path, methods, func))
            return func

        return decorator


def _build_app() -> tuple[Starlette, _FakeMCP]:
    fake = _FakeMCP()
    gpr.register_gateway_playground_routes(fake)  # type: ignore[arg-type]
    routes = [
        Route(path, endpoint=fn, methods=methods)
        for path, methods, fn in fake.captured
    ]
    return Starlette(routes=routes), fake


def _registry_lookup(**overrides: Any) -> RegistryServerLookup:
    base: Dict[str, Any] = {
        "saved_name": "my-fs",
        "server_version": "v1",
        "config_dict": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "env": None,
        },
        "server_name": "@modelcontextprotocol/server-filesystem",
        "description": "Filesystem MCP",
        "registry_id": "reg-id-abc",
        "registry_name": "default",
        "project_name": "default",
        "is_active": True,
        "is_sample": False,
        "source_url": "https://example.com/src",
        "source_version": "v0.6.2",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
        "raw": {},
    }
    base.update(overrides)
    return RegistryServerLookup(**base)


@pytest.fixture
def client() -> TestClient:
    app, _ = _build_app()
    return TestClient(app)


@pytest.fixture
def patch_config_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gpr, "_load_config_from_disk", lambda: dict(LOCAL_PROVIDER_CONFIG)
    )


@pytest.fixture
def patch_config_enkrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gpr, "_load_config_from_disk", lambda: dict(ENKRYPT_PROVIDER_CONFIG)
    )


@pytest.fixture
def patch_service(monkeypatch: pytest.MonkeyPatch) -> Dict[str, AsyncMock]:
    mocks = {
        "check_server_health": AsyncMock(
            return_value={
                "server_name": "ignored",
                "connectivity": {"status": "connected", "response_time_ms": 12.3},
            }
        ),
        "get_server_info": AsyncMock(
            return_value={"server_name": "ignored", "tools": [{"name": "read_file"}]}
        ),
        "execute_tool_health_check": AsyncMock(
            return_value={"server_name": "ignored", "result": {"ok": True}}
        ),
    }
    for name, m in mocks.items():
        monkeypatch.setattr(gpr._service, name, m)
    return mocks


@pytest.fixture
def patch_fetch_registry(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock()
    monkeypatch.setattr(gpr, "fetch_registry_server", mock)
    return mock


@pytest.fixture
def patch_fetch_consumer_info(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock()
    monkeypatch.setattr(gpr, "fetch_consumer_info", mock)
    return mock


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_attaches_three_routes() -> None:
    _, fake = _build_app()
    paths = {p for p, _, _ in fake.captured}
    methods_by_path = {p: set(m) for p, m, _ in fake.captured}
    assert paths == {
        "/mcp-playground/test-server",
        "/mcp-playground/get-tools",
        "/mcp-playground/call-tool",
    }
    assert methods_by_path["/mcp-playground/test-server"] == {"POST"}
    assert methods_by_path["/mcp-playground/get-tools"] == {"GET"}
    assert methods_by_path["/mcp-playground/call-tool"] == {"POST"}


# ---------------------------------------------------------------------------
# Registry mode -- the reported bug
# ---------------------------------------------------------------------------


def test_registry_mode_no_body_succeeds(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """The exact failing request: registry headers, NO body, cloud apikey.

    Must NOT 400 on body parsing; must resolve via the cloud and 200.
    """
    patch_fetch_registry.return_value = _registry_lookup(
        saved_name="test-private-time-server"
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "test-private-time-server",
            "X-Enkrypt-MCP-Registry-Server-Version": "v1",
            "Accept": "application/json",
        },
        # no content at all -- bodyless request
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["playground_mode"] == "registry"
    assert data["registry"]["saved_name"] == "test-private-time-server"

    patch_fetch_registry.assert_awaited_once_with(
        base_url="https://api.cloud.test",
        apikey=CLOUD_APIKEY,
        saved_name="test-private-time-server",
        server_version="v1",
        registry_name="default",
        project_name="default",
    )
    kwargs = patch_service["check_server_health"].call_args.kwargs
    assert kwargs["server_name"] == "test-private-time-server"
    assert kwargs["config"]["command"] == "npx"
    assert kwargs["sandbox"] is None


def test_registry_mode_get_tools_no_body(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    patch_fetch_registry.return_value = _registry_lookup()
    resp = client.get(
        "/mcp-playground/get-tools",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "my-fs"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["playground_mode"] == "registry"
    patch_service["get_server_info"].assert_awaited_once()


def test_registry_mode_call_tool_with_tool_in_body(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    patch_fetch_registry.return_value = _registry_lookup()
    resp = client.post(
        "/mcp-playground/call-tool",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "my-fs"},
        json={"tool_name": "read_file", "tool_args": {"path": "/tmp/x"}},
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_service["execute_tool_health_check"].call_args.kwargs
    assert kwargs["server_name"] == "my-fs"
    assert kwargs["tool_name"] == "read_file"
    assert kwargs["tool_args"] == {"path": "/tmp/x"}


def test_registry_mode_url_transport(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    patch_fetch_registry.return_value = _registry_lookup(
        config_dict={"url": "https://mcp.deepwiki.com/mcp", "type": "http"}
    )
    resp = client.get(
        "/mcp-playground/get-tools",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "hosted"},
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_service["get_server_info"].call_args.kwargs
    assert kwargs["config"] == {"url": "https://mcp.deepwiki.com/mcp", "type": "http"}


def test_registry_mode_maps_cloud_auth_error(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    from secure_mcp_gateway.services.health import registry_client as rc

    patch_fetch_registry.side_effect = rc.RegistryAuthError("nope")
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "bad", "X-Enkrypt-MCP-Registry-Server": "my-fs"},
    )
    assert resp.status_code == 401, resp.text
    assert "Invalid Enkrypt apikey" in resp.json()["detail"]
    patch_service["check_server_health"].assert_not_called()


def test_registry_mode_maps_cloud_not_found(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    from secure_mcp_gateway.services.health import registry_client as rc

    patch_fetch_registry.side_effect = rc.RegistryNotFoundError("missing")
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "ghost"},
    )
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# Mode invariants
# ---------------------------------------------------------------------------


def test_registry_header_requires_enkrypt_provider(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY, "X-Enkrypt-MCP-Registry-Server": "my-fs"},
    )
    assert resp.status_code == 400
    assert "plugins.auth.provider='enkrypt'" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_body_and_header_conflict_is_400(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "my-fs"},
        json={"server_name": "echo", "config": {"command": "python", "args": ["e.py"]}},
    )
    assert resp.status_code == 400
    assert "Ambiguous" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_neither_body_nor_header_is_400(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={},
    )
    assert resp.status_code == 400
    assert "Missing config" in resp.json()["detail"]


def test_registry_mode_rejects_body_server_name(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": CLOUD_APIKEY, "X-Enkrypt-MCP-Registry-Server": "my-fs"},
        json={"server_name": "should-not-be-here"},
    )
    assert resp.status_code == 400
    assert "server_name" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_missing_apikey_is_401(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"X-Enkrypt-MCP-Registry-Server": "my-fs"},
    )
    assert resp.status_code == 401
    assert "apikey header required" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


# ---------------------------------------------------------------------------
# Inline mode (back-compat) -- local_apikey provider
# ---------------------------------------------------------------------------


def test_inline_mode_local_success(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
            "description": "test",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["playground_mode"] == "inline"
    assert "registry" not in data
    kwargs = patch_service["check_server_health"].call_args.kwargs
    assert kwargs["server_name"] == "echo"


def test_inline_mode_invalid_apikey(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "wrong"},
        json={"server_name": "echo", "config": {"command": "python", "args": ["e.py"]}},
    )
    assert resp.status_code == 401
    assert "Invalid API key" in resp.json()["detail"]
    patch_service["check_server_health"].assert_not_called()


def test_inline_mode_sandbox_passes_through(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["e.py"]},
            "sandbox": {"enabled": False},
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_service["check_server_health"].call_args.kwargs
    assert kwargs["sandbox"] == {"enabled": False}


def test_inline_mode_malformed_json_still_400(
    client: TestClient,
    patch_config_local: None,
    patch_service: Dict[str, AsyncMock],
) -> None:
    """A present-but-broken body still 400s (only EMPTY bodies are tolerated)."""
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY, "Content-Type": "application/json"},
        content="{not valid json",
    )
    assert resp.status_code == 400
    assert "invalid JSON body" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Inline mode -- enkrypt provider (cloud /consumer-info auth)
# ---------------------------------------------------------------------------


def test_inline_enkrypt_provider_uses_consumer_info(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    patch_fetch_consumer_info.return_value = ConsumerInfo(
        user_id="u1", org_id="o1", project_name="mcp-demo", is_internal_req=False
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "random-cloud-user-apikey"},
        json={"server_name": "echo", "config": {"command": "python", "args": ["e.py"]}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["playground_mode"] == "inline"
    assert data["consumer"] == {
        "user_id": "u1",
        "org_id": "o1",
        "project_name": "mcp-demo",
        "is_internal_req": False,
    }
    patch_fetch_consumer_info.assert_awaited_once_with(
        base_url="https://api.cloud.test", apikey="random-cloud-user-apikey"
    )


def test_inline_enkrypt_provider_cloud_401(
    client: TestClient,
    patch_config_enkrypt: None,
    patch_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    from secure_mcp_gateway.services.health import consumer_info_client as cic

    patch_fetch_consumer_info.side_effect = cic.ConsumerAuthError("bad key")
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "wrong"},
        json={"server_name": "echo", "config": {"command": "python", "args": ["e.py"]}},
    )
    assert resp.status_code == 401
    assert "Invalid Enkrypt apikey" in resp.json()["detail"]
    patch_service["check_server_health"].assert_not_called()
