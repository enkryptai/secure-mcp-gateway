"""Tests for the /mcp-playground/* registry-header mode.

Coverage:

* **Inline mode** (back-compat): body with ``server_name`` + ``config`` and a
  valid local admin apikey reaches ``MCPHealthService`` unchanged; invalid
  apikey is 401'd; missing fields are 400'd.
* **Registry mode** (new): empty body + ``X-Enkrypt-MCP-Registry-Server``
  header with ``plugins.auth.provider == "enkrypt"`` triggers a cloud
  ``GET /mcp-registry/get-server``. Cloud 200 succeeds, 401/403/404/400/5xx
  and timeouts map to the right HTTP statuses, malformed bodies map to 502.
* **Mode invariants**: body+header conflict → 400 ambiguous; neither → 400
  missing config; provider=local_apikey + headers → 400 unsupported;
  registry mode rejects ``body.server_name`` / ``body.sandbox``.
* **Response decoration**: ``playground_mode`` field plus ``registry`` block
  with the cloud's authoritative identifiers in registry mode.
* **env passthrough**: ``mcp_config.config.env`` from the cloud reaches the
  ``MCPHealthService`` config dict.
* **Cache** (``services/health/registry_client``): identical (apikey,
  saved_name, version, registry, project) returns the cached lookup
  without a second cloud call within the 10s TTL; differing apikeys are
  cached separately; expired entries refetch.

No real network calls — ``aiohttp.ClientSession`` is patched module-level
in the cache tests; the route tests stub ``fetch_registry_server`` and
``MCPHealthService`` methods directly.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_mcp_gateway import api_health_routes as h
from secure_mcp_gateway.services.health import (
    consumer_info_client as cic,
    registry_client as rc,
)
from secure_mcp_gateway.services.health.consumer_info_client import (
    ConsumerInfo,
    fetch_consumer_info,
)
from secure_mcp_gateway.services.health.registry_client import (
    RegistryServerLookup,
    fetch_registry_server,
)


# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(h.health_router)
    return a


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    """Drop the registry_client and consumer_info_client TTL caches between
    tests so they don't bleed across cases."""
    asyncio.run(rc._cache_clear())
    asyncio.run(cic._cache_clear())


@pytest.fixture
def patch_load_config_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        h, "load_config", lambda _path: dict(LOCAL_PROVIDER_CONFIG)
    )


@pytest.fixture
def patch_load_config_enkrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        h, "load_config", lambda _path: dict(ENKRYPT_PROVIDER_CONFIG)
    )


@pytest.fixture
def patch_health_service(monkeypatch: pytest.MonkeyPatch) -> Dict[str, AsyncMock]:
    """Replace the three MCPHealthService methods with AsyncMocks and return them."""
    mocks = {
        "check_server_health": AsyncMock(
            return_value={
                "server_name": "ignored",
                "connectivity": {"status": "connected", "response_time_ms": 12.3},
                "sandbox": {"applied": "disabled"},
            }
        ),
        "get_server_info": AsyncMock(
            return_value={
                "server_name": "ignored",
                "tools": [{"name": "read_file"}],
                "sandbox": {"applied": "disabled"},
            }
        ),
        "execute_tool_health_check": AsyncMock(
            return_value={
                "server_name": "ignored",
                "result": {"content": [{"type": "text", "text": "ok"}]},
                "sandbox": {"applied": "disabled"},
            }
        ),
    }
    for name, m in mocks.items():
        monkeypatch.setattr(h._service, name, m)
    return mocks


@pytest.fixture
def patch_fetch_registry(monkeypatch: pytest.MonkeyPatch):
    """Replace api_health_routes.fetch_registry_server with a controllable AsyncMock."""
    mock = AsyncMock()
    monkeypatch.setattr(h, "fetch_registry_server", mock)
    return mock


@pytest.fixture
def patch_fetch_consumer_info(monkeypatch: pytest.MonkeyPatch):
    """Replace api_health_routes.fetch_consumer_info with a controllable AsyncMock."""
    mock = AsyncMock()
    monkeypatch.setattr(h, "fetch_consumer_info", mock)
    return mock


def _consumer_info(**overrides: Any) -> ConsumerInfo:
    base: Dict[str, Any] = {
        "user_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "project_name": "mcp-demo",
        "email": "akhil@enkryptai.com",
        "is_internal_req": False,
        "raw": {},
    }
    base.update(overrides)
    return ConsumerInfo(**base)


# ---------------------------------------------------------------------------
# Inline mode (back-compat)
# ---------------------------------------------------------------------------


def test_inline_mode_success(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    """Inline body with a valid admin apikey reaches MCPHealthService unchanged."""
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
    body = resp.json()
    assert body["data"]["playground_mode"] == "inline"
    assert "registry" not in body["data"]

    patch_health_service["check_server_health"].assert_awaited_once()
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["server_name"] == "echo"
    # ``exclude_none=True`` is now used when dumping the body config so the
    # gateway runtime never sees ``None`` for the unused-branch fields
    # (e.g. ``url``/``type`` on a stdio config). ``env`` was never set, so
    # it's stripped here too.
    assert kwargs["config"] == {
        "command": "python",
        "args": ["echo.py"],
    }
    assert kwargs["description"] == "test"
    assert kwargs["sandbox"] is None


def test_inline_mode_invalid_apikey(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "wrong"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 401
    assert "Invalid API key" in resp.json()["detail"]
    patch_health_service["check_server_health"].assert_not_called()


def test_inline_mode_missing_apikey(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 401
    assert "apikey header required" in resp.json()["detail"]


def test_inline_mode_missing_server_name(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    """server_name is required when config is supplied (inline mode)."""
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={"config": {"command": "python", "args": ["echo.py"]}},
    )
    assert resp.status_code == 400
    assert "server_name" in resp.json()["detail"]


def test_inline_mode_sandbox_passes_through(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
            "sandbox": {"enabled": False},
        },
    )
    assert resp.status_code == 200
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["sandbox"] == {"enabled": False}


# ---------------------------------------------------------------------------
# Inline mode — URL transport + empty-config dispatcher (regression suite for
# Vibhav's 422 "Field required: command" — a frontend sending either a
# URL-shaped config or an empty config in the body used to hit pydantic's
# stdio-only validator before the route handler could surface a clean 400).
# ---------------------------------------------------------------------------


def test_inline_mode_accepts_url_transport_config(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    """Inline mode now accepts a ``{url, type}`` URL-transport config.

    Before the fix this returned 422
    ``{"loc":["body","config","command"],"msg":"Field required"}`` because
    ``MCPServerConfigBody`` only modelled the stdio shape.
    """
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "deepwiki-hosted",
            "config": {
                "url": "https://mcp.deepwiki.com/mcp",
                "type": "http",
            },
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    # ``exclude_none=True`` strips the unused-branch fields so the runtime
    # sees a clean URL config.
    assert kwargs["config"] == {
        "url": "https://mcp.deepwiki.com/mcp",
        "type": "http",
    }


def test_inline_mode_url_transport_passes_through_headers(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    """Inline URL configs carry optional ``headers`` (e.g. ``Authorization``)."""
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "hosted",
            "config": {
                "url": "https://hosted.example.com/mcp",
                "type": "http",
                "headers": {"Authorization": "Bearer user-supplied"},
            },
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["config"]["headers"] == {"Authorization": "Bearer user-supplied"}


def test_empty_body_config_falls_back_to_registry_mode(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """A bare ``{"config": {}}`` from a frontend default must NOT be treated as
    inline mode. With a registry header present we route to registry mode.

    Before the fix this combo returned 422 (pydantic rejected the empty
    config) before the dispatcher could see the registry header.
    """
    patch_fetch_registry.return_value = _registry_lookup()
    # ``TestClient.get`` doesn't accept ``json=`` — use the generic
    # ``request`` so we can attach a body to a GET (which is what some
    # frontend HTTP clients do for read-style endpoints).
    resp = client.request(
        "GET",
        "/mcp-playground/get-tools",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={"config": {}},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["playground_mode"] == "registry"


def test_empty_body_config_without_registry_header_is_400(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    """``{"config": {}}`` alone (no command/url, no registry header) is now a
    clean 400 ``Missing config`` from the dispatcher instead of 422 from pydantic.
    """
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={"config": {}},
    )
    assert resp.status_code == 400, resp.text
    assert "Missing config" in resp.json()["detail"]


def test_url_config_in_body_with_registry_header_is_400_ambiguous(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """Sending both a real inline URL config AND the registry header now
    surfaces the dispatcher's 400 ambiguity message instead of a 422.
    """
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={
            "server_name": "x",
            "config": {"url": "https://example.com/mcp", "type": "http"},
        },
    )
    assert resp.status_code == 400, resp.text
    assert "Ambiguous request" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Registry mode — success path
# ---------------------------------------------------------------------------


def test_registry_mode_success_test_server(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    patch_fetch_registry.return_value = _registry_lookup()
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
            "X-Enkrypt-MCP-Registry-Server-Version": "v1",
            "X-Enkrypt-MCP-Registry": "prod",
            "X-Enkrypt-Project": "team-a",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["playground_mode"] == "registry"
    assert body["data"]["registry"]["saved_name"] == "my-fs"
    assert body["data"]["registry"]["registry_id"] == "reg-id-abc"
    assert body["data"]["registry"]["server_name"] == "@modelcontextprotocol/server-filesystem"

    patch_fetch_registry.assert_awaited_once_with(
        base_url="https://api.cloud.test",
        apikey=CLOUD_APIKEY,
        saved_name="my-fs",
        server_version="v1",
        registry_name="prod",
        project_name="team-a",
    )

    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["server_name"] == "my-fs"
    assert kwargs["config"]["command"] == "npx"
    assert kwargs["config"]["args"] == [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp",
    ]
    # No per-call sandbox override in registry mode.
    assert kwargs["sandbox"] is None


def test_registry_mode_success_get_tools_no_body(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """GET /mcp-playground/get-tools works with no body at all."""
    patch_fetch_registry.return_value = _registry_lookup()
    resp = client.get(
        "/mcp-playground/get-tools",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["playground_mode"] == "registry"
    patch_health_service["get_server_info"].assert_awaited_once()
    # Defaults applied for the optional headers
    patch_fetch_registry.assert_awaited_once_with(
        base_url="https://api.cloud.test",
        apikey=CLOUD_APIKEY,
        saved_name="my-fs",
        server_version="v1",
        registry_name="default",
        project_name="default",
    )


def test_registry_mode_call_tool_with_tool_in_body(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """call-tool in registry mode: server from cloud, tool_name/args from body."""
    patch_fetch_registry.return_value = _registry_lookup()
    resp = client.post(
        "/mcp-playground/call-tool",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={"tool_name": "read_file", "tool_args": {"path": "/tmp/x"}},
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["execute_tool_health_check"].call_args.kwargs
    assert kwargs["server_name"] == "my-fs"
    assert kwargs["tool_name"] == "read_file"
    assert kwargs["tool_args"] == {"path": "/tmp/x"}
    assert kwargs["config"]["command"] == "npx"


def test_registry_mode_env_passthrough(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """``mcp_config.config.env`` from the cloud reaches the service config dict."""
    patch_fetch_registry.return_value = _registry_lookup(
        config_dict={
            "command": "node",
            "args": ["server.js"],
            "env": {"OPENAI_API_KEY": "sk-test", "FOO": "bar"},
        }
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["config"]["env"] == {"OPENAI_API_KEY": "sk-test", "FOO": "bar"}


# ---------------------------------------------------------------------------
# Registry mode — URL transport (hosted ``type: http`` / ``sse`` servers)
# ---------------------------------------------------------------------------
#
# Hosted servers in the cloud registry (e.g. ``test-deepwiki-hosted-public``)
# return ``mcp_config.config = {"url": "...", "type": "http"}`` instead of the
# stdio ``{command, args, env}`` shape. The playground must pass these
# through to MCPHealthService unchanged — the gateway's transport layer
# already understands them via ``is_url_config``.


def test_registry_mode_url_transport_http(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """Hosted ``type=http`` server config is passed through to the health service."""
    patch_fetch_registry.return_value = _registry_lookup(
        saved_name="test-deepwiki-hosted-public",
        server_name="deepwiki-mcp-server",
        description="DeepWiki MCP Server (Hosted)",
        config_dict={
            "url": "https://mcp.deepwiki.com/mcp",
            "type": "http",
        },
    )
    resp = client.get(
        "/mcp-playground/get-tools",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "test-deepwiki-hosted-public",
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["get_server_info"].call_args.kwargs
    assert kwargs["config"] == {
        "url": "https://mcp.deepwiki.com/mcp",
        "type": "http",
    }


def test_registry_mode_url_transport_sse(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """Hosted ``type=sse`` server config is also accepted."""
    patch_fetch_registry.return_value = _registry_lookup(
        config_dict={
            "url": "https://sse.example.com/mcp",
            "type": "sse",
        },
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-sse-server",
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["check_server_health"].call_args.kwargs
    assert kwargs["config"]["url"] == "https://sse.example.com/mcp"
    assert kwargs["config"]["type"] == "sse"


def test_registry_mode_url_transport_passes_through_headers(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    """Optional ``headers`` on a URL config are forwarded to the gateway runtime."""
    patch_fetch_registry.return_value = _registry_lookup(
        config_dict={
            "url": "https://hosted.example.com/mcp",
            "type": "http",
            "headers": {"Authorization": "Bearer cloud-injected"},
        },
    )
    resp = client.get(
        "/mcp-playground/get-tools",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-hosted-server",
        },
    )
    assert resp.status_code == 200, resp.text
    kwargs = patch_health_service["get_server_info"].call_args.kwargs
    assert kwargs["config"]["headers"] == {"Authorization": "Bearer cloud-injected"}


# ---------------------------------------------------------------------------
# Registry mode — cloud error mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc_factory", "want_status", "want_detail_contains"),
    [
        (
            lambda: rc.RegistryAuthError("nope"),
            401,
            "Invalid Enkrypt apikey",
        ),
        (
            lambda: rc.RegistryForbiddenError("nope"),
            403,
            "not authorised",
        ),
        (
            lambda: rc.RegistryNotFoundError("missing"),
            404,
            "missing",
        ),
        (
            lambda: rc.RegistryBadRequestError("bad header"),
            400,
            "bad header",
        ),
        (
            lambda: rc.RegistryTimeoutError("Timeout after 10s"),
            504,
            "Timeout",
        ),
        (
            lambda: rc.RegistryParseError("missing mcp_config"),
            502,
            "missing mcp_config",
        ),
        (
            lambda: rc.RegistryUpstreamError("HTTP 503", status_code=502),
            502,
            "HTTP 503",
        ),
    ],
)
def test_registry_mode_maps_cloud_errors(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
    exc_factory,
    want_status: int,
    want_detail_contains: str,
) -> None:
    patch_fetch_registry.side_effect = exc_factory()
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
    )
    assert resp.status_code == want_status, resp.text
    assert want_detail_contains in resp.json()["detail"]
    patch_health_service["check_server_health"].assert_not_called()


# ---------------------------------------------------------------------------
# Mode-invariant errors
# ---------------------------------------------------------------------------


def test_body_and_header_conflict_is_400(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 400
    assert "Ambiguous" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_neither_body_nor_header_is_400(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={},
    )
    assert resp.status_code == 400
    assert "Missing config" in resp.json()["detail"]


def test_local_provider_rejects_registry_headers(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": ADMIN_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
    )
    assert resp.status_code == 400
    assert "plugins.auth.provider='enkrypt'" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_registry_mode_rejects_body_sandbox(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={"sandbox": {"enabled": False}},
    )
    assert resp.status_code == 400
    assert "sandbox" in resp.json()["detail"].lower()
    patch_fetch_registry.assert_not_called()


def test_registry_mode_rejects_body_server_name(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
        json={"server_name": "should-not-be-here"},
    )
    assert resp.status_code == 400
    assert "server_name" in resp.json()["detail"]
    patch_fetch_registry.assert_not_called()


def test_missing_apikey_in_registry_mode_is_401(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
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
# Registry response decoration
# ---------------------------------------------------------------------------


def test_registry_response_includes_all_identifiers(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_registry: AsyncMock,
) -> None:
    patch_fetch_registry.return_value = _registry_lookup(
        registry_id="reg-xyz",
        registry_name="prod",
        project_name="acme",
        server_name="custom/pkg",
        is_active=False,
        is_sample=True,
        source_url="https://example.com/repo",
        source_version="1.2.3",
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={
            "apikey": CLOUD_APIKEY,
            "X-Enkrypt-MCP-Registry-Server": "my-fs",
        },
    )
    assert resp.status_code == 200
    reg = resp.json()["data"]["registry"]
    assert reg["registry_id"] == "reg-xyz"
    assert reg["registry_name"] == "prod"
    assert reg["project_name"] == "acme"
    assert reg["server_name"] == "custom/pkg"
    assert reg["is_active"] is False
    assert reg["is_sample"] is True
    assert reg["source_url"] == "https://example.com/repo"
    assert reg["source_version"] == "1.2.3"


# ===========================================================================
# Registry client — direct cache tests (no FastAPI)
# ===========================================================================


class _MockResponse:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *a: Any) -> bool:
        return False


class _MockSession:
    """Records every .get() call and returns canned responses in order."""

    def __init__(self, responses: List[tuple]) -> None:
        self._responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: Any = None):
        self.calls.append({"url": url, "headers": dict(headers or {})})
        if not self._responses:
            raise AssertionError(f"Unexpected extra call to {url}")
        status, body = self._responses.pop(0)
        return _MockResponse(status, body)

    async def __aenter__(self) -> "_MockSession":
        return self

    async def __aexit__(self, *a: Any) -> bool:
        return False


# ---------------------------------------------------------------------------
# registry_client._parse_response — unit tests for transport dispatch
# ---------------------------------------------------------------------------
#
# These bypass FastAPI and the cloud HTTP layer entirely so we can lock in
# the parse-time dispatch between stdio and URL-transport configs. Anchored
# to the same canonical predicate (``is_url_config``) that the gateway's
# sandbox layer uses, so the playground can never disagree about what is
# / isn't a URL server.


def test_parse_response_accepts_stdio_config() -> None:
    out = rc._parse_response(
        {
            "saved_name": "my-fs",
            "server_version": "v1",
            "mcp_config": {
                "config": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "env": {"FOO": "bar"},
                }
            },
        }
    )
    assert out.saved_name == "my-fs"
    assert out.config_dict == {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem"],
        "env": {"FOO": "bar"},
    }


def test_parse_response_accepts_url_transport_type_http() -> None:
    """The exact shape ``test-deepwiki-hosted-public`` returns on the dev cloud.

    Regression: before commit ``<this change>`` the parser required a
    ``command`` field and this payload triggered HTTP 502 with the message
    ``"Registry server mcp_config.config.command is missing or empty"``.
    """
    out = rc._parse_response(
        {
            "saved_name": "test-deepwiki-hosted-public",
            "server_version": "v1",
            "server_name": "deepwiki-mcp-server",
            "description": "DeepWiki MCP Server (Hosted)",
            "mcp_config": {
                "config": {
                    "url": "https://mcp.deepwiki.com/mcp",
                    "type": "http",
                }
            },
        }
    )
    assert out.saved_name == "test-deepwiki-hosted-public"
    assert out.config_dict == {
        "url": "https://mcp.deepwiki.com/mcp",
        "type": "http",
    }


def test_parse_response_accepts_url_transport_type_sse() -> None:
    out = rc._parse_response(
        {
            "saved_name": "sse-server",
            "server_version": "v1",
            "mcp_config": {
                "config": {"url": "https://sse.example.com/mcp", "type": "sse"}
            },
        }
    )
    assert out.config_dict["url"] == "https://sse.example.com/mcp"
    assert out.config_dict["type"] == "sse"


def test_parse_response_accepts_url_transport_explicit_transport_key() -> None:
    """Gateway-native shape with ``transport`` but no ``type`` is also accepted."""
    out = rc._parse_response(
        {
            "saved_name": "x",
            "server_version": "v1",
            "mcp_config": {
                "config": {
                    "url": "https://example.com/mcp",
                    "transport": "streamable_http",
                }
            },
        }
    )
    assert out.config_dict["url"] == "https://example.com/mcp"
    assert out.config_dict["transport"] == "streamable_http"


def test_parse_response_url_transport_passes_through_headers() -> None:
    out = rc._parse_response(
        {
            "saved_name": "x",
            "server_version": "v1",
            "mcp_config": {
                "config": {
                    "url": "https://example.com/mcp",
                    "type": "http",
                    "headers": {"Authorization": "Bearer foo"},
                }
            },
        }
    )
    assert out.config_dict["headers"] == {"Authorization": "Bearer foo"}


def test_parse_response_rejects_type_http_without_url() -> None:
    """``{"type": "http"}`` alone is a URL config per ``is_url_config`` but
    has nothing for the MCP SDK to connect to — fail loudly at parse time."""
    with pytest.raises(rc.RegistryParseError, match="type=http/sse but no url"):
        rc._parse_response(
            {
                "saved_name": "x",
                "server_version": "v1",
                "mcp_config": {"config": {"type": "http"}},
            }
        )


def test_parse_response_url_transport_rejects_non_object_headers() -> None:
    with pytest.raises(rc.RegistryParseError, match="headers is not an object"):
        rc._parse_response(
            {
                "saved_name": "x",
                "server_version": "v1",
                "mcp_config": {
                    "config": {
                        "url": "https://example.com/mcp",
                        "type": "http",
                        "headers": "Authorization: Bearer foo",  # wrong type
                    }
                },
            }
        )


def test_parse_response_stdio_still_rejects_missing_command() -> None:
    """When neither ``url`` nor ``type: http/sse`` is set we fall back to
    stdio validation, which must keep enforcing ``command``."""
    with pytest.raises(rc.RegistryParseError, match="command is missing or empty"):
        rc._parse_response(
            {
                "saved_name": "x",
                "server_version": "v1",
                "mcp_config": {"config": {"args": ["foo"]}},
            }
        )


def _good_body(saved_name: str = "my-fs") -> str:
    import json

    return json.dumps(
        {
            "saved_name": saved_name,
            "server_version": "v1",
            "server_name": "@modelcontextprotocol/server-filesystem",
            "description": "fs",
            "registry_id": "reg-1",
            "registry_name": "default",
            "project_name": "default",
            "is_active": True,
            "is_sample": False,
            "mcp_config": {
                "config": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                },
                "tools": {},
            },
        }
    )


@pytest.mark.asyncio
async def test_cache_hit_short_circuits_second_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(200, _good_body())])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)

    a = await fetch_registry_server(
        base_url="https://cloud.test",
        apikey="k",
        saved_name="my-fs",
    )
    b = await fetch_registry_server(
        base_url="https://cloud.test",
        apikey="k",
        saved_name="my-fs",
    )
    assert a.saved_name == b.saved_name == "my-fs"
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_cache_separated_per_apikey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(200, _good_body()), (200, _good_body())])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)

    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k1", saved_name="my-fs"
    )
    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k2", saved_name="my-fs"
    )
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_cache_separated_per_saved_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(200, _good_body("a")), (200, _good_body("b"))])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)

    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k", saved_name="a"
    )
    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k", saved_name="b"
    )
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(200, _good_body()), (200, _good_body())])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)

    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k", saved_name="my-fs"
    )
    # Backdate every cache entry so it's expired.
    async with rc._CACHE_LOCK:
        for k, (_exp, val) in list(rc._CACHE.items()):
            rc._CACHE[k] = (0.0, val)
    await fetch_registry_server(
        base_url="https://cloud.test", apikey="k", saved_name="my-fs"
    )
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_error_responses_are_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient 503 should not poison the cache and lock the user out."""
    await rc._cache_clear()
    session = _MockSession([(503, "boom"), (200, _good_body())])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)

    with pytest.raises(rc.RegistryUpstreamError):
        await fetch_registry_server(
            base_url="https://cloud.test", apikey="k", saved_name="my-fs"
        )
    # Second call should still hit the network and succeed.
    out = await fetch_registry_server(
        base_url="https://cloud.test", apikey="k", saved_name="my-fs"
    )
    assert out.saved_name == "my-fs"
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_404_response_raises_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(404, '{"error":"not found"}')])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(rc.RegistryNotFoundError):
        await fetch_registry_server(
            base_url="https://cloud.test", apikey="k", saved_name="missing"
        )


@pytest.mark.asyncio
async def test_401_response_raises_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    session = _MockSession([(401, "nope")])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(rc.RegistryAuthError):
        await fetch_registry_server(
            base_url="https://cloud.test", apikey="bad", saved_name="x"
        )


@pytest.mark.asyncio
async def test_missing_mcp_config_raises_parse_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()
    import json as _json

    body = _json.dumps(
        {"saved_name": "x", "server_version": "v1", "mcp_config": None}
    )
    session = _MockSession([(200, body)])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(rc.RegistryParseError):
        await fetch_registry_server(
            base_url="https://cloud.test", apikey="k", saved_name="x"
        )


@pytest.mark.asyncio
async def test_request_headers_match_cloud_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The GET must carry the four registry headers + apikey + Accept."""
    await rc._cache_clear()
    session = _MockSession([(200, _good_body())])
    monkeypatch.setattr(rc.aiohttp, "ClientSession", lambda: session)
    await fetch_registry_server(
        base_url="https://cloud.test",
        apikey="my-key",
        saved_name="my-fs",
        server_version="v2",
        registry_name="prod",
        project_name="acme",
    )
    call = session.calls[0]
    assert call["url"] == "https://cloud.test/mcp-registry/get-server"
    assert call["headers"]["apikey"] == "my-key"
    assert call["headers"]["X-Enkrypt-MCP-Registry-Server"] == "my-fs"
    assert call["headers"]["X-Enkrypt-MCP-Registry-Server-Version"] == "v2"
    assert call["headers"]["X-Enkrypt-MCP-Registry"] == "prod"
    assert call["headers"]["X-Enkrypt-Project"] == "acme"
    assert call["headers"]["Accept"] == "application/json"


@pytest.mark.asyncio
async def test_timeout_raises_timeout_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await rc._cache_clear()

    class _TimeoutSession:
        def get(self, *a: Any, **k: Any):
            raise asyncio.TimeoutError("boom")

        async def __aenter__(self) -> "_TimeoutSession":
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

    monkeypatch.setattr(rc.aiohttp, "ClientSession", _TimeoutSession)
    with pytest.raises(rc.RegistryTimeoutError):
        await fetch_registry_server(
            base_url="https://cloud.test", apikey="k", saved_name="x"
        )


# ---------------------------------------------------------------------------
# get_enkrypt_base_url
# ---------------------------------------------------------------------------


def test_get_enkrypt_base_url_reads_root_enkrypt_config() -> None:
    out = rc.get_enkrypt_base_url(
        {"enkrypt_config": {"base_url": "https://staging.cloud.test/"}}
    )
    assert out == "https://staging.cloud.test"  # trailing slash stripped


def test_get_enkrypt_base_url_falls_back_to_default() -> None:
    assert rc.get_enkrypt_base_url({}) == rc.DEFAULT_BASE_URL
    assert rc.get_enkrypt_base_url({"enkrypt_config": {}}) == rc.DEFAULT_BASE_URL
    assert (
        rc.get_enkrypt_base_url({"enkrypt_config": {"base_url": ""}})
        == rc.DEFAULT_BASE_URL
    )


# ===========================================================================
# Inline mode + provider=enkrypt -> cloud /consumer-info auth
# ===========================================================================


def test_inline_enkrypt_provider_calls_consumer_info(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    """Inline mode on an enkrypt-provider gateway: any cloud-200 apikey works,
    even one that doesn't match the local admin allow-list."""
    patch_fetch_consumer_info.return_value = _consumer_info()
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "random-cloud-user-apikey"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["playground_mode"] == "inline"
    # Consumer block present with the 4 indexed fields (email excluded).
    consumer = body["data"]["consumer"]
    assert consumer == {
        "user_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "project_name": "mcp-demo",
        "is_internal_req": False,
    }
    assert "email" not in consumer

    # Cloud was contacted with the apikey verbatim, base_url from
    # enkrypt_config.base_url.
    patch_fetch_consumer_info.assert_awaited_once_with(
        base_url="https://api.cloud.test", apikey="random-cloud-user-apikey"
    )
    patch_health_service["check_server_health"].assert_awaited_once()


def test_inline_enkrypt_provider_skips_local_admin_check(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    """The local resolve_admin_keys check is NOT applied when
    provider=enkrypt in inline mode -- the cloud is the sole gate."""
    patch_fetch_consumer_info.return_value = _consumer_info()
    # ENKRYPT_PROVIDER_CONFIG's admin key is ADMIN_APIKEY; we send a
    # totally different apikey to prove cloud is the gate.
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "not-in-local-admin-list"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 200, resp.text


def test_inline_enkrypt_provider_cloud_401_propagates(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    patch_fetch_consumer_info.side_effect = cic.ConsumerAuthError("bad key")
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "wrong"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 401
    assert "Invalid Enkrypt apikey" in resp.json()["detail"]
    patch_health_service["check_server_health"].assert_not_called()


def test_inline_enkrypt_provider_cloud_timeout(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    patch_fetch_consumer_info.side_effect = cic.ConsumerTimeoutError(
        "Timeout after 10s"
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "k"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 504
    assert "Timeout" in resp.json()["detail"]


def test_inline_enkrypt_provider_cloud_5xx(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    patch_fetch_consumer_info.side_effect = cic.ConsumerUpstreamError(
        "HTTP 503", status_code=502
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "k"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 502
    assert "HTTP 503" in resp.json()["detail"]


def test_inline_enkrypt_provider_parse_error(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    patch_fetch_consumer_info.side_effect = cic.ConsumerParseError(
        "non-JSON body"
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "k"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 502


def test_inline_local_provider_unchanged_no_consumer_block(
    client: TestClient,
    patch_load_config_local: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    """Inline mode + provider=local_apikey still uses resolve_admin_keys
    and never touches /consumer-info. No consumer block in the response."""
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["playground_mode"] == "inline"
    assert "consumer" not in body["data"]
    patch_fetch_consumer_info.assert_not_called()


def test_inline_enkrypt_provider_call_tool(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    """call-tool inline + enkrypt: tool_name reaches service, consumer block in response."""
    patch_fetch_consumer_info.return_value = _consumer_info(
        is_internal_req=True
    )
    resp = client.post(
        "/mcp-playground/call-tool",
        headers={"apikey": "cloud-key"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
            "tool_name": "echo",
            "tool_args": {"message": "hi"},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["consumer"]["is_internal_req"] is True
    kwargs = patch_health_service["execute_tool_health_check"].call_args.kwargs
    assert kwargs["tool_name"] == "echo"
    assert kwargs["tool_args"] == {"message": "hi"}


def test_inline_enkrypt_provider_response_partial_fields(
    client: TestClient,
    patch_load_config_enkrypt: None,
    patch_health_service: Dict[str, AsyncMock],
    patch_fetch_consumer_info: AsyncMock,
) -> None:
    """Lenient on missing optional fields -- cloud response with only user_id
    still passes auth and surfaces what it has."""
    patch_fetch_consumer_info.return_value = ConsumerInfo(
        user_id="abc", raw={}
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "k"},
        json={
            "server_name": "echo",
            "config": {"command": "python", "args": ["echo.py"]},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    consumer = body["data"]["consumer"]
    assert consumer["user_id"] == "abc"
    assert consumer["org_id"] is None
    assert consumer["project_name"] is None
    assert consumer["is_internal_req"] is None


# ===========================================================================
# Consumer-info client direct tests (mock aiohttp)
# ===========================================================================


def _consumer_info_body(**overrides: Any) -> str:
    """Build a /consumer-info response body matching the real cloud shape."""
    import json as _json

    base: Dict[str, Any] = {
        "org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "custom_id": "akhil@enkryptai.com|28cbcf05|20-20|100-200|mcp-demo",
        "username": "_project:mcp-demo|28cbcf05",
        "project_name": "mcp-demo",
        "user_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        "id": "1388b711-f2c5-45b2-930b-3c91eb26e26d",
        "email": "akhil@enkryptai.com",
        "is_project_user": True,
        "is_internal_req": False,
    }
    base.update(overrides)
    return _json.dumps(base)


@pytest.mark.asyncio
async def test_consumer_info_cache_hit_short_circuits_second_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()
    session = _MockSession([(200, _consumer_info_body())])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)

    a = await fetch_consumer_info(base_url="https://cloud.test", apikey="k")
    b = await fetch_consumer_info(base_url="https://cloud.test", apikey="k")
    assert a.user_id == b.user_id
    assert a.email == b.email == "akhil@enkryptai.com"
    assert len(session.calls) == 1  # cache hit absorbed the second call


@pytest.mark.asyncio
async def test_consumer_info_cache_separated_per_apikey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()
    session = _MockSession(
        [(200, _consumer_info_body()), (200, _consumer_info_body())]
    )
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)

    await fetch_consumer_info(base_url="https://cloud.test", apikey="k1")
    await fetch_consumer_info(base_url="https://cloud.test", apikey="k2")
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_consumer_info_cache_ttl_is_5_minutes() -> None:
    """Document-by-test: the consumer-info TTL is intentionally 5 min."""
    assert cic.CONSUMER_INFO_CACHE_TTL_SECONDS == 300


@pytest.mark.asyncio
async def test_consumer_info_401_raises_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()
    session = _MockSession([(401, "nope")])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(cic.ConsumerAuthError):
        await fetch_consumer_info(
            base_url="https://cloud.test", apikey="bad"
        )


@pytest.mark.asyncio
async def test_consumer_info_403_collapses_to_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()
    session = _MockSession([(403, "forbidden")])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(cic.ConsumerAuthError):
        await fetch_consumer_info(base_url="https://cloud.test", apikey="x")


@pytest.mark.asyncio
async def test_consumer_info_404_collapses_to_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/consumer-info has no distinct 'not found' semantics -- 404 collapsed."""
    await cic._cache_clear()
    session = _MockSession([(404, "no consumer")])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(cic.ConsumerAuthError):
        await fetch_consumer_info(base_url="https://cloud.test", apikey="x")


@pytest.mark.asyncio
async def test_consumer_info_5xx_raises_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()
    session = _MockSession([(503, "boom")])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)
    with pytest.raises(cic.ConsumerUpstreamError):
        await fetch_consumer_info(base_url="https://cloud.test", apikey="x")


@pytest.mark.asyncio
async def test_consumer_info_errors_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient 503 must not poison the cache."""
    await cic._cache_clear()
    session = _MockSession([(503, "boom"), (200, _consumer_info_body())])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)

    with pytest.raises(cic.ConsumerUpstreamError):
        await fetch_consumer_info(
            base_url="https://cloud.test", apikey="k"
        )
    info = await fetch_consumer_info(
        base_url="https://cloud.test", apikey="k"
    )
    assert info.user_id is not None
    assert len(session.calls) == 2


@pytest.mark.asyncio
async def test_consumer_info_request_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /consumer-info with apikey + Accept headers, no others."""
    await cic._cache_clear()
    session = _MockSession([(200, _consumer_info_body())])
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)

    await fetch_consumer_info(
        base_url="https://cloud.test", apikey="my-key"
    )
    call = session.calls[0]
    assert call["url"] == "https://cloud.test/consumer-info"
    assert call["headers"]["apikey"] == "my-key"
    assert call["headers"]["Accept"] == "application/json"
    # Don't leak registry-server headers onto this endpoint.
    assert "X-Enkrypt-MCP-Registry-Server" not in call["headers"]


@pytest.mark.asyncio
async def test_consumer_info_is_internal_req_coerces_stringy_bool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cloud may return is_internal_req as 'true'/'false' strings."""
    await cic._cache_clear()
    session = _MockSession(
        [(200, _consumer_info_body(is_internal_req="true"))]
    )
    monkeypatch.setattr(cic.aiohttp, "ClientSession", lambda: session)
    info = await fetch_consumer_info(
        base_url="https://cloud.test", apikey="k"
    )
    assert info.is_internal_req is True


@pytest.mark.asyncio
async def test_consumer_info_timeout_raises_timeout_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await cic._cache_clear()

    class _TimeoutSession:
        def get(self, *a: Any, **k: Any):
            raise asyncio.TimeoutError("boom")

        async def __aenter__(self) -> "_TimeoutSession":
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

    monkeypatch.setattr(cic.aiohttp, "ClientSession", _TimeoutSession)
    with pytest.raises(cic.ConsumerTimeoutError):
        await fetch_consumer_info(base_url="https://cloud.test", apikey="k")
