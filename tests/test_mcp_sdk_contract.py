"""The gateway's MCP client and server paths against the real ``mcp`` SDK, no mocks
of the SDK: stdio and streamable-HTTP upstreams, the gateway's own FastMCP server,
the session pool, and the MCP OAuth client provider."""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

# gateway must import first: it sets up the telemetry the execution service needs at import.
from secure_mcp_gateway import gateway
from secure_mcp_gateway.client import forward_tool_call, get_server_metadata_only
from secure_mcp_gateway.services.execution.tool_execution_service import (
    ToolExecutionService,
)
from secure_mcp_gateway.services.session.session_pool import SessionPool

ECHO_MCP = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "secure_mcp_gateway"
    / "bad_mcps"
    / "echo_mcp.py"
)

GATEWAY_TOOL_NAMES = {
    "enkrypt_list_all_servers",
    "enkrypt_get_server_info",
    "enkrypt_discover_all_tools",
    "enkrypt_secure_call_tools",
    "enkrypt_get_cache_status",
    "enkrypt_clear_cache",
    "enkrypt_get_timeout_metrics",
    "enkrypt_oauth_authorize",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _BackgroundServer:
    def __init__(self, app) -> None:
        self.port = _free_port()
        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="warning"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _BackgroundServer:
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


def _build_upstream() -> FastMCP:
    upstream = FastMCP("Contract Upstream")

    @upstream.tool(description="Echo back the message.")
    def echo(message: str) -> str:
        return message

    @upstream.tool(description="Add two integers.")
    def add(a: int, b: int) -> int:
        return a + b

    return upstream


@pytest.fixture(scope="module")
def http_upstream():
    with _BackgroundServer(_build_upstream().streamable_http_app()) as server:
        yield server


@pytest.fixture
def allow_stdio(monkeypatch):
    monkeypatch.setenv("ENKRYPT_ALLOW_STDIO_SERVERS", "true")


def _gateway_config(server_name: str, config: dict) -> dict:
    return {"mcp_config": [{"server_name": server_name, "config": config}]}


def _stdio_echo_config() -> dict:
    return _gateway_config(
        "echo", {"command": sys.executable, "args": [str(ECHO_MCP)], "env": None}
    )


def _text(result) -> str:
    return result.content[0].text


async def test_stdio_upstream_discovery_returns_tools_and_server_info(allow_stdio):
    result = await forward_tool_call("echo", None, gateway_config=_stdio_echo_config())

    assert {tool.name for tool in result["tools"].tools} >= {"echo", "list_tools"}
    assert result["server_metadata"]["name"] == "Simple Echo MCP Server"


async def test_stdio_upstream_tool_call_round_trips(allow_stdio):
    result = await forward_tool_call(
        "echo", "echo", {"message": "hello stdio"}, gateway_config=_stdio_echo_config()
    )

    assert result.isError is False
    assert _text(result) == "hello stdio"


async def test_stdio_upstream_metadata_only(allow_stdio):
    result = await get_server_metadata_only("echo", gateway_config=_stdio_echo_config())

    assert result["server_metadata"]["name"] == "Simple Echo MCP Server"


async def test_http_upstream_discovery_and_structured_tool_call(http_upstream):
    config = _gateway_config("remote", {"url": http_upstream.url("/mcp")})

    discovered = await forward_tool_call("remote", None, gateway_config=config)
    added = await forward_tool_call(
        "remote", "add", {"a": 2, "b": 3}, gateway_config=config
    )

    tools = {tool.name: tool for tool in discovered["tools"].tools}
    assert set(tools) == {"echo", "add"}
    assert discovered["server_metadata"]["name"] == "Contract Upstream"
    assert tools["add"].outputSchema is not None
    assert added.isError is False
    assert added.structuredContent == {"result": 5}
    assert _text(added) == "5"


async def test_http_upstream_same_origin_trailing_slash_redirect_is_followed(
    http_upstream,
):
    config = _gateway_config("remote", {"url": http_upstream.url("/mcp/")})

    result = await forward_tool_call(
        "remote", "echo", {"message": "via redirect"}, gateway_config=config
    )

    assert _text(result) == "via redirect"


async def test_http_upstream_unknown_tool_is_reported_as_tool_error(http_upstream):
    config = _gateway_config("remote", {"url": http_upstream.url("/mcp")})

    result = await forward_tool_call(
        "remote", "no_such_tool", {}, gateway_config=config
    )

    assert result.isError is True


async def test_http_upstream_type_http_config_is_accepted(http_upstream):
    config = _gateway_config(
        "remote", {"type": "http", "url": http_upstream.url("/mcp")}
    )

    result = await forward_tool_call(
        "remote", "echo", {"message": "typed"}, gateway_config=config
    )

    assert _text(result) == "typed"


async def test_tool_execution_service_session_against_http_upstream(http_upstream):
    server_config = {"url": http_upstream.url("/mcp")}
    entry = {"server_name": "remote", "config": server_config}
    service = ToolExecutionService()

    async with service.open_session(server_config, entry) as session:
        first = await service.call_tool(session, "echo", {"message": "one"})
        second = await service.call_tool(session, "add", {"a": 1, "b": 1})

    assert session._server_name == "Contract Upstream"
    assert _text(first) == "one"
    assert second.structuredContent == {"result": 2}


async def test_session_pool_reuses_one_http_session(http_upstream):
    server_config = {"url": http_upstream.url("/mcp")}
    entry = {"server_name": "remote", "config": server_config}
    pool = SessionPool(ttl_seconds=60)
    try:
        first, reused_first = await pool.acquire(
            "user-1", "remote", server_config, entry
        )
        assert _text(await first.call_tool("echo", arguments={"message": "a"})) == "a"
        await pool.release("user-1", "remote")

        second, reused_second = await pool.acquire(
            "user-1", "remote", server_config, entry
        )
        assert _text(await second.call_tool("echo", arguments={"message": "b"})) == "b"
        await pool.release("user-1", "remote")
    finally:
        await pool.close_all()

    assert reused_first is False
    assert reused_second is True
    assert first is second


async def test_gateway_server_lists_its_tools_in_memory():
    async with create_connected_server_and_client_session(
        gateway.mcp._mcp_server
    ) as client:
        tools = (await client.list_tools()).tools

    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == GATEWAY_TOOL_NAMES
    assert by_name["enkrypt_list_all_servers"].annotations.readOnlyHint is True
    assert by_name["enkrypt_secure_call_tools"].annotations.destructiveHint is True
    assert (
        "server_name" in by_name["enkrypt_secure_call_tools"].inputSchema["properties"]
    )


async def test_gateway_server_over_streamable_http():
    with _BackgroundServer(gateway.mcp.streamable_http_app()) as server:
        async with streamablehttp_client(server.url("/mcp/")) as (
            read,
            write,
            session_id,
        ):
            async with ClientSession(read, write) as client:
                init = await client.initialize()
                tools = (await client.list_tools()).tools
                assert session_id()

    assert init.serverInfo.name == "Enkrypt Secure MCP Gateway"
    assert {tool.name for tool in tools} == GATEWAY_TOOL_NAMES


MCP_URL = "https://mcp.contract.test/mcp"
AUTH_SERVER = "https://auth.contract.test"


def _oauth_mock_handler(seen: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.setdefault("paths", []).append(
            f"{request.method} {request.url.host}{request.url.path}"
        )
        if url.startswith(MCP_URL):
            if request.headers.get("authorization") == "Bearer access-123":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.contract.test/'
                        '.well-known/oauth-protected-resource/mcp"'
                    )
                },
            )
        if request.url.host == "mcp.contract.test" and request.url.path.startswith(
            "/.well-known/oauth-protected-resource"
        ):
            return httpx.Response(
                200, json={"resource": MCP_URL, "authorization_servers": [AUTH_SERVER]}
            )
        if url.startswith(f"{AUTH_SERVER}/.well-known/oauth-authorization-server"):
            return httpx.Response(
                200,
                json={
                    "issuer": AUTH_SERVER,
                    "authorization_endpoint": f"{AUTH_SERVER}/authorize",
                    "token_endpoint": f"{AUTH_SERVER}/token",
                    "registration_endpoint": f"{AUTH_SERVER}/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        if url == f"{AUTH_SERVER}/register":
            return httpx.Response(
                201,
                json={
                    "client_id": "client-1",
                    "client_secret": "secret-1",
                    "redirect_uris": ["http://127.0.0.1:9876/callback"],
                    "token_endpoint_auth_method": "client_secret_post",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                },
            )
        if url == f"{AUTH_SERVER}/token":
            seen["token_form"] = parse_qs(request.content.decode())
            return httpx.Response(
                200,
                json={
                    "access_token": "access-123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "refresh-123",
                },
            )
        return httpx.Response(404)

    return handler


async def test_mcp_oauth_provider_completes_authorization_code_flow(
    monkeypatch, tmp_path
):
    from secure_mcp_gateway.services.oauth import mcp_oauth_provider as provider_mod

    seen: dict = {}

    async def redirect_handler(authorize_url: str) -> None:
        seen["authorize_url"] = authorize_url

    async def callback_handler(port: int, timeout: float):
        state = parse_qs(urlparse(seen["authorize_url"]).query)["state"][0]
        return "code-123", state

    monkeypatch.setattr(provider_mod, "_token_dir", lambda: tmp_path)
    monkeypatch.setattr(provider_mod, "_redirect_handler", redirect_handler)
    monkeypatch.setattr(provider_mod, "_callback_handler_factory", callback_handler)

    auth = await provider_mod.build_mcp_oauth_auth(
        {
            "server_name": "remote",
            "config": {"url": MCP_URL},
            "mcp_oauth": {"enabled": True},
        }
    )
    assert isinstance(auth, httpx.Auth)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_oauth_mock_handler(seen)), auth=auth
    ) as http:
        response = await http.post(
            MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )

    assert response.status_code == 200
    query = parse_qs(urlparse(seen["authorize_url"]).query)
    assert seen["authorize_url"].startswith(f"{AUTH_SERVER}/authorize")
    assert query["client_id"] == ["client-1"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["resource"] == [MCP_URL]
    assert seen["token_form"]["code"] == ["code-123"]
    assert seen["token_form"]["grant_type"] == ["authorization_code"]

    storage = provider_mod.GatewayTokenStorage(MCP_URL)
    assert (await storage.get_tokens()).access_token == "access-123"
    assert (await storage.get_client_info()).client_id == "client-1"


async def test_mcp_oauth_is_off_unless_enabled():
    from secure_mcp_gateway.services.oauth.mcp_oauth_provider import (
        build_mcp_oauth_auth,
    )

    assert await build_mcp_oauth_auth({"config": {"url": MCP_URL}}) is None
    assert (
        await build_mcp_oauth_auth(
            {"config": {"url": MCP_URL}, "mcp_oauth": {"enabled": False}}
        )
        is None
    )
