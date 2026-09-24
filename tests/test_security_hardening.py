"""Hosted-gateway hardening: stdio kill switch, sandbox fail-closed, blocked output, PII wiring."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest
from starlette.testclient import TestClient

from secure_mcp_gateway import gateway_playground_routes as gpr
from secure_mcp_gateway import utils
from secure_mcp_gateway.exceptions import ErrorCode, TransportError
from secure_mcp_gateway.plugins.guardrails import enkrypt_provider as ep
from secure_mcp_gateway.plugins.sandbox import server_params as sp
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.services.health.consumer_info_client import ConsumerInfo
from tests.test_gateway_playground_routes import (
    ADMIN_APIKEY,
    ENKRYPT_PROVIDER_CONFIG,
    LOCAL_PROVIDER_CONFIG,
    _build_app,
    _registry_lookup,
)


def _ensure_telemetry() -> None:
    # The execution service grabs a tracer at import time.
    manager = get_telemetry_config_manager()
    if manager.get_active_provider() is None:
        from secure_mcp_gateway.plugins.telemetry.example_providers import (
            ConsoleTelemetryProvider,
        )

        manager.register_provider(ConsoleTelemetryProvider())
        manager.initialize_provider("console", {})


_ensure_telemetry()
from secure_mcp_gateway.services.execution.secure_tool_execution_service import (
    SecureToolExecutionService,
)

STDIO_CONFIG = {"command": "python", "args": ["e.py"]}
URL_CONFIG = {"url": "https://mcp.example.com/mcp", "type": "http"}


@pytest.fixture
def client() -> TestClient:
    app, _ = _build_app()
    return TestClient(app)


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> Dict[str, AsyncMock]:
    ok = {"server_name": "x", "connectivity": {"status": "connected"}}
    mocks = {
        "check_server_health": AsyncMock(return_value=ok),
        "get_server_info": AsyncMock(return_value=ok),
        "execute_tool_health_check": AsyncMock(return_value=ok),
    }
    for name, m in mocks.items():
        monkeypatch.setattr(gpr._service, name, m)
    return mocks


@pytest.fixture
def enkrypt_cfg(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    monkeypatch.setattr(
        gpr, "_load_config_from_disk", lambda: dict(ENKRYPT_PROVIDER_CONFIG)
    )
    consumer = AsyncMock(
        return_value=ConsumerInfo(
            user_id="u1", org_id="o1", project_name="p", is_internal_req=False
        )
    )
    monkeypatch.setattr(gpr, "fetch_consumer_info", consumer)
    return consumer


@pytest.fixture
def stdio_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENKRYPT_ALLOW_STDIO_SERVERS", "false")


# --- allow_stdio_servers ------------------------------------------------------


def test_stdio_allowed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENKRYPT_ALLOW_STDIO_SERVERS", raising=False)
    monkeypatch.setattr(utils, "get_common_config", lambda *a, **k: {})
    assert utils.allow_stdio_servers() is True


@pytest.mark.parametrize("raw", ["false", "0", "no", "OFF"])
def test_env_disables_stdio(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("ENKRYPT_ALLOW_STDIO_SERVERS", raw)
    monkeypatch.setattr(
        utils,
        "get_common_config",
        lambda *a, **k: {"enkrypt_allow_stdio_servers": True},
    )
    assert utils.allow_stdio_servers() is False


def test_config_key_disables_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENKRYPT_ALLOW_STDIO_SERVERS", raising=False)
    monkeypatch.setattr(
        utils,
        "get_common_config",
        lambda *a, **k: {"enkrypt_allow_stdio_servers": False},
    )
    assert utils.allow_stdio_servers() is False


# --- build_server_params ------------------------------------------------------


async def test_build_server_params_refuses_stdio_when_disabled(stdio_off: None) -> None:
    entry = {"server_name": "s", "config": dict(STDIO_CONFIG)}
    with pytest.raises(TransportError) as exc:
        async with sp.build_server_params(entry, "python", ["e.py"], None):
            pytest.fail("stdio server must not start")
    assert exc.value.code == ErrorCode.TRANSPORT_STDIO_DISABLED


async def test_sandbox_without_provider_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENKRYPT_ALLOW_STDIO_SERVERS", raising=False)
    manager = SimpleNamespace(
        is_sandbox_enabled=lambda entry: True,
        get_provider=lambda: None,
        get_effective_sandbox_config=lambda entry: {},
    )
    monkeypatch.setattr(sp, "get_sandbox_config_manager", lambda: manager)
    spawned = AsyncMock()
    monkeypatch.setattr(sp, "stdio_client", spawned)
    entry = {"server_name": "s", "config": dict(STDIO_CONFIG)}
    with pytest.raises(TransportError) as exc:
        async with sp.build_server_params(entry, "python", ["e.py"], None):
            pytest.fail("must not run unsandboxed")
    assert exc.value.code == ErrorCode.TRANSPORT_SANDBOX_UNAVAILABLE
    spawned.assert_not_called()


# --- playground ---------------------------------------------------------------


def test_playground_inline_stdio_refused_when_disabled(
    client: TestClient,
    enkrypt_cfg: AsyncMock,
    service: Dict[str, AsyncMock],
    stdio_off: None,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "any-cloud-key"},
        json={"server_name": "evil", "config": dict(STDIO_CONFIG)},
    )
    assert resp.status_code == 403, resp.text
    service["check_server_health"].assert_not_called()


def test_playground_inline_url_still_allowed_when_stdio_disabled(
    client: TestClient,
    enkrypt_cfg: AsyncMock,
    service: Dict[str, AsyncMock],
    stdio_off: None,
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "any-cloud-key"},
        json={"server_name": "remote", "config": dict(URL_CONFIG)},
    )
    assert resp.status_code == 200, resp.text


def test_playground_registry_stdio_refused_when_disabled(
    client: TestClient,
    enkrypt_cfg: AsyncMock,
    service: Dict[str, AsyncMock],
    stdio_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gpr, "fetch_registry_server", AsyncMock(return_value=_registry_lookup())
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "any-cloud-key", "X-Enkrypt-MCP-Registry-Server": "my-fs"},
    )
    assert resp.status_code == 403, resp.text
    service["check_server_health"].assert_not_called()


def test_cloud_key_cannot_override_sandbox(
    client: TestClient, enkrypt_cfg: AsyncMock, service: Dict[str, AsyncMock]
) -> None:
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": "any-cloud-key"},
        json={
            "server_name": "echo",
            "config": dict(STDIO_CONFIG),
            "sandbox": {"enabled": False},
        },
    )
    assert resp.status_code == 403, resp.text
    service["check_server_health"].assert_not_called()


def test_admin_key_can_still_override_sandbox(
    client: TestClient,
    service: Dict[str, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENKRYPT_ALLOW_STDIO_SERVERS", raising=False)
    monkeypatch.setattr(
        gpr, "_load_config_from_disk", lambda: dict(LOCAL_PROVIDER_CONFIG)
    )
    resp = client.post(
        "/mcp-playground/test-server",
        headers={"apikey": ADMIN_APIKEY},
        json={
            "server_name": "echo",
            "config": dict(STDIO_CONFIG),
            "sandbox": {"enabled": False},
        },
    )
    assert resp.status_code == 200, resp.text
    assert service["check_server_health"].call_args.kwargs["sandbox"] == {
        "enabled": False
    }


# --- blocked output -----------------------------------------------------------


def test_blocked_output_does_not_return_the_blocked_text() -> None:
    result = SecureToolExecutionService._build_blocked_result(
        None,
        "blocked_output",
        "blocked",
        0,
        "srv",
        "tool",
        {},
        "SECRET OUTPUT",
        {"input_guardrails_config": {}, "output_guardrails_config": {}},
        {},
        {},
        {},
        {},
    )
    assert result["response"] == ""
    assert "SECRET OUTPUT" not in json.dumps(result)


# --- PII ----------------------------------------------------------------------


def test_pii_handler_created_from_additional_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ep.EnkryptGuardrailProvider(api_key="k", base_url="https://x")
    monkeypatch.setattr(provider, "_get_api_credentials", lambda: ("k", "https://x"))
    policy = {"enabled": True, "additional_config": {"pii_redaction": True}}
    assert isinstance(provider.create_pii_handler(policy), ep.EnkryptPIIHandler)
    assert provider.create_pii_handler({"additional_config": {}}) is None


@pytest.mark.parametrize(
    "response", [(0, {"error": "connection refused"}), (500, {"message": "boom"})]
)
async def test_redact_pii_raises_instead_of_passing_text_through(
    monkeypatch: pytest.MonkeyPatch, response: tuple[int, Dict[str, Any]]
) -> None:
    monkeypatch.setattr(ep, "_post_with_metrics", AsyncMock(return_value=response))
    handler = ep.EnkryptPIIHandler("k", "https://x")
    with pytest.raises(RuntimeError):
        await handler.redact_pii('{"email": "a@b.com"}')


async def test_redact_pii_returns_text_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ep,
        "_post_with_metrics",
        AsyncMock(return_value=(200, {"text": '{"email": "<EMAIL_0>"}', "key": "k1"})),
    )
    handler = ep.EnkryptPIIHandler("k", "https://x")
    text, mapping = await handler.redact_pii('{"email": "a@b.com"}')
    assert text == '{"email": "<EMAIL_0>"}'
    assert mapping == {"key": "k1"}


def _fake_service(handler: Any) -> SimpleNamespace:
    return SimpleNamespace(
        guardrail_manager=SimpleNamespace(get_pii_handler=lambda cfg: handler),
        _unwrap_timeout_result=SecureToolExecutionService._unwrap_timeout_result,
    )


GUARDRAILS_CONFIG = {
    "input_guardrails_config": {
        "enabled": True,
        "additional_config": {"pii_redaction": True},
    }
}


async def test_redact_pii_args_returns_redacted_args() -> None:
    handler = SimpleNamespace(
        redact_pii=AsyncMock(return_value=('{"email": "<EMAIL_0>"}', {"key": "k1"}))
    )
    args, got_handler, mapping = await SecureToolExecutionService._redact_pii_args(
        _fake_service(handler), {"email": "a@b.com"}, GUARDRAILS_CONFIG, 0
    )
    assert args == {"email": "<EMAIL_0>"}
    assert got_handler is handler
    assert mapping == {"key": "k1"}


async def test_redact_pii_args_fails_closed_on_redaction_error() -> None:
    handler = SimpleNamespace(redact_pii=AsyncMock(side_effect=RuntimeError("down")))
    with pytest.raises(Exception, match="down"):
        await SecureToolExecutionService._redact_pii_args(
            _fake_service(handler), {"email": "a@b.com"}, GUARDRAILS_CONFIG, 0
        )


async def test_redact_pii_args_fails_closed_without_handler() -> None:
    with pytest.raises(RuntimeError):
        await SecureToolExecutionService._redact_pii_args(
            _fake_service(None), {"email": "a@b.com"}, GUARDRAILS_CONFIG, 0
        )
