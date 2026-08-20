"""Registration / tool-batch guardrail checks must use the caller's apikey.

Guardrails resolve per apikey+project, so a batch check made with the
gateway's boot-time key looks up names in the wrong account and 404s even
though the caller's account has the guardrail. The nine detect/PII calls
already forwarded the caller key; the batch route did not.
"""

from __future__ import annotations

import json

import pytest

from secure_mcp_gateway.plugins.guardrails import enkrypt_provider as ep
from secure_mcp_gateway.request_context import request_apikey_var


class _Resp:
    status = 200

    async def json(self):
        return [{"text": "t", "summary": {}, "details": {}}]

    async def text(self):
        return json.dumps([])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture()
def seen(monkeypatch) -> dict:
    captured: dict = {}

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def post(self, url, json=None, headers=None, **kw):
            captured.update(url=url, headers=headers)
            return _Resp()

    monkeypatch.setattr(ep.aiohttp, "ClientSession", lambda *a, **k: _Session())
    return captured


@pytest.fixture()
def api():
    return ep.EnkryptServerRegistrationGuardrail(
        api_key="gateway-boot-key", base_url="https://api.example.com"
    )


async def test_batch_uses_caller_apikey(seen, api) -> None:
    token = request_apikey_var.set("caller-key")
    try:
        await api._call_batch_api(["t"], guardrail_name="demo guardrail")
    finally:
        request_apikey_var.reset(token)

    assert seen["headers"]["apikey"] == "caller-key"


async def test_batch_falls_back_to_static_key(seen, api) -> None:
    """Local single-tenant installs have no per-request key."""
    await api._call_batch_api(["t"], guardrail_name="demo guardrail")

    assert seen["headers"]["apikey"] == "gateway-boot-key"


async def test_discovery_publishes_caller_apikey() -> None:
    """DiscoveryService sets the contextvar the guardrail calls read, and
    resets it so the key can't leak into the next request."""
    # The package binds ``discovery_service`` to a singleton, shadowing the
    # submodule, so import the class directly.
    from secure_mcp_gateway.services.discovery import DiscoveryService

    seen: dict = {}

    class _StubAuth:
        def get_gateway_credentials(self, ctx):
            return {"gateway_key": "gw", "api_key": "caller-key"}

        async def get_local_mcp_config(self, *a, **kw):
            return {"mcp_config_id": "cfg", "project_name": "p", "email": "e"}

        def create_session_key(self, *a, **kw):
            return "sk"

        def is_session_authenticated(self, session_key):
            # First hook that runs after the contextvar is published.
            seen["apikey"] = request_apikey_var.get()
            raise RuntimeError("stop here")

    svc = DiscoveryService()
    svc.auth_manager = _StubAuth()

    class _Span:
        def set_attribute(self, *a, **kw):
            pass

        def record_exception(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Tracer:
        def start_as_current_span(self, *a, **kw):
            return _Span()

    class _Ctx:
        request_id = "r1"
        request_context = None

    await svc.discover_tools(_Ctx(), "demo-github-server", _Tracer(), None, False)

    assert seen["apikey"] == "caller-key"
    assert request_apikey_var.get() == ""
