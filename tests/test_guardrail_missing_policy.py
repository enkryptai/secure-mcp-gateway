"""A missing guardrail policy must surface as GUARD_010, not a raw 404."""

from __future__ import annotations

import json

import pytest

from secure_mcp_gateway.exceptions import ErrorCode, MCPGatewayError
from secure_mcp_gateway.plugins.guardrails import enkrypt_provider as ep

NOT_FOUND_BODY = json.dumps(
    {"code": 404, "error": "Resource not found", "message": "Guardrail not found"}
)


class _Resp:
    status = 404

    async def text(self):
        return NOT_FOUND_BODY

    async def json(self):
        return json.loads(NOT_FOUND_BODY)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def post(self, *a, **kw):
        return _Resp()


@pytest.fixture()
def batch_api(monkeypatch):
    monkeypatch.setattr(ep.aiohttp, "ClientSession", lambda *a, **k: _Session())
    return ep.EnkryptServerRegistrationGuardrail(
        api_key="k", base_url="https://api.example.com"
    )


async def test_missing_policy_raises_guard_010(batch_api) -> None:
    with pytest.raises(MCPGatewayError) as exc:
        await batch_api._call_batch_api(["tool description"], guardrail_name="demo guardrail")

    assert exc.value.code == ErrorCode.GUARDRAIL_POLICY_NOT_FOUND
    assert "demo guardrail" in str(exc.value)
    assert "does not exist" in str(exc.value)


async def test_other_api_errors_stay_generic(batch_api, monkeypatch) -> None:
    class _ServerErr(_Resp):
        status = 502

        async def text(self):
            return "Bad Gateway"

    class _ErrSession(_Session):
        def post(self, *a, **kw):
            return _ServerErr()

    monkeypatch.setattr(ep.aiohttp, "ClientSession", lambda *a, **k: _ErrSession())

    with pytest.raises(MCPGatewayError) as exc:
        await batch_api._call_batch_api(["x"], guardrail_name="demo guardrail")

    assert exc.value.code == ErrorCode.GUARDRAIL_API_ERROR
