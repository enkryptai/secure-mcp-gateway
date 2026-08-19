"""``X-Enkrypt-MCP-Gateway-Version`` extraction and manager plumbing.

Provider-side precedence lives in ``test_enkrypt_auth_provider.py``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager


def _ctx(headers: dict[str, str]) -> SimpleNamespace:
    """Minimal stand-in for an MCP ``Context`` carrying HTTP headers."""
    return SimpleNamespace(
        request_context=SimpleNamespace(request=SimpleNamespace(headers=headers))
    )


@pytest.fixture()
def manager(monkeypatch) -> AuthConfigManager:
    # extract_credentials falls back to these, which would mask the headers.
    for var in (
        "ENKRYPT_APIKEY",
        "ENKRYPT_GATEWAY_KEY",
        "ENKRYPT_PROJECT_ID",
        "ENKRYPT_USER_ID",
    ):
        monkeypatch.delenv(var, raising=False)
    return AuthConfigManager()


def test_extract_credentials_reads_version_header(manager) -> None:
    creds = manager.extract_credentials(
        _ctx(
            {
                "apikey": "cloud-key",
                "X-Enkrypt-MCP-Gateway": "demo-mcp-gateway",
                "X-Enkrypt-MCP-Gateway-Version": "1",
            }
        )
    )
    assert creds.gateway_name == "demo-mcp-gateway"
    assert creds.gateway_version == "1"


def test_extract_credentials_version_absent_is_none(manager) -> None:
    """Absent header stays ``None`` so the provider applies its default."""
    creds = manager.extract_credentials(
        _ctx({"apikey": "cloud-key", "X-Enkrypt-MCP-Gateway": "demo-mcp-gateway"})
    )
    assert creds.gateway_version is None


def test_get_gateway_credentials_exposes_version(manager) -> None:
    """Service layer reads credentials through this dict."""
    creds = manager.get_gateway_credentials(
        _ctx(
            {
                "apikey": "cloud-key",
                "X-Enkrypt-MCP-Gateway": "demo-mcp-gateway",
                "X-Enkrypt-MCP-Gateway-Version": "1",
            }
        )
    )
    assert creds["gateway_version"] == "1"
    assert creds["gateway_name"] == "demo-mcp-gateway"


@pytest.mark.asyncio
async def test_get_local_mcp_config_forwards_version(manager, monkeypatch) -> None:
    """The manager hands the version to the provider unchanged."""
    seen: dict[str, object] = {}

    class _StubProvider:
        async def _get_local_config(self, gateway_key, project_id=None, user_id=None,
                                    *, gateway_name=None, gateway_version=None):
            seen.update(
                gateway_key=gateway_key,
                gateway_name=gateway_name,
                gateway_version=gateway_version,
            )
            return {"mcp_config_id": "cfg-1"}

    monkeypatch.setattr(manager, "get_provider", lambda name=None: _StubProvider())

    out = await manager.get_local_mcp_config(
        "cloud-key", None, None, gateway_name="demo-mcp-gateway", gateway_version="1"
    )
    assert out == {"mcp_config_id": "cfg-1"}
    assert seen["gateway_name"] == "demo-mcp-gateway"
    assert seen["gateway_version"] == "1"


@pytest.mark.asyncio
async def test_local_apikey_provider_tolerates_version_kwarg() -> None:
    """Local mode must not raise ``TypeError`` on the forwarded kwarg."""
    from secure_mcp_gateway.plugins.auth.local_apikey_provider import (
        LocalApiKeyProvider,
    )

    provider = LocalApiKeyProvider()
    result = await provider._get_local_config(
        "no-such-key", None, None, gateway_name="ignored", gateway_version="1"
    )
    assert result in (None, {}, )
