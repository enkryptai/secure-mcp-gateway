"""Tests for ``auth_policy.authorize_apikey_for_cache_flush``.

Covers the two acceptance paths (static admin key + cloud-org match) plus
every rejection branch (missing key, bad key, no admin configured, no org
gating configured, org mismatch, cloud auth error, cloud timeout, cloud
upstream error). Cloud calls are stubbed via ``monkeypatch`` so the suite
doesn't talk to the network.
"""

from __future__ import annotations

import pytest

from secure_mcp_gateway import auth_policy
from secure_mcp_gateway.auth_policy import (
    AUTHZ_BAD_KEY,
    AUTHZ_CLOUD_UNAVAILABLE,
    AUTHZ_MISSING_KEY,
    AUTHZ_NO_ADMIN_CONFIGURED,
    AUTHZ_NO_ORG_CONFIGURED,
    AUTHZ_OK_ORG_MATCH,
    AUTHZ_OK_STATIC,
    AUTHZ_ORG_MISMATCH,
    authorize_apikey_for_cache_flush,
)


# ---------------------------------------------------------------------------
# Static-key acceptance (no cloud call)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_root_admin_key_accepted_for_any_provider():
    cfg = {"admin_apikey": "root-secret"}
    r = await authorize_apikey_for_cache_flush(cfg, "root-secret")
    assert r["authorized"] is True
    assert r["reason"] == AUTHZ_OK_STATIC
    assert r["via"] == "static_admin_key"
    assert r["status_code"] == 200


@pytest.mark.asyncio
async def test_nested_admin_key_accepted_for_local_provider():
    cfg = {
        "enkrypt_config": {"admin_apikey": "nested-secret"},
        "plugins": {"auth": {"provider": "local_apikey"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "nested-secret")
    assert r["authorized"] is True
    assert r["via"] == "static_admin_key"


@pytest.mark.asyncio
async def test_enkrypt_config_api_key_accepted_when_provider_enkrypt():
    cfg = {
        "enkrypt_config": {"api_key": "cloud-key"},
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "cloud-key")
    assert r["authorized"] is True
    assert r["via"] == "static_admin_key"


@pytest.mark.asyncio
async def test_enkrypt_config_api_key_NOT_accepted_when_provider_local():
    # Bug we'd never want to ship: local-apikey provider should not trust
    # the cloud apikey as an admin token.
    cfg = {
        "enkrypt_config": {"api_key": "cloud-key"},
        "plugins": {"auth": {"provider": "local_apikey"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "cloud-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ADMIN_CONFIGURED
    assert r["status_code"] == 500


# ---------------------------------------------------------------------------
# Rejection without cloud roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_apikey_returns_401_missing():
    r = await authorize_apikey_for_cache_flush({"admin_apikey": "x"}, None)
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_MISSING_KEY
    assert r["status_code"] == 401


@pytest.mark.asyncio
async def test_empty_apikey_returns_401_missing():
    r = await authorize_apikey_for_cache_flush({"admin_apikey": "x"}, "")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_MISSING_KEY


@pytest.mark.asyncio
async def test_no_admin_no_provider_returns_500():
    # Plain empty config -> nothing to authenticate against.
    r = await authorize_apikey_for_cache_flush({}, "any-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ADMIN_CONFIGURED
    assert r["status_code"] == 500


@pytest.mark.asyncio
async def test_local_provider_bad_apikey_returns_401():
    cfg = {
        "admin_apikey": "right-key",
        "plugins": {"auth": {"provider": "local_apikey"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "wrong-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_BAD_KEY
    assert r["status_code"] == 401


# ---------------------------------------------------------------------------
# Cloud-org match path (provider=enkrypt)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_consumer_info_ok(monkeypatch):
    """Stub fetch_consumer_info to return a successful ConsumerInfo."""
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerInfo,
    )

    captured = {}

    async def _fake(*, base_url, apikey):
        captured["base_url"] = base_url
        captured["apikey"] = apikey
        return ConsumerInfo(
            user_id="user-uuid-1",
            org_id="org-uuid-1",
            project_name="demo",
            email="alice@example.com",
            is_internal_req=False,
        )

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    return captured


@pytest.mark.asyncio
async def test_org_match_accepts(fake_consumer_info_ok):
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "org-uuid-1",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "any-customer-key")
    assert r["authorized"] is True
    assert r["reason"] == AUTHZ_OK_ORG_MATCH
    assert r["via"] == "org_match"
    assert r["principal"] == "alice@example.com"
    assert r["status_code"] == 200
    # Confirm we hit the configured base_url with the presented apikey.
    assert fake_consumer_info_ok["base_url"] == "https://api.dev.example.com"
    assert fake_consumer_info_ok["apikey"] == "any-customer-key"


@pytest.mark.asyncio
async def test_org_mismatch_rejects_403(fake_consumer_info_ok):
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "org-uuid-OTHER",  # mismatch
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "different-org-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_ORG_MISMATCH
    assert r["status_code"] == 403
    assert r["principal"] == "alice@example.com"  # we still know who tried


@pytest.mark.asyncio
async def test_no_org_id_configured_returns_401(monkeypatch):
    """When provider=enkrypt but org_id is blank, only static keys work."""
    # No cloud call should happen, so don't bother stubbing.
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            # org_id intentionally absent
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "some-customer-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ORG_CONFIGURED
    assert r["status_code"] == 401


@pytest.mark.asyncio
async def test_cloud_auth_error_rejects_401(monkeypatch):
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerAuthError,
    )

    async def _fake(*, base_url, apikey):
        raise ConsumerAuthError("nope")

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "org-uuid-1",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "invalid-cloud-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_BAD_KEY
    assert r["status_code"] == 401


@pytest.mark.asyncio
async def test_cloud_timeout_rejects_502(monkeypatch):
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerTimeoutError,
    )

    async def _fake(*, base_url, apikey):
        raise ConsumerTimeoutError("timeout")

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "org-uuid-1",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "ok-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_CLOUD_UNAVAILABLE
    assert r["status_code"] == 502


@pytest.mark.asyncio
async def test_cloud_upstream_error_rejects_502(monkeypatch):
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerUpstreamError,
    )

    async def _fake(*, base_url, apikey):
        raise ConsumerUpstreamError("503 from cloud", status_code=503)

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "org-uuid-1",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "ok-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_CLOUD_UNAVAILABLE
    assert r["status_code"] == 502


@pytest.mark.asyncio
async def test_static_key_short_circuits_before_cloud_call(monkeypatch):
    """Static admin key must NOT trigger a cloud roundtrip, even when
    provider=enkrypt + org_id is set + the key matches a static admin
    slot. Important for break-glass operability when the cloud is down.
    """
    cloud_called = {"hit": False}

    async def _fake(*, base_url, apikey):
        cloud_called["hit"] = True
        raise AssertionError("cloud should not be called when static admin matches")

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    cfg = {
        "admin_apikey": "break-glass",
        "enkrypt_config": {
            "api_key": "operator-key",
            "org_id": "org-uuid-1",
            "base_url": "https://api.dev.example.com",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "break-glass")
    assert r["authorized"] is True
    assert r["via"] == "static_admin_key"
    assert cloud_called["hit"] is False
