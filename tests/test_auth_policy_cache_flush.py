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
async def test_enkrypt_config_api_key_NOT_static_when_provider_enkrypt(monkeypatch):
    """Strict mode: under provider=enkrypt, even the operator's own
    `enkrypt_config.api_key` doesn't short-circuit the cloud check.
    It still works -- because it survives /consumer-info and its org_id
    matches by construction -- but the request must round-trip the cloud
    so the principal is recorded.
    """
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerInfo,
    )

    async def _fake(*, base_url, apikey):
        return ConsumerInfo(
            user_id="op-uuid",
            org_id="op-org-uuid",
            email="ops@enkryptai.com",
        )

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )

    cfg = {
        "enkrypt_config": {
            "api_key": "cloud-key",
            "org_id": "op-org-uuid",
            "base_url": "https://api.dev.example.com",
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "cloud-key")
    assert r["authorized"] is True
    # Strict mode: even the operator's own key goes through the cloud
    # so principal is always recorded.
    assert r["via"] == "org_match"
    assert r["principal"] == "ops@enkryptai.com"


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
async def test_no_org_id_configured_returns_500_strict():
    """When provider=enkrypt + org_id missing/placeholder, no flush is
    possible at all -- strict mode blocks every request with a 500
    (mis-configuration) rather than letting static keys through."""
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
    assert r["status_code"] == 500


# ---------------------------------------------------------------------------
# org_id list-mode (multi-org allow-list for one gateway)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_match_accepts_when_configured_as_list_with_match(
    fake_consumer_info_ok,
):
    """org_id can be a list; consumer.org_id present in list -> authorized."""
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": ["org-uuid-other-a", "org-uuid-1", "org-uuid-other-b"],
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "any-customer-key")
    assert r["authorized"] is True
    assert r["reason"] == AUTHZ_OK_ORG_MATCH
    assert r["via"] == "org_match"
    assert r["principal"] == "alice@example.com"
    assert r["status_code"] == 200


@pytest.mark.asyncio
async def test_org_mismatch_rejects_when_list_excludes_cloud_org(
    fake_consumer_info_ok,
):
    """org_id list; consumer.org_id NOT in list -> 403, message shows list."""
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": ["org-uuid-foo", "org-uuid-bar"],  # cloud says "org-uuid-1"
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "different-org-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_ORG_MISMATCH
    assert r["status_code"] == 403
    assert r["principal"] == "alice@example.com"
    # Error message should surface the full allow-list so operators know
    # what was actually configured (not just one entry).
    assert "['org-uuid-foo', 'org-uuid-bar']" in r["detail"]
    assert "'org-uuid-1'" in r["detail"]


@pytest.mark.asyncio
async def test_single_item_list_renders_like_string_in_error(monkeypatch):
    """org_id: ['org-uuid-X'] should produce the same error shape as the
    legacy string form ``org_id: 'org-uuid-X'`` so single-org operators
    don't see surprise [...] brackets in alert messages."""
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerInfo,
    )

    async def _fake(*, base_url, apikey):
        return ConsumerInfo(
            user_id="u",
            org_id="org-uuid-FROM-CLOUD",
            project_name="p",
            email="x@y",
            is_internal_req=False,
        )

    monkeypatch.setattr(
        "secure_mcp_gateway.services.health.consumer_info_client.fetch_consumer_info",
        _fake,
    )
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": ["org-uuid-EXPECTED"],  # single-entry list
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "k")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_ORG_MISMATCH
    # Single-entry list collapses to bare-string display (no brackets).
    assert "'org-uuid-EXPECTED'" in r["detail"]
    assert "[" not in r["detail"]


@pytest.mark.asyncio
async def test_org_id_list_dedupes_and_strips():
    """Duplicate / blank / placeholder entries in the list are normalized
    away. After normalization, an empty effective list collapses to the
    same 500 'not configured' response as a missing field."""
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": [
                "  ",  # blank
                "YOUR_ENKRYPT_ORG_ID",  # placeholder
                "",  # empty
                None,  # wrong type, silently dropped
            ],
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "any-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ORG_CONFIGURED
    assert r["status_code"] == 500


@pytest.mark.asyncio
async def test_empty_list_org_id_is_not_configured():
    """``org_id: []`` collapses to NO_ORG_CONFIGURED."""
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": [],
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "any-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ORG_CONFIGURED
    assert r["status_code"] == 500


def test_normalize_org_ids_handles_all_shapes():
    """Unit test for the normalizer so future call sites stay correct."""
    from secure_mcp_gateway.auth_policy import _normalize_org_ids

    # String shape
    assert _normalize_org_ids("org-1") == ["org-1"]
    assert _normalize_org_ids("  org-1  ") == ["org-1"]
    assert _normalize_org_ids("") == []
    assert _normalize_org_ids("   ") == []
    assert _normalize_org_ids("YOUR_ENKRYPT_ORG_ID") == []
    assert _normalize_org_ids(None) == []

    # List shape
    assert _normalize_org_ids(["a", "b"]) == ["a", "b"]
    assert _normalize_org_ids(["a", "a", "b"]) == ["a", "b"]  # de-duped
    assert _normalize_org_ids([" a ", "b "]) == ["a", "b"]  # stripped
    assert _normalize_org_ids(["", " ", None, 42]) == []  # all invalid -> []
    assert _normalize_org_ids(["YOUR_ENKRYPT_ORG_ID", "real-org"]) == ["real-org"]
    assert _normalize_org_ids([]) == []

    # Tuple is also a list-like
    assert _normalize_org_ids(("a", "b")) == ["a", "b"]

    # Wrong types collapse to []
    assert _normalize_org_ids(42) == []
    assert _normalize_org_ids({"org_id": "x"}) == []


@pytest.mark.asyncio
async def test_placeholder_org_id_also_returns_500():
    cfg = {
        "enkrypt_config": {
            "api_key": "operator-key",
            "base_url": "https://api.dev.example.com",
            "org_id": "YOUR_ENKRYPT_ORG_ID",  # generator placeholder
        },
        "plugins": {"auth": {"provider": "enkrypt"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "any-key")
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_NO_ORG_CONFIGURED
    assert r["status_code"] == 500


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
async def test_static_admin_key_REJECTED_under_enkrypt_provider(monkeypatch):
    """Strict mode: root-level ``admin_apikey`` must NOT bypass the
    cloud check when provider=enkrypt. Every flush goes to the cloud
    so the principal is recorded. (Operators who need break-glass
    flush access must switch provider back to local_apikey.)
    """
    from secure_mcp_gateway.services.health.consumer_info_client import (
        ConsumerAuthError,
    )

    async def _fake(*, base_url, apikey):
        # The static break-glass key is not a real cloud apikey so the
        # cloud rejects it.
        raise ConsumerAuthError("not a cloud key")

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
    assert r["authorized"] is False
    assert r["reason"] == AUTHZ_BAD_KEY
    assert r["status_code"] == 401


@pytest.mark.asyncio
async def test_static_admin_key_still_works_for_local_provider():
    """Sanity: the strict policy is gated on provider=enkrypt. Under
    local_apikey, the static admin key path is preserved (otherwise
    local installs would have no flush mechanism)."""
    cfg = {
        "admin_apikey": "local-admin",
        "plugins": {"auth": {"provider": "local_apikey"}},
    }
    r = await authorize_apikey_for_cache_flush(cfg, "local-admin")
    assert r["authorized"] is True
    assert r["via"] == "static_admin_key"
