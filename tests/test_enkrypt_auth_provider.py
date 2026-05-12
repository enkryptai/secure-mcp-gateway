"""Tests for ``plugins.auth.enkrypt_provider.EnkryptAuthProvider``.

These tests cover the cloud-config rewrite in isolation — every test stubs
``aiohttp`` so no real network call is made.

Coverage:
  * constructor rejects removed legacy keys (``api_key``, ``use_remote_config``)
  * constructor accepts the new shape and stores defaults
  * ``_map_response`` honours ``request_context`` (forwarded_user wins),
    falls back to top-level user_id when forwarded_* is absent, mirrors
    ``project_name`` into ``project_id``, and stashes unmapped fields under
    ``_request_context_extra``
  * ``_map_server`` lets ``gateway_overrides`` win over base policies
  * ``_map_server`` layers local-only fields (``sandbox`` / ``denied_tools``)
    when the cloud server has none
  * the in-process cache returns the same dict twice without a second
    cloud call, and re-fetches after the TTL expires
  * cloud transport errors surface as ``AuthStatus.ERROR`` (no fallback)
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

import pytest

from secure_mcp_gateway.plugins.auth.base import AuthCredentials, AuthStatus
from secure_mcp_gateway.plugins.auth import enkrypt_provider as ep_mod
from secure_mcp_gateway.plugins.auth.enkrypt_provider import (
    EnkryptAuthProvider,
    _CloudFetchError,
    _empty_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_provider(**overrides: Any) -> EnkryptAuthProvider:
    kwargs: Dict[str, Any] = {
        "apikey": "fallback-apikey",
        "gateway_name": "test-gateway",
        "gateway_version": "v1",
        "project_name": "default",
        "base_url": "https://api.example.com",
        "cache_ttl_seconds": 600,
    }
    kwargs.update(overrides)
    return EnkryptAuthProvider(**kwargs)


def sample_response(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "gateway_id": "gw-123",
        "gateway_saved_name": "test-gateway",
        "request_context": {
            "user_id": "owner-uuid",
            "org_id": "org-1",
            "project_name": "Default",
            "registry_name": "primary",
            "gateway_saved_name": "test-gateway",
            "gateway_version": "v1",
            "actioner": "owner-uuid",
            "forwarded_user_id": "end-user-42",
            "forwarded_user_email": "alice@example.com",
        },
        "expanded_servers": [
            {
                "saved_name": "echo_server",
                "description": "echo",
                "mcp_config": {
                    "config": {"command": "python", "args": ["echo.py"]},
                    "tools": {},
                    "input_guardrails_config": {
                        "enabled": True,
                        "guardrail_name": "Base Input",
                        "additional_config": {},
                        "block": ["injection_attack"],
                    },
                    "output_guardrails_config": {
                        "enabled": False,
                        "guardrail_name": "",
                        "additional_config": {},
                        "block": [],
                    },
                    "tool_guardrails_config": None,
                },
                "gateway_overrides": {},
            }
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Constructor behaviour
# ---------------------------------------------------------------------------


def test_constructor_rejects_removed_legacy_keys() -> None:
    with pytest.raises(ValueError) as exc:
        EnkryptAuthProvider(
            apikey="x",
            gateway_name="g",
            api_key="legacy-value",  # removed in v2.2
        )
    assert "api_key" in str(exc.value)


def test_constructor_allows_missing_gateway_name() -> None:
    """gateway_name is optional at boot — it can come from the request header."""
    p = EnkryptAuthProvider(apikey="x")
    assert p.gateway_name is None


def test_constructor_applies_defaults() -> None:
    p = EnkryptAuthProvider(apikey="x", gateway_name="g")
    assert p.gateway_version == "v1"
    assert p.base_url == "https://api.enkryptai.com"
    assert p.cache_ttl_seconds == 600


def test_constructor_strips_trailing_base_url_slash() -> None:
    p = EnkryptAuthProvider(
        apikey="x", gateway_name="g", base_url="https://api.example.com/"
    )
    assert p.base_url == "https://api.example.com"


# ---------------------------------------------------------------------------
# _map_response: identity propagation
# ---------------------------------------------------------------------------


def test_map_response_prefers_forwarded_user_over_owner() -> None:
    p = make_provider()
    out = p._map_response(sample_response())
    assert out["user_id"] == "end-user-42"
    assert out["email"] == "alice@example.com"


def test_map_response_falls_back_to_top_level_user_id() -> None:
    p = make_provider()
    resp = sample_response()
    resp["request_context"].pop("forwarded_user_id")
    resp["request_context"].pop("forwarded_user_email")
    out = p._map_response(resp)
    assert out["user_id"] == "owner-uuid"
    assert out["email"] == "not_provided"


def test_map_response_mirrors_project_name_into_project_id_when_absent() -> None:
    p = make_provider()
    out = p._map_response(sample_response())
    assert out["project_name"] == "Default"
    # No project_id in request_context → mirror project_name
    assert out["project_id"] == "Default"


def test_map_response_uses_explicit_project_id_when_cloud_provides_one() -> None:
    p = make_provider()
    resp = sample_response()
    resp["request_context"]["project_id"] = "proj-uuid-9"
    out = p._map_response(resp)
    assert out["project_id"] == "proj-uuid-9"


def test_map_response_keeps_unmapped_request_context_fields_for_logging() -> None:
    p = make_provider()
    out = p._map_response(sample_response())
    extra = out["_request_context_extra"]
    # promoted fields are NOT in extras...
    assert "user_id" not in extra
    assert "forwarded_user_id" not in extra
    assert "project_name" not in extra
    # ...but org_id / actioner / registry_name are.
    assert extra["org_id"] == "org-1"
    assert extra["actioner"] == "owner-uuid"
    assert extra["registry_name"] == "primary"


def test_map_response_handles_missing_request_context() -> None:
    p = make_provider()
    resp = sample_response()
    resp.pop("request_context")
    out = p._map_response(resp)
    # falls back through to provider defaults / placeholders
    assert out["user_id"] == "enkrypt_principal"
    assert out["project_name"] == "default"  # from provider's project_name
    assert out["email"] == "not_provided"
    assert out["_request_context_extra"] == {}


def test_map_response_filters_null_values_from_request_context_extra() -> None:
    """Cloud team confirmed ``org_id`` and ``project_name`` may be null when
    not bound to a gateway. Null entries must not land in
    ``_request_context_extra`` because that dict gets spread into
    ``AuthResult.metadata`` and downstream OTel attribute setters reject
    ``None`` with ``Invalid type NoneType`` warnings. Promoted fields
    (``project_name``) still fall back through the normal chain."""
    p = make_provider(project_name="fallback-project")
    resp = {
        "gateway_id": "gw-1",
        "request_context": {
            "user_id": "u-1",
            "project_name": None,
            "org_id": None,
            "actioner": None,
            "registry_name": "default",
            "gateway_saved_name": "g-1",
        },
        "expanded_servers": [],
    }
    out = p._map_response(resp)
    extra = out["_request_context_extra"]
    # Null fields must NOT leak into the extras dict.
    assert "org_id" not in extra
    assert "actioner" not in extra
    # Non-null extras still come through.
    assert extra["registry_name"] == "default"
    assert extra["gateway_saved_name"] == "g-1"


def test_map_response_falls_back_when_project_name_is_null() -> None:
    """When the cloud's ``request_context.project_name`` is null, the mapper
    must skip past it through the fallback chain (top-level
    ``response.project_name`` → provider's auth.config ``project_name`` →
    ``'default'``) instead of producing ``None`` for the project label."""
    # Case 1: top-level response.project_name fills the gap.
    p = make_provider(project_name="auth-cfg-project")
    resp = {
        "gateway_id": "gw-2",
        "project_name": "from-top-level",
        "request_context": {
            "user_id": "u-1",
            "project_name": None,
        },
        "expanded_servers": [],
    }
    out = p._map_response(resp)
    assert out["project_name"] == "from-top-level"
    assert out["project_id"] == "from-top-level"

    # Case 2: nothing on the cloud side — fall back to auth.config value.
    resp2 = {
        "gateway_id": "gw-3",
        "request_context": {
            "user_id": "u-1",
            "project_name": None,
        },
        "expanded_servers": [],
    }
    out2 = p._map_response(resp2)
    assert out2["project_name"] == "auth-cfg-project"

    # Case 3: nothing anywhere — last-resort default.
    p_no_proj = EnkryptAuthProvider(apikey="x", gateway_name="g")
    out3 = p_no_proj._map_response(resp2)
    assert out3["project_name"] == "default"
    assert out3["project_id"] == "default"


def test_map_response_handles_real_cloud_shape() -> None:
    """Lock in the exact response shape from the deployed dev cloud
    (``api.dev.enkryptai.com``) as captured 2026-05-05. Covers:

    * ``gateway_id`` is an integer (must be coerced to string)
    * cloud policy objects only carry ``enabled`` + ``guardrail_name`` and
      need the missing ``additional_config`` / ``block`` keys filled in
    * ``gateway_overrides.input_guardrails_config`` wins over
      ``mcp_config.input_guardrails_config`` (in this fixture they are
      identical, so the assertion is on the guardrail_name)
    * ``request_context`` carries ``org_id`` but no ``forwarded_*`` /
      ``actioner`` yet
    """
    p = make_provider(project_name="test")
    resp = {
        "gateway_saved_name": "my-dev-gateway",
        "gateway_version": "v1",
        "project_name": "test",
        "gateway_id": 1456247350,
        "is_active": True,
        "expanded_servers": [
            {
                "saved_name": "my-filesystem-server",
                "server_name": "@modelcontextprotocol/server-filesystem",
                "server_version": "v1",
                "description": "Updated filesystem access with enhanced security",
                "is_active": True,
                "mcp_config": {
                    "config": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@modelcontextprotocol/server-filesystem",
                            "/tmp",
                        ],
                    },
                    "enable_server_info_validation": True,
                    "input_guardrails_config": {
                        "enabled": True,
                        "guardrail_name": "Updated Guardrail",
                        "block": ["topic_detector", "nsfw", "keyword_detector"],
                    },
                    "tool_guardrails_config": {
                        "enabled": False,
                        "guardrail_name": "",
                    },
                },
                "gateway_overrides": {
                    "input_guardrails_config": {
                        "enabled": True,
                        "guardrail_name": "Updated Guardrail",
                        "block": ["topic_detector", "nsfw", "keyword_detector"],
                    }
                },
            }
        ],
        "request_context": {
            "gateway_saved_name": "my-dev-gateway",
            "gateway_version": "v1",
            "project_name": "test",
            "user_id": "731e726b-c5f4-47ed-9f5c-e02ea96ab6d0",
            "registry_name": "default",
            "org_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
        },
    }
    out = p._map_response(resp)

    assert out["user_id"] == "731e726b-c5f4-47ed-9f5c-e02ea96ab6d0"
    assert out["email"] == "not_provided"
    assert out["project_name"] == "test"
    assert out["project_id"] == "test"
    # gateway_id arrives as int from the cloud — must be coerced to str.
    assert out["mcp_config_id"] == "1456247350"
    assert isinstance(out["mcp_config_id"], str)

    server = out["mcp_config"][0]
    assert server["server_name"] == "my-filesystem-server"
    assert server["enable_server_info_validation"] is True

    # Cloud returned a partial tool_guardrails_config — missing keys filled
    # in from _empty_config.
    tool_policy = server["tool_guardrails_config"]
    assert tool_policy == {
        "enabled": False,
        "guardrail_name": "",
        "additional_config": {},
        "block": [],
    }

    # gateway_overrides won; same shape as cloud value here.
    assert (
        server["input_guardrails_config"]["guardrail_name"] == "Updated Guardrail"
    )
    assert "topic_detector" in server["input_guardrails_config"]["block"]

    # extras carry unmapped fields including org_id (now landed on the dev
    # cloud), but no forwarded_* / actioner yet.
    extra = out["_request_context_extra"]
    assert extra["registry_name"] == "default"
    assert extra["gateway_saved_name"] == "my-dev-gateway"
    assert extra["gateway_version"] == "v1"
    assert extra["org_id"] == "28cbcf05-653c-46fb-971c-2db57f4106ab"
    assert "actioner" not in extra
    assert "forwarded_user_id" not in extra


# ---------------------------------------------------------------------------
# _map_response: is_active filter
# ---------------------------------------------------------------------------


def test_map_response_skips_servers_marked_inactive() -> None:
    """Servers with ``is_active: false`` must not appear in the merged
    ``mcp_config`` list. They should never reach discovery / execution / cache.
    """
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"] = [
        {**resp["expanded_servers"][0], "saved_name": "active_one", "is_active": True},
        {**resp["expanded_servers"][0], "saved_name": "deleted_one", "is_active": False},
        {**resp["expanded_servers"][0], "saved_name": "another_active", "is_active": True},
    ]
    out = p._map_response(resp)
    names = [s["server_name"] for s in out["mcp_config"]]
    assert names == ["active_one", "another_active"]


def test_map_response_keeps_servers_when_is_active_missing() -> None:
    """Backward-compat: cloud responses that pre-date the ``is_active`` flag
    don't include the key at all. The mapper must default to keep.
    """
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0].pop("is_active", None)
    out = p._map_response(resp)
    assert len(out["mcp_config"]) == 1
    assert out["mcp_config"][0]["server_name"] == "echo_server"


def test_map_response_keeps_servers_when_is_active_is_null() -> None:
    """``null`` from the cloud means 'not authoritatively set' — conservative
    default is keep, matching the cloud's optimistic semantics."""
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["is_active"] = None
    out = p._map_response(resp)
    assert len(out["mcp_config"]) == 1


def test_map_response_keeps_servers_when_is_active_true() -> None:
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["is_active"] = True
    out = p._map_response(resp)
    assert len(out["mcp_config"]) == 1


def test_map_response_returns_empty_list_when_all_servers_inactive() -> None:
    """All-inactive responses are rare but plausible (gateway flushed in the
    dashboard). The mapper must not crash and should produce an empty list,
    not the ``None`` sentinel — downstream code iterates ``mcp_config``."""
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"] = [
        {**resp["expanded_servers"][0], "saved_name": "one", "is_active": False},
        {**resp["expanded_servers"][0], "saved_name": "two", "is_active": False},
    ]
    out = p._map_response(resp)
    assert out["mcp_config"] == []


# ---------------------------------------------------------------------------
# _map_server: gateway_overrides + local layering
# ---------------------------------------------------------------------------


def test_map_server_gateway_overrides_replace_base_policy() -> None:
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["gateway_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Stricter",
            "additional_config": {},
            "block": ["pii", "injection_attack", "toxicity"],
        }
    }
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"]["guardrail_name"] == "Stricter"
    assert server["input_guardrails_config"]["block"] == [
        "pii",
        "injection_attack",
        "toxicity",
    ]


def test_map_server_uses_base_policy_when_no_gateway_override() -> None:
    p = make_provider()
    out = p._map_response(sample_response())
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"]["guardrail_name"] == "Base Input"


def test_map_server_returns_empty_config_when_neither_set() -> None:
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["mcp_config"]["input_guardrails_config"] = None
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"] == _empty_config()


def test_map_server_layers_local_overrides_for_unmapped_fields() -> None:
    p = make_provider()
    local_overrides = {
        "echo_server": {
            "sandbox": {"enabled": True, "image": "python:3.11-slim"},
            "denied_tools": [{"pattern": "delete_*", "reason": "no destructive ops"}],
        }
    }
    out = p._map_response(sample_response(), local_overrides=local_overrides)
    server = out["mcp_config"][0]
    assert server["sandbox"]["enabled"] is True
    assert server["denied_tools"][0]["pattern"] == "delete_*"


def test_map_server_common_overrides_win_over_per_server_and_base() -> None:
    """When ``response.common_overrides.<key>`` is set, it must win even if
    the per-server entry also set ``gateway_overrides.<key>`` (echoed by the
    cloud for visibility) and even when the registry base ``mcp_config.<key>``
    is set. Common-wins is the contract; the cloud already strips the key
    from the per-server ``mcp_config``, but we must also ignore the
    ``gateway_overrides`` echo so the runtime stays consistent."""
    p = make_provider()
    resp = sample_response()
    # Per-server tries to set input_guardrails_config — it's echoed by the
    # cloud but must NOT win because common_overrides also sets the same key.
    resp["expanded_servers"][0]["gateway_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Per-Server Loses",
            "additional_config": {},
            "block": ["pii"],
        }
    }
    resp["common_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Org Wins",
            "additional_config": {},
            "block": ["injection_attack", "topic_detector"],
        }
    }
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"]["guardrail_name"] == "Org Wins"
    assert server["input_guardrails_config"]["block"] == [
        "injection_attack",
        "topic_detector",
    ]


def test_map_server_common_overrides_apply_when_no_per_server_or_base() -> None:
    """common_overrides supplies the policy even when neither per-server
    gateway_overrides nor the per-server mcp_config carry it. The cloud
    strips the key from mcp_config when common_overrides has it; we must
    still produce a fully-populated policy on the merged server."""
    p = make_provider()
    resp = sample_response()
    # Simulate the dedup the cloud does: tool_guardrails_config absent
    # from this server's mcp_config because common_overrides handles it.
    resp["expanded_servers"][0]["mcp_config"].pop("tool_guardrails_config", None)
    resp["expanded_servers"][0]["gateway_overrides"] = {}
    resp["common_overrides"] = {
        "tool_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Org Tool Guardrail",
            "block": ["policy_violation"],
        }
    }
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    # Missing keys filled from _empty_config template.
    assert server["tool_guardrails_config"] == {
        "enabled": True,
        "guardrail_name": "Org Tool Guardrail",
        "additional_config": {},
        "block": ["policy_violation"],
    }
    assert server["enable_tool_guardrails"] is True


def test_map_server_per_server_override_used_when_common_misses_that_key() -> None:
    """common_overrides and per-server gateway_overrides for *different* keys
    coexist fine. The per-server override is effective for the key common
    doesn't set; common's separate key applies to every server."""
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["gateway_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Per-Server Input",
            "additional_config": {},
            "block": ["pii"],
        }
    }
    resp["common_overrides"] = {
        "output_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Org Output",
            "additional_config": {},
            "block": ["hallucination"],
        }
    }
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    # Per-server wins for input (common doesn't set it).
    assert server["input_guardrails_config"]["guardrail_name"] == "Per-Server Input"
    # Common wins for output (per-server doesn't set it).
    assert server["output_guardrails_config"]["guardrail_name"] == "Org Output"


def test_map_server_common_overrides_enable_server_info_validation_honours_false() -> None:
    """The ``enable_server_info_validation`` boolean must use ``is not None``
    semantics so an explicit False from common_overrides is respected and
    not coalesced with 'unset'."""
    p = make_provider()
    resp = sample_response()
    # Base value would say True; common explicitly turns it off for the gateway.
    resp["expanded_servers"][0]["mcp_config"]["enable_server_info_validation"] = True
    resp["common_overrides"] = {"enable_server_info_validation": False}
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["enable_server_info_validation"] is False


def test_map_server_empty_common_overrides_dict_falls_through_to_per_server() -> None:
    """An empty `{}` for a specific policy in common_overrides is treated
    the same as 'not set' — fall through to per-server / base. Matches the
    existing truthiness convention for gateway_overrides."""
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["gateway_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Per-Server Used",
            "additional_config": {},
            "block": ["pii"],
        }
    }
    # Empty dict for the same key — should NOT win, per-server takes over.
    resp["common_overrides"] = {"input_guardrails_config": {}}
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"]["guardrail_name"] == "Per-Server Used"


def test_map_server_missing_common_overrides_key_does_not_break() -> None:
    """Responses pre-dating the common_overrides field must still map cleanly
    — the mapper treats the absent key as `{}` and per-server behaviour is
    unchanged."""
    p = make_provider()
    resp = sample_response()
    resp.pop("common_overrides", None)
    # Sanity: existing per-server-only behavior still works.
    resp["expanded_servers"][0]["gateway_overrides"] = {
        "input_guardrails_config": {
            "enabled": True,
            "guardrail_name": "Per-Server Only",
            "additional_config": {},
            "block": ["pii"],
        }
    }
    out = p._map_response(resp)
    server = out["mcp_config"][0]
    assert server["input_guardrails_config"]["guardrail_name"] == "Per-Server Only"


def test_map_server_does_not_clobber_cloud_oauth_with_local() -> None:
    p = make_provider()
    resp = sample_response()
    resp["expanded_servers"][0]["mcp_config"]["oauth_config"] = {
        "enabled": True,
        "version": "2.1",
    }
    local = {"echo_server": {"oauth_config": {"enabled": False}}}
    out = p._map_response(resp, local_overrides=local)
    # cloud value wins (we only fill gaps, never overwrite)
    assert out["mcp_config"][0]["oauth_config"]["enabled"] is True


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_hit_short_circuits_second_fetch(monkeypatch) -> None:
    p = make_provider(cache_ttl_seconds=600)

    call_count = {"n": 0}

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        call_count["n"] += 1
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    a = await p._get_local_config("apikey-x")
    b = await p._get_local_config("apikey-x")
    assert call_count["n"] == 1
    assert a == b


@pytest.mark.asyncio
async def test_cache_separated_per_apikey(monkeypatch) -> None:
    p = make_provider()

    call_count = {"n": 0}

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        call_count["n"] += 1
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    await p._get_local_config("apikey-A")
    await p._get_local_config("apikey-B")
    assert call_count["n"] == 2


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(monkeypatch) -> None:
    p = make_provider(cache_ttl_seconds=600)

    call_count = {"n": 0}

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        call_count["n"] += 1
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    await p._get_local_config("apikey-x")

    # Move every cached entry's expiry to 1s ago.
    for k, (_exp, val) in list(p._cache.items()):
        p._cache[k] = (0.0, val)

    await p._get_local_config("apikey-x")
    assert call_count["n"] == 2


def test_invalidate_cache_clears_all_entries() -> None:
    p = make_provider()
    p._cache["foo"] = (1e18, {"x": 1})
    p._cache["bar"] = (1e18, {"y": 2})
    p.invalidate_cache()
    assert p._cache == {}


# ---------------------------------------------------------------------------
# Authenticate end-to-end with a stubbed cloud
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_succeeds_with_stubbed_cloud(monkeypatch) -> None:
    p = make_provider()

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    creds = AuthCredentials(api_key="caller-apikey", gateway_key="caller-apikey")
    result = await p.authenticate(creds)
    assert result.authenticated is True
    assert result.status == AuthStatus.SUCCESS
    assert result.user_id == "end-user-42"
    assert result.metadata["source"] == "enkrypt-cloud"
    assert result.metadata["gateway_name"] == "test-gateway"
    # request_context_extra is surfaced into AuthResult.metadata
    assert result.metadata["org_id"] == "org-1"


@pytest.mark.asyncio
async def test_authenticate_rejects_missing_apikey() -> None:
    p = EnkryptAuthProvider(gateway_name="g")  # no fallback apikey
    creds = AuthCredentials(api_key=None, gateway_key=None)
    result = await p.authenticate(creds)
    assert result.authenticated is False
    assert result.status == AuthStatus.INVALID_CREDENTIALS


@pytest.mark.asyncio
async def test_authenticate_rejects_missing_gateway_name() -> None:
    """When neither config nor header supplies a gateway_name, auth must fail."""
    p = EnkryptAuthProvider(apikey="x")  # no gateway_name at boot
    creds = AuthCredentials(api_key="x", gateway_key="x")
    result = await p.authenticate(creds)
    assert result.authenticated is False
    assert result.status == AuthStatus.INVALID_CREDENTIALS
    assert "gateway" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_authenticate_uses_header_gateway_name(monkeypatch) -> None:
    """Header gateway_name overrides config and is used for cloud fetch."""
    p = make_provider()  # config has gateway_name="test-gateway"

    seen_gateway = {}

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        seen_gateway["name"] = kw.get("gateway_name")
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    creds = AuthCredentials(
        api_key="x", gateway_key="x", gateway_name="header-override-gw"
    )
    result = await p.authenticate(creds)
    assert result.authenticated is True
    assert result.metadata["gateway_name"] == "header-override-gw"
    assert seen_gateway["name"] == "header-override-gw"


@pytest.mark.asyncio
async def test_authenticate_falls_back_to_config_gateway_name(monkeypatch) -> None:
    """When header has no gateway_name, config value is used."""
    p = make_provider()  # config has gateway_name="test-gateway"

    seen_gateway = {}

    async def fake_fetch(self: EnkryptAuthProvider, gateway_key: str, **kw):
        seen_gateway["name"] = kw.get("gateway_name")
        return sample_response()

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(
        EnkryptAuthProvider, "_fetch_remote_gateway_config", fake_fetch
    )
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    creds = AuthCredentials(api_key="x", gateway_key="x")  # no gateway_name
    result = await p.authenticate(creds)
    assert result.authenticated is True
    assert result.metadata["gateway_name"] == "test-gateway"
    assert seen_gateway["name"] == "test-gateway"


@pytest.mark.asyncio
async def test_authenticate_hard_fails_on_cloud_error(monkeypatch) -> None:
    p = make_provider()

    async def boom(self: EnkryptAuthProvider, gateway_key: str, **kw):
        raise _CloudFetchError("HTTP 503 from upstream")

    async def empty_overrides(self: EnkryptAuthProvider):
        return {}

    monkeypatch.setattr(EnkryptAuthProvider, "_fetch_remote_gateway_config", boom)
    monkeypatch.setattr(
        EnkryptAuthProvider, "_load_local_server_overrides", empty_overrides
    )

    creds = AuthCredentials(api_key="x", gateway_key="x")
    result = await p.authenticate(creds)
    assert result.authenticated is False
    assert result.status == AuthStatus.ERROR
    assert "503" in (result.error or "")


# ---------------------------------------------------------------------------
# Module sanity
# ---------------------------------------------------------------------------


def test_truncate_helper() -> None:
    assert ep_mod._truncate("short") == "short"
    big = "x" * 1000
    out = ep_mod._truncate(big, limit=100)
    assert out.endswith("...(truncated)")
    assert len(out) <= 200


# ---------------------------------------------------------------------------
# AuthConfigManager.create_session_key — None-coercion regression
# ---------------------------------------------------------------------------
#
# Regression test for the cloud-auth bug where the gateway tried to look up a
# session under ``apikey_not_provided_not_provided_<id>`` while it had been
# stored under ``apikey_None_None_<id>`` (literal "None" string from raw
# f-string interpolation), causing every cached-session lookup to raise
# ``ValueError: Session ... not found`` even though authentication succeeded.
# See ``AuthConfigManager.create_session_key``.


def test_create_session_key_coerces_none_components() -> None:
    """``create_session_key`` must canonicalize ``None`` -> ``"not_provided"``.

    The cloud-auth path produces ``credentials.project_id is None`` /
    ``credentials.user_id is None`` (clients only send the ``apikey`` header).
    Service-layer call sites canonicalize these via
    ``credentials.get(k) or "not_provided"`` before building lookup keys.
    The store side must produce the same string or sessions become
    unreachable.
    """
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    mgr = AuthConfigManager()

    # All-None path (only gateway_key supplied — the cloud-auth shape).
    key = mgr.create_session_key("apikey-xyz", None, None, "mcp-1")
    assert key == "apikey-xyz_not_provided_not_provided_mcp-1"

    # Empty string is treated identically (defensive).
    assert (
        mgr.create_session_key("apikey-xyz", "", "", "mcp-1")
        == "apikey-xyz_not_provided_not_provided_mcp-1"
    )

    # Real values pass through unchanged.
    assert (
        mgr.create_session_key("apikey-xyz", "p1", "u1", "mcp-1")
        == "apikey-xyz_p1_u1_mcp-1"
    )

    # Defensive: even gateway_key / mcp_config_id get coerced (we never want
    # a bare "None" appearing in a session key on a hot path).
    assert (
        mgr.create_session_key(None, None, None, None)
        == "not_provided_not_provided_not_provided_not_provided"
    )


def test_create_session_key_store_lookup_symmetry() -> None:
    """Store side (``authenticate`` -> ``create_session_key``) and lookup
    side (service layer ``credentials.get(k) or "not_provided"``) must
    produce identical keys for the same logical request.
    """
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    mgr = AuthConfigManager()

    # Cloud-auth credentials: project_id and user_id are absent.
    raw_creds = {"gateway_key": "cloud-apikey", "project_id": None, "user_id": None}
    mcp_id = "1456247350"

    # Store side replicates ``authenticate``: passes raw credential values
    # straight through ``create_session_key`` (which now coerces them).
    store_key = mgr.create_session_key(
        raw_creds["gateway_key"],
        raw_creds["project_id"],
        raw_creds["user_id"],
        mcp_id,
    )

    # Lookup side replicates the service-layer pattern: callers either pass
    # the same raw values to ``create_session_key`` or build with already
    # ``or "not_provided"``-coerced locals. Both must yield the same string.
    lookup_via_helper = mgr.create_session_key(
        raw_creds.get("gateway_key"),
        raw_creds.get("project_id"),
        raw_creds.get("user_id"),
        mcp_id,
    )
    coerced_pid = raw_creds.get("project_id") or "not_provided"
    coerced_uid = raw_creds.get("user_id") or "not_provided"
    lookup_via_inline_fstring = (
        f"{raw_creds['gateway_key']}_{coerced_pid}_{coerced_uid}_{mcp_id}"
    )

    assert store_key == lookup_via_helper == lookup_via_inline_fstring
