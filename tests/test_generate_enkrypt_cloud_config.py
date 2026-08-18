"""Tests for :py:func:`secure_mcp_gateway.cli.generate_enkrypt_cloud_config`.

This is the in-process generator that powers
``secure-mcp-gateway generate-config --provider enkrypt``. The function's
job is to produce the *minimum viable* config for the Enkrypt-cloud auth
provider so a first-time operator only has to fill in two placeholders
(``enkrypt_config.api_key`` and ``plugins.auth.config.gateway_name``)
before booting the gateway.

These tests pin the contract so a stray edit can't reintroduce legacy
fields, accidentally bake in cloud-owned blocks, or quietly desync
from ``example_enkrypt_cloud_config.json`` on disk.

Why so many small tests instead of one big one? Each assertion documents
a single design rule. When one breaks, the failure message tells you
exactly which rule the change violated — much friendlier than a single
giant ``dict-equality`` diff for someone reading CI output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from secure_mcp_gateway.auth_policy import resolve_admin_keys
from secure_mcp_gateway.cli import generate_enkrypt_cloud_config


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def generated() -> Dict[str, Any]:
    return generate_enkrypt_cloud_config()


# ---------------------------------------------------------------------------
# Shape: only the keys the cloud-auth provider strictly needs
# ---------------------------------------------------------------------------


def test_top_level_keys_are_exactly_the_minimal_set(generated):
    # Pinning the EXACT key set protects against two regressions:
    # (1) extra fields creeping in that the user has to remove, and
    # (2) required fields being silently dropped during a refactor.
    assert set(generated.keys()) == {
        "enkrypt_config",
        "plugins",
        "common_mcp_gateway_config",
    }


def test_no_doc_keys_anywhere(generated):
    # The minimal generator must stay clean — operators read the README
    # for explanations, not JSON commentary.
    def _walk(node: Any, path: str = "$") -> list[str]:
        hits: list[str] = []
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}.{k}"
                if isinstance(k, str) and k.startswith("_doc"):
                    hits.append(p)
                hits.extend(_walk(v, p))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                hits.extend(_walk(item, f"{path}[{i}]"))
        return hits

    leaks = _walk(generated)
    assert leaks == [], f"generator leaked _doc_* keys: {leaks}"


# ---------------------------------------------------------------------------
# enkrypt_config: api_key + base_url
# ---------------------------------------------------------------------------


def test_enkrypt_config_has_api_key_and_base_url(generated):
    enkrypt_cfg = generated["enkrypt_config"]
    assert "api_key" in enkrypt_cfg
    assert "base_url" in enkrypt_cfg


def test_api_key_is_a_placeholder_not_a_real_secret(generated):
    # We must never bake a real key into a generated config. The
    # placeholder is also the value that ``auth_policy`` filters out
    # of admin-key resolution (defense-in-depth so a freshly-generated
    # config doesn't accidentally grant admin to "YOUR_ENKRYPT_API_KEY").
    assert generated["enkrypt_config"]["api_key"] == "YOUR_ENKRYPT_API_KEY"


def test_base_url_defaults_to_production_enkrypt_cloud(generated):
    # Dev/staging URLs would be a footgun for prod-bound users. The
    # default must point at the prod endpoint.
    assert generated["enkrypt_config"]["base_url"] == "https://api.enkryptai.com"


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------


def test_auth_provider_is_enkrypt(generated):
    assert generated["plugins"]["auth"]["provider"] == "enkrypt"


def test_guardrails_provider_is_enkrypt(generated):
    assert generated["plugins"]["guardrails"]["provider"] == "enkrypt"


def test_auth_config_has_gateway_name_placeholder(generated):
    auth_cfg = generated["plugins"]["auth"]["config"]
    assert "gateway_name" in auth_cfg, (
        "gateway_name is the single mandatory field the operator must "
        "edit before first boot — it must be present so the placeholder "
        "is visible"
    )
    # A clearly fake placeholder so 'works on my laptop' boots fail
    # early rather than hitting Enkrypt cloud with a typo.
    assert auth_cfg["gateway_name"] == "your-gateway-saved-name"


def test_auth_config_has_optional_knobs(generated):
    # gateway_version and cache_ttl_seconds aren't strictly required, but
    # showing them in the generated file teaches the operator they exist.
    auth_cfg = generated["plugins"]["auth"]["config"]
    assert auth_cfg["gateway_version"] == "v1"
    assert isinstance(auth_cfg["cache_ttl_seconds"], int)
    assert auth_cfg["cache_ttl_seconds"] > 0


def test_telemetry_provider_is_opentelemetry(generated):
    # The cloud config mirrors the local config's telemetry default
    # (opentelemetry over OTLP gRPC to ``localhost:4317``) so the
    # bundled observability stack works out of the box. Operators
    # without a collector running can either swap to ``"stdout"`` or
    # set ``enabled: false`` in the plugin config.
    telemetry = generated["plugins"]["telemetry"]
    assert telemetry["provider"] == "opentelemetry"
    cfg = telemetry["config"]
    assert cfg.get("enabled") is True
    assert cfg.get("url") == "http://localhost:4317"
    assert cfg.get("insecure") is True


# ---------------------------------------------------------------------------
# common_mcp_gateway_config: only the knobs operators commonly tweak
# ---------------------------------------------------------------------------


def test_common_block_is_minimal(generated):
    # We deliberately only emit the two most-often-tweaked knobs; the
    # rest take their defaults from consts.DEFAULT_COMMON_CONFIG. If
    # someone adds 12 more fields, they need to update this test and
    # justify it in code review.
    common = generated["common_mcp_gateway_config"]
    assert set(common.keys()) == {
        "enkrypt_log_level",
        "enkrypt_gateway_cache_expiration_minutes",
    }


def test_log_level_default_is_info(generated):
    assert generated["common_mcp_gateway_config"]["enkrypt_log_level"] == "INFO"


# ---------------------------------------------------------------------------
# What MUST be absent — cloud-owned blocks + legacy local-only fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cloud_owned_block",
    ["mcp_configs", "projects", "users", "apikeys"],
)
def test_cloud_owned_blocks_are_not_emitted(generated, cloud_owned_block):
    # These live in Enkrypt cloud when provider=enkrypt. Baking them in
    # would mislead operators into populating fields the gateway then
    # ignores in favour of cloud data — silently confusing.
    assert cloud_owned_block not in generated


def test_admin_apikey_is_not_emitted(generated):
    # With provider=enkrypt, the cloud api_key doubles as the admin
    # credential (see ``auth_policy.resolve_admin_keys``). Generating a
    # second random root-level admin_apikey would defeat the simplicity
    # the cloud config is sold on.
    assert "admin_apikey" not in generated


@pytest.mark.parametrize(
    "legacy_field",
    [
        "enkrypt_use_remote_mcp_config",
        "enkrypt_remote_mcp_gateway_name",
        "enkrypt_remote_mcp_gateway_version",
    ],
)
def test_legacy_local_only_fields_are_not_emitted(generated, legacy_field):
    # These three fields only matter to the deprecated LocalApiKeyProvider
    # remote-fetch path. They're no-ops under provider=enkrypt and would
    # invite the operator to set them "just in case".
    common = generated.get("common_mcp_gateway_config", {})
    assert legacy_field not in common
    assert legacy_field not in generated


# ---------------------------------------------------------------------------
# Round-trip: matches what's on disk + works with the admin-key policy
# ---------------------------------------------------------------------------


def test_generator_matches_shipped_example(generated):
    # Pin that ``generate_enkrypt_cloud_config()`` is the single source
    # of truth for ``example_enkrypt_cloud_config.json``. If a future
    # edit changes the generator OR the file independently, this test
    # fires and the contributor knows to update both together.
    example_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "secure_mcp_gateway"
        / "example_enkrypt_cloud_config.json"
    )
    on_disk = json.loads(example_path.read_text(encoding="utf-8"))
    assert generated == on_disk


def test_placeholder_apikey_is_filtered_by_admin_policy(generated):
    # As shipped, the cloud api_key is "YOUR_ENKRYPT_API_KEY" — this
    # MUST be rejected by ``auth_policy.resolve_admin_keys`` so a
    # freshly-generated, unedited config cannot administer the gateway.
    assert resolve_admin_keys(generated) == []


def test_real_apikey_is_accepted_by_admin_policy(generated):
    # Once the operator fills in a real key, it should work as the
    # admin credential without them needing to also set admin_apikey.
    edited = json.loads(json.dumps(generated))
    edited["enkrypt_config"]["api_key"] = "a-real-looking-cloud-key"

    keys = resolve_admin_keys(edited)
    assert "a-real-looking-cloud-key" in keys


# ---------------------------------------------------------------------------
# Determinism: the generator must be a pure function
# ---------------------------------------------------------------------------


def test_generator_is_deterministic():
    # No timestamps, no UUIDs, no random IDs — the cloud config is
    # entirely declarative. Two back-to-back calls must produce the
    # same dict (this also implicitly proves the equality check
    # against the on-disk example file will keep working across calls).
    assert generate_enkrypt_cloud_config() == generate_enkrypt_cloud_config()
