"""Smoke + contract tests for the shipped minimal enkrypt-cloud config.

The file ``src/secure_mcp_gateway/example_enkrypt_cloud_config.json`` is
the recommended starting point for operators using the Enkrypt cloud
auth provider. These tests pin the contract so the example doesn't drift
from the code:

* It's valid JSON.
* It contains exactly the fields the cloud-auth provider requires at
  boot (and explicitly NOT the legacy fields that only the local_apikey
  provider consumes).
* When the admin REST API loads it, the cloud ``api_key`` resolves as
  an acceptable admin credential — because ``provider == "enkrypt"``.
* The file is the *minimal* shape — no ``_doc_*`` keys, no
  placeholder server-overrides, nothing the operator does not strictly
  need. The companion ``example_enkrypt_mcp_config.json`` is the
  reference for advanced fields.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_mcp_gateway.auth_policy import resolve_admin_keys

EXAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "secure_mcp_gateway"
    / "example_enkrypt_cloud_config.json"
)


@pytest.fixture(scope="module")
def example_config() -> dict:
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Required fields are present
# ---------------------------------------------------------------------------


def test_example_file_exists():
    assert EXAMPLE_PATH.is_file(), f"Missing minimal example at {EXAMPLE_PATH}"


def test_example_is_valid_json(example_config):
    assert isinstance(example_config, dict)


def test_enkrypt_config_block_has_api_key_and_base_url(example_config):
    enkrypt_cfg = example_config["enkrypt_config"]
    assert "api_key" in enkrypt_cfg
    assert "base_url" in enkrypt_cfg


def test_plugins_block_uses_enkrypt_provider(example_config):
    plugins = example_config["plugins"]
    assert plugins["auth"]["provider"] == "enkrypt"
    assert plugins["guardrails"]["provider"] == "enkrypt"


def test_auth_config_has_gateway_name(example_config):
    auth_cfg = example_config["plugins"]["auth"]["config"]
    assert "gateway_name" in auth_cfg, (
        "gateway_name is mandatory for the enkrypt auth provider"
    )


# ---------------------------------------------------------------------------
# Legacy fields that became no-ops with enkrypt provider must NOT appear
# in the minimal example. Drift here means a new user gets confused by
# fields that look meaningful but actually do nothing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "legacy_field",
    [
        "enkrypt_use_remote_mcp_config",
        "enkrypt_remote_mcp_gateway_name",
        "enkrypt_remote_mcp_gateway_version",
    ],
)
def test_legacy_remote_config_flags_omitted_from_common(example_config, legacy_field):
    common = example_config.get("common_mcp_gateway_config", {})
    assert legacy_field not in common, (
        f"{legacy_field} only applies to the local_apikey provider's "
        f"legacy 'remote fetch' path. Don't show it in the minimal "
        f"enkrypt-cloud example or new users will think they need to set it."
    )


@pytest.mark.parametrize(
    "cloud_owned_block",
    ["mcp_configs", "projects", "users", "apikeys"],
)
def test_cloud_owned_blocks_omitted(example_config, cloud_owned_block):
    assert cloud_owned_block not in example_config, (
        f"{cloud_owned_block} is owned by Enkrypt cloud when "
        f"plugins.auth.provider is 'enkrypt'. Including it in the "
        f"minimal example would mislead users into thinking they must "
        f"populate it locally."
    )


# ---------------------------------------------------------------------------
# Admin-key policy: cloud api_key must be acceptable as admin credential
# in this layout (admin_apikey is intentionally absent).
# ---------------------------------------------------------------------------


def test_admin_key_resolution_accepts_cloud_apikey(example_config):
    # The example ships with a placeholder api_key; substitute a real-looking
    # one so resolve_admin_keys does not filter it out.
    cfg = json.loads(json.dumps(example_config))  # deep copy
    cfg["enkrypt_config"]["api_key"] = "real-looking-cloud-key"

    keys = resolve_admin_keys(cfg)
    assert "real-looking-cloud-key" in keys, (
        "With provider=enkrypt and api_key set, the cloud apikey should "
        "authenticate against the REST admin API."
    )


def test_admin_apikey_is_not_required_in_minimal_layout(example_config):
    assert "admin_apikey" not in example_config, (
        "The whole point of the minimal layout is that admin_apikey is "
        "optional when provider=enkrypt. Don't bake one in."
    )


def test_placeholder_apikey_does_not_grant_admin(example_config):
    """As shipped (with the YOUR_ENKRYPT_API_KEY placeholder), nobody can
    administer the gateway — confirms the placeholder filter in
    resolve_admin_keys is doing its job.
    """
    keys = resolve_admin_keys(example_config)
    assert keys == [], (
        "Shipped placeholder must not be accepted as an admin credential."
    )


# ---------------------------------------------------------------------------
# The example must stay minimal — no ``_doc_*`` keys, no stub overrides.
# Helpful prose lives in the docs/README, not in JSON keys, so the file
# can be copied straight into ``~/.enkrypt/enkrypt_mcp_config.json``.
# ---------------------------------------------------------------------------


def _collect_doc_keys(node: object, path: str = "$") -> list[str]:
    """Recursively walk a JSON tree and return every ``_doc_*`` key path."""
    hits: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str) and key.startswith("_doc"):
                hits.append(child_path)
            hits.extend(_collect_doc_keys(value, child_path))
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            hits.extend(_collect_doc_keys(item, f"{path}[{idx}]"))
    return hits


def test_example_has_no_doc_keys_anywhere(example_config):
    """Pin the 'minimal' contract.

    Earlier versions of this file leaned heavily on ``_doc_*`` keys to
    explain every field. We deliberately stripped them so the example
    looks like a real config a user can drop straight into
    ``~/.enkrypt/`` without editing. If anyone re-adds ``_doc_*`` keys,
    they need to update this test and the file's docstring together.
    """
    doc_keys = _collect_doc_keys(example_config)
    assert doc_keys == [], (
        "example_enkrypt_cloud_config.json must contain ZERO _doc_* keys; "
        f"found: {doc_keys}"
    )


def test_example_has_no_local_server_overrides_block(example_config):
    """The placeholder ``local_server_overrides`` block only made sense
    next to its ``_doc_local_server_overrides`` explainer. Once the doc
    is stripped, the block becomes confusing (it ships with a fake
    ``_example_server_saved_name`` key that does nothing). It is OPTIONAL
    anyway — operators who need it can add it from the README. Pin
    its absence so it can't sneak back in alongside future edits.
    """
    assert "local_server_overrides" not in example_config


def test_example_matches_cli_generator(example_config):
    """The file on disk and ``generate_enkrypt_cloud_config()`` must be
    structurally identical. ``secure-mcp-gateway generate-config
    --provider enkrypt`` is what most users will actually run, and the
    example is supposed to mirror that output exactly. If they drift,
    one of them is misleading.
    """
    from secure_mcp_gateway.cli import generate_enkrypt_cloud_config

    generated = generate_enkrypt_cloud_config()
    assert generated == example_config, (
        "example_enkrypt_cloud_config.json and "
        "cli.generate_enkrypt_cloud_config() must produce the same dict. "
        f"Generated: {generated!r}\nOn disk: {example_config!r}"
    )
