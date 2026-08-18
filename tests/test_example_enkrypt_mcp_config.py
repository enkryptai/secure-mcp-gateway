"""Smoke/contract tests for ``example_enkrypt_mcp_config.json``.

This is the example bundled with the package for the **local_apikey**
auth path (the cloud-equivalent example is
``example_enkrypt_cloud_config.json``, covered by its own test module).

The example doubles as documentation: it must demonstrate the canonical
config shape the local-API-key provider expects. These tests pin that
shape so a stray edit to the example doesn't silently teach operators
the wrong layout.

In particular we assert:

* ``server_tools_guardrails_config`` lives at
  ``mcp_configs.<id>.common_overrides.server_tools_guardrails_config``
  and NOT on any individual server entry. This mirrors the cloud's
  ``servers_config.common_overrides`` contract and matches the
  promote-in-provider behavior in
  :py:meth:`LocalApiKeyProvider._apply_common_overrides`.
* The deprecated keys (``tool_guardrails_config``,
  ``enable_server_info_validation``) are gone from server entries.
* ``input_guardrails_config`` / ``output_guardrails_config`` stay
  per-server — they are intentionally NOT promoted, because operators
  often want different input/output policies on different servers.
* A human-readable explainer (``_doc_common_overrides``) sits next to
  the block so anyone reading the file knows why it's there.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest


EXAMPLE_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "secure_mcp_gateway"
    / "example_enkrypt_mcp_config.json"
)


@pytest.fixture(scope="module")
def example_config() -> Dict[str, Any]:
    assert EXAMPLE_PATH.exists(), f"missing example config at {EXAMPLE_PATH}"
    with EXAMPLE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def mcp_config_entry(example_config: Dict[str, Any]) -> Dict[str, Any]:
    mcp_configs = example_config.get("mcp_configs", {})
    assert mcp_configs, "example config must declare at least one mcp_config"
    first_id = next(iter(mcp_configs))
    return mcp_configs[first_id]


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestTopLevelShape:
    def test_is_valid_json(self, example_config):
        # The fixture having loaded successfully is the assertion. We just
        # poke a key so the test reads as a real assertion.
        assert isinstance(example_config, dict) and example_config

    def test_has_mcp_configs(self, example_config):
        assert "mcp_configs" in example_config

    def test_admin_apikey_is_root_level(self, example_config):
        # The admin key policy mandates root-level placement; keep the
        # example aligned with the policy so operators copy the right shape.
        assert "admin_apikey" in example_config, (
            "example must show admin_apikey at the root level "
            "(see auth_policy.resolve_admin_keys)"
        )


# ---------------------------------------------------------------------------
# common_overrides slot
# ---------------------------------------------------------------------------


class TestCommonOverridesSlot:
    def test_common_overrides_is_present(self, mcp_config_entry):
        assert "common_overrides" in mcp_config_entry, (
            "The example must demonstrate the common_overrides slot at "
            "mcp_configs.<id>.common_overrides — that's where "
            "server_tools_guardrails_config now lives."
        )

    def test_common_overrides_has_server_tools_guardrails_config(
        self, mcp_config_entry
    ):
        co = mcp_config_entry["common_overrides"]
        assert "server_tools_guardrails_config" in co

    def test_server_tools_guardrails_config_shape(self, mcp_config_entry):
        stg = mcp_config_entry["common_overrides"]["server_tools_guardrails_config"]
        assert isinstance(stg, dict)
        for required_key in ("enabled", "guardrail_name", "block"):
            assert required_key in stg, (
                f"server_tools_guardrails_config missing {required_key!r}"
            )
        assert isinstance(stg["enabled"], bool)
        assert isinstance(stg["guardrail_name"], str) and stg["guardrail_name"]
        assert isinstance(stg["block"], list) and stg["block"]

    def test_common_overrides_does_NOT_include_input_or_output_guardrails(
        self, mcp_config_entry
    ):
        # Flavor 1 contract: input/output policies stay per-server. The
        # example must not falsely advertise them as common-only by
        # putting sample values in common_overrides.
        co = mcp_config_entry["common_overrides"]
        assert "input_guardrails_config" not in co
        assert "output_guardrails_config" not in co

    def test_explainer_doc_is_present(self, mcp_config_entry):
        # Self-documenting config: operators reading the file should see
        # WHY this block exists without having to open the source.
        assert "_doc_common_overrides" in mcp_config_entry
        doc = mcp_config_entry["_doc_common_overrides"]
        assert isinstance(doc, str) and len(doc) > 50
        # Touchstone phrases that prove the doc is meaningful, not stub.
        assert "common_overrides" in doc.lower() or "common-only" in doc.lower()


# ---------------------------------------------------------------------------
# Per-server entries — what MUST and MUST NOT be there
# ---------------------------------------------------------------------------


class TestPerServerEntries:
    def test_no_per_server_server_tools_guardrails_config(self, mcp_config_entry):
        for srv in mcp_config_entry.get("mcp_config", []):
            assert "server_tools_guardrails_config" not in srv, (
                f"Server {srv.get('server_name')!r} still has "
                "server_tools_guardrails_config inline. This key is now "
                "common-only — move it under common_overrides."
            )

    def test_no_legacy_tool_guardrails_config(self, mcp_config_entry):
        for srv in mcp_config_entry.get("mcp_config", []):
            assert "tool_guardrails_config" not in srv, (
                f"Server {srv.get('server_name')!r} still has the deprecated "
                "tool_guardrails_config key — should be removed (replaced by "
                "common_overrides.server_tools_guardrails_config)."
            )

    def test_no_legacy_enable_server_info_validation(self, mcp_config_entry):
        for srv in mcp_config_entry.get("mcp_config", []):
            assert "enable_server_info_validation" not in srv, (
                f"Server {srv.get('server_name')!r} still has the deprecated "
                "enable_server_info_validation key — should be removed "
                "(rolled into common_overrides.server_tools_guardrails_config)."
            )

    def test_input_output_guardrails_remain_per_server(self, mcp_config_entry):
        # At least one server should still demonstrate per-server input/output
        # policies — that's how the example teaches the intended pattern.
        servers = mcp_config_entry.get("mcp_config", [])
        has_input = any("input_guardrails_config" in s for s in servers)
        has_output = any("output_guardrails_config" in s for s in servers)
        assert has_input, (
            "Example must show input_guardrails_config on at least one server "
            "(it stays per-server, not promoted from common_overrides)."
        )
        assert has_output, (
            "Example must show output_guardrails_config on at least one server "
            "(it stays per-server, not promoted from common_overrides)."
        )


# ---------------------------------------------------------------------------
# Roundtrip: provider promotion produces the exact value from common
# ---------------------------------------------------------------------------


class TestPromotionRoundtrip:
    """The example must promote cleanly through the real provider."""

    def test_promotion_yields_common_value_on_every_server(self, mcp_config_entry):
        from secure_mcp_gateway.plugins.auth.local_apikey_provider import (
            LocalApiKeyProvider,
        )

        expected = mcp_config_entry["common_overrides"]["server_tools_guardrails_config"]
        promoted = LocalApiKeyProvider._apply_common_overrides(mcp_config_entry)
        assert promoted, "example must declare at least one server"
        for srv in promoted:
            assert srv.get("server_tools_guardrails_config") == expected
