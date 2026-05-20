"""Tests for :py:meth:`LocalApiKeyProvider._apply_common_overrides`.

The local-API-key auth provider must mirror the cloud-auth contract for
``server_tools_guardrails_config``: the field lives ONLY in
``mcp_configs.<id>.common_overrides`` and gets *promoted* onto every
server entry before the server list leaves the provider. The rest of the
gateway (``discovery_service``, ``secure_tool_execution_service``, etc.)
then reads ``server_info["server_tools_guardrails_config"]`` exactly as
it does for the cloud path — no call-site changes were required.

These tests pin the contract end-to-end at the seam where promotion
happens:

- Common value wins over a stale per-server value (common-wins semantics).
- Common alone is copied onto every server.
- Per-server alone is honored for back-compat *with a logged warning*.
- ``input_guardrails_config`` and ``output_guardrails_config`` are
  intentionally NOT promoted (per-server policies are a legitimate use
  case and must not be silently overwritten by a common slot).
- The original ``mcp_config_entry`` is never mutated (defensive copy on
  every promoted server).
- Non-dict entries are passed through untouched (defensive against
  malformed configs).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

import pytest

from secure_mcp_gateway.plugins.auth.local_apikey_provider import LocalApiKeyProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stg(enabled: bool, name: str = "Test Guard") -> Dict[str, Any]:
    """Build a representative server_tools_guardrails_config block."""
    return {
        "enabled": enabled,
        "guardrail_name": name,
        "block": ["policy_violation", "injection_attack"],
    }


def _entry(
    *,
    servers: List[Dict[str, Any]],
    common: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build a synthetic mcp_config_entry matching the on-disk shape."""
    out: Dict[str, Any] = {
        "mcp_config_name": "test_cfg",
        "mcp_config": servers,
    }
    if common is not None:
        out["common_overrides"] = common
    return out


# ---------------------------------------------------------------------------
# Common-only path (the new canonical shape)
# ---------------------------------------------------------------------------


class TestCommonOnlyPath:
    """common_overrides is set, server entries are clean → fan-out."""

    def test_promotes_to_every_server(self):
        entry = _entry(
            servers=[{"server_name": "a"}, {"server_name": "b"}, {"server_name": "c"}],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert len(result) == 3
        for srv in result:
            assert srv["server_tools_guardrails_config"] == _stg(True)

    def test_disabled_common_is_still_promoted(self):
        # The whole point of the common slot is that 'enabled: false' is
        # the explicit-off signal, not the absence of the key. Promote it.
        entry = _entry(
            servers=[{"server_name": "a"}],
            common={"server_tools_guardrails_config": _stg(False)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result[0]["server_tools_guardrails_config"]["enabled"] is False

    def test_empty_server_list_is_fine(self):
        entry = _entry(
            servers=[],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result == []

    def test_other_server_keys_are_preserved(self):
        entry = _entry(
            servers=[
                {
                    "server_name": "echo",
                    "description": "Echo server",
                    "config": {"command": "python"},
                    "input_guardrails_config": {"enabled": True},
                    "output_guardrails_config": {"enabled": False},
                }
            ],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        srv = result[0]
        assert srv["server_name"] == "echo"
        assert srv["description"] == "Echo server"
        assert srv["config"] == {"command": "python"}
        # Per-server input/output policies MUST survive promotion.
        assert srv["input_guardrails_config"] == {"enabled": True}
        assert srv["output_guardrails_config"] == {"enabled": False}


# ---------------------------------------------------------------------------
# Common-wins semantics (stale per-server values)
# ---------------------------------------------------------------------------


class TestCommonWinsOverStalePerServer:
    """If common AND per-server both present, common always wins."""

    def test_common_overrides_per_server_value(self):
        entry = _entry(
            servers=[
                {
                    "server_name": "a",
                    "server_tools_guardrails_config": _stg(False, name="Stale"),
                }
            ],
            common={"server_tools_guardrails_config": _stg(True, name="Fresh")},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result[0]["server_tools_guardrails_config"]["enabled"] is True
        assert result[0]["server_tools_guardrails_config"]["guardrail_name"] == "Fresh"

    def test_common_wins_even_when_per_server_is_more_permissive(self):
        # Defense-in-depth: a stale 'enabled: true' per-server value
        # must not survive when the common slot says 'enabled: false'.
        entry = _entry(
            servers=[
                {
                    "server_name": "a",
                    "server_tools_guardrails_config": _stg(True),
                }
            ],
            common={"server_tools_guardrails_config": _stg(False)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result[0]["server_tools_guardrails_config"]["enabled"] is False


# ---------------------------------------------------------------------------
# Per-server-only path (legacy, back-compat with warning)
# ---------------------------------------------------------------------------


class TestLegacyPerServerOnlyPath:
    """No common slot but per-server values present → honored + warning."""

    def test_per_server_is_left_untouched(self):
        entry = _entry(
            servers=[
                {
                    "server_name": "a",
                    "server_tools_guardrails_config": _stg(True),
                },
                {"server_name": "b"},
            ],
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        # Legacy value still wins for back-compat (we only WARN, not strip).
        assert result[0]["server_tools_guardrails_config"]["enabled"] is True
        # Servers without the legacy value stay clean (no synthesized default).
        assert "server_tools_guardrails_config" not in result[1]

    @staticmethod
    def _patch_logger(monkeypatch) -> List[str]:
        """Capture ``logger.warning`` calls at the source.

        The gateway uses ``structlog`` which routes records differently
        depending on telemetry-init state — sometimes to stdout via a
        console renderer, sometimes through stdlib to pytest's caplog
        handler. To stay independent of routing, we patch the
        ``warning`` attribute on the module-level logger directly and
        record every call to a local list.
        """
        from secure_mcp_gateway.plugins.auth import local_apikey_provider as mod

        captured: List[str] = []

        def _record(msg: str, *args: Any, **kwargs: Any) -> None:
            try:
                rendered = msg % args if args else msg
            except (TypeError, ValueError):
                rendered = f"{msg} | args={args}"
            captured.append(rendered)

        monkeypatch.setattr(mod.logger, "warning", _record, raising=False)
        return captured

    def test_per_server_only_logs_deprecation_warning(self, monkeypatch):
        captured = self._patch_logger(monkeypatch)

        entry = _entry(
            servers=[
                {
                    "server_name": "echo_server",
                    "server_tools_guardrails_config": _stg(True),
                }
            ],
        )
        LocalApiKeyProvider._apply_common_overrides(entry)

        joined = "\n".join(captured).lower()
        assert "server_tools_guardrails_config" in joined, (
            f"Expected a deprecation warning. Captured: {captured!r}"
        )
        assert "common-only" in joined
        # The warning should name the offending server so operators can find it.
        assert "echo_server" in joined

    def test_clean_servers_with_no_common_no_warning(self, monkeypatch):
        captured = self._patch_logger(monkeypatch)

        entry = _entry(
            servers=[{"server_name": "a"}, {"server_name": "b"}],
        )
        LocalApiKeyProvider._apply_common_overrides(entry)

        assert not any(
            "server_tools_guardrails_config" in c.lower() for c in captured
        ), f"Unexpected warning(s): {captured!r}"


# ---------------------------------------------------------------------------
# What MUST NOT be promoted (Flavor 1 boundary)
# ---------------------------------------------------------------------------


class TestNonPromotedKeys:
    """input/output guardrail policies remain per-server, never promoted."""

    def test_common_input_guardrails_is_ignored(self):
        # Even if someone puts input_guardrails_config under common_overrides,
        # we do NOT fan it out — different servers legitimately need
        # different input policies.
        entry = _entry(
            servers=[{"server_name": "a"}],
            common={
                "server_tools_guardrails_config": _stg(True),
                "input_guardrails_config": {"enabled": True, "block": ["pii"]},
            },
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert "input_guardrails_config" not in result[0]

    def test_common_output_guardrails_is_ignored(self):
        entry = _entry(
            servers=[{"server_name": "a"}],
            common={
                "server_tools_guardrails_config": _stg(True),
                "output_guardrails_config": {"enabled": True, "block": ["pii"]},
            },
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert "output_guardrails_config" not in result[0]

    def test_per_server_input_output_survive_promotion(self):
        entry = _entry(
            servers=[
                {
                    "server_name": "a",
                    "input_guardrails_config": {"enabled": True, "tag": "in"},
                    "output_guardrails_config": {"enabled": True, "tag": "out"},
                }
            ],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result[0]["input_guardrails_config"] == {"enabled": True, "tag": "in"}
        assert result[0]["output_guardrails_config"] == {"enabled": True, "tag": "out"}


# ---------------------------------------------------------------------------
# Mutation safety (defensive copy)
# ---------------------------------------------------------------------------


class TestMutationSafety:
    """Promotion must never mutate the caller's mcp_config_entry."""

    def test_original_entry_is_unchanged(self):
        entry = _entry(
            servers=[{"server_name": "a"}],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        snapshot = copy.deepcopy(entry)
        LocalApiKeyProvider._apply_common_overrides(entry)
        assert entry == snapshot, "input mcp_config_entry was mutated"

    def test_returned_servers_are_independent_copies(self):
        original_servers = [{"server_name": "a"}]
        entry = _entry(
            servers=original_servers,
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        # Mutating result must not bleed back into the source list.
        result[0]["server_tools_guardrails_config"]["enabled"] = False
        assert "server_tools_guardrails_config" not in original_servers[0]

    def test_repeated_calls_are_idempotent(self):
        # Re-running on the SAME entry many times should keep producing
        # the same result and never accumulate state on the entry.
        entry = _entry(
            servers=[{"server_name": "a"}],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        snapshot = copy.deepcopy(entry)
        r1 = LocalApiKeyProvider._apply_common_overrides(entry)
        r2 = LocalApiKeyProvider._apply_common_overrides(entry)
        assert r1 == r2
        assert entry == snapshot


# ---------------------------------------------------------------------------
# Robustness against malformed configs
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_missing_mcp_config_key(self):
        # An entry without 'mcp_config' must not crash — return [].
        result = LocalApiKeyProvider._apply_common_overrides(
            {"mcp_config_name": "x", "common_overrides": {"server_tools_guardrails_config": _stg(True)}}
        )
        assert result == []

    def test_non_dict_server_passes_through(self):
        # If someone wedges a non-dict into the server list, we shouldn't
        # blow up — we just leave it alone and promote where we can.
        entry = _entry(
            servers=[{"server_name": "a"}, "not-a-dict", 42, None],
            common={"server_tools_guardrails_config": _stg(True)},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result[0]["server_tools_guardrails_config"] == _stg(True)
        assert result[1] == "not-a-dict"
        assert result[2] == 42
        assert result[3] is None

    def test_empty_common_overrides_is_a_no_op(self):
        entry = _entry(
            servers=[{"server_name": "a", "x": 1}],
            common={},
        )
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result == [{"server_name": "a", "x": 1}]

    def test_null_common_overrides_is_a_no_op(self):
        # Some operators may write "common_overrides": null in JSON.
        entry = {
            "mcp_config_name": "x",
            "common_overrides": None,
            "mcp_config": [{"server_name": "a"}],
        }
        result = LocalApiKeyProvider._apply_common_overrides(entry)
        assert result == [{"server_name": "a"}]


# ---------------------------------------------------------------------------
# Live shape: assert generate_default_config + provider stay in sync
# ---------------------------------------------------------------------------


class TestGeneratedConfigSurvivesPromotion:
    """End-to-end-ish: take the CLI's default config and promote it.

    Pins that the *generator* and the *consumer* speak the same dialect.
    If anyone moves server_tools_guardrails_config out of common_overrides
    in cli.generate_default_config (or moves it back onto a per-server
    entry), this test fails loudly.
    """

    def test_default_config_promotes_cleanly(self):
        pytest.importorskip("secure_mcp_gateway.cli")
        from secure_mcp_gateway.cli import generate_default_config

        cfg = generate_default_config()
        mc_id = next(iter(cfg["mcp_configs"]))
        entry = cfg["mcp_configs"][mc_id]

        assert "common_overrides" in entry, (
            "generate_default_config must emit common_overrides "
            "alongside mcp_config"
        )
        assert "server_tools_guardrails_config" in entry["common_overrides"]

        # No per-server STG should sneak into the defaults.
        for srv in entry["mcp_config"]:
            assert "server_tools_guardrails_config" not in srv

        promoted = LocalApiKeyProvider._apply_common_overrides(entry)
        for srv in promoted:
            assert (
                srv["server_tools_guardrails_config"]
                == entry["common_overrides"]["server_tools_guardrails_config"]
            )


# ---------------------------------------------------------------------------
# Signature parity with EnkryptAuthProvider
# ---------------------------------------------------------------------------


def test_get_local_config_accepts_gateway_name_kwarg() -> None:
    """``AuthConfigManager.get_local_mcp_config`` forwards ``gateway_name=``
    unconditionally to whichever provider is active. The local provider has
    no use for the value, but it must accept the kwarg — without that
    parity, every call site (``build_log_extra``, discovery, listing,
    secure-call-tools) hits ``TypeError: unexpected keyword argument
    'gateway_name'`` and ``build_log_extra`` silently swallows it, leaving
    ``email`` / ``project_name`` / identity attrs stuck at ``not_provided``
    on every log line, span, and metric for local-apikey deployments.
    """
    import inspect

    sig = inspect.signature(LocalApiKeyProvider._get_local_config)
    assert "gateway_name" in sig.parameters, (
        "LocalApiKeyProvider._get_local_config must accept ``gateway_name`` for "
        "signature parity with EnkryptAuthProvider — see "
        "AuthConfigManager.get_local_mcp_config which forwards it."
    )
