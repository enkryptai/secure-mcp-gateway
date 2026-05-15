"""Regression tests for the legacy remote-config-fetch cleanup.

Three fields used to live in ``common_mcp_gateway_config``:

    * ``enkrypt_use_remote_mcp_config``
    * ``enkrypt_remote_mcp_gateway_name``
    * ``enkrypt_remote_mcp_gateway_version``

They only drive the legacy ``LocalApiKeyProvider`` + ``/mcp-gateway/get-gateway``
remote-fetch code path. New deployments should use
``plugins.auth.provider = "enkrypt"`` (the ``EnkryptAuthProvider``)
which has its own cloud-config flow.

This module pins three guarantees so the fields can't sneak back into
the canonical surfaces:

1. ``consts.DEFAULT_COMMON_CONFIG`` does not contain them.
2. ``cli.generate_default_config()`` does not emit them.
3. The shipped ``example_enkrypt_mcp_config.json`` does not contain them
   in its ``common_mcp_gateway_config`` block.

The accessor functions in ``utils`` and the ``LocalApiKeyProvider``
constructor STILL accept the fields when explicitly set, for
backward-compat. Those code paths are intentionally not exercised here
— a separate test would be needed for that, and we don't want to
encourage new usage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

LEGACY_FIELDS = (
    "enkrypt_use_remote_mcp_config",
    "enkrypt_remote_mcp_gateway_name",
    "enkrypt_remote_mcp_gateway_version",
)


# ---------------------------------------------------------------------------
# consts.DEFAULT_COMMON_CONFIG
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("legacy_field", LEGACY_FIELDS)
def test_default_common_config_omits_legacy_field(legacy_field: str) -> None:
    from secure_mcp_gateway.consts import DEFAULT_COMMON_CONFIG

    assert legacy_field not in DEFAULT_COMMON_CONFIG, (
        f"{legacy_field} is deprecated and must not appear in "
        f"DEFAULT_COMMON_CONFIG — putting it back would silently re-enable "
        f"the legacy LocalApiKeyProvider remote-fetch path for every newly-"
        f"loaded config."
    )


# ---------------------------------------------------------------------------
# cli.generate_default_config()
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def generated_config() -> Dict[str, Any]:
    from secure_mcp_gateway.cli import generate_default_config

    return generate_default_config()


@pytest.mark.parametrize("legacy_field", LEGACY_FIELDS)
def test_generated_default_config_omits_legacy_field(
    generated_config: Dict[str, Any], legacy_field: str
) -> None:
    common = generated_config.get("common_mcp_gateway_config", {})
    assert legacy_field not in common, (
        f"`secure-mcp-gateway generate-config` must not emit {legacy_field} "
        f"into newly created configs. New users would otherwise inherit a "
        f"deprecated knob with confusing semantics."
    )


def test_generated_default_config_still_has_non_legacy_fields(
    generated_config: Dict[str, Any],
) -> None:
    """Sanity check: the cleanup removed only the legacy fields, not the
    surrounding ``common_mcp_gateway_config`` block.
    """
    common = generated_config.get("common_mcp_gateway_config", {})
    for required in (
        "enkrypt_log_level",
        "enkrypt_mcp_use_external_cache",
        "enkrypt_gateway_cache_expiration_minutes",
        "timeout_settings",
    ):
        assert required in common, (
            f"Cleanup must not have nuked {required!r} from "
            f"common_mcp_gateway_config."
        )


# ---------------------------------------------------------------------------
# Full example file (example_enkrypt_mcp_config.json)
# ---------------------------------------------------------------------------


EXAMPLE_FULL_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "secure_mcp_gateway"
    / "example_enkrypt_mcp_config.json"
)


@pytest.fixture(scope="module")
def example_full() -> Dict[str, Any]:
    return json.loads(EXAMPLE_FULL_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("legacy_field", LEGACY_FIELDS)
def test_full_example_omits_legacy_field_in_common(
    example_full: Dict[str, Any], legacy_field: str
) -> None:
    common = example_full.get("common_mcp_gateway_config", {})
    assert legacy_field not in common, (
        f"{legacy_field} should not appear in example_enkrypt_mcp_config.json. "
        f"That example is what users copy when they want the full reference "
        f"schema — keeping a deprecated knob visible there teaches new users "
        f"to use it."
    )


def test_full_example_has_deprecation_note(example_full: Dict[str, Any]) -> None:
    """The example documents WHY the legacy fields were removed so any
    operator who was previously using them knows what to do.
    """
    assert "_doc_legacy_local_apikey_remote_fetch" in example_full, (
        "Removing the legacy fields without a forwarding pointer in the "
        "example would leave operators silently puzzled."
    )
