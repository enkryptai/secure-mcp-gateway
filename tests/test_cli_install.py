"""Tests for the provider-aware ``secure-mcp-gateway install`` flow.

Covers the two pieces that were added to fix the
``ENKRYPT_GATEWAY_KEY -> 401`` debugging session:

  * ``cli.get_install_credentials`` — branches on
    ``plugins.auth.provider`` to emit the correct credential shape
    (single ``apikey`` for cloud, legacy triple for local).
  * ``AuthConfigManager.extract_credentials`` — picks up the cloud-mode
    ``ENKRYPT_APIKEY`` env var that the new install path emits, in
    addition to the legacy ``ENKRYPT_GATEWAY_KEY``.

Tests deliberately avoid spawning the gateway or hitting the cloud — they
build minimal config dicts on disk and inspect the credential payloads
the install path would write into ``mcp.json`` /
``claude_desktop_config.json``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest


# ---------------------------------------------------------------------------
# get_install_credentials — provider branching
# ---------------------------------------------------------------------------


def _write_config(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_install_credentials_enkrypt_provider_uses_cli_apikey(tmp_path: Path) -> None:
    """Cloud auth + ``--apikey CLI_KEY`` -> single env/header entry, CLI wins."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {
            "plugins": {
                "auth": {
                    "provider": "enkrypt",
                    "config": {
                        "apikey": "from-config-file",
                        "gateway_name": "g",
                        "gateway_version": "v1",
                        "project_name": "p",
                        "base_url": "https://api.dev.enkryptai.com",
                    },
                }
            }
        },
    )

    result = get_install_credentials(str(cfg), override_apikey="from-cli-flag")

    assert result["provider"] == "enkrypt"
    assert result["env"] == {"ENKRYPT_APIKEY": "from-cli-flag"}
    assert result["headers"] == {"apikey": "from-cli-flag"}
    # Local-only keys must not leak into either payload.
    for k in ("ENKRYPT_GATEWAY_KEY", "ENKRYPT_PROJECT_ID", "ENKRYPT_USER_ID"):
        assert k not in result["env"]
    for k in ("ENKRYPT_GATEWAY_KEY", "project_id", "user_id"):
        assert k not in result["headers"]


def test_install_credentials_enkrypt_provider_falls_back_to_config_apikey(
    tmp_path: Path,
) -> None:
    """Cloud auth without ``--apikey`` falls back to ``auth.config.apikey``."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {
            "plugins": {
                "auth": {
                    "provider": "enkrypt",
                    "config": {"apikey": "from-config-file"},
                }
            }
        },
    )

    result = get_install_credentials(str(cfg), override_apikey=None)

    assert result["env"] == {"ENKRYPT_APIKEY": "from-config-file"}
    assert result["headers"] == {"apikey": "from-config-file"}


def test_install_credentials_enkrypt_provider_raises_when_no_apikey(
    tmp_path: Path,
) -> None:
    """No ``--apikey`` and no ``auth.config.apikey`` -> ValueError with hint."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {"plugins": {"auth": {"provider": "enkrypt", "config": {}}}},
    )

    with pytest.raises(ValueError) as exc:
        get_install_credentials(str(cfg), override_apikey=None)
    msg = str(exc.value)
    assert "auth.provider is 'enkrypt'" in msg
    assert "--apikey" in msg


def test_install_credentials_local_apikey_provider_emits_legacy_triple(
    tmp_path: Path,
) -> None:
    """Local mode keeps the historical 3-env-var install shape unchanged."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {
            "plugins": {"auth": {"provider": "local_apikey"}},
            "apikeys": {
                "GATEWAY_KEY_VALUE": {
                    "project_id": "PROJ_UUID",
                    "user_id": "USER_UUID",
                }
            },
            "projects": {
                "PROJ_UUID": {
                    "project_name": "default",
                    "mcp_configs": [{"mcp_config_id": "MCP_CFG_ID"}],
                }
            },
        },
    )

    result = get_install_credentials(str(cfg), override_apikey=None)

    assert result["provider"] == "local_apikey"
    assert result["env"] == {
        "ENKRYPT_GATEWAY_KEY": "GATEWAY_KEY_VALUE",
        "ENKRYPT_PROJECT_ID": "PROJ_UUID",
        "ENKRYPT_USER_ID": "USER_UUID",
    }
    assert result["headers"] == {
        "ENKRYPT_GATEWAY_KEY": "GATEWAY_KEY_VALUE",
        "project_id": "PROJ_UUID",
        "user_id": "USER_UUID",
    }
    # ENKRYPT_APIKEY must NOT appear in local-mode installs — it would
    # confuse extract_credentials' fallback chain.
    assert "ENKRYPT_APIKEY" not in result["env"]
    assert "apikey" not in result["headers"]


def test_install_credentials_local_apikey_apikey_flag_is_ignored(
    tmp_path: Path,
) -> None:
    """``--apikey`` is a cloud-mode flag — local mode ignores it silently."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {
            "plugins": {"auth": {"provider": "local_apikey"}},
            "apikeys": {
                "GATEWAY_KEY_VALUE": {
                    "project_id": "PROJ_UUID",
                    "user_id": "USER_UUID",
                }
            },
            "projects": {
                "PROJ_UUID": {
                    "project_name": "default",
                    "mcp_configs": [{"mcp_config_id": "MCP_CFG_ID"}],
                }
            },
        },
    )

    result = get_install_credentials(
        str(cfg), override_apikey="should-be-ignored-in-local-mode"
    )

    assert result["env"]["ENKRYPT_GATEWAY_KEY"] == "GATEWAY_KEY_VALUE"
    assert "ENKRYPT_APIKEY" not in result["env"]


def test_install_credentials_default_provider_is_local_apikey(tmp_path: Path) -> None:
    """Missing ``plugins.auth.provider`` -> default to local_apikey behaviour."""
    from secure_mcp_gateway.cli import get_install_credentials

    cfg = tmp_path / "config.json"
    _write_config(
        cfg,
        {
            "apikeys": {"K": {"project_id": "P", "user_id": "U"}},
            "projects": {"P": {"project_name": "default", "mcp_configs": []}},
        },
    )
    result = get_install_credentials(str(cfg), override_apikey=None)
    assert result["provider"] == "local_apikey"


# ---------------------------------------------------------------------------
# extract_credentials — env-var fallback
# ---------------------------------------------------------------------------


def test_extract_credentials_reads_enkrypt_apikey_env(monkeypatch) -> None:
    """The new ENKRYPT_APIKEY env var feeds gateway_key when no header is sent.

    This is the contract that lets cloud-mode stdio installs work: the
    install command writes ``ENKRYPT_APIKEY=<key>``, the gateway picks it
    up here, and ``EnkryptAuthProvider`` forwards it as the ``apikey``
    header on its outbound cloud call.
    """
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    for var in (
        "ENKRYPT_APIKEY",
        "ENKRYPT_GATEWAY_KEY",
        "ENKRYPT_PROJECT_ID",
        "ENKRYPT_USER_ID",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ENKRYPT_APIKEY", "cloud-key-from-env")

    mgr = AuthConfigManager()
    creds = mgr.extract_credentials(ctx=None)

    assert creds.gateway_key == "cloud-key-from-env"
    assert creds.api_key == "cloud-key-from-env"


def test_extract_credentials_apikey_takes_priority_over_legacy_env(
    monkeypatch,
) -> None:
    """If both env vars are set, the new ENKRYPT_APIKEY wins.

    Rationale: the new var is provider-aware (cloud-mode installs only
    emit it) while the legacy var is ambient (could leak in from a
    previous local-mode install or shell session).
    """
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    monkeypatch.setenv("ENKRYPT_APIKEY", "cloud-key")
    monkeypatch.setenv("ENKRYPT_GATEWAY_KEY", "legacy-key")
    monkeypatch.delenv("ENKRYPT_PROJECT_ID", raising=False)
    monkeypatch.delenv("ENKRYPT_USER_ID", raising=False)

    mgr = AuthConfigManager()
    creds = mgr.extract_credentials(ctx=None)
    assert creds.gateway_key == "cloud-key"


def test_extract_credentials_legacy_env_still_works(monkeypatch) -> None:
    """Local-mode installs (legacy env vars only) keep working unchanged."""
    from secure_mcp_gateway.plugins.auth.config_manager import AuthConfigManager

    monkeypatch.delenv("ENKRYPT_APIKEY", raising=False)
    monkeypatch.setenv("ENKRYPT_GATEWAY_KEY", "legacy-gateway-key")
    monkeypatch.setenv("ENKRYPT_PROJECT_ID", "PROJ")
    monkeypatch.setenv("ENKRYPT_USER_ID", "USER")

    mgr = AuthConfigManager()
    creds = mgr.extract_credentials(ctx=None)
    assert creds.gateway_key == "legacy-gateway-key"
    assert creds.project_id == "PROJ"
    assert creds.user_id == "USER"
    # api_key stays None because ENKRYPT_APIKEY isn't set — that's correct.
    assert creds.api_key is None
