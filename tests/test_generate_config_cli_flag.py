"""End-to-end test for ``secure-mcp-gateway generate-config --provider``.

Most of the contract is already covered in
``test_generate_enkrypt_cloud_config.py`` (the pure function) and
``test_example_enkrypt_cloud_config.py`` (the shipped example). What
this file exercises is the **argparse + dispatch glue**:

* ``--provider enkrypt`` writes the minimal cloud config to disk.
* ``--provider local_apikey`` writes the full local schema.
* Default (no flag) preserves the historical ``local_apikey`` shape so
  upgrading the package doesn't silently change what existing
  ``generate-config`` runs produce.

Because ``CONFIG_PATH`` is computed at import time from
``os.path.expanduser("~")``, we run the CLI in a **subprocess** with
``HOME``/``USERPROFILE`` redirected to a pytest ``tmp_path``. That way
each test has an isolated config directory and we don't risk
clobbering the developer's ``~/.enkrypt/enkrypt_mcp_config.json``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_generate_config(
    tmp_home: Path, *extra_args: str
) -> Tuple[subprocess.CompletedProcess[str], Path]:
    """Invoke ``python -m secure_mcp_gateway.cli generate-config ...``.

    Returns the completed process plus the path the CLI should have
    written its config to (``<tmp_home>/.enkrypt/enkrypt_mcp_config.json``).
    """
    env = os.environ.copy()
    # ``os.path.expanduser("~")`` on Windows checks ``USERPROFILE``
    # first, then ``HOMEDRIVE``+``HOMEPATH``. On POSIX it checks ``HOME``.
    # Setting all three keeps the test cross-platform with no branches.
    env["HOME"] = str(tmp_home)
    env["USERPROFILE"] = str(tmp_home)
    env["HOMEDRIVE"] = ""
    env["HOMEPATH"] = str(tmp_home)
    # Defensive: ``is_docker()`` short-circuits to a different path if any
    # docker env hints are set — strip them so the test always lands in
    # the user-home branch of ``PICKED_CONFIG_PATH``.
    for k in (
        "RUNNING_IN_DOCKER",
        "DOCKER_CONTAINER",
        "KUBERNETES_SERVICE_HOST",
    ):
        env.pop(k, None)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_mcp_gateway.cli",
            "generate-config",
            "--overwrite",
            *extra_args,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    expected_path = tmp_home / ".enkrypt" / "enkrypt_mcp_config.json"
    return proc, expected_path


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# --provider enkrypt
# ---------------------------------------------------------------------------


class TestEnkryptProviderFlag:
    """``--provider enkrypt`` produces the minimal cloud config."""

    @pytest.fixture(scope="class")
    def generated(self, tmp_path_factory) -> dict:
        # One-shot class-scoped run to keep the test suite fast — the
        # subprocess call is the slow part. Per-assertion tests then
        # share the result.
        tmp_home = tmp_path_factory.mktemp("enkrypt_home")
        proc, path = _run_generate_config(tmp_home, "--provider", "enkrypt")
        assert proc.returncode == 0, (
            f"CLI exited non-zero. stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert path.is_file(), f"CLI did not write config at expected path: {path}"
        return _load(path)

    def test_top_level_keys_match_minimal_shape(self, generated):
        assert set(generated.keys()) == {
            "enkrypt_config",
            "plugins",
            "common_mcp_gateway_config",
        }

    def test_no_cloud_owned_blocks_were_baked_in(self, generated):
        for blocked in ("mcp_configs", "projects", "users", "apikeys"):
            assert blocked not in generated, (
                f"--provider enkrypt must NOT emit {blocked!r} — cloud owns it"
            )

    def test_no_admin_apikey_baked_in(self, generated):
        # With provider=enkrypt the cloud api_key doubles as the admin
        # credential; a separate admin_apikey would defeat that
        # simplicity.
        assert "admin_apikey" not in generated

    def test_auth_provider_is_enkrypt(self, generated):
        assert generated["plugins"]["auth"]["provider"] == "enkrypt"

    def test_gateway_name_placeholder_is_present(self, generated):
        auth_cfg = generated["plugins"]["auth"]["config"]
        assert auth_cfg.get("gateway_name") == "your-gateway-saved-name"

    def test_matches_in_process_generator(self, generated):
        # The CLI's on-disk output and the in-process function must agree
        # — pins the dispatch glue against accidental mutation.
        from secure_mcp_gateway.cli import generate_enkrypt_cloud_config

        assert generated == generate_enkrypt_cloud_config()


# ---------------------------------------------------------------------------
# --provider local_apikey (and the default-when-flag-omitted)
# ---------------------------------------------------------------------------


class TestLocalApikeyProviderFlag:
    """Explicit and default invocations both produce the local schema."""

    @pytest.fixture(scope="class")
    def explicit(self, tmp_path_factory) -> dict:
        tmp_home = tmp_path_factory.mktemp("local_home_explicit")
        proc, path = _run_generate_config(tmp_home, "--provider", "local_apikey")
        assert proc.returncode == 0, (
            f"CLI exited non-zero. stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        return _load(path)

    @pytest.fixture(scope="class")
    def default(self, tmp_path_factory) -> dict:
        tmp_home = tmp_path_factory.mktemp("local_home_default")
        # No ``--provider`` flag at all — backward-compat path.
        proc, path = _run_generate_config(tmp_home)
        assert proc.returncode == 0, (
            f"CLI exited non-zero. stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        return _load(path)

    def test_explicit_local_emits_full_schema(self, explicit):
        # The full local schema has cloud-owned-equivalent blocks
        # populated locally (because local_apikey IS the local store).
        for required in ("mcp_configs", "projects", "users", "apikeys"):
            assert required in explicit

    def test_explicit_local_auth_provider_is_local_apikey(self, explicit):
        assert explicit["plugins"]["auth"]["provider"] == "local_apikey"

    def test_default_without_flag_matches_local_provider(self, default, explicit):
        # The default must not silently change shape across releases.
        # ``apikeys`` and friends contain random UUIDs so two
        # invocations don't dict-equal — but the SET of top-level keys
        # must match exactly.
        assert set(default.keys()) == set(explicit.keys())
        assert default["plugins"]["auth"]["provider"] == "local_apikey"

    def test_default_still_bakes_in_admin_apikey(self, default):
        # The historical local-provider config generates a random
        # admin_apikey — that behavior must NOT regress when the
        # cloud branch was added.
        assert "admin_apikey" in default
        assert isinstance(default["admin_apikey"], str)
        assert len(default["admin_apikey"]) > 40


# ---------------------------------------------------------------------------
# --provider validation
# ---------------------------------------------------------------------------


def test_invalid_provider_value_is_rejected(tmp_path: Path) -> None:
    # argparse ``choices`` enforces the allowed values. A typo (e.g.
    # ``--provider enkypt``) must exit non-zero with a helpful error
    # rather than silently writing the wrong config.
    proc, _ = _run_generate_config(tmp_path, "--provider", "encrypt-typo")
    assert proc.returncode != 0
    combined = (proc.stdout + proc.stderr).lower()
    assert "invalid choice" in combined or "--provider" in combined
