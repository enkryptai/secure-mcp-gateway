"""Tests for remote-gateway OAuth redirect-URI resolution.

These cover the feature that lets a *remotely deployed* gateway (e.g.
``https://mcp.dev.enkryptai.com``) advertise its own public OAuth callback to
the IdP instead of the local ``http://localhost`` loopback:

  * ``utils.get_gateway_base_url`` / ``utils.get_gateway_oauth_redirect_uri``
    read the new ``ENKRYPT_GATEWAY_BASE_URL`` env / ``enkrypt_gateway_base_url``
    config (and the explicit ``ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI`` override).
  * ``gateway_oauth_routes.begin_authorization`` resolves the redirect with the
    priority: explicit oauth_config > configured public URL > keyfile loopback.
  * ``gateway_oauth_routes._request_derived_redirect`` honors X-Forwarded-* so a
    TLS-terminating ingress still yields an https:// public callback.

All cases are offline (PKCE auth-URL generation does no network I/O) and never
open a browser (``open_browser=False``).
"""

from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def tmp_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate get_common_config() on a minimal temp config with no public URL,
    and clear any ENKRYPT_GATEWAY_* env leaking from the host."""
    cfg = tmp_path / "enkrypt_mcp_config.json"
    cfg.write_text(
        json.dumps(
            {
                "common_mcp_gateway_config": {
                    "enkrypt_log_level": "INFO",
                    "enkrypt_config_watcher_poll_seconds": 0,
                },
                "plugins": {
                    "auth": {"provider": "local_apikey", "config": {}},
                    "guardrails": {"provider": "enkrypt", "config": {}},
                    "telemetry": {"provider": "stdout", "config": {}},
                },
                "mcp_configs": {},
                "projects": {},
                "users": {},
                "apikeys": {},
            }
        ),
        encoding="utf-8",
    )
    from secure_mcp_gateway import consts, utils

    monkeypatch.setattr(consts, "CONFIG_PATH", str(cfg), raising=False)
    monkeypatch.setattr(utils, "CONFIG_PATH", str(cfg), raising=False)
    monkeypatch.delenv("ENKRYPT_GATEWAY_BASE_URL", raising=False)
    monkeypatch.delenv("ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI", raising=False)
    utils.clear_config_cache()
    yield cfg
    utils.clear_config_cache()


def _set_config_base_url(cfg: Path, base_url: str) -> None:
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data["common_mcp_gateway_config"]["enkrypt_gateway_base_url"] = base_url
    cfg.write_text(json.dumps(data), encoding="utf-8")
    t = time.time() + 2.0  # bump mtime so the hot-reload picks it up
    os.utime(str(cfg), (t, t))
    from secure_mcp_gateway import utils

    utils.clear_config_cache()


def _server_entry(
    tmp_path: Path, *, with_keyfile: bool, oauth_overrides: dict | None = None
) -> dict:
    """A google_sheets-shaped stdio server entry; optionally with a mounted
    gcp-oauth.keys.json carrying a localhost loopback redirect."""
    js = tmp_path / "index.js"
    js.write_text("// test entrypoint", encoding="utf-8")
    entry = {
        "server_name": "google_sheets",
        "config": {"command": "node", "args": [str(js)]},
        "oauth_config": {
            "enabled": True,
            "OAUTH_GRANT_TYPE": "authorization_code",
            "OAUTH_TOKEN_URL": "https://oauth2.googleapis.com/token",
            "OAUTH_AUTHORIZATION_URL": "https://accounts.google.com/o/oauth2/v2/auth",
            "OAUTH_SCOPE": "https://www.googleapis.com/auth/spreadsheets",
        },
    }
    if oauth_overrides:
        entry["oauth_config"].update(oauth_overrides)
    if with_keyfile:
        keyfile = tmp_path / "gcp-oauth.keys.json"
        keyfile.write_text(
            json.dumps(
                {
                    "web": {
                        "client_id": "test-client-id.apps.googleusercontent.com",
                        "client_secret": "test-secret",
                        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["http://localhost:3000/oauth2callback"],
                    }
                }
            ),
            encoding="utf-8",
        )
    else:
        # No keyfile to read client_id from -> supply it inline.
        entry["oauth_config"]["OAUTH_CLIENT_ID"] = (
            "test-client-id.apps.googleusercontent.com"
        )
    return entry


# ---------------------------------------------------------------------------
# Accessor tests
# ---------------------------------------------------------------------------
def test_base_url_and_redirect_from_env(tmp_config, monkeypatch):
    from secure_mcp_gateway import utils

    # Trailing slash and path must be stripped down to scheme+host.
    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://mcp.dev.enkryptai.com/")
    utils.clear_config_cache()

    assert utils.get_gateway_base_url() == "https://mcp.dev.enkryptai.com"
    assert (
        utils.get_gateway_oauth_redirect_uri()
        == "https://mcp.dev.enkryptai.com/oauth2callback"
    )


def test_redirect_from_config_file(tmp_config):
    from secure_mcp_gateway import utils

    _set_config_base_url(tmp_config, "https://gw.example.com")
    assert (
        utils.get_gateway_oauth_redirect_uri()
        == "https://gw.example.com/oauth2callback"
    )


def test_env_overrides_config(tmp_config, monkeypatch):
    from secure_mcp_gateway import utils

    _set_config_base_url(tmp_config, "https://from-config.example.com")
    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://from-env.example.com")
    utils.clear_config_cache()
    assert utils.get_gateway_base_url() == "https://from-env.example.com"


def test_explicit_redirect_uri_wins_over_base_url(tmp_config, monkeypatch):
    from secure_mcp_gateway import utils

    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://gw.example.com")
    monkeypatch.setenv(
        "ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI", "https://gw.example.com/custom/cb"
    )
    utils.clear_config_cache()
    assert utils.get_gateway_oauth_redirect_uri() == "https://gw.example.com/custom/cb"


def test_unset_returns_none(tmp_config):
    from secure_mcp_gateway import utils

    assert utils.get_gateway_base_url() is None
    assert utils.get_gateway_oauth_redirect_uri() is None


# ---------------------------------------------------------------------------
# begin_authorization() resolution-priority tests
# ---------------------------------------------------------------------------
async def test_begin_auth_prefers_configured_public_url_over_keyfile(
    tmp_path, tmp_config, monkeypatch
):
    from secure_mcp_gateway import utils
    from secure_mcp_gateway.gateway_oauth_routes import begin_authorization

    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://mcp.dev.enkryptai.com")
    utils.clear_config_cache()

    entry = _server_entry(tmp_path, with_keyfile=True)
    res = await begin_authorization("google_sheets", entry, {}, open_browser=False)

    assert res["status"] == "ok", res
    assert res["redirect_uri"] == "https://mcp.dev.enkryptai.com/oauth2callback"
    assert res["browser_opened"] is False
    # The redirect_uri must be reflected (url-encoded) in the auth URL.
    assert (
        "redirect_uri=https%3A%2F%2Fmcp.dev.enkryptai.com%2Foauth2callback"
        in res["auth_url"]
    )


async def test_begin_auth_falls_back_to_keyfile_loopback(tmp_path, tmp_config):
    from secure_mcp_gateway.gateway_oauth_routes import begin_authorization

    # No public URL configured -> local-install behavior is unchanged.
    entry = _server_entry(tmp_path, with_keyfile=True)
    res = await begin_authorization("google_sheets", entry, {}, open_browser=False)

    assert res["status"] == "ok", res
    assert res["redirect_uri"] == "http://localhost:3000/oauth2callback"


async def test_begin_auth_explicit_override_wins(tmp_path, tmp_config, monkeypatch):
    from secure_mcp_gateway import utils
    from secure_mcp_gateway.gateway_oauth_routes import begin_authorization

    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://mcp.dev.enkryptai.com")
    utils.clear_config_cache()

    entry = _server_entry(
        tmp_path,
        with_keyfile=True,
        oauth_overrides={"OAUTH_REDIRECT_URI": "https://explicit.example.com/cb"},
    )
    res = await begin_authorization("google_sheets", entry, {}, open_browser=False)

    assert res["status"] == "ok", res
    assert res["redirect_uri"] == "https://explicit.example.com/cb"


async def test_begin_auth_body_override_redirect_wins(
    tmp_path, tmp_config, monkeypatch
):
    from secure_mcp_gateway import utils
    from secure_mcp_gateway.gateway_oauth_routes import begin_authorization

    monkeypatch.setenv("ENKRYPT_GATEWAY_BASE_URL", "https://mcp.dev.enkryptai.com")
    utils.clear_config_cache()

    entry = _server_entry(tmp_path, with_keyfile=True)
    res = await begin_authorization(
        "google_sheets",
        entry,
        {},
        body_overrides={"OAUTH_REDIRECT_URI": "https://body.example.com/cb"},
        open_browser=False,
    )
    assert res["redirect_uri"] == "https://body.example.com/cb"


# ---------------------------------------------------------------------------
# _request_derived_redirect() (last-resort fallback)
# ---------------------------------------------------------------------------
class _FakeURL:
    scheme = "http"
    netloc = "10.0.0.5:8000"


class _FakeRequest:
    def __init__(self, headers: dict):
        self.headers = headers
        self.url = _FakeURL()

    @property
    def base_url(self):
        return "http://10.0.0.5:8000/"


def test_request_derived_redirect_honors_forwarded_headers():
    from secure_mcp_gateway.gateway_oauth_routes import _request_derived_redirect

    req = _FakeRequest(
        {
            "x-forwarded-proto": "https",
            "x-forwarded-host": "mcp.dev.enkryptai.com",
            "host": "10.0.0.5:8000",
        }
    )
    assert (
        _request_derived_redirect(req) == "https://mcp.dev.enkryptai.com/oauth2callback"
    )


def test_request_derived_redirect_uses_host_when_no_forwarded():
    from secure_mcp_gateway.gateway_oauth_routes import _request_derived_redirect

    req = _FakeRequest({"host": "gw.example.com"})
    assert _request_derived_redirect(req) == "http://gw.example.com/oauth2callback"


# ---------------------------------------------------------------------------
# Multiple callback paths (_resolve_callback_paths)
# ---------------------------------------------------------------------------
def test_callback_paths_include_well_known_aliases():
    from secure_mcp_gateway.gateway_oauth_routes import _resolve_callback_paths

    paths = _resolve_callback_paths(None)
    # Canonical default first, plus the common aliases.
    assert paths[0] == "/oauth2callback"
    for alias in ("/oauth/callback", "/oauth2/callback", "/callback", "/auth/callback"):
        assert alias in paths
    # No duplicates.
    assert len(paths) == len(set(paths))


def test_callback_paths_standard_redirect_adds_nothing_extra():
    from secure_mcp_gateway.gateway_oauth_routes import _resolve_callback_paths

    base = _resolve_callback_paths(None)
    # A configured redirect whose path is already a well-known alias.
    same = _resolve_callback_paths("https://mcp.dev.enkryptai.com/oauth2callback")
    assert same == base


def test_callback_paths_custom_redirect_path_is_served():
    from secure_mcp_gateway.gateway_oauth_routes import _resolve_callback_paths

    # A custom redirect path must be added so the advertised URI is served.
    paths = _resolve_callback_paths("https://gw.example.com/sso/oauth/return")
    assert "/sso/oauth/return" in paths


def test_callback_paths_root_only_redirect_not_duplicated():
    from secure_mcp_gateway.gateway_oauth_routes import _resolve_callback_paths

    # A bare base URL (path "/") is handled by the separate root route, not here.
    paths = _resolve_callback_paths("https://gw.example.com/")
    assert "/" not in paths
