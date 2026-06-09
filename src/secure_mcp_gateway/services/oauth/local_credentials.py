"""Materialize local OAuth credential FILES for stdio MCP servers that manage
their own provider login but cannot run a browser flow inside a container.

Some local stdio MCP servers (notably ``mkummer225/google-sheets-mcp``) run the
Google OAuth flow *themselves* at startup using ``@google-cloud/local-auth``:
they open a browser, bind an ephemeral ``localhost`` redirect server, exchange
the code, and persist a credentials file. On the next start, if that file
exists, they load it and never open a browser again.

That self-driven flow is impossible when the gateway runs inside Docker (no
browser, ephemeral redirect port unreachable from the host). Such servers also
ignore an injected ``ENKRYPT_ACCESS_TOKEN`` / ``Authorization`` env var, so the
gateway's normal env-injection OAuth path does not help them.

This module implements the alternative: the gateway runs the authorization-code
+ PKCE flow itself (via ``gateway_oauth_routes``) and writes the *exact*
credentials file the server reads on startup. The written shape matches what
``@google-cloud/local-auth``'s ``authenticate()`` produces
(``OAuth2Client.credentials``)::

    { "access_token", "refresh_token", "scope", "token_type", "expiry_date" }

so the materialized file is a faithful drop-in for the server's own output.

NOTE on refresh: mkummer225 reconstructs an empty ``new google.auth.OAuth2()``
on reload (no client_id/secret), so it cannot self-refresh an expired access
token. The materialized access token is therefore valid for the provider's
token lifetime (~1h for Google). Re-run the authorize flow to refresh.
"""

import json
import os
import time
from typing import Optional

from secure_mcp_gateway.services.oauth.models import OAuthToken
from secure_mcp_gateway.utils import logger

# token_delivery modes (mirror OAuthConfig.token_delivery)
ENV_INJECTION = "env_injection"
GOOGLE_CREDENTIALS_FILE = "google_credentials_file"

# mkummer225/google-sheets-mcp default credentials filename (stored beside index.js)
DEFAULT_GOOGLE_CREDS_FILENAME = ".gsheets-server-credentials.json"


def _server_oauth_dict(server_entry: dict) -> dict:
    """Return the raw oauth_config dict for a server entry (or {})."""
    return server_entry.get("oauth_config") or {}


def get_token_delivery(server_entry: dict) -> str:
    """Resolve the token-delivery mode for a server.

    Explicit ``OAUTH_TOKEN_DELIVERY`` in oauth_config wins. Otherwise a
    heuristic is used so this still works even if a cloud registry strips the
    custom key from oauth_config: a *stdio* server (``config.command`` set, no
    ``config.url``) doing an ``authorization_code`` grant against Google's token
    endpoint is treated as ``google_credentials_file`` mode, because such
    servers consume a credentials FILE rather than an injected env token.
    """
    oauth = _server_oauth_dict(server_entry)
    explicit = (oauth.get("OAUTH_TOKEN_DELIVERY") or "").strip().lower()
    if explicit:
        return explicit

    grant = (oauth.get("OAUTH_GRANT_TYPE") or "").strip().lower()
    token_url = (oauth.get("OAUTH_TOKEN_URL") or "").lower()
    config = server_entry.get("config") or {}
    is_stdio = bool(config.get("command")) and not config.get("url")
    if grant == "authorization_code" and is_stdio and "googleapis.com" in token_url:
        return GOOGLE_CREDENTIALS_FILE
    return ENV_INJECTION


def is_local_credentials_file_mode(server_entry: dict) -> bool:
    """True if this server's OAuth is delivered via a materialized creds file."""
    oauth = _server_oauth_dict(server_entry)
    if not oauth or not oauth.get("enabled", False):
        return False
    return get_token_delivery(server_entry) == GOOGLE_CREDENTIALS_FILE


def resolve_credentials_file_path(server_entry: dict) -> str | None:
    """Resolve where the downstream server reads its credentials file.

    Priority:
      1. ``oauth_config.OAUTH_CREDENTIALS_FILE`` (explicit)
      2. ``config.env.GSHEETS_CREDENTIALS_PATH`` (mkummer225's own override)
      3. ``<dir of the .js entrypoint arg>/.gsheets-server-credentials.json``
         (mkummer225 stores creds beside ``index.js`` by default)

    Returns None if a path cannot be determined.
    """
    oauth = _server_oauth_dict(server_entry)
    explicit = oauth.get("OAUTH_CREDENTIALS_FILE")
    if explicit:
        return explicit

    config = server_entry.get("config") or {}
    env = config.get("env") or {}
    if env.get("GSHEETS_CREDENTIALS_PATH"):
        return env["GSHEETS_CREDENTIALS_PATH"]

    args = config.get("args") or []
    js_path = next((a for a in args if isinstance(a, str) and a.endswith(".js")), None)
    if not js_path and args:
        last = args[-1]
        if isinstance(last, str) and ("/" in last or "\\" in last):
            js_path = last
    if js_path:
        return os.path.join(os.path.dirname(js_path), DEFAULT_GOOGLE_CREDS_FILENAME)
    return None


def credentials_file_exists(server_entry: dict) -> bool:
    """True if the server's resolved credentials file is present on disk."""
    path = resolve_credentials_file_path(server_entry)
    return bool(path) and os.path.exists(path)


def resolve_oauth_keys_file_path(server_entry: dict) -> str | None:
    """Resolve the OAuth *client* keys file (gcp-oauth.keys.json) the server uses.

    Priority:
      1. oauth_config.OAUTH_CLIENT_KEYS_FILE (explicit)
      2. config.env.GSHEETS_OAUTH_PATH (mkummer225's own override)
      3. <dir of the .js entrypoint arg>/gcp-oauth.keys.json (default)
    """
    oauth = _server_oauth_dict(server_entry)
    explicit = oauth.get("OAUTH_CLIENT_KEYS_FILE")
    if explicit:
        return explicit

    config = server_entry.get("config") or {}
    env = config.get("env") or {}
    if env.get("GSHEETS_OAUTH_PATH"):
        return env["GSHEETS_OAUTH_PATH"]

    args = config.get("args") or []
    js_path = next((a for a in args if isinstance(a, str) and a.endswith(".js")), None)
    if js_path:
        return os.path.join(os.path.dirname(js_path), "gcp-oauth.keys.json")
    return None


def load_oauth_client_from_keys_file(server_entry: dict) -> dict | None:
    """Read OAuth client config from the mounted gcp-oauth.keys.json.

    Lets the gateway run the authorization-code flow for a Google file-mode
    server WITHOUT the caller supplying client_id/secret/redirect -- the same
    keyfile the downstream server reads (``web`` or ``installed`` block) carries
    them, including the registered redirect_uri (so the loopback/web redirect
    is guaranteed to match what Google has on file).

    Returns a dict with client_id / client_secret / auth_uri / token_uri /
    redirect_uri, or None if the file is missing / unreadable / lacks a
    client_id.
    """
    path = resolve_oauth_keys_file_path(server_entry)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"[OAuth LocalCreds] Could not read keys file {path}: {e}")
        return None

    block = data.get("web") or data.get("installed") or {}
    if not block.get("client_id"):
        return None
    redirect_uris = block.get("redirect_uris") or []
    return {
        "client_id": block.get("client_id"),
        "client_secret": block.get("client_secret"),
        "auth_uri": block.get("auth_uri"),
        "token_uri": block.get("token_uri"),
        "redirect_uri": redirect_uris[0] if redirect_uris else None,
    }


def materialize_google_credentials_file(
    token: OAuthToken,
    output_path: str,
    scope: str | None = None,
) -> None:
    """Write the google-auth Credentials JSON that the server reads on startup.

    Shape matches ``@google-cloud/local-auth``'s ``OAuth2Client.credentials``::

        { access_token, refresh_token, scope, token_type, expiry_date(ms) }

    Written atomically (tmp file + os.replace) so a concurrent server start
    never reads a half-written file.
    """
    creds: dict = {
        "access_token": token.access_token,
        "scope": token.scope or scope,
        "token_type": token.token_type or "Bearer",
    }
    if token.refresh_token:
        creds["refresh_token"] = token.refresh_token
    if token.expires_in:
        # google-auth-library expects expiry_date in milliseconds since epoch
        creds["expiry_date"] = int((time.time() + int(token.expires_in)) * 1000)

    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{output_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(creds, f)
    os.replace(tmp_path, output_path)

    logger.info(
        "[OAuth LocalCreds] Materialized credentials file",
        path=output_path,
        has_refresh_token=bool(token.refresh_token),
        has_expiry=bool(token.expires_in),
        scope=creds.get("scope"),
    )


async def ensure_google_credentials_fresh(
    server_entry: dict, *, expiry_buffer_seconds: int = 120
) -> tuple[bool, str | None]:
    """Make sure a file-mode server's credentials file has a usable access token.

    Because the downstream server (mkummer225) reconstructs an empty OAuth2 client
    on reload and cannot self-refresh, the *gateway* owns the token lifecycle: it
    holds the refresh_token (in the materialized file) and the client id/secret
    (in the mounted keyfile), so it refreshes the access token and rewrites the
    file before the server is spawned. No browser, no re-auth — until the
    refresh_token itself is revoked/expired.

    Returns ``(ok, error)``:
      - ``(True, None)``  -> file present with a valid (or freshly refreshed) token
      - ``(False, msg)``  -> not authorized yet, or refresh failed (caller should
                              surface ``msg`` telling the user to run authorize)

    For non-file-mode servers this is a no-op returning ``(True, None)``.
    """
    if not is_local_credentials_file_mode(server_entry):
        return True, None

    creds_path = resolve_credentials_file_path(server_entry)
    if not creds_path or not os.path.exists(creds_path):
        return (
            False,
            f"credentials file not found at {creds_path or '<unresolved path>'}",
        )

    try:
        with open(creds_path, encoding="utf-8") as f:
            creds = json.load(f)
    except Exception as e:
        return False, f"could not read credentials file: {e}"

    expiry_ms = creds.get("expiry_date")
    now_ms = time.time() * 1000
    if (
        creds.get("access_token")
        and isinstance(expiry_ms, (int, float))
        and expiry_ms > now_ms + expiry_buffer_seconds * 1000
    ):
        return True, None  # still valid, nothing to do

    # Token missing/expired -> try a refresh_token grant.
    refresh_token = creds.get("refresh_token")
    keys = load_oauth_client_from_keys_file(server_entry)
    if not refresh_token or not keys or not keys.get("client_id"):
        return (
            False,
            "access token expired and cannot be refreshed (no refresh_token or client "
            "credentials available) — re-run authorization",
        )

    token_url = keys.get("token_uri") or "https://oauth2.googleapis.com/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": keys["client_id"],
    }
    if keys.get("client_secret"):
        data["client_secret"] = keys["client_secret"]

    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url, data=data, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                body = await resp.json(content_type=None)
                if resp.status != 200:
                    err = (body or {}).get("error", f"HTTP {resp.status}")
                    return (
                        False,
                        f"token refresh failed ({err}) — re-run authorization",
                    )
    except Exception as e:
        return False, f"token refresh error: {e}"

    new_creds = dict(creds)
    new_creds["access_token"] = body.get("access_token", creds.get("access_token"))
    new_creds["token_type"] = body.get("token_type", creds.get("token_type", "Bearer"))
    if body.get("scope"):
        new_creds["scope"] = body["scope"]
    if body.get("expires_in"):
        new_creds["expiry_date"] = int(now_ms + int(body["expires_in"]) * 1000)
    if body.get("refresh_token"):  # Google usually omits this on refresh
        new_creds["refresh_token"] = body["refresh_token"]

    try:
        tmp_path = f"{creds_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(new_creds, f)
        os.replace(tmp_path, creds_path)
    except Exception as e:
        return False, f"could not write refreshed credentials file: {e}"

    logger.info(
        "[OAuth LocalCreds] Refreshed access token in credentials file",
        path=creds_path,
        expires_in=body.get("expires_in"),
    )
    return True, None


__all__ = [
    "ENV_INJECTION",
    "GOOGLE_CREDENTIALS_FILE",
    "credentials_file_exists",
    "ensure_google_credentials_fresh",
    "get_token_delivery",
    "is_local_credentials_file_mode",
    "load_oauth_client_from_keys_file",
    "materialize_google_credentials_file",
    "resolve_credentials_file_path",
    "resolve_oauth_keys_file_path",
]
