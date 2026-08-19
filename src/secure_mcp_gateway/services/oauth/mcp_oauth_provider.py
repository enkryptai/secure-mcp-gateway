"""
MCP-native OAuth provider for URL-based MCP servers.

Bridges the gateway with the MCP SDK's built-in ``OAuthClientProvider``
(``mcp.client.auth.oauth2``), which implements Authorization Code + PKCE
according to the MCP OAuth specification.

Usage::

    auth = await build_mcp_oauth_auth(server_entry)
    async with streamablehttp_client(url, auth=auth) as ...:
        ...

The provider handles:
- File-based token + client-registration persistence per server URL
- Browser-based redirect for interactive authorization
- Local HTTP callback server to receive the authorization code
- Headless / Docker mode where the URL is printed for manual visit
"""

import asyncio
import hashlib
import json
import os
import platform
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Event, Thread
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.client.auth.oauth2 import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from secure_mcp_gateway.utils import is_docker, logger

_DEFAULT_CALLBACK_PORT = 9876
_DEFAULT_TIMEOUT = 300  # seconds


def _token_dir() -> Path:
    """Return the directory used for persisting MCP OAuth tokens.

    In Docker the path sits under the volume-mounted ``/app/.enkrypt/docker/``
    so tokens survive container restarts without an extra mount.
    """
    if is_docker():
        base = Path("/app/.enkrypt/docker/oauth_tokens")
    else:
        base = Path.home() / ".enkrypt" / "oauth_tokens"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _server_hash(server_url: str) -> str:
    """Stable, filesystem-safe hash for a server URL."""
    return hashlib.sha256(server_url.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Token Storage
# ---------------------------------------------------------------------------


class GatewayTokenStorage:
    """File-backed implementation of the MCP SDK ``TokenStorage`` protocol.

    Tokens and client registration info are stored as JSON files keyed by
    a hash of the server URL.  This survives gateway restarts (including
    Docker, provided the storage directory is volume-mounted).
    """

    def __init__(self, server_url: str) -> None:
        h = _server_hash(server_url)
        d = _token_dir()
        self._token_path = d / f"{h}_tokens.json"
        self._client_path = d / f"{h}_client.json"

    async def get_tokens(self) -> Optional[OAuthToken]:
        if not self._token_path.exists():
            return None
        try:
            data = json.loads(self._token_path.read_text(encoding="utf-8"))
            return OAuthToken.model_validate(data)
        except Exception:
            logger.warning("[MCPOAuth] Could not load cached tokens, starting fresh")
            return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        try:
            self._token_path.write_text(
                tokens.model_dump_json(indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error(f"[MCPOAuth] Failed to persist tokens: {exc}")

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        if not self._client_path.exists():
            return None
        try:
            data = json.loads(self._client_path.read_text(encoding="utf-8"))
            return OAuthClientInformationFull.model_validate(data)
        except Exception:
            logger.warning("[MCPOAuth] Could not load cached client info")
            return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        try:
            self._client_path.write_text(
                client_info.model_dump_json(indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error(f"[MCPOAuth] Failed to persist client info: {exc}")


# ---------------------------------------------------------------------------
# Callback HTTP server (receives OAuth redirect)
# ---------------------------------------------------------------------------

_callback_result: Dict[str, Optional[str]] = {
    "code": None,
    "state": None,
    "error": None,
}
_callback_event = Event()


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that captures ``code`` and ``state`` from the
    OAuth authorization redirect."""

    def do_GET(self) -> None:
        qs = parse_qs(urlparse(self.path).query)
        _callback_result["code"] = (qs.get("code") or [None])[0]
        _callback_result["state"] = (qs.get("state") or [None])[0]
        _callback_result["error"] = (qs.get("error") or [None])[0]

        if _callback_result["code"]:
            body = (
                "<html><body><h2>Authorization successful</h2>"
                "<p>You may close this tab and return to the gateway.</p>"
                "</body></html>"
            )
            self.send_response(200)
        else:
            err = _callback_result["error"] or "unknown error"
            body = f"<html><body><h2>Authorization failed: {err}</h2></body></html>"
            self.send_response(400)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())
        _callback_event.set()

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # silence default stderr logging


def _run_callback_server(port: int, ready: Event) -> None:
    """Start the callback HTTP server in a daemon thread."""
    bind_addr = "0.0.0.0" if is_docker() else "127.0.0.1"
    server = HTTPServer((bind_addr, port), _OAuthCallbackHandler)
    server.timeout = 1
    ready.set()
    while not _callback_event.is_set():
        server.handle_request()
    server.server_close()


# ---------------------------------------------------------------------------
# Redirect + callback handlers (async wrappers)
# ---------------------------------------------------------------------------


async def _redirect_handler(authorize_url: str) -> None:
    """Open the authorization URL in the user's browser, or print it in
    headless mode."""
    if is_docker():
        logger.info(
            f"[MCPOAuth] Running in Docker — please open this URL in your browser "
            f"to authorize:\n\n  {authorize_url}\n"
        )
        print(
            f"\n{'=' * 60}\n"
            f"MCP OAuth: open this URL in your browser to authorize:\n\n"
            f"  {authorize_url}\n"
            f"\n{'=' * 60}\n",
            flush=True,
        )
    else:
        logger.info(f"[MCPOAuth] Opening browser for authorization: {authorize_url}")
        webbrowser.open(authorize_url)


async def _callback_handler_factory(
    port: int, timeout: float
) -> Tuple[str, Optional[str]]:
    """Wait for the OAuth callback and return ``(code, state)``."""
    _callback_result.update(code=None, state=None, error=None)
    _callback_event.clear()

    ready = Event()
    thread = Thread(target=_run_callback_server, args=(port, ready), daemon=True)
    thread.start()
    ready.wait(timeout=5)

    loop = asyncio.get_event_loop()
    got_it = await loop.run_in_executor(None, _callback_event.wait, timeout)

    if not got_it:
        raise TimeoutError(f"[MCPOAuth] OAuth callback not received within {timeout}s")

    if _callback_result["error"]:
        raise RuntimeError(
            f"[MCPOAuth] Authorization failed: {_callback_result['error']}"
        )

    code = _callback_result["code"]
    state = _callback_result["state"]
    if not code:
        raise RuntimeError("[MCPOAuth] No authorization code received")

    return code, state


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _get_mcp_oauth_config(server_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the ``mcp_oauth`` config dict if MCP OAuth is enabled, else None."""
    oauth_cfg = server_entry.get("mcp_oauth")
    if not oauth_cfg:
        return None
    if isinstance(oauth_cfg, dict) and oauth_cfg.get("enabled", False):
        return oauth_cfg
    if oauth_cfg is True:
        return {"enabled": True}
    return None


async def build_mcp_oauth_auth(
    server_entry: Dict[str, Any],
) -> Optional[httpx.Auth]:
    """Build an ``OAuthClientProvider`` for a URL-based MCP server, or
    return ``None`` if MCP OAuth is not configured.

    The returned object is an ``httpx.Auth`` that can be passed straight to
    ``streamablehttp_client(..., auth=...)``.
    """
    oauth_cfg = _get_mcp_oauth_config(server_entry)
    if oauth_cfg is None:
        return None

    config = server_entry.get("config", {})
    url = config.get("url") or config.get("serverUrl", "")
    if not url:
        logger.warning("[MCPOAuth] mcp_oauth enabled but no URL in server config")
        return None

    port = int(oauth_cfg.get("callback_port", _DEFAULT_CALLBACK_PORT))
    timeout = float(oauth_cfg.get("timeout", _DEFAULT_TIMEOUT))
    server_name = server_entry.get("server_name", "unknown")

    logger.info(
        f"[MCPOAuth] Building OAuth provider for '{server_name}' "
        f"url={url} callback_port={port} timeout={timeout}"
    )

    storage = GatewayTokenStorage(url)
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    client_metadata = OAuthClientMetadata(
        redirect_uris=[redirect_uri],
        token_endpoint_auth_method="client_secret_post",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=f"Enkrypt MCP Gateway ({server_name})",
    )

    async def callback_handler() -> Tuple[str, Optional[str]]:
        return await _callback_handler_factory(port, timeout)

    return OAuthClientProvider(
        server_url=url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=_redirect_handler,
        callback_handler=callback_handler,
        timeout=timeout,
    )
