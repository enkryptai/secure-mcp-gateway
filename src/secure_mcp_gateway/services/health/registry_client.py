"""Cloud registry-server lookup for the /mcp-playground/* routes.

When the playground receives a request in registry-header mode
(``X-Enkrypt-MCP-Registry-Server`` present, no inline body config), it
delegates to :func:`fetch_registry_server` here.  This module owns:

- the HTTP call to ``GET {base_url}/mcp-registry/get-server`` (aiohttp),
- a tiny in-process TTL cache (default 10s) keyed by
  ``sha256(apikey|saved_name|server_version|registry_name|project_name)``
  so dashboard double-fires don't double-hit the cloud,
- mapping cloud HTTP statuses to a small set of typed exceptions that the
  FastAPI route handler translates to ``HTTPException`` responses, and
- one OTel child span + one latency histogram per call so per-tenant /
  per-registry dashboards work without log scraping.

The cloud's apikey check **is** our apikey check in registry mode: a 200
implies the apikey is valid, a 401/403 means it isn't.  We forward the
apikey verbatim in the ``apikey`` header.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

from secure_mcp_gateway.plugins.telemetry.conventions import (
    SpanAttributes,
    SpanNames,
)
from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (
    record_registry_lookup,
)
from secure_mcp_gateway.utils import logger, mask_key

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://api.enkryptai.com"
REGISTRY_LOOKUP_TIMEOUT_SECONDS = 10
# Short TTL is deliberate: the playground is interactive and registry data
# can change at any time.  10s is just enough to absorb dashboard double-fires
# (e.g. React Strict Mode mounting effects twice in dev).
REGISTRY_LOOKUP_CACHE_TTL_SECONDS = 10
# Truncate long upstream error bodies so 502 responses don't blow up log
# pipelines.  Matches the ``_truncate`` pattern in ``enkrypt_provider.py``.
_MAX_ERROR_BODY = 512


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RegistryLookupError(Exception):
    """Base class for cloud /mcp-registry/get-server lookup failures."""


class RegistryAuthError(RegistryLookupError):
    """Cloud returned 401.  The caller's apikey is invalid."""


class RegistryForbiddenError(RegistryLookupError):
    """Cloud returned 403.  The apikey is valid but lacks access."""


class RegistryNotFoundError(RegistryLookupError):
    """Cloud returned 404.  The requested registry server doesn't exist."""


class RegistryBadRequestError(RegistryLookupError):
    """Cloud returned 400 — usually a malformed header value (e.g. too long)."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class RegistryUpstreamError(RegistryLookupError):
    """Cloud returned 5xx or an unexpected status code."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class RegistryTimeoutError(RegistryLookupError):
    """The HTTP call to the cloud timed out."""


class RegistryParseError(RegistryLookupError):
    """The cloud returned 200 but the body wasn't usable JSON/shape we expect."""


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


@dataclass
class RegistryServerLookup:
    """Subset of the cloud /mcp-registry/get-server response the playground uses.

    ``config_dict`` is the executable shape that ``MCPHealthService`` expects:
    ``{"command": str, "args": list[str], "env": dict[str, str] | None}``.

    The remaining fields are authoritative server-side identifiers we log
    and attach as span attributes — the client headers gave us a *requested*
    identity, this is what the cloud actually returned.
    """

    saved_name: str
    server_version: str
    config_dict: dict[str, Any]
    server_name: str | None = None
    description: str | None = None
    registry_id: str | None = None
    registry_name: str | None = None
    project_name: str | None = None
    is_active: bool | None = None
    is_sample: bool | None = None
    source_url: str | None = None
    source_version: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    # Raw response retained for log diagnostics (never returned to the
    # caller; redact-by-omission rather than redact-by-allowlist if you ever
    # surface it externally).
    raw: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# In-process TTL cache
# ---------------------------------------------------------------------------

# Keyed by sha256 hash so the apikey is never held in memory in plaintext as
# a dict key.  Value is ``(expires_at_epoch, RegistryServerLookup)``.
_CACHE: dict[str, tuple[float, RegistryServerLookup]] = {}
_CACHE_LOCK = asyncio.Lock()


def _cache_key(
    apikey: str,
    saved_name: str,
    server_version: str,
    registry_name: str,
    project_name: str,
) -> str:
    h = hashlib.sha256()
    # Pipe is a safe separator: it can't appear in apikeys (base64ish) or in
    # the cloud's saved_name / version / registry_name / project_name
    # (alphanumeric + ``-_``, see registry server schema).
    h.update(
        f"{apikey}|{saved_name}|{server_version}|{registry_name}|{project_name}".encode()
    )
    return h.hexdigest()[:16]


async def _cache_get(key: str) -> RegistryServerLookup | None:
    async with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at < time.time():
            _CACHE.pop(key, None)
            return None
        return value


async def _cache_put(key: str, value: RegistryServerLookup) -> None:
    async with _CACHE_LOCK:
        _CACHE[key] = (time.time() + REGISTRY_LOOKUP_CACHE_TTL_SECONDS, value)


async def _cache_clear() -> None:
    """Test-only helper.  Not used in production code paths."""
    async with _CACHE_LOCK:
        _CACHE.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(body: str, limit: int = _MAX_ERROR_BODY) -> str:
    if len(body) <= limit:
        return body
    return body[:limit] + f"... ({len(body) - limit} more bytes)"


def get_enkrypt_base_url(config: dict[str, Any]) -> str:
    """Resolve the cloud base_url used for the registry GET call.

    Decision (see plan): we read ``enkrypt_config.base_url`` at config root.
    Falls back to ``DEFAULT_BASE_URL`` when the key is absent or empty so the
    playground works against the public cloud out of the box.
    """
    enkrypt_cfg = (
        (config.get("enkrypt_config") or {}) if isinstance(config, dict) else {}
    )
    base_url = enkrypt_cfg.get("base_url") or DEFAULT_BASE_URL
    return base_url.rstrip("/")


def _parse_response(body: dict[str, Any]) -> RegistryServerLookup:
    """Validate the cloud response shape and project it onto the dataclass.

    Raises ``RegistryParseError`` if ``mcp_config.config.command`` is missing —
    without that the playground has nothing to spawn.
    """
    mcp_config = body.get("mcp_config")
    if not isinstance(mcp_config, dict):
        raise RegistryParseError(
            "Registry server has no mcp_config — cannot spawn server"
        )
    inner = mcp_config.get("config")
    if not isinstance(inner, dict):
        raise RegistryParseError(
            "Registry server mcp_config.config block is missing or wrong type"
        )
    command = inner.get("command")
    if not isinstance(command, str) or not command.strip():
        raise RegistryParseError(
            "Registry server mcp_config.config.command is missing or empty"
        )
    args = inner.get("args") or []
    if not isinstance(args, list):
        raise RegistryParseError("Registry server mcp_config.config.args is not a list")
    env_raw = inner.get("env")
    env: dict[str, str] | None = None
    if env_raw is not None:
        if not isinstance(env_raw, dict):
            raise RegistryParseError(
                "Registry server mcp_config.config.env is not an object"
            )
        # Cloud should already enforce str-str, but coerce defensively so the
        # MCP SDK's stdio launcher doesn't blow up on a non-str value.
        env = {str(k): str(v) for k, v in env_raw.items()}

    return RegistryServerLookup(
        saved_name=str(body.get("saved_name") or ""),
        server_version=str(body.get("server_version") or ""),
        config_dict={
            "command": command,
            "args": [str(a) for a in args],
            "env": env,
        },
        server_name=body.get("server_name"),
        description=body.get("description"),
        registry_id=body.get("registry_id"),
        registry_name=body.get("registry_name"),
        project_name=body.get("project_name"),
        is_active=body.get("is_active"),
        is_sample=body.get("is_sample"),
        source_url=body.get("source_url"),
        source_version=body.get("source_version"),
        created_at=body.get("created_at"),
        updated_at=body.get("updated_at"),
        raw=body,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def fetch_registry_server(
    *,
    base_url: str,
    apikey: str,
    saved_name: str,
    server_version: str = "v1",
    registry_name: str = "default",
    project_name: str = "default",
) -> RegistryServerLookup:
    """Fetch a registry server from the Enkrypt cloud.

    Returns a :class:`RegistryServerLookup` on success.  Raises a
    :class:`RegistryLookupError` subclass on every other outcome so the
    FastAPI route handler can map cleanly to HTTPException.

    The ``apikey`` is also the auth check: cloud 200 => valid apikey, cloud
    401/403 => invalid.
    """
    cache_key = _cache_key(
        apikey, saved_name, server_version, registry_name, project_name
    )
    cached = await _cache_get(cache_key)
    if cached is not None:
        record_registry_lookup(
            outcome="success",
            duration_ms=0.0,
            status_code=200,
            cache="hit",
            saved_name=saved_name,
            server_version=server_version,
            registry_name=registry_name,
            project_name=project_name,
        )
        logger.debug(
            "[playground.registry] cache hit: saved_name=%s version=%s registry=%s project=%s",
            saved_name,
            server_version,
            registry_name,
            project_name,
        )
        return cached

    url = f"{base_url.rstrip('/')}/mcp-registry/get-server"
    headers = {
        "apikey": apikey,
        "X-Enkrypt-MCP-Registry-Server": saved_name,
        "X-Enkrypt-MCP-Registry-Server-Version": server_version,
        "X-Enkrypt-MCP-Registry": registry_name,
        "X-Enkrypt-Project": project_name,
        "Accept": "application/json",
    }

    logger.info(
        "[playground.registry] GET %s saved_name=%s version=%s registry=%s "
        "project=%s apikey=%s",
        url,
        saved_name,
        server_version,
        registry_name,
        project_name,
        mask_key(apikey),
    )

    # Child span around the cloud call.  No-op when telemetry isn't
    # initialised (matches the AUTH_FETCH_CONFIG pattern in enkrypt_provider).
    from opentelemetry import trace  # local import: optional dependency

    tracer = trace.get_tracer("secure_mcp_gateway.playground.registry")

    start = time.monotonic()
    status_code: int | None = None
    outcome = "upstream_error"
    body_text = ""

    with tracer.start_as_current_span(SpanNames.PLAYGROUND_REGISTRY_LOOKUP) as span:
        span.set_attribute(SpanAttributes.PLAYGROUND_LOOKUP_URL, url)
        span.set_attribute(SpanAttributes.PLAYGROUND_REGISTRY_SAVED_NAME, saved_name)
        span.set_attribute(
            SpanAttributes.PLAYGROUND_REGISTRY_SERVER_VERSION, server_version
        )
        span.set_attribute(SpanAttributes.PLAYGROUND_REGISTRY_NAME, registry_name)
        span.set_attribute(SpanAttributes.PLAYGROUND_PROJECT_NAME, project_name)
        span.set_attribute(SpanAttributes.PLAYGROUND_LOOKUP_CACHE, "miss")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(
                        total=REGISTRY_LOOKUP_TIMEOUT_SECONDS
                    ),
                ) as resp:
                    status_code = resp.status
                    body_text = await resp.text()
                    span.set_attribute(
                        SpanAttributes.PLAYGROUND_LOOKUP_STATUS_CODE, status_code
                    )
        except asyncio.TimeoutError as e:
            duration_ms = (time.monotonic() - start) * 1000.0
            span.set_attribute(SpanAttributes.SUCCESS, False)
            span.set_attribute(SpanAttributes.ERROR_MESSAGE, "timeout")
            span.set_attribute(
                SpanAttributes.PLAYGROUND_LOOKUP_DURATION_MS, duration_ms
            )
            record_registry_lookup(
                outcome="timeout",
                duration_ms=duration_ms,
                status_code=None,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryTimeoutError(
                f"Timeout after {REGISTRY_LOOKUP_TIMEOUT_SECONDS}s contacting {url}"
            ) from e
        except aiohttp.ClientError as e:
            duration_ms = (time.monotonic() - start) * 1000.0
            span.set_attribute(SpanAttributes.SUCCESS, False)
            span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(e))
            span.set_attribute(
                SpanAttributes.PLAYGROUND_LOOKUP_DURATION_MS, duration_ms
            )
            record_registry_lookup(
                outcome="upstream_error",
                duration_ms=duration_ms,
                status_code=None,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryUpstreamError(f"Transport error contacting {url}: {e}") from e

        duration_ms = (time.monotonic() - start) * 1000.0
        span.set_attribute(SpanAttributes.PLAYGROUND_LOOKUP_DURATION_MS, duration_ms)

        if status_code == 200:
            try:
                payload = json.loads(body_text)
            except json.JSONDecodeError as e:
                span.set_attribute(SpanAttributes.SUCCESS, False)
                span.set_attribute(SpanAttributes.ERROR_MESSAGE, f"json: {e}")
                record_registry_lookup(
                    outcome="upstream_error",
                    duration_ms=duration_ms,
                    status_code=status_code,
                    cache="miss",
                    saved_name=saved_name,
                    server_version=server_version,
                    registry_name=registry_name,
                    project_name=project_name,
                )
                raise RegistryParseError(
                    f"Cloud returned 200 with non-JSON body: {e}"
                ) from e

            try:
                lookup = _parse_response(payload)
            except RegistryParseError as e:
                span.set_attribute(SpanAttributes.SUCCESS, False)
                span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(e))
                record_registry_lookup(
                    outcome="upstream_error",
                    duration_ms=duration_ms,
                    status_code=status_code,
                    cache="miss",
                    saved_name=saved_name,
                    server_version=server_version,
                    registry_name=registry_name,
                    project_name=project_name,
                )
                raise

            # Successful lookup — attach authoritative server-side identifiers
            # to the span so trace consumers can pivot on what the cloud
            # actually returned, not what the client claimed.
            if lookup.registry_id:
                span.set_attribute(
                    SpanAttributes.PLAYGROUND_REGISTRY_ID, lookup.registry_id
                )
            if lookup.server_name:
                span.set_attribute(
                    SpanAttributes.PLAYGROUND_REGISTRY_SERVER_NAME,
                    lookup.server_name,
                )
            if lookup.is_active is not None:
                span.set_attribute(
                    SpanAttributes.PLAYGROUND_REGISTRY_IS_ACTIVE, lookup.is_active
                )
            if lookup.is_sample is not None:
                span.set_attribute(
                    SpanAttributes.PLAYGROUND_REGISTRY_IS_SAMPLE, lookup.is_sample
                )
            span.set_attribute(SpanAttributes.SUCCESS, True)

            await _cache_put(cache_key, lookup)
            outcome = "success"
            record_registry_lookup(
                outcome=outcome,
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                saved_name=lookup.saved_name or saved_name,
                server_version=lookup.server_version or server_version,
                registry_name=lookup.registry_name or registry_name,
                project_name=lookup.project_name or project_name,
            )

            logger.info(
                "[playground.registry] 200 ok: saved_name=%s server_version=%s "
                "registry_id=%s registry_name=%s project_name=%s server_name=%s "
                "is_active=%s is_sample=%s duration_ms=%.1f",
                lookup.saved_name,
                lookup.server_version,
                lookup.registry_id,
                lookup.registry_name,
                lookup.project_name,
                lookup.server_name,
                lookup.is_active,
                lookup.is_sample,
                duration_ms,
            )
            return lookup

        # --- Non-200 path -------------------------------------------------
        span.set_attribute(SpanAttributes.SUCCESS, False)
        span.set_attribute(
            SpanAttributes.ERROR_MESSAGE,
            f"HTTP {status_code} from cloud",
        )

        truncated = _truncate(body_text)
        logger.warning(
            "[playground.registry] %s from %s: %s (saved_name=%s version=%s)",
            status_code,
            url,
            truncated,
            saved_name,
            server_version,
        )

        if status_code == 401:
            outcome = "auth_error"
            record_registry_lookup(
                outcome=outcome,
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryAuthError(f"Cloud rejected apikey (401): {truncated}")
        if status_code == 403:
            outcome = "auth_error"
            record_registry_lookup(
                outcome=outcome,
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryForbiddenError(f"Cloud forbade apikey (403): {truncated}")
        if status_code == 404:
            outcome = "not_found"
            record_registry_lookup(
                outcome=outcome,
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryNotFoundError(
                f"Registry server '{saved_name}@{server_version}' not found: {truncated}"
            )
        if status_code == 400:
            outcome = "upstream_error"
            record_registry_lookup(
                outcome=outcome,
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                saved_name=saved_name,
                server_version=server_version,
                registry_name=registry_name,
                project_name=project_name,
            )
            raise RegistryBadRequestError(
                f"Cloud rejected request (400): {truncated}", status_code=400
            )

        # 5xx and any other unexpected status
        outcome = "upstream_error"
        record_registry_lookup(
            outcome=outcome,
            duration_ms=duration_ms,
            status_code=status_code,
            cache="miss",
            saved_name=saved_name,
            server_version=server_version,
            registry_name=registry_name,
            project_name=project_name,
        )
        raise RegistryUpstreamError(
            f"HTTP {status_code} from {url}: {truncated}", status_code=502
        )
