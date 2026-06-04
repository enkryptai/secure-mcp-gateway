"""Cloud /consumer-info lookup for the /mcp-playground/* routes.

When the playground receives an inline-mode request (body has ``config``)
on a gateway configured with ``plugins.auth.provider == "enkrypt"``, the
local admin-key allow-list (``resolve_admin_keys``) isn't appropriate --
the caller's apikey belongs to an Enkrypt cloud user, not the gateway's
operator. This module's :func:`fetch_consumer_info` makes a
``GET {base_url}/consumer-info`` call with the apikey and uses the
cloud's 200 / 401 / 403 response as the auth gate.

The 4 identity fields the cloud returns (``user_id``, ``project_name``,
``org_id``, ``is_internal_req``) are returned via :class:`ConsumerInfo`
and set on the parent route span using the existing identity
SpanAttributes (``enkrypt.user.id`` / ``enkrypt.org.id`` /
``enkrypt.project.name`` / ``enkrypt.user.email``) plus the one new
``enkrypt.user.is_internal_req``. This keeps playground traffic indexed
the same way as gateway traffic in OpenSearch / Grafana.

Cache TTL is 5 minutes -- /consumer-info is mostly static (user / org /
project bindings change rarely) and the cloud call is comparatively
expensive, so a longer TTL than the registry lookup is the right
tradeoff.
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
    set_span_attr_with_legacy,
)
from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (
    record_consumer_info_lookup,
)
from secure_mcp_gateway.utils import logger, mask_key

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONSUMER_INFO_TIMEOUT_SECONDS = 30  # bumped 10s -> 30s to match auth_timeout default (Enkrypt cloud occasionally hangs)
# Longer TTL than the registry lookup: /consumer-info is mostly static
# (user / org / project bindings change rarely), and the calling path is
# inline-mode admin / dev tooling, not customer hot path.
CONSUMER_INFO_CACHE_TTL_SECONDS = 300  # 5 minutes
# Truncate long upstream error bodies so 502 responses don't blow up log
# pipelines. Matches the registry-client pattern.
_MAX_ERROR_BODY = 512


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConsumerInfoError(Exception):
    """Base class for cloud /consumer-info lookup failures."""


class ConsumerAuthError(ConsumerInfoError):
    """Cloud returned 401 / 403 / 404. The apikey is invalid or unknown."""


class ConsumerUpstreamError(ConsumerInfoError):
    """Cloud returned 5xx or an unexpected status code."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class ConsumerTimeoutError(ConsumerInfoError):
    """The HTTP call to the cloud timed out."""


class ConsumerParseError(ConsumerInfoError):
    """Cloud returned 200 but the body wasn't usable JSON/shape we expect."""


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


@dataclass
class ConsumerInfo:
    """Subset of the cloud /consumer-info response the playground indexes.

    Only the 4 identity fields the user asked us to surface, plus the
    cloud's ``email`` (mirrored to ``enkrypt.user.email`` because that
    span attribute is already set in 6 other services and dashboards
    expect it).

    ``raw`` keeps the full response for log diagnostics; never returned
    to the API caller.
    """

    user_id: str | None = None
    org_id: str | None = None
    project_name: str | None = None
    email: str | None = None
    is_internal_req: bool | None = None
    raw: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# In-process TTL cache
# ---------------------------------------------------------------------------

# Keyed by sha256 hash so the apikey is never held in memory in plaintext
# as a dict key. Separate cache instance from the registry-lookup cache
# (different TTL, different lookup path).
_CACHE: dict[str, tuple[float, ConsumerInfo]] = {}
_CACHE_LOCK = asyncio.Lock()


def _cache_key(apikey: str) -> str:
    return hashlib.sha256(apikey.encode()).hexdigest()[:16]


async def _cache_get(key: str) -> ConsumerInfo | None:
    async with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at < time.time():
            _CACHE.pop(key, None)
            return None
        return value


async def _cache_put(key: str, value: ConsumerInfo) -> None:
    async with _CACHE_LOCK:
        _CACHE[key] = (time.time() + CONSUMER_INFO_CACHE_TTL_SECONDS, value)


async def _cache_clear() -> None:
    """Test-only helper. Not used in production code paths."""
    async with _CACHE_LOCK:
        _CACHE.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(body: str, limit: int = _MAX_ERROR_BODY) -> str:
    if len(body) <= limit:
        return body
    return body[:limit] + f"... ({len(body) - limit} more bytes)"


def _coerce_bool(value: Any) -> bool | None:
    """Be lenient on ``is_internal_req`` -- accept bool or stringy bool."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no", ""):
            return False
    return None


def _parse_response(body: dict[str, Any]) -> ConsumerInfo:
    """Project the cloud response onto :class:`ConsumerInfo`.

    All four indexed fields are *best-effort* -- missing fields are fine
    (we just won't set the corresponding span attribute). What we do NOT
    tolerate is a non-dict response body, which would indicate the cloud
    is returning the wrong content type entirely.
    """
    if not isinstance(body, dict):
        raise ConsumerParseError(
            f"Cloud returned 200 but body is not a JSON object: {type(body).__name__}"
        )
    return ConsumerInfo(
        user_id=body.get("user_id") or None,
        org_id=body.get("org_id") or None,
        project_name=body.get("project_name") or None,
        email=body.get("email") or None,
        is_internal_req=_coerce_bool(body.get("is_internal_req")),
        raw=body,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def fetch_consumer_info(*, base_url: str, apikey: str) -> ConsumerInfo:
    """Fetch consumer info from the Enkrypt cloud.

    Returns a :class:`ConsumerInfo` on success. Raises a
    :class:`ConsumerInfoError` subclass on every other outcome so the
    FastAPI route handler can map cleanly to HTTPException.

    The ``apikey`` itself is the auth check: cloud 200 implies the apikey
    is valid, cloud 401 / 403 / 404 means it isn't (we collapse all three
    into ``ConsumerAuthError`` because /consumer-info has no semantic
    distinction between them).
    """
    cache_key = _cache_key(apikey)
    cached = await _cache_get(cache_key)
    if cached is not None:
        record_consumer_info_lookup(
            outcome="success",
            duration_ms=0.0,
            status_code=200,
            cache="hit",
            user_id=cached.user_id,
            org_id=cached.org_id,
            project_name=cached.project_name,
            is_internal_req=cached.is_internal_req,
        )
        logger.debug(
            "[playground.consumer_info] cache hit: user_id=%s org_id=%s project=%s",
            cached.user_id,
            cached.org_id,
            cached.project_name,
        )
        return cached

    url = f"{base_url.rstrip('/')}/consumer-info"
    headers = {"apikey": apikey, "Accept": "application/json"}

    logger.info("[playground.consumer_info] GET %s apikey=%s", url, mask_key(apikey))

    from opentelemetry import trace  # local import: optional dependency

    tracer = trace.get_tracer("secure_mcp_gateway.playground.consumer_info")

    start = time.monotonic()

    with tracer.start_as_current_span(
        SpanNames.PLAYGROUND_CONSUMER_INFO_LOOKUP
    ) as span:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=CONSUMER_INFO_TIMEOUT_SECONDS),
                ) as resp:
                    status_code = resp.status
                    body_text = await resp.text()
        except asyncio.TimeoutError as e:
            duration_ms = (time.monotonic() - start) * 1000.0
            span.set_attribute(SpanAttributes.SUCCESS, False)
            span.set_attribute(SpanAttributes.ERROR_MESSAGE, "timeout")
            record_consumer_info_lookup(
                outcome="timeout",
                duration_ms=duration_ms,
                status_code=None,
                cache="miss",
            )
            raise ConsumerTimeoutError(
                f"Timeout after {CONSUMER_INFO_TIMEOUT_SECONDS}s contacting {url}"
            ) from e
        except aiohttp.ClientError as e:
            duration_ms = (time.monotonic() - start) * 1000.0
            span.set_attribute(SpanAttributes.SUCCESS, False)
            span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(e))
            record_consumer_info_lookup(
                outcome="upstream_error",
                duration_ms=duration_ms,
                status_code=None,
                cache="miss",
            )
            raise ConsumerUpstreamError(f"Transport error contacting {url}: {e}") from e

        duration_ms = (time.monotonic() - start) * 1000.0

        if status_code == 200:
            try:
                payload = json.loads(body_text)
            except json.JSONDecodeError as e:
                span.set_attribute(SpanAttributes.SUCCESS, False)
                span.set_attribute(SpanAttributes.ERROR_MESSAGE, f"json: {e}")
                record_consumer_info_lookup(
                    outcome="upstream_error",
                    duration_ms=duration_ms,
                    status_code=status_code,
                    cache="miss",
                )
                raise ConsumerParseError(
                    f"Cloud returned 200 with non-JSON body: {e}"
                ) from e

            try:
                info = _parse_response(payload)
            except ConsumerParseError as e:
                span.set_attribute(SpanAttributes.SUCCESS, False)
                span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(e))
                record_consumer_info_lookup(
                    outcome="upstream_error",
                    duration_ms=duration_ms,
                    status_code=status_code,
                    cache="miss",
                )
                raise

            # Set identity attributes on the lookup span itself. The
            # caller is responsible for also setting them on the parent
            # route span so dashboards filtering by user_id / org_id /
            # project_name pick this up regardless of which span they're
            # looking at.
            if info.user_id:
                set_span_attr_with_legacy(span, SpanAttributes.USER_ID, info.user_id)
            if info.org_id:
                set_span_attr_with_legacy(span, SpanAttributes.ORG_ID, info.org_id)
            if info.project_name:
                set_span_attr_with_legacy(
                    span, SpanAttributes.PROJECT_NAME, info.project_name
                )
            if info.email:
                set_span_attr_with_legacy(
                    span, SpanAttributes.USER_EMAIL, info.email
                )
            if info.is_internal_req is not None:
                span.set_attribute(
                    SpanAttributes.USER_IS_INTERNAL_REQ, info.is_internal_req
                )
            span.set_attribute(SpanAttributes.SUCCESS, True)

            await _cache_put(cache_key, info)
            record_consumer_info_lookup(
                outcome="success",
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
                user_id=info.user_id,
                org_id=info.org_id,
                project_name=info.project_name,
                is_internal_req=info.is_internal_req,
            )
            logger.info(
                "[playground.consumer_info] 200 ok: user_id=%s org_id=%s "
                "project=%s is_internal_req=%s duration_ms=%.1f",
                info.user_id,
                info.org_id,
                info.project_name,
                info.is_internal_req,
                duration_ms,
            )
            return info

        # --- Non-200 path ---------------------------------------------
        span.set_attribute(SpanAttributes.SUCCESS, False)
        span.set_attribute(
            SpanAttributes.ERROR_MESSAGE,
            f"HTTP {status_code} from cloud",
        )

        truncated = _truncate(body_text)
        logger.warning(
            "[playground.consumer_info] %s from %s: %s",
            status_code,
            url,
            truncated,
        )

        # /consumer-info has no "not found" semantics distinct from "bad
        # apikey": both 401 and 404 mean the apikey isn't recognised.
        # Collapse 401/403/404 into a single auth-error class.
        if status_code in (401, 403, 404):
            record_consumer_info_lookup(
                outcome="auth_error",
                duration_ms=duration_ms,
                status_code=status_code,
                cache="miss",
            )
            raise ConsumerAuthError(
                f"Cloud rejected apikey ({status_code}): {truncated}"
            )

        # Everything else (5xx, weird 4xx, etc.) is an upstream problem.
        record_consumer_info_lookup(
            outcome="upstream_error",
            duration_ms=duration_ms,
            status_code=status_code,
            cache="miss",
        )
        raise ConsumerUpstreamError(
            f"HTTP {status_code} from {url}: {truncated}", status_code=502
        )
