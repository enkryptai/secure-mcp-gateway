"""Enkrypt authentication provider — fetches gateway config from the cloud.

Talks to ``GET {base_url}/mcp-gateway/get-gateway-config`` and maps the
response (``ExpandedGatewayConfig`` shape, defined in the
``enkryptai-apiaas`` repo's ``mcp-gateway-api-spec.yaml``) into the internal
``mcp_config`` list shape that the rest of the gateway runtime consumes.

Design decisions
----------------

1. **Per-request multi-tenancy.** Every MCP client passes its own Enkrypt
   apikey via the ``apikey`` header (already extracted upstream as
   ``credentials.gateway_key``). That value is forwarded as the ``apikey``
   header on the cloud call, so each client gets its own gateway config.
   The boot-time ``apikey`` from ``auth.config`` is only a fallback.

2. **Hard-fail on cloud errors.** No local-file fallback, no stale-cache
   serving. A 5xx / network blip surfaces as an authentication failure to
   the caller. Operational decision recorded in CHANGELOG and observability
   docs.

3. **Per-server ``gateway_overrides`` merge.** When the cloud response
   includes ``expanded_servers[].gateway_overrides.<policy>``, that value
   wins over the corresponding ``mcp_config.<policy>`` field. Otherwise the
   base policy is used as-is. The merge is shallow (whole-policy
   replacement), matching what the cloud already does internally.

4. **Local-only fields layered on top.** ``sandbox`` / ``oauth_config`` /
   ``denied_tools`` are not yet part of the cloud spec but are first-class
   in the gateway. If the local config file contains a top-level
   ``local_server_overrides`` map keyed by ``server_name``, those fields
   are layered onto the corresponding cloud server (cloud server wins for
   any field present on both sides).

5. **Short TTL cache.** Configurations are cached in-process for 10 minutes
   keyed on (apikey hash, gateway_name, version, project_name). Avoids
   hitting the cloud on every tool call without keeping stale config too
   long. The TTL is overridable via
   ``auth.config.cache_ttl_seconds``.

6. **Identity propagation.** The cloud's ``request_context`` block (added
   in the dev cloud image, May 2026) supplies ``user_id``, ``project_name``,
   ``forwarded_user_id``, ``forwarded_user_email`` and friends. The mapper
   prefers ``forwarded_user_id`` over ``user_id`` for the metric ``user_id``
   label so that alerts attribute to the actual end-user of the calling
   app, not the gateway-owner principal. Until the cloud surfaces a stable
   ``project_id`` UUID we mirror ``project_name`` into the ``project_id``
   slot for the existing label set.

7. **Per-server ``is_active`` filter.** Cloud responses carry an
   ``is_active`` flag on every entry of ``expanded_servers`` that the
   dashboard flips when a server is soft-deleted or temporarily disabled.
   The mapper drops any server with ``is_active is False`` before merging,
   so disabled servers never reach discovery, execution, or the
   in-process cache. The check is strict (``is False``) — missing /
   ``null`` / ``true`` all retain the server, matching the cloud's
   optimistic default.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from secure_mcp_gateway.plugins.auth.base import (
    AuthCredentials,
    AuthMethod,
    AuthProvider,
    AuthResult,
    AuthStatus,
)
from secure_mcp_gateway.consts import ENKRYPT_REMOTE_CONFIG_TTL_SECONDS
from secure_mcp_gateway.plugins.telemetry.metrics_helpers import record_auth_outcome
from secure_mcp_gateway.utils import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    is_docker,
    logger,
    mask_key,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://api.enkryptai.com"
DEFAULT_GATEWAY_VERSION = "v1"
DEFAULT_CACHE_TTL_SECONDS = ENKRYPT_REMOTE_CONFIG_TTL_SECONDS
DEFAULT_FETCH_TIMEOUT_SECONDS = 10

# These auth.config keys belonged to the v1 ("local fallback") provider.
# We hard-fail at boot when they are still set, so configs surface the
# rename instead of silently using the new wiring with old values.
_REMOVED_CONFIG_KEYS = ("api_key", "use_remote_config", "timeout")


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class EnkryptAuthProvider(AuthProvider):
    """Authenticate by looking up the gateway config in Enkrypt cloud.

    Constructor accepts the new ``auth.config`` block::

        {
            "apikey": "<fallback boot-time enkrypt apikey>",
            "gateway_name": "<saved_name from /mcp-gateway/add-gateway>",
            "gateway_version": "v1",
            "project_name": "default",
            "base_url": "https://api.enkryptai.com",
            "cache_ttl_seconds": 600
        }

    All keys except ``gateway_name`` are optional / have defaults.
    """

    def __init__(
        self,
        apikey: Optional[str] = None,
        gateway_name: Optional[str] = None,
        gateway_version: str = DEFAULT_GATEWAY_VERSION,
        project_name: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        **legacy_kwargs: Any,
    ):
        # Detect old-shape configs and fail loudly. The kwargs catch handles
        # forwards-compat (so a future field doesn't crash boot) but flags
        # known-removed keys explicitly.
        bad_keys = [k for k in _REMOVED_CONFIG_KEYS if k in legacy_kwargs]
        if bad_keys:
            raise ValueError(
                f"EnkryptAuthProvider: auth.config keys {bad_keys} were removed in "
                f"the cloud-config rewrite. Replace with: apikey, gateway_name, "
                f"gateway_version, project_name, base_url. See "
                f"docs/auth-providers.md or CHANGELOG."
            )
        if legacy_kwargs:
            logger.warning(
                "[EnkryptAuthProvider] Unknown auth.config keys ignored: %s",
                list(legacy_kwargs.keys()),
            )

        if not gateway_name:
            raise ValueError(
                "EnkryptAuthProvider: 'gateway_name' is required in auth.config"
            )

        self.apikey = apikey or ""
        self.gateway_name = gateway_name
        self.gateway_version = gateway_version or DEFAULT_GATEWAY_VERSION
        self.project_name = project_name or None  # treat empty string as absent
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.cache_ttl_seconds = int(cache_ttl_seconds)

        # In-process cache: hash(apikey) -> (expires_at_epoch, mapped_config)
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

        logger.info(
            "[EnkryptAuthProvider] initialised: gateway_name=%s gateway_version=%s "
            "project_name=%s base_url=%s ttl=%ss",
            self.gateway_name,
            self.gateway_version,
            self.project_name or "(inferred from apikey)",
            self.base_url,
            self.cache_ttl_seconds,
        )

    # ------------------------------------------------------------------
    # AuthProvider boilerplate
    # ------------------------------------------------------------------

    def get_name(self) -> str:
        return "enkrypt"

    def get_version(self) -> str:
        return "2.0.0"

    def get_supported_methods(self) -> List[AuthMethod]:
        return [AuthMethod.API_KEY]

    def validate_config(self, config: Dict[str, Any]) -> bool:
        return bool(self.gateway_name)

    def get_required_config_keys(self) -> List[str]:
        return ["gateway_name"]

    # ------------------------------------------------------------------
    # Public auth surface
    # ------------------------------------------------------------------

    async def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        result = await self._authenticate_impl(credentials)
        record_auth_outcome(
            provider=self.get_name(),
            outcome="success" if result.authenticated else "failure",
            failure_reason=(result.error or result.status.value)
            if not result.authenticated
            else None,
        )
        return result

    async def _authenticate_impl(self, credentials: AuthCredentials) -> AuthResult:
        gateway_key = credentials.gateway_key or credentials.api_key or self.apikey
        if not gateway_key:
            return AuthResult(
                status=AuthStatus.INVALID_CREDENTIALS,
                authenticated=False,
                message="No apikey provided",
                error="Missing apikey on request and no boot-time fallback configured",
            )

        try:
            mapped = await self._get_local_config(
                gateway_key,
                credentials.project_id,
                credentials.user_id,
            )
        except _CloudFetchError as exc:
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message="Failed to fetch gateway config from Enkrypt cloud",
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("[EnkryptAuthProvider] Unexpected auth error")
            return AuthResult(
                status=AuthStatus.ERROR,
                authenticated=False,
                message=f"Authentication failed: {exc}",
                error=str(exc),
            )

        if not mapped:
            return AuthResult(
                status=AuthStatus.INVALID_CREDENTIALS,
                authenticated=False,
                message="No configuration returned for provided apikey",
                error="empty_response",
            )

        return AuthResult(
            status=AuthStatus.SUCCESS,
            authenticated=True,
            message="Authentication successful (enkrypt cloud)",
            user_id=mapped.get("user_id"),
            project_id=mapped.get("project_id"),
            session_id=mapped.get("id"),
            gateway_config=mapped,
            mcp_config=mapped.get("mcp_config", []),
            metadata={
                "source": "enkrypt-cloud",
                "config_id": mapped.get("mcp_config_id"),
                "gateway_name": self.gateway_name,
                "gateway_version": self.gateway_version,
                **mapped.get("_request_context_extra", {}),
            },
        )

    async def validate_session(self, session_id: str) -> bool:
        # Sessions are stateless w.r.t. apikeys; the auth manager handles TTL.
        return True

    async def refresh_authentication(
        self, session_id: str, credentials: AuthCredentials
    ) -> AuthResult:
        return await self.authenticate(credentials)

    # ------------------------------------------------------------------
    # Backwards-compatible entry point used by AuthConfigManager and the
    # rest of the runtime via ``auth_manager.get_local_mcp_config``.
    # ------------------------------------------------------------------

    async def _get_local_config(
        self,
        gateway_key: str,
        project_id: Optional[str] = None,  # noqa: ARG002 - signature parity
        user_id: Optional[str] = None,  # noqa: ARG002 - signature parity
    ) -> Optional[Dict[str, Any]]:
        """Return the internal ``gateway_config`` dict for a given apikey.

        The signature mirrors ``LocalApiKeyProvider._get_local_config`` so all
        callers (cache_status_service, secure_tool_execution_service,
        discovery_service, etc.) work unchanged. ``project_id`` / ``user_id``
        are accepted but ignored: cloud auth derives them from the apikey
        and the response's ``request_context`` block.
        """
        cache_key = self._cache_key(gateway_key)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        response = await self._fetch_remote_gateway_config(gateway_key)
        if response is None:
            return None

        local_overrides = await self._load_local_server_overrides()
        mapped = self._map_response(response, local_overrides=local_overrides)
        self._cache_put(cache_key, mapped)
        return mapped

    # ------------------------------------------------------------------
    # Cloud fetch
    # ------------------------------------------------------------------

    async def _fetch_remote_gateway_config(
        self, gateway_key: str
    ) -> Optional[Dict[str, Any]]:
        """Call ``GET /mcp-gateway/get-gateway-config`` and return the body.

        Raises ``_CloudFetchError`` on transport / HTTP failures so the
        caller can surface a clear AuthResult.ERROR.
        """
        url = f"{self.base_url}/mcp-gateway/get-gateway-config"
        headers = {
            "apikey": gateway_key,
            "X-Enkrypt-MCP-Gateway": self.gateway_name,
            "X-Enkrypt-MCP-Gateway-Version": self.gateway_version,
        }
        if self.project_name:
            headers["X-Enkrypt-Project"] = self.project_name

        timeout_seconds = self._get_timeout_seconds()

        logger.info(
            "[EnkryptAuthProvider] fetching gateway config: gateway=%s/%s "
            "project=%s apikey=%s",
            self.gateway_name,
            self.gateway_version,
            self.project_name or "(inferred)",
            mask_key(gateway_key),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                ) as resp:
                    body_text = await resp.text()
                    if resp.status == 200:
                        try:
                            return json.loads(body_text)
                        except json.JSONDecodeError as e:
                            raise _CloudFetchError(
                                f"Cloud returned 200 with non-JSON body: {e}"
                            ) from e

                    # Hard-fail on every non-200 with the cloud's error body.
                    raise _CloudFetchError(
                        f"HTTP {resp.status} from {url}: {_truncate(body_text)}"
                    )
        except aiohttp.ClientError as e:
            raise _CloudFetchError(f"Transport error contacting {url}: {e}") from e
        except asyncio.TimeoutError as e:
            raise _CloudFetchError(
                f"Timeout after {timeout_seconds}s contacting {url}"
            ) from e

    def _get_timeout_seconds(self) -> float:
        """Pull the auth timeout from TimeoutManager if available."""
        try:
            from secure_mcp_gateway.services.timeout import get_timeout_manager

            return float(get_timeout_manager().get_timeout("auth"))
        except Exception:  # noqa: BLE001
            return float(DEFAULT_FETCH_TIMEOUT_SECONDS)

    # ------------------------------------------------------------------
    # Response mapping
    # ------------------------------------------------------------------

    def _map_response(
        self,
        response: Dict[str, Any],
        local_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Map ``ExpandedGatewayConfig`` → internal gateway-config dict.

        Internal contract (matches LocalApiKeyProvider._get_local_config)::

            {
                "id": "<composite cache id>",
                "project_name": str,
                "project_id": str,
                "user_id": str,
                "email": str,
                "mcp_config": [<server entries>],
                "mcp_config_id": str,
                "_request_context_extra": {<unmapped fields, for logging>},
            }
        """
        local_overrides = local_overrides or {}
        request_context = response.get("request_context") or {}

        # Cloud returns gateway_id as a numeric type — coerce to string so
        # downstream code (cache keys, session keys, log fields) can rely on
        # the same type as the local-file path produces.
        gateway_id = str(
            response.get("gateway_id")
            or response.get("gateway_saved_name")
            or self.gateway_name
        )
        # Prefer end-user (forwarded_*) if the calling app forwarded it,
        # else fall back to the apikey owner's user_id.
        user_id = (
            request_context.get("forwarded_user_id")
            or request_context.get("user_id")
            or "enkrypt_principal"
        )
        email = request_context.get("forwarded_user_email") or "not_provided"
        project_name = (
            request_context.get("project_name")
            or response.get("project_name")
            or self.project_name
            or "default"
        )
        # Until the cloud surfaces a stable project_id UUID, mirror the name.
        project_id = request_context.get("project_id") or project_name

        composite_id = f"{user_id}_{project_id}_{gateway_id}"

        # Cloud may mark individual servers as ``is_active: false`` (soft-
        # delete / disabled in the dashboard). Treat that as "do not surface
        # this server" — skip it before the per-server merge so it never
        # reaches discovery, tool execution, or the in-process cache. The
        # check is strict (``is False``) so missing / null / true all keep
        # the server, matching the cloud's own optimistic default.
        servers_in = response.get("expanded_servers") or []
        servers_out: List[Dict[str, Any]] = []
        for srv in servers_in:
            if isinstance(srv, dict) and srv.get("is_active") is False:
                logger.info(
                    "[EnkryptAuthProvider] skipping inactive server "
                    "saved_name=%s gateway=%s/%s",
                    srv.get("saved_name") or srv.get("server_name") or "?",
                    self.gateway_name,
                    self.gateway_version,
                )
                continue
            servers_out.append(self._map_server(srv, local_overrides))

        # Audit context: anything in request_context that we didn't promote
        # to a top-level field stays here for log enrichment. ``None`` values
        # are filtered out so they don't fan out to OTel attribute setters
        # (which raise ``Invalid type NoneType for attribute`` warnings) or
        # masquerade as real metric labels. The cloud explicitly returns
        # ``null`` for some fields like ``org_id`` and ``project_name`` when
        # they aren't bound for a given gateway, so this filter is load-
        # bearing, not defensive padding.
        promoted_keys = {
            "user_id",
            "forwarded_user_id",
            "forwarded_user_email",
            "project_name",
            "project_id",
        }
        rc_extra = {
            k: v
            for k, v in request_context.items()
            if k not in promoted_keys and v is not None
        }

        return {
            "id": composite_id,
            "project_name": project_name,
            "project_id": project_id,
            "user_id": user_id,
            "email": email,
            "mcp_config": servers_out,
            "mcp_config_id": gateway_id,
            "_request_context_extra": rc_extra,
        }

    def _map_server(
        self,
        server: Dict[str, Any],
        local_overrides: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Map one ``expanded_servers[]`` entry → one local mcp_config[] entry.

        The mapping is order-sensitive:

        1. Take the registry-shipped policy from ``mcp_config.<policy>``.
        2. If ``gateway_overrides.<policy>`` is non-null, replace the whole
           policy with it (cloud-spec semantics: gateway-level beats
           server-level).
        3. Layer ``local_server_overrides[saved_name]`` on top for fields
           the cloud doesn't model yet (sandbox / oauth_config / denied_tools).
        """
        saved_name = server.get("saved_name") or server.get("server_name") or "unknown"
        cloud_mcp = server.get("mcp_config") or {}
        gateway_overrides = server.get("gateway_overrides") or {}

        # Policy fields: gateway_overrides wins when present. The cloud
        # often returns partial policy objects (e.g. only ``enabled`` and
        # ``guardrail_name``); fill missing keys from the empty-policy template
        # so downstream consumers can safely index ``policy["block"]`` etc.
        def _pick_policy(name: str) -> Optional[Dict[str, Any]]:
            override = gateway_overrides.get(name)
            chosen = override if override else cloud_mcp.get(name)
            if chosen is None:
                return None
            return {**_empty_policy(), **chosen}

        tool_policy = _pick_policy("tool_guardrails_policy")
        input_policy = _pick_policy("input_guardrails_policy")
        output_policy = _pick_policy("output_guardrails_policy")

        # OAuth lives inside mcp_config in the cloud spec; gateway_overrides
        # may override it too.
        oauth_config = (
            gateway_overrides.get("oauth_config")
            or cloud_mcp.get("oauth_config")
        )

        merged: Dict[str, Any] = {
            "server_name": saved_name,
            "description": server.get("description", ""),
            "config": cloud_mcp.get("config", {}),
            "tools": cloud_mcp.get("tools", {}),
            "enable_server_info_validation": cloud_mcp.get(
                "enable_server_info_validation", False
            ),
            "enable_tool_guardrails": (tool_policy or {}).get("enabled", False),
            "tool_guardrails_policy": tool_policy or _empty_policy(),
            "input_guardrails_policy": input_policy or _empty_policy(),
            "output_guardrails_policy": output_policy or _empty_policy(),
        }
        if oauth_config:
            merged["oauth_config"] = oauth_config

        # Layer local-only fields the cloud spec doesn't carry yet.
        # Cloud value (when ever it lands in spec) will win — local overrides
        # are intentionally fall-throughs, not authoritative.
        local = local_overrides.get(saved_name) or {}
        for field_name in ("sandbox", "denied_tools", "oauth_config"):
            if field_name not in merged and field_name in local:
                merged[field_name] = local[field_name]

        return merged

    # ------------------------------------------------------------------
    # Local-only field overrides (sandbox / denied_tools / oauth_config)
    # ------------------------------------------------------------------

    async def _load_local_server_overrides(
        self,
    ) -> Dict[str, Dict[str, Any]]:
        """Read the optional ``local_server_overrides`` block from the local
        config file. Returns ``{}`` if the file is missing or the block is
        absent — does NOT fall back to the file's full ``mcp_configs``."""
        running_in_docker = is_docker()
        config_path = DOCKER_CONFIG_PATH if running_in_docker else CONFIG_PATH
        if not os.path.exists(config_path):
            return {}

        def _load() -> Dict[str, Any]:
                with open(config_path, encoding="utf-8") as f:
                    return json.load(f)

        try:
            data = await asyncio.to_thread(_load)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[EnkryptAuthProvider] could not read %s for local_server_overrides: %s",
                config_path,
                exc,
            )
            return {}

        block = data.get("local_server_overrides") or {}
        if not isinstance(block, dict):
            logger.warning(
                "[EnkryptAuthProvider] local_server_overrides is not an object — ignoring"
            )
            return {}
        return block

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _cache_key(self, gateway_key: str) -> str:
        # Hash the apikey so even an in-memory dump doesn't leak it. The
        # gateway_name+version+project_name are part of the key so a single
        # process that handles multiple gateways/projects (uncommon, but
        # supported) doesn't cross-contaminate.
        h = hashlib.sha256(
            f"{gateway_key}|{self.gateway_name}|{self.gateway_version}|{self.project_name or ''}".encode()
        ).hexdigest()
        return h[:16]

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self._cache.get(key)
        if not entry:
                return None
        expires_at, value = entry
        if expires_at < time.time():
            self._cache.pop(key, None)
            return None
        return value

    def _cache_put(self, key: str, value: Dict[str, Any]) -> None:
        self._cache[key] = (time.time() + self.cache_ttl_seconds, value)

    def invalidate_cache(self) -> None:
        """Public method so CLI / API can blow away the cache after rotation."""
        self._cache.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CloudFetchError(Exception):
    """Raised when the cloud call fails for any reason (HTTP, transport,
    JSON). The provider catches this and surfaces it as AuthStatus.ERROR
    with the original message attached, so operators can grep logs for
    the cloud failure rather than seeing a generic auth error."""


def _empty_policy() -> Dict[str, Any]:
    """Default GuardrailsPolicy used when neither base nor override is set."""
    return {
        "enabled": False,
        "guardrail_name": "",
        "additional_config": {},
        "block": [],
    }


def _truncate(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else text[:limit] + "...(truncated)"
