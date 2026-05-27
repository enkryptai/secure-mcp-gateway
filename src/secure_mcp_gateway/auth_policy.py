"""Provider-aware admin-API-key resolution policy.

Lives in its own module (with **no side-effect imports**) so it can be
unit-tested in isolation and reused by both ``api_models.py`` and
``api_server.py`` without pulling in the heavy package init chain
(``cli`` / ``utils`` / telemetry / ...).

Policy
------

The local REST admin API on port 8001 has its own credential because it
ultimately writes to the on-disk config and orchestrates the gateway. We
resolve the set of acceptable admin credentials from the loaded config:

* ``plugins.auth.provider == "enkrypt"`` — ``admin_apikey`` is **optional**.
  The Enkrypt cloud ``api_key`` from ``enkrypt_config`` is also accepted
  because the operator already holds it for cloud calls, and requiring a
  second secret on the same machine adds friction without meaningful
  security gain (anyone with the cloud apikey can already manage the
  gateway via the Enkrypt cloud APIs).

* Any other provider (``local_apikey``, custom, ...) — ``admin_apikey`` is
  **required**. The cloud ``api_key`` is NOT accepted because the local
  auth provider has no trust relationship with Enkrypt cloud and we must
  not silently widen the admin trust boundary.

* The generator placeholder ``"YOUR_ENKRYPT_API_KEY"`` is never accepted
  as a credential — a freshly generated, unfilled config must not grant
  admin access by accident.

Where ``admin_apikey`` lives in the config
------------------------------------------

The canonical location is **root-level** ``admin_apikey``. It is not
semantically an Enkrypt-cloud credential (the cloud never sees it), so
nesting it under ``enkrypt_config`` was misleading. To keep migration
painless, we also accept ``enkrypt_config.admin_apikey`` as a
**deprecated** location — older installs that still have the key there
continue to work without manual editing. When both are present, both
keys are accepted so admins can copy-paste-rotate during migration.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Placeholder string emitted by ``secure-mcp-gateway generate-config`` for
# the Enkrypt cloud apikey. Treating it as a credential would let an
# unconfigured install be administered with a well-known value.
ENKRYPT_API_KEY_PLACEHOLDER = "YOUR_ENKRYPT_API_KEY"

# Same idea for the optional cache-flush org-id gate -- the generator
# emits this placeholder so operators can see the field exists, but the
# placeholder must NOT enable org-id-gated flush (every gateway would
# share the same magic value).
ENKRYPT_ORG_ID_PLACEHOLDER = "YOUR_ENKRYPT_ORG_ID"


def resolve_admin_keys(config: Dict[str, Any]) -> List[str]:
    """Return the list of API keys that authenticate the REST admin API.

    See module docstring for the policy. The returned list preserves a
    deterministic order:

    1. Root-level ``admin_apikey`` (canonical)
    2. ``enkrypt_config.admin_apikey`` (deprecated, still honored)
    3. ``enkrypt_config.api_key`` (only if provider == "enkrypt")

    Empty/blank entries are filtered. Duplicate values across locations
    are de-duplicated. The result is a ``list`` rather than a ``set`` so
    callers can log which slot matched a request if needed, but ``in``
    membership checks are still safe.
    """
    enkrypt_cfg = config.get("enkrypt_config") or {}
    provider = (
        (config.get("plugins") or {}).get("auth", {}).get("provider")
        or "local_apikey"
    )

    keys: List[str] = []

    root_admin = config.get("admin_apikey") or ""
    if root_admin:
        keys.append(root_admin)

    nested_admin = enkrypt_cfg.get("admin_apikey") or ""
    if nested_admin and nested_admin not in keys:
        keys.append(nested_admin)

    if provider == "enkrypt":
        enkrypt_api_key = enkrypt_cfg.get("api_key") or ""
        if (
            enkrypt_api_key
            and enkrypt_api_key != ENKRYPT_API_KEY_PLACEHOLDER
            and enkrypt_api_key not in keys
        ):
            keys.append(enkrypt_api_key)

    return keys


def describe_missing_admin_key_hint(provider: str) -> str:
    """Human-readable hint for the 500 response when no admin key resolves.

    Pulled out so the two ``get_api_key`` call sites stay in lock-step on
    the error message.
    """
    if provider == "enkrypt":
        return (
            "Set enkrypt_config.api_key (cloud apikey) or "
            "enkrypt_config.admin_apikey."
        )
    return (
        f"Auth provider is '{provider}'; "
        "set enkrypt_config.admin_apikey to enable the REST admin API."
    )


# ---------------------------------------------------------------------------
# Cache-flush authorization (org-id-gated, for provider=enkrypt)
# ---------------------------------------------------------------------------

# Outcome strings returned by ``authorize_apikey_for_cache_flush`` so call
# sites (the FastAPI dep on port 8001 and the Starlette handler on port
# 8000) emit identical structured error responses + log lines.
AUTHZ_OK_STATIC = "ok_static_admin_key"
AUTHZ_OK_ORG_MATCH = "ok_org_match"
AUTHZ_MISSING_KEY = "missing_apikey"
AUTHZ_BAD_KEY = "invalid_apikey"
AUTHZ_NO_ADMIN_CONFIGURED = "no_admin_configured"
AUTHZ_NO_ORG_CONFIGURED = "no_org_gating_configured"
AUTHZ_ORG_MISMATCH = "org_mismatch"
AUTHZ_CLOUD_UNAVAILABLE = "cloud_unavailable"


async def authorize_apikey_for_cache_flush(
    config: Dict[str, Any],
    apikey: str | None,
) -> Dict[str, Any]:
    """Authorize an apikey for the cache-flush admin endpoints.

    Two acceptance paths (tried in order):

    1. **Static admin key.** The apikey matches one of the keys returned by
       :func:`resolve_admin_keys` (root-level ``admin_apikey``, deprecated
       ``enkrypt_config.admin_apikey``, or under ``provider=enkrypt`` the
       operator's own ``enkrypt_config.api_key``). Returns immediately
       without a cloud roundtrip.

    2. **Cloud-org match.** When ``plugins.auth.provider == "enkrypt"``
       AND ``enkrypt_config.org_id`` is configured, we call
       ``GET {enkrypt_config.base_url}/consumer-info`` with the presented
       apikey. If the cloud accepts the apikey AND the returned
       ``org_id`` matches the configured ``org_id``, the request is
       authorized. This lets ANY cloud user belonging to the gateway's
       org trigger a flush -- needed because under cloud auth the
       customer doesn't necessarily hold the gateway operator's static
       admin key.

    Returns a dict with the following shape::

        {
            "authorized": bool,
            "reason": AUTHZ_*,
            "via": "static_admin_key" | "org_match" | None,
            "principal": Optional[str],   # email / user_id when known
            "status_code": int,            # HTTP code the caller should return
        }

    The function NEVER raises. Network errors / cloud rejections are
    translated to ``authorized=False`` with a descriptive ``reason``.

    Heavy imports (``aiohttp`` via ``ConsumerInfoClient``) are deferred
    inside the cloud path so plain static-key admin flushes don't pull
    in the playground dependency stack at import time.
    """
    if not apikey:
        return {
            "authorized": False,
            "reason": AUTHZ_MISSING_KEY,
            "via": None,
            "principal": None,
            "status_code": 401,
            "detail": "apikey header required",
        }

    # --- Path 1: static admin keys (cheap, no I/O) --------------------------
    accepted = resolve_admin_keys(config)
    if apikey in accepted:
        return {
            "authorized": True,
            "reason": AUTHZ_OK_STATIC,
            "via": "static_admin_key",
            "principal": None,
            "status_code": 200,
        }

    # --- Path 2: cloud /consumer-info org-id match --------------------------
    provider = (
        (config.get("plugins") or {}).get("auth", {}).get("provider")
        or "local_apikey"
    )
    if provider != "enkrypt":
        # No static match AND no cloud check available. If admin is
        # *configured* but didn't match, the apikey is just wrong.
        # Otherwise, the gateway isn't admin-configured at all.
        if accepted:
            return {
                "authorized": False,
                "reason": AUTHZ_BAD_KEY,
                "via": None,
                "principal": None,
                "status_code": 401,
                "detail": "invalid apikey",
            }
        return {
            "authorized": False,
            "reason": AUTHZ_NO_ADMIN_CONFIGURED,
            "via": None,
            "principal": None,
            "status_code": 500,
            "detail": (
                "Admin API key not configured on the gateway. Set "
                "'admin_apikey' (or, for the enkrypt provider, "
                "'enkrypt_config.api_key') in enkrypt_mcp_config.json."
            ),
        }

    enkrypt_cfg = config.get("enkrypt_config") or {}
    configured_org_id = (enkrypt_cfg.get("org_id") or "").strip()
    if not configured_org_id or configured_org_id == ENKRYPT_ORG_ID_PLACEHOLDER:
        # No org gating configured (empty, missing, or still the
        # generator placeholder). Static-key didn't match either, so
        # we're done -- but the message should hint at the new feature.
        return {
            "authorized": False,
            "reason": AUTHZ_NO_ORG_CONFIGURED,
            "via": None,
            "principal": None,
            "status_code": 401,
            "detail": (
                "invalid apikey (and 'enkrypt_config.org_id' is not "
                "configured -- set it to enable org-id-gated flush)"
            ),
        }

    base_url = (enkrypt_cfg.get("base_url") or "https://api.enkryptai.com").rstrip("/")

    try:
        # Lazy import: pulls in aiohttp + the playground consumer-info
        # cache. Module-level imports here would force every CLI / API
        # entry point to pay the cost on boot.
        from secure_mcp_gateway.services.health.consumer_info_client import (
            ConsumerAuthError,
            ConsumerInfoError,
            ConsumerTimeoutError,
            ConsumerUpstreamError,
            fetch_consumer_info,
        )
    except Exception as e:  # noqa: BLE001
        return {
            "authorized": False,
            "reason": AUTHZ_CLOUD_UNAVAILABLE,
            "via": None,
            "principal": None,
            "status_code": 500,
            "detail": f"consumer-info client unavailable: {e}",
        }

    try:
        info = await fetch_consumer_info(base_url=base_url, apikey=apikey)
    except ConsumerAuthError:
        return {
            "authorized": False,
            "reason": AUTHZ_BAD_KEY,
            "via": None,
            "principal": None,
            "status_code": 401,
            "detail": "invalid apikey (cloud /consumer-info rejected)",
        }
    except ConsumerTimeoutError:
        return {
            "authorized": False,
            "reason": AUTHZ_CLOUD_UNAVAILABLE,
            "via": None,
            "principal": None,
            "status_code": 502,
            "detail": "cloud /consumer-info timed out",
        }
    except ConsumerUpstreamError as e:
        return {
            "authorized": False,
            "reason": AUTHZ_CLOUD_UNAVAILABLE,
            "via": None,
            "principal": None,
            "status_code": 502,
            "detail": f"cloud /consumer-info upstream error: {e}",
        }
    except ConsumerInfoError as e:
        return {
            "authorized": False,
            "reason": AUTHZ_CLOUD_UNAVAILABLE,
            "via": None,
            "principal": None,
            "status_code": 502,
            "detail": f"cloud /consumer-info error: {e}",
        }
    except Exception as e:  # noqa: BLE001 -- defense-in-depth
        return {
            "authorized": False,
            "reason": AUTHZ_CLOUD_UNAVAILABLE,
            "via": None,
            "principal": None,
            "status_code": 502,
            "detail": f"unexpected cloud error: {e}",
        }

    cloud_org_id = (info.org_id or "").strip()
    if not cloud_org_id or cloud_org_id != configured_org_id:
        return {
            "authorized": False,
            "reason": AUTHZ_ORG_MISMATCH,
            "via": None,
            "principal": info.email or info.user_id,
            "status_code": 403,
            "detail": (
                f"apikey org_id {cloud_org_id!r} does not match gateway "
                f"configured org_id {configured_org_id!r}"
            ),
        }

    return {
        "authorized": True,
        "reason": AUTHZ_OK_ORG_MATCH,
        "via": "org_match",
        "principal": info.email or info.user_id,
        "status_code": 200,
    }
