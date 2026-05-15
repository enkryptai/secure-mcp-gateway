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
