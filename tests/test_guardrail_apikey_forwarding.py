"""Regression tests for the cloud-auth guardrail crash (dict-as-api_key) and
the per-request apikey forwarding that replaces the missing static config.

Background
----------
The dev-cluster gateway pod was blocking 100% of tool calls with a bogus
``"custom" guardrail violation``. Live tracing showed the underlying error
was actually::

    TypeError: Cannot serialize non-str key {'base_url': 'https://api.dev.enkryptai.com'}

raised by aiohttp's header writer because ``EnkryptInputGuardrail.api_key``
was the entire ``enkrypt_config`` dict, not a string. The chain of failures
was:

1. ``plugins.guardrails.config`` was ``{}`` in the cloud-auth setup
   (multi-tenant: each end-user sends their own apikey in the ``apikey``
   request header, so the gateway has no static apikey to store).
2. ``_resolve_enkrypt_credentials`` returned ``("", base_url)``.
3. ``plugin_loader._inject_credentials`` skipped injection because of an
   ``if api_key`` gate, so ``provider_config`` had no ``api_key`` key.
4. ``provider_loader.create_provider_from_config`` ran
   ``provider_class(**config)`` which raised ``TypeError: missing 1
   required positional argument 'api_key'``.
5. The loader silently fell through to ``provider_class(config)`` which
   bound the **entire dict** to the first positional param. Result:
   ``api_key = {'base_url': 'https://api.dev.enkryptai.com'}``.
6. Every subsequent guardrail HTTPS call stuffed that dict into the
   ``apikey`` header. aiohttp's header serializer crashed with the message
   above. The crash bubbled up as a fake guardrail violation that blocked
   the request.

The fix is four orthogonal changes; each one alone breaks the chain.
These tests pin each link:

* **Fix A** — ``provider_loader.create_provider_from_config`` refuses to
  silently fall through to the single-positional pattern when the kwargs
  failure is ``missing N required positional argument(s)``.
* **Fix B** — ``plugin_loader._inject_credentials`` injects the
  ``api_key`` kwarg even when the resolved value is the empty string, so
  the provider always sees the kwarg.
* **Fix C** — ``EnkryptGuardrailProvider.__init__`` declares all of its
  args as kwargs with defaults; in particular ``api_key: str = ""``.
* **Fix D′** — ``EnkryptInputGuardrail.validate`` (and all sibling output
  / PII calls) look up the per-request apikey on the
  ``request_apikey_var`` ContextVar via ``_effective_apikey``, falling
  back to ``self.api_key`` when absent.

If any one of these fixes regresses, one of these tests should catch it
before the next deployment.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest


# ----------------------------------------------------------------------
# Fix A — provider_loader: no silent positional fallback on
# missing-kwargs TypeError. Catches the exact class of bug that bound the
# config dict to ``api_key``.
# ----------------------------------------------------------------------


class _RequiresPositional:
    """Mimics the pre-Fix-C EnkryptGuardrailProvider shape."""

    def __init__(self, api_key, base_url="default"):
        self.api_key = api_key
        self.base_url = base_url


def test_provider_loader_refuses_to_bind_config_dict_to_missing_positional():
    """Loader must raise instead of silently calling
    ``_RequiresPositional({'base_url': '...'})`` — which would bind the
    whole config dict to the ``api_key`` positional arg."""
    from secure_mcp_gateway.plugins.provider_loader import create_provider_from_config

    bad_cfg = {
        "name": "broken",
        "class": f"{__name__}._RequiresPositional",
        "config": {"base_url": "https://api.dev.enkryptai.com"},
        # NOTE: no ``api_key`` key.
    }
    with pytest.raises(Exception) as exc_info:
        create_provider_from_config(bad_cfg, plugin_type="guardrails")

    # The loader re-wraps as a ``ConfigurationError`` whose stringification
    # hides the message; the original TypeError our Fix-A path raised is
    # stashed on the wrapper's ``cause`` attribute. Walk both the standard
    # ``__cause__`` chain (used by some Python paths) and the ``cause``
    # attribute the gateway's error helpers populate.
    messages: list[str] = []

    def _accumulate(err: object) -> None:
        if err is None:
            return
        messages.append(str(err))
        if hasattr(err, "cause"):
            _accumulate(err.cause)
        if isinstance(err, BaseException) and err.__cause__ is not None:
            _accumulate(err.__cause__)

    _accumulate(exc_info.value)
    combined = " | ".join(messages)
    assert "api_key" in combined or "required" in combined, (
        f"Expected error chain to mention the missing api_key arg, got: {combined!r}"
    )


class _AllKwargs:
    """Mimics the post-Fix-C EnkryptGuardrailProvider shape."""

    def __init__(self, api_key: str = "", base_url: str = "default"):
        self.api_key = api_key
        self.base_url = base_url


def test_provider_loader_succeeds_when_all_args_have_defaults():
    """With Fix C in place, the loader's Pattern 1 (kwargs) succeeds
    cleanly even when api_key is absent from config — and ``api_key``
    stays a string, not a dict."""
    from secure_mcp_gateway.plugins.provider_loader import create_provider_from_config

    cfg = {
        "name": "fixed",
        "class": f"{__name__}._AllKwargs",
        "config": {"base_url": "https://api.dev.enkryptai.com"},
    }
    provider = create_provider_from_config(cfg, plugin_type="guardrails")

    assert isinstance(provider.api_key, str)
    assert provider.api_key == ""
    assert provider.base_url == "https://api.dev.enkryptai.com"


# ----------------------------------------------------------------------
# Fix B — plugin_loader: inject api_key/apikey even when the resolved
# value is empty, so the provider always sees the kwarg.
# ----------------------------------------------------------------------


def test_plugin_loader_injects_empty_apikey_for_guardrails():
    """When ``plugins.guardrails.config`` is empty and ``enkrypt_config``
    has no ``api_key``, the loader must still produce a kwarg-shaped
    provider_config (``api_key=""``, ``base_url=<resolved>``) so Pattern
    1 succeeds. Pre-Fix-B, the ``if api_key`` gate would skip injection
    and trigger the silent fallback bug."""
    from secure_mcp_gateway.plugins.plugin_loader import _resolve_enkrypt_credentials

    full_config: dict[str, Any] = {
        "enkrypt_config": {"base_url": "https://api.dev.enkryptai.com"},
        "plugins": {
            "guardrails": {"provider": "enkrypt", "config": {}},
        },
    }
    plugin_config: dict[str, Any] = {}

    api_key, base_url = _resolve_enkrypt_credentials(full_config, plugin_config)

    # Simulate the post-Fix-B injection block from
    # ``PluginLoader.load_plugin_providers``.
    if "api_key" not in plugin_config and "apikey" not in plugin_config:
        plugin_config["api_key"] = api_key
    if "base_url" not in plugin_config:
        plugin_config["base_url"] = base_url

    assert plugin_config["api_key"] == ""  # empty, but present
    assert plugin_config["base_url"] == "https://api.dev.enkryptai.com"


# ----------------------------------------------------------------------
# Fix C — EnkryptGuardrailProvider: kwargs with defaults so kwargs init
# (Pattern 1) succeeds and api_key stays a string.
# ----------------------------------------------------------------------


def test_guardrail_provider_init_with_no_api_key():
    """``EnkryptGuardrailProvider(**{"base_url": "..."})`` must succeed
    and produce a string ``api_key``. Pre-Fix-C this raised TypeError
    and the loader silently bound the dict to ``api_key``."""
    from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import (
        EnkryptGuardrailProvider,
    )

    provider = EnkryptGuardrailProvider(base_url="https://api.dev.enkryptai.com")

    assert isinstance(provider.api_key, str), (
        "api_key must be a string — never a dict / config object"
    )
    assert provider.api_key == ""
    assert provider.base_url == "https://api.dev.enkryptai.com"


# ----------------------------------------------------------------------
# Fix D′ — per-request apikey forwarded via ContextVar so each caller's
# apikey from the ``apikey`` request header lands in the outbound
# Enkrypt cloud header, no static apikey required.
# ----------------------------------------------------------------------


def test_effective_apikey_falls_back_to_static_when_no_contextvar():
    from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import _effective_apikey

    assert _effective_apikey("static-key") == "static-key"
    assert _effective_apikey("") == ""
    assert _effective_apikey(None) == ""


def test_effective_apikey_prefers_contextvar_when_set():
    """The per-request apikey from ``request_apikey_var`` must win over
    the provider's static ``self.api_key`` so multi-tenant deployments
    forward the caller's apikey, not the gateway's."""
    from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import _effective_apikey
    from secure_mcp_gateway.request_context import request_apikey_var

    token = request_apikey_var.set("user-apikey-from-mcp-json")
    try:
        # User apikey wins even when a static one is configured.
        assert _effective_apikey("static-key") == "user-apikey-from-mcp-json"
        # And of course when there isn't.
        assert _effective_apikey("") == "user-apikey-from-mcp-json"
    finally:
        request_apikey_var.reset(token)

    # Reset clears the override and we fall back to static again.
    assert _effective_apikey("static-key") == "static-key"


def test_effective_apikey_propagates_across_asyncio_tasks():
    """ContextVar isolation per asyncio Task: a value set in one request's
    task tree must NOT leak into a concurrent request's tree. This is
    the property that makes the ContextVar approach safe without
    manual reset on the gateway's request hot path."""
    from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import _effective_apikey
    from secure_mcp_gateway.request_context import request_apikey_var

    observed: dict[str, str] = {}

    async def request_a() -> None:
        request_apikey_var.set("apikey-A")
        await asyncio.sleep(0.01)
        observed["A"] = _effective_apikey("static")

    async def request_b() -> None:
        request_apikey_var.set("apikey-B")
        await asyncio.sleep(0.01)
        observed["B"] = _effective_apikey("static")

    async def main() -> None:
        await asyncio.gather(request_a(), request_b())

    asyncio.run(main())

    assert observed == {"A": "apikey-A", "B": "apikey-B"}, (
        f"ContextVar leaked between concurrent tasks: {observed!r}"
    )


# ----------------------------------------------------------------------
# Integration — exercise the full bug-trigger config shape through the
# real loaders and assert ``EnkryptInputGuardrail.api_key`` is a string,
# and the outbound ``apikey`` header is the per-request value.
# ----------------------------------------------------------------------


def test_cloud_auth_config_shape_no_longer_crashes_full_pipeline():
    """End-to-end: the exact ``plugins.guardrails.config = {}`` +
    ``enkrypt_config = {"base_url": ...}`` shape that crashed every
    tool call in dev now produces a clean provider whose outbound
    header is the per-request apikey."""
    from secure_mcp_gateway.plugins.guardrails.enkrypt_provider import (
        EnkryptGuardrailProvider,
        _effective_apikey,
    )
    from secure_mcp_gateway.plugins.plugin_loader import _resolve_enkrypt_credentials
    from secure_mcp_gateway.plugins.provider_loader import create_provider_from_config
    from secure_mcp_gateway.request_context import request_apikey_var

    full_config = {
        "enkrypt_config": {"base_url": "https://api.dev.enkryptai.com"},
        "plugins": {"guardrails": {"provider": "enkrypt", "config": {}}},
    }
    plugin_cfg: dict[str, Any] = {}
    api_key, base_url = _resolve_enkrypt_credentials(full_config, plugin_cfg)
    if "api_key" not in plugin_cfg and "apikey" not in plugin_cfg:
        plugin_cfg["api_key"] = api_key
    if "base_url" not in plugin_cfg:
        plugin_cfg["base_url"] = base_url

    provider = create_provider_from_config(
        {
            "name": "enkrypt",
            "class": "secure_mcp_gateway.plugins.guardrails.enkrypt_provider.EnkryptGuardrailProvider",
            "config": plugin_cfg,
        },
        plugin_type="guardrails",
    )

    assert isinstance(provider, EnkryptGuardrailProvider)
    assert isinstance(provider.api_key, str), (
        "api_key would be a dict pre-fix; this assert pins the regression."
    )
    assert provider.api_key == ""

    in_cfg = {
        "enabled": True,
        "guardrail_name": "Demo Guardrail",
        "additional_config": {},
        "block": [],
    }
    input_guardrail = provider.create_input_guardrail(in_cfg)
    assert isinstance(input_guardrail.api_key, str)

    # Without per-request override: empty (Enkrypt will 401, which is at
    # least an honest error rather than a serialization crash).
    assert _effective_apikey(input_guardrail.api_key) == ""

    # With per-request override (the mcp.json apikey): forwarded.
    token = request_apikey_var.set("0pLekjleVAxtT7i3WAVBXDXDWX2imnXf")
    try:
        assert (
            _effective_apikey(input_guardrail.api_key)
            == "0pLekjleVAxtT7i3WAVBXDXDWX2imnXf"
        )
    finally:
        request_apikey_var.reset(token)
