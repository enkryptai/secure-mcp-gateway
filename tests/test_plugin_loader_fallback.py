"""Regression tests for PluginLoader fallback behavior.

Background
----------
A user-facing crash was observed in v2.2.0 when ``plugins.telemetry.provider``
in the gateway config was set to a value that the loader does not recognise
(historic example: ``"stdout"`` — never a real provider name, leaked into
some early example configs).

The sequence was:

1. ``PluginLoader.load_plugin_providers`` detected the unknown name and
   *intended* to fall back to ``opentelemetry``.
2. It rewrote ``class_path``/``provider_name`` but **did not** repopulate
   ``provider_config``. The caller's empty ``"config": {}`` flowed through
   to ``OpenTelemetryProvider(**{})``.
3. ``OpenTelemetryProvider.__init__`` only called ``self.initialize(config)``
   when ``config`` was truthy; with no kwargs unpacked it ran the no-op
   branch, leaving ``self._initialized == False``.
4. First call to ``manager.get_tracer()`` → ``provider.create_tracer()``
   raised ``RuntimeError: Provider not initialized. Call initialize() first.``
   which killed the MCP server before the first request, surfacing in
   Cursor as ``MCP error -32000: Connection closed``.

These tests pin the two fixes that prevent the regression:

* The fallback path in :pyfunc:`PluginLoader.load_plugin_providers` delegates
  to :pyfunc:`PluginLoader._load_default_provider`, which knows the correct
  per-plugin defaults (``enabled/url/insecure`` for telemetry, the centralised
  ``enkrypt_config`` credentials for auth/guardrails).

* :pyclass:`OpenTelemetryProvider` always invokes ``initialize`` from its
  constructor, even when called with ``None``/``{}`` — defence in depth in
  case any future code path skips the loader's config wiring.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest


# ----------------------------------------------------------------------
# Bare-minimum stub manager so the loader has somewhere to register into.
# Mirrors the surface area the real ``TelemetryConfigManager`` exposes
# (``list_providers`` + ``register_provider``) without dragging in
# telemetry singletons or globals.
# ----------------------------------------------------------------------
class _StubManager:
    def __init__(self) -> None:
        self.registered: List[Any] = []

    def list_providers(self) -> List[str]:
        return [getattr(p, "name", "") for p in self.registered]

    def register_provider(self, provider: Any) -> None:
        self.registered.append(provider)


def _fresh_telemetry_config(provider_name: str) -> Dict[str, Any]:
    """Return a config that drives the loader to the supplied provider name."""
    return {
        "plugins": {
            "telemetry": {
                "provider": provider_name,
                "config": {},
            }
        }
    }


# ======================================================================
# Section 1 — PluginLoader fallback path
# ======================================================================
class TestUnknownTelemetryProviderFallback:
    """The exact scenario observed in the wild: a stale ``stdout`` value."""

    def test_unknown_provider_falls_back_to_opentelemetry_initialized(self) -> None:
        """An unknown telemetry provider name must produce a *fully
        initialized* opentelemetry provider, not a half-built one."""
        from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

        manager = _StubManager()
        PluginLoader.load_plugin_providers(
            _fresh_telemetry_config("stdout"), "telemetry", manager
        )

        assert len(manager.registered) == 1, (
            "Exactly one provider should be registered after fallback, "
            f"got {len(manager.registered)}"
        )
        provider = manager.registered[0]
        assert provider.name == "opentelemetry"
        assert getattr(provider, "_initialized", False) is True, (
            "Fallback provider must have ``_initialized == True`` so the "
            "first ``get_tracer`` / ``create_tracer`` call does not raise."
        )

    def test_unknown_provider_does_not_raise(self) -> None:
        """The legacy crash bubbled out of ``get_tracer``. Verify that even
        the *naive* path of constructing a tracer right after loading works
        — that was the failure mode in the Cursor log."""
        from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

        manager = _StubManager()
        PluginLoader.load_plugin_providers(
            _fresh_telemetry_config("stdout"), "telemetry", manager
        )

        provider = manager.registered[0]
        provider.create_tracer("regression-probe")  # must not raise

    def test_known_opentelemetry_provider_still_initialized(self) -> None:
        """The fix to the fallback path must not regress the happy path."""
        from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

        manager = _StubManager()
        PluginLoader.load_plugin_providers(
            _fresh_telemetry_config("opentelemetry"), "telemetry", manager
        )

        assert len(manager.registered) == 1
        assert manager.registered[0].name == "opentelemetry"
        assert manager.registered[0]._initialized is True

    @pytest.mark.parametrize(
        "junk_name",
        ["stdout", "json", "console", "loguru", "DataDog", "random-string", ""],
    )
    def test_a_range_of_unknown_names_all_fall_back_safely(
        self, junk_name: str
    ) -> None:
        """Defence in depth: any unknown name should land us on a healthy
        opentelemetry provider, not crash the loader."""
        from secure_mcp_gateway.plugins.plugin_loader import PluginLoader

        manager = _StubManager()
        PluginLoader.load_plugin_providers(
            _fresh_telemetry_config(junk_name), "telemetry", manager
        )

        assert len(manager.registered) == 1
        provider = manager.registered[0]
        assert provider.name == "opentelemetry"
        assert provider._initialized is True


# ======================================================================
# Section 2 — OpenTelemetryProvider hardening
# ======================================================================
class TestOpenTelemetryProviderAlwaysInitializes:
    """The constructor must always call ``initialize`` so the provider is
    usable even if a caller (test, fallback path, future plugin) forgets to
    pass a config dict."""

    def test_no_arg_construction_initializes_with_defaults(self) -> None:
        from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
            OpenTelemetryProvider,
        )

        provider = OpenTelemetryProvider()

        assert provider._initialized is True
        provider.create_tracer("regression-probe")  # must not raise

    def test_empty_dict_construction_initializes(self) -> None:
        from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
            OpenTelemetryProvider,
        )

        provider = OpenTelemetryProvider({})

        assert provider._initialized is True
        provider.create_tracer("regression-probe")

    def test_none_construction_initializes(self) -> None:
        from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
            OpenTelemetryProvider,
        )

        provider = OpenTelemetryProvider(None)

        assert provider._initialized is True
        provider.create_tracer("regression-probe")

    def test_explicit_disabled_config_still_initializes_object(self) -> None:
        """Telemetry can be turned off, but the *provider object* itself
        must still be initialized so it satisfies the ``TelemetryProvider``
        protocol (tracer/meter calls return no-op spans, never raise)."""
        from secure_mcp_gateway.plugins.telemetry.opentelemetry_provider import (
            OpenTelemetryProvider,
        )

        provider = OpenTelemetryProvider({"enabled": False})

        assert provider._initialized is True
        provider.create_tracer("regression-probe")
