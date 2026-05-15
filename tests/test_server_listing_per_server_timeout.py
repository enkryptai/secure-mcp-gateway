"""Regression tests for ``ServerListingService._discover_and_return_servers``.

Background
----------
A user-facing defect was observed in v2.2.x where calling
``enkrypt_list_all_servers(discover_tools=True)`` against a gateway with one
slow-cold-starting server (``uvx`` / ``npx`` first run downloading wheels)
returned this misleading shape::

    {
      "status": "success",                       # <-- silently misleading
      "message": "Tools discovery tried for all servers",
      "discovery_failed_servers": [],            # <-- empty
      "discovery_success_servers": [],           # <-- empty
      "available_servers": {
        <every server>: { "tools": {}, "tools_source": "needs_discovery", ... }
      }
    }

Root cause
~~~~~~~~~~
The historic implementation wrapped the entire ``asyncio.gather`` of all
per-server discoveries in a single ``execute_with_timeout`` budget. When the
slowest server blew that budget, the wrapper returned ``None``, the
listing-service's ``for item in results`` loop ran zero times, and the
placeholder ``servers_with_tools`` entries (set by ``_process_servers``) were
returned unchanged. ``status`` was initialised to ``"success"`` and never
overwritten because no items were processed -- so the failure was hidden.

Fix that these tests pin
~~~~~~~~~~~~~~~~~~~~~~~~
* Each server's discovery is wrapped in its own ``asyncio.wait_for`` -- one
  slow server can fail in isolation while warm ones still return populated
  ``tools``.
* Every per-server failure path (``TimeoutError``, raised exception, downstream
  ``status != "success"``) appends to ``discovery_failed_servers``, sets the
  top-level ``status="error"``, and overlays a structured ``discovery_error``
  block onto the original placeholder so callers don't lose the server's
  config / guardrail metadata.
* The top-level ``message`` summarises *what* happened (count of failures,
  the per-server timeout that was applied).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable


# ----------------------------------------------------------------------
# Lightweight stubs so we can drive the listing service without spinning
# up a real auth provider / cache client / OpenTelemetry tracer.
# ----------------------------------------------------------------------
class _NoopSpan:
    """Mimics the surface area of an OTel span used by the listing service."""

    def set_attribute(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def record_exception(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _NoopTracer:
    """Returns ``_NoopSpan`` from both context-manager and bare ``start_span``."""

    @contextlib.contextmanager
    def start_as_current_span(self, *_args: Any, **_kwargs: Any):
        yield _NoopSpan()

    @contextlib.contextmanager
    def start_span(self, *_args: Any, **_kwargs: Any):
        yield _NoopSpan()


class _StubTimeoutManager:
    """Returns whatever per-server discovery timeout the test supplied."""

    def __init__(self, discovery_timeout: float) -> None:
        self._discovery_timeout = discovery_timeout

    def get_timeout(self, operation_type: str) -> float:
        # The fix only ever asks for "discovery"; assert that contract so
        # silent regressions to a different operation_type get caught.
        assert operation_type == "discovery", (
            f"Listing service must request the 'discovery' timeout bucket, "
            f"got {operation_type!r}"
        )
        return self._discovery_timeout


def _placeholder_entry(server_name: str) -> dict[str, Any]:
    """Mirrors the shape that ``cache_service.get_latest_server_info``
    writes for a server with no cached tools."""
    return {
        "server_name": server_name,
        "description": f"stub for {server_name}",
        "config": {"command": "noop"},
        "tools": {},
        "has_cached_tools": False,
        "tools_source": "needs_discovery",
    }


def _success_entry(server_name: str, tool_names: list[str]) -> dict[str, Any]:
    """Shape returned by a successful ``enkrypt_discover_all_tools`` call."""
    return {
        "status": "success",
        "server_name": server_name,
        "source": "discovery",
        "tools": {name: {"description": f"tool {name}"} for name in tool_names},
    }


def _make_discovery_stub(
    plan: dict[str, str],
    slow_sleep_seconds: float = 5.0,
) -> Callable[[Any, str], asyncio.Future[Any] | dict[str, Any]]:
    """Build a stub ``enkrypt_discover_all_tools`` whose behaviour is
    selected per-server-name from ``plan``.

    Plan values:
        "ok"         -- return success-shaped result with two tools
        "slow"       -- ``asyncio.sleep`` past the per-server timeout, then
                        return success (should never be observed because
                        ``asyncio.wait_for`` cancels it)
        "raises"     -- raise ``RuntimeError("boom")``
        "ok_no_tools"-- return ``status="success"`` but no tools
        "downstream_error" -- return ``status="error"`` with a typed payload
    """

    async def _stub(_ctx: Any, server_name: str):
        plan_for_server = plan.get(server_name, "ok")
        if plan_for_server == "ok":
            return _success_entry(server_name, ["alpha", "beta"])
        if plan_for_server == "ok_no_tools":
            return {"status": "success", "server_name": server_name, "tools": {}}
        if plan_for_server == "raises":
            raise RuntimeError("boom")
        if plan_for_server == "downstream_error":
            return {
                "status": "error",
                "error_kind": "policy_violation",
                "message": "Tool schema blocked by guardrail",
            }
        if plan_for_server == "slow":
            await asyncio.sleep(slow_sleep_seconds)
            # Success here would only land if asyncio.wait_for failed to cancel.
            return _success_entry(server_name, ["should-never-appear"])
        raise AssertionError(f"unknown plan {plan_for_server!r}")

    return _stub


# ----------------------------------------------------------------------
# Pytest plumbing: every test patches the same set of dependencies
# behind ``ServerListingService._discover_and_return_servers``.
# ----------------------------------------------------------------------
@pytest.fixture
def patched_listing_service(monkeypatch: pytest.MonkeyPatch):
    """Yield a factory that wires the stubs into the listing service module."""
    from secure_mcp_gateway.services.server import server_listing_service as svc_mod

    def _install(
        plan: dict[str, str],
        per_server_timeout: float = 0.5,
        slow_sleep_seconds: float = 5.0,
    ) -> svc_mod.ServerListingService:
        # ``_discover_and_return_servers`` does ``from secure_mcp_gateway.gateway
        # import enkrypt_discover_all_tools`` at *call* time; patching the
        # symbol on the gateway module is enough.
        import secure_mcp_gateway.gateway as gateway_mod

        monkeypatch.setattr(
            gateway_mod,
            "enkrypt_discover_all_tools",
            _make_discovery_stub(plan, slow_sleep_seconds=slow_sleep_seconds),
            raising=False,
        )

        # Same trick for the timeout manager.
        import secure_mcp_gateway.services.timeout as timeout_pkg

        monkeypatch.setattr(
            timeout_pkg,
            "get_timeout_manager",
            lambda: _StubTimeoutManager(per_server_timeout),
            raising=False,
        )

        # Disable masking so test assertions can read raw env / no env at all.
        monkeypatch.setattr(
            svc_mod,
            "mask_server_config_sensitive_data",
            lambda entry: entry,
            raising=False,
        )

        return svc_mod.ServerListingService()

    return _install


# ======================================================================
# Section 1 — happy path stays happy
# ======================================================================
class TestAllServersSucceed:
    """The fix must not regress the all-good case."""

    async def test_status_success_and_tools_populated(
        self, patched_listing_service
    ) -> None:
        service = patched_listing_service(
            plan={"alpha": "ok", "beta": "ok"},
            per_server_timeout=2.0,
        )
        servers_with_tools = {
            "alpha": _placeholder_entry("alpha"),
            "beta": _placeholder_entry("beta"),
        }

        response = await service._discover_and_return_servers(
            servers_with_tools=servers_with_tools,
            servers_needing_discovery=["alpha", "beta"],
            ctx=object(),
            tracer=_NoopTracer(),
            main_span=_NoopSpan(),
        )

        assert response["status"] == "success"
        assert response["message"] == "Tools discovery tried for all servers"
        assert sorted(response["discovery_success_servers"]) == ["alpha", "beta"]
        assert response["discovery_failed_servers"] == []
        assert set(response["available_servers"].keys()) == {"alpha", "beta"}
        # Successful entries are *replaced* with the discovery result,
        # so the placeholder marker disappears and tools land in.
        for server_name in ("alpha", "beta"):
            entry = response["available_servers"][server_name]
            assert entry["status"] == "success"
            assert entry.get("tools"), (
                "successful entry must carry populated tools, "
                "not the placeholder dict"
            )
            assert "discovery_error" not in entry


# ======================================================================
# Section 2 — per-server timeout isolation
# ======================================================================
class TestPerServerTimeoutIsolation:
    """One slow server must not sink the warm ones."""

    async def test_slow_server_fails_warm_servers_succeed(
        self, patched_listing_service
    ) -> None:
        service = patched_listing_service(
            plan={"warm-1": "ok", "cold": "slow", "warm-2": "ok"},
            # Tight enough that the "slow" stub's ``await asyncio.sleep(5.0)``
            # is cancelled, but loose enough that warm stubs always finish.
            per_server_timeout=0.2,
            slow_sleep_seconds=5.0,
        )
        servers_with_tools = {
            name: _placeholder_entry(name) for name in ("warm-1", "cold", "warm-2")
        }

        response = await service._discover_and_return_servers(
            servers_with_tools=servers_with_tools,
            servers_needing_discovery=["warm-1", "cold", "warm-2"],
            ctx=object(),
            tracer=_NoopTracer(),
            main_span=_NoopSpan(),
        )

        # Top-level surface
        assert response["status"] == "error", (
            "any per-server failure must flip the top-level status; "
            "the historic bug was that this stayed 'success'"
        )
        assert response["discovery_failed_servers"] == ["cold"]
        assert sorted(response["discovery_success_servers"]) == ["warm-1", "warm-2"]
        # Message tells the operator how to fix it.
        assert "1 of 3" in response["message"]
        assert "0.2s" in response["message"]

        # Warm servers should have tools populated, not a placeholder.
        for warm in ("warm-1", "warm-2"):
            entry = response["available_servers"][warm]
            assert entry["status"] == "success"
            assert entry["tools"], f"{warm} should have populated tools"
            assert "discovery_error" not in entry

        # Failed server keeps its placeholder (config / has_cached_tools /
        # tools_source) AND gains a structured ``discovery_error`` overlay.
        cold_entry = response["available_servers"]["cold"]
        assert cold_entry["server_name"] == "cold"
        assert cold_entry["has_cached_tools"] is False
        assert cold_entry["tools_source"] == "needs_discovery"
        assert cold_entry["tools"] == {}, (
            "placeholder must be preserved on failure -- it is what the "
            "client renders when tools are unavailable"
        )

        discovery_error = cold_entry["discovery_error"]
        assert discovery_error["status"] == "error"
        assert discovery_error["error_kind"] == "discovery_timeout"
        assert "0.2s" in discovery_error["message"]
        assert "discovery_timeout" in discovery_error["message"]


# ======================================================================
# Section 3 — exception path
# ======================================================================
class TestPerServerException:
    """Raised exceptions must be attributed to the offending server."""

    async def test_raised_exception_attributed_with_error_kind(
        self, patched_listing_service
    ) -> None:
        service = patched_listing_service(
            plan={"good": "ok", "bad": "raises"},
            per_server_timeout=2.0,
        )
        servers_with_tools = {
            "good": _placeholder_entry("good"),
            "bad": _placeholder_entry("bad"),
        }

        response = await service._discover_and_return_servers(
            servers_with_tools=servers_with_tools,
            servers_needing_discovery=["good", "bad"],
            ctx=object(),
            tracer=_NoopTracer(),
            main_span=_NoopSpan(),
        )

        assert response["status"] == "error"
        assert response["discovery_failed_servers"] == ["bad"]
        assert response["discovery_success_servers"] == ["good"]

        bad_entry = response["available_servers"]["bad"]
        assert bad_entry["server_name"] == "bad", (
            "placeholder metadata must survive even when the underlying "
            "discovery raised"
        )
        discovery_error = bad_entry["discovery_error"]
        assert discovery_error["error_kind"] == "RuntimeError"
        assert "boom" in discovery_error["message"]


# ======================================================================
# Section 4 — downstream "status: error" path
# ======================================================================
class TestDownstreamErrorPropagation:
    """If ``enkrypt_discover_all_tools`` returns ``status='error'`` we still
    need to count it as a failure with full error attribution."""

    async def test_downstream_error_status_propagated(
        self, patched_listing_service
    ) -> None:
        service = patched_listing_service(
            plan={"happy": "ok", "blocked": "downstream_error"},
            per_server_timeout=2.0,
        )
        servers_with_tools = {
            "happy": _placeholder_entry("happy"),
            "blocked": _placeholder_entry("blocked"),
        }

        response = await service._discover_and_return_servers(
            servers_with_tools=servers_with_tools,
            servers_needing_discovery=["happy", "blocked"],
            ctx=object(),
            tracer=_NoopTracer(),
            main_span=_NoopSpan(),
        )

        assert response["status"] == "error"
        assert response["discovery_failed_servers"] == ["blocked"]
        assert response["discovery_success_servers"] == ["happy"]

        blocked_entry = response["available_servers"]["blocked"]
        discovery_error = blocked_entry["discovery_error"]
        # ``error_kind`` is whatever the downstream tool returned.
        assert discovery_error["error_kind"] == "policy_violation"
        assert "guardrail" in discovery_error["message"]


# ======================================================================
# Section 5 — empty case
# ======================================================================
class TestNoServersToDiscover:
    """An empty discovery batch must report success cleanly."""

    async def test_no_servers_returns_success_no_failures(
        self, patched_listing_service
    ) -> None:
        service = patched_listing_service(plan={}, per_server_timeout=1.0)

        response = await service._discover_and_return_servers(
            servers_with_tools={},
            servers_needing_discovery=[],
            ctx=object(),
            tracer=_NoopTracer(),
            main_span=_NoopSpan(),
        )

        assert response["status"] == "success"
        assert response["message"] == "Tools discovery tried for all servers"
        assert response["discovery_failed_servers"] == []
        assert response["discovery_success_servers"] == []
        assert response["available_servers"] == {}


# ======================================================================
# Section 6 — TimeoutConfig default sanity
# ======================================================================
class TestDiscoveryTimeoutDefault:
    """Pin the default to the post-fix value so a future refactor that
    re-introduces the old 20s/120s default trips this test."""

    def test_default_discovery_timeout_is_180s(self) -> None:
        from secure_mcp_gateway.services.timeout.timeout_manager import (
            TimeoutConfig,
        )

        config = TimeoutConfig()
        assert config.discovery_timeout == 180

    def test_load_config_default_discovery_timeout_is_180s(self) -> None:
        """An empty ``timeout_settings`` block must also resolve to 180s --
        not the historic 120s -- so users with minimal configs get the same
        runtime budget as those who explicitly set the value."""
        from secure_mcp_gateway.services.timeout.timeout_manager import (
            TimeoutManager,
        )

        manager = TimeoutManager(config={"timeout_settings": {}})
        assert manager.get_timeout("discovery") == 180
