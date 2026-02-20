"""Global singleton state — owns the observer, guard engine, and telemetry providers.

Modelled after AgentSight's ``_state.py``: module-level globals guarded by a lock,
with idempotent ``initialize()`` and ``shutdown()`` lifecycle functions.
"""

from __future__ import annotations

import atexit
import threading
from typing import Any

from enkrypt_agent_sdk.config import SDKConfig
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import init_telemetry, shutdown_telemetry

_lock = threading.Lock()
_observer: AgentObserver | None = None
_guard_engine: GuardEngine | None = None
_tracer_provider: Any = None
_meter_provider: Any = None
_config: SDKConfig | None = None
_initialized: bool = False
_instrumented: set[str] = set()


def initialize(config: SDKConfig | None = None) -> tuple[AgentObserver, GuardEngine]:
    """Idempotent SDK initialisation.  Safe to call multiple times."""
    global _observer, _guard_engine, _tracer_provider, _meter_provider, _config, _initialized

    with _lock:
        if _initialized and _observer is not None and _guard_engine is not None:
            return _observer, _guard_engine

        cfg = config or SDKConfig()
        _config = cfg

        # Telemetry
        tp, mp = init_telemetry(
            service_name=cfg.service_name,
            exporter=cfg.exporter,
            otlp_endpoint=cfg.otlp_endpoint or None,
            otlp_headers=cfg.otlp_headers or None,
        )
        _tracer_provider = tp
        _meter_provider = mp

        tracer = _resolve_tracer(tp, cfg.service_name)
        meter = _resolve_meter(mp, cfg.service_name)

        # Observer
        _observer = AgentObserver(tracer, meter, payload_policy=cfg.payload_policy)

        # Guardrail registry
        registry = GuardrailRegistry()
        if cfg.enkrypt_api_key:
            registry.register(
                EnkryptGuardrailProvider(cfg.enkrypt_api_key, cfg.enkrypt_base_url)
            )

        _guard_engine = GuardEngine(
            registry,
            input_policy=cfg.input_policy_dict(),
            output_policy=cfg.output_policy_dict(),
            timeout_seconds=cfg.guardrail_timeout_seconds,
            fail_open=cfg.fail_open,
            checkpoints=cfg.checkpoints,
        )

        _initialized = True
        atexit.register(shutdown)
        return _observer, _guard_engine


def get_observer() -> AgentObserver | None:
    return _observer


def get_guard_engine() -> GuardEngine | None:
    return _guard_engine


def get_config() -> SDKConfig | None:
    return _config


def mark_instrumented(framework: str) -> None:
    _instrumented.add(framework)


def is_instrumented(framework: str) -> bool:
    return framework in _instrumented


def instrumented_frameworks() -> frozenset[str]:
    return frozenset(_instrumented)


def shutdown() -> None:
    global _observer, _guard_engine, _tracer_provider, _meter_provider, _initialized
    with _lock:
        if not _initialized:
            return
        shutdown_telemetry(_tracer_provider, _meter_provider)
        _observer = None
        _guard_engine = None
        _tracer_provider = None
        _meter_provider = None
        _initialized = False
        _instrumented.clear()


def reset() -> None:
    """For tests only — fully resets global state."""
    shutdown()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_tracer(tp: Any, name: str) -> Any:
    if hasattr(tp, "get_tracer"):
        return tp.get_tracer(name)
    return tp


def _resolve_meter(mp: Any, name: str) -> Any:
    if hasattr(mp, "get_meter"):
        return mp.get_meter(name)
    return mp
