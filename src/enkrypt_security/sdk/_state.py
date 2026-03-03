"""Global singleton state — owns the observer, guard engine, and telemetry providers.

Modelled after AgentSight's ``_state.py``: module-level globals guarded by a lock,
with idempotent ``initialize()`` and ``shutdown()`` lifecycle functions.
"""

from __future__ import annotations

import atexit
import os
import threading

from enkrypt_security.sdk.config import SDKConfig
from enkrypt_security.sdk.guard import GuardEngine
from enkrypt_security.sdk.guardrails.base import GuardrailRegistry
from enkrypt_security.sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkrypt_security.sdk.observer import AgentObserver
from enkrypt_security.sdk.otel_setup import TelemetryContext, init_telemetry

_lock = threading.Lock()
_observer: AgentObserver | None = None
_guard_engine: GuardEngine | None = None
_telemetry_ctx: TelemetryContext | None = None
_config: SDKConfig | None = None
_initialized: bool = False
_instrumented: set[str] = set()


def initialize(config: SDKConfig | None = None) -> tuple[AgentObserver, GuardEngine]:
    """Idempotent SDK initialisation.  Safe to call multiple times."""
    global _observer, _guard_engine, _telemetry_ctx, _config, _initialized

    with _lock:
        if _initialized and _observer is not None and _guard_engine is not None:
            return _observer, _guard_engine

        if config is not None:
            cfg = config
        elif os.environ.get("ENKRYPT_API_KEY") or os.environ.get("ENKRYPT_CONFIG_PATH"):
            cfg = SDKConfig.auto_load()
        else:
            cfg = SDKConfig()
        _config = cfg

        cfg.inject_provider_keys()

        ctx = init_telemetry(
            service_name=cfg.service_name,
            exporter=cfg.exporter,
            otlp_endpoint=cfg.otlp_endpoint or None,
            otlp_headers=cfg.otlp_headers or None,
        )
        _telemetry_ctx = ctx

        _observer = AgentObserver(ctx.tracer, ctx.meter, payload_policy=cfg.payload_policy)

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
    global _observer, _guard_engine, _telemetry_ctx, _initialized
    with _lock:
        if not _initialized:
            return
        if _telemetry_ctx is not None:
            _telemetry_ctx.shutdown()
        _observer = None
        _guard_engine = None
        _telemetry_ctx = None
        _initialized = False
        _instrumented.clear()


def reset() -> None:
    """For tests only — fully resets global state."""
    shutdown()
