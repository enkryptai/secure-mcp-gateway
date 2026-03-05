"""Global singleton state — owns the observer, guard engine, and telemetry providers.

Modelled after AgentSight's ``_state.py``: module-level globals guarded by a lock,
with idempotent ``initialize()`` and ``shutdown()`` lifecycle functions.
"""

from __future__ import annotations

import atexit
import os
import threading

from enkryptai_agent_security.sdk.config import SDKConfig
from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.guardrails.base import GuardrailRegistry
from enkryptai_agent_security.sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkryptai_agent_security.sdk.observer import AgentObserver
from enkryptai_agent_security.sdk.otel_setup import TelemetryContext, init_telemetry

_lock = threading.Lock()
_observer: AgentObserver | None = None
_guard_engine: GuardEngine | None = None
_guard_engines: dict[str, GuardEngine] = {}
_telemetry_ctx: TelemetryContext | None = None
_config: SDKConfig | None = None
_initialized: bool = False
_instrumented: set[str] = set()


def _build_guard_engine(
    registry: GuardrailRegistry,
    cfg: SDKConfig,
    *,
    agent_name: str | None = None,
) -> GuardEngine:
    """Build a GuardEngine with per-checkpoint policies resolved for *agent_name*."""
    checkpoints = cfg.checkpoints_for_agent(agent_name)
    return GuardEngine(
        registry,
        pre_llm_policy=cfg.policy_for_checkpoint("pre_llm", agent_name=agent_name),
        pre_tool_policy=cfg.policy_for_checkpoint("pre_tool", agent_name=agent_name),
        post_tool_policy=cfg.policy_for_checkpoint("post_tool", agent_name=agent_name),
        post_llm_policy=cfg.policy_for_checkpoint("post_llm", agent_name=agent_name),
        timeout_seconds=cfg.guardrail_timeout_seconds,
        fail_open=cfg.fail_open,
        checkpoints=checkpoints,
    )


def initialize(config: SDKConfig | None = None) -> tuple[AgentObserver, GuardEngine]:
    """Idempotent SDK initialisation.  Safe to call multiple times."""
    global _observer, _guard_engine, _guard_engines, _telemetry_ctx, _config, _initialized

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

        # Default guard engine (uses global + global checkpoint policies)
        _guard_engine = _build_guard_engine(registry, cfg)

        # Per-agent guard engines
        _guard_engines = {}
        for agent_name in cfg.agents:
            _guard_engines[agent_name] = _build_guard_engine(registry, cfg, agent_name=agent_name)

        _initialized = True
        atexit.register(shutdown)
        return _observer, _guard_engine


def get_observer() -> AgentObserver | None:
    return _observer


def get_guard_engine(agent_name: str | None = None) -> GuardEngine | None:
    """Return the guard engine for *agent_name*, or the default engine."""
    if agent_name and agent_name in _guard_engines:
        return _guard_engines[agent_name]
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
    global _observer, _guard_engine, _guard_engines, _telemetry_ctx, _initialized
    with _lock:
        if not _initialized:
            return
        if _telemetry_ctx is not None:
            _telemetry_ctx.shutdown()
        _observer = None
        _guard_engine = None
        _guard_engines = {}
        _telemetry_ctx = None
        _initialized = False
        _instrumented.clear()


def reset() -> None:
    """For tests only — fully resets global state."""
    shutdown()
