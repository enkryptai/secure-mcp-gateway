"""Unified event protocol for the Enkrypt Agent SDK.

Modelled after AgentSight's ``AgentEvent`` but extended with security-specific
fields (``guardrail_result``, ``blocked``, ``pii_redacted``).  Events are
**immutable** value objects emitted by adapters and consumed by the
:class:`~enkrypt_agent_sdk.observer.AgentObserver`.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Event taxonomy
# ---------------------------------------------------------------------------

class EventName(str, Enum):
    # Agent lifecycle
    LIFECYCLE_START = "agent.lifecycle.start"
    LIFECYCLE_END = "agent.lifecycle.end"

    # Reasoning / planning steps
    STEP_START = "agent.step.start"
    STEP_END = "agent.step.end"

    # Tool invocations
    TOOL_CALL_START = "agent.tool.call.start"
    TOOL_CALL_END = "agent.tool.call.end"

    # LLM calls
    LLM_CALL_START = "agent.llm.call.start"
    LLM_CALL_END = "agent.llm.call.end"

    # Memory / RAG
    MEMORY_READ = "agent.memory.read"
    MEMORY_WRITE = "agent.memory.write"

    # Guardrail verdicts (unique to Enkrypt)
    GUARDRAIL_CHECK = "agent.guardrail.check"
    GUARDRAIL_BLOCK = "agent.guardrail.block"

    # Errors
    ERROR = "agent.error"


# ---------------------------------------------------------------------------
# Guardrail result (embedded in events)
# ---------------------------------------------------------------------------

class GuardrailAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    MODIFY = "modify"


@dataclass(frozen=True)
class GuardrailVerdict:
    """Lightweight summary attached to any event that was guardrail-checked."""

    action: GuardrailAction = GuardrailAction.ALLOW
    violations: tuple[str, ...] = ()
    modified_content: str | None = None
    processing_time_ms: float = 0.0
    provider: str = ""

    @property
    def is_safe(self) -> bool:
        return self.action in (GuardrailAction.ALLOW, GuardrailAction.WARN)


# ---------------------------------------------------------------------------
# Core event
# ---------------------------------------------------------------------------

def _now_ns() -> int:
    return time.time_ns()


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class AgentEvent:
    """Immutable event emitted for every observable action inside an agent.

    Parameters that are ``None`` simply mean "not applicable for this event".
    """

    # --- required ---
    name: EventName
    agent_id: str
    run_id: str

    # --- correlation ---
    step_id: str | None = None
    tool_call_id: str | None = None
    llm_call_id: str | None = None
    trace_id: str | None = None
    parent_span_id: str | None = None

    # --- descriptors ---
    tool_name: str | None = None
    model_name: str | None = None

    # --- outcome ---
    ok: bool | None = None
    error_type: str | None = None
    error_message: str | None = None

    # --- security (Enkrypt-specific) ---
    guardrail: GuardrailVerdict | None = None
    blocked: bool = False
    pii_redacted: bool = False

    # --- payload ---
    attributes: dict[str, Any] = field(default_factory=dict)

    # --- metadata ---
    ts_ns: int = field(default_factory=_now_ns)
    event_id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ValueError("agent_id is required")
        if not self.run_id:
            raise ValueError("run_id is required")


# ---------------------------------------------------------------------------
# ID factories (convenience)
# ---------------------------------------------------------------------------

def new_run_id() -> str:
    return uuid.uuid4().hex


def new_step_id() -> str:
    return uuid.uuid4().hex


def new_tool_call_id() -> str:
    return uuid.uuid4().hex


def new_llm_call_id() -> str:
    return uuid.uuid4().hex
