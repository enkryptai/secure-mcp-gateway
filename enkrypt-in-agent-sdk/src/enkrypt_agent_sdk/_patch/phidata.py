"""Auto-patch for Phidata / Agno — wraps ``Agent.run()`` to inject guardrail
checks at pre_llm and post_llm checkpoints, plus emit lifecycle events.

Checkpoints:

1. **pre_llm**:  Check user message BEFORE the agent runs.
2. **post_llm**: Check agent response AFTER execution completes.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import AgentEvent, EventName, new_run_id
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.phidata")

_installed = False
_orig_run: Any = None
_orig_print_response: Any = None
_target_cls: Any = None

AGENT_ID = "phidata-auto"


def _extract_phidata_input(args: tuple, kwargs: dict) -> str:
    """Extract user message from Agent.run(message, ...) or Agent.print_response(message, ...)."""
    msg = kwargs.get("message", "")
    if not msg and args:
        msg = args[0]
    return str(msg) if msg else ""


def _extract_phidata_output(result: Any) -> str:
    """Extract text from a Phidata RunResponse."""
    if result is None:
        return ""
    for attr in ("content", "text", "data", "output"):
        val = getattr(result, attr, None)
        if val is not None and isinstance(val, str):
            return val
    return str(result)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run, _orig_print_response, _target_cls
    if _installed:
        return
    set_on_block(on_block)

    try:
        from phi.agent import Agent
        _target_cls = Agent
    except ImportError:
        try:
            from agno.agent import Agent
            _target_cls = Agent
        except ImportError:
            return

    _orig_run = _target_cls.run
    _orig_print_response = getattr(_target_cls, "print_response", None)

    def _patched_run(self: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        agent_name = getattr(self, "name", "") or "phidata"
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
            attributes={"agent_name": agent_name},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            msg = _extract_phidata_input(args, kwargs)
            if msg:
                sync_checkpoint(guard_engine, "pre_llm", msg, AGENT_ID)

            result = _orig_run(self, *args, **kwargs)

            output_text = _extract_phidata_output(result)
            if output_text:
                sync_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

            return result
        except Exception as exc:
            error_type = type(exc).__name__
            error_msg = str(exc)
            raise
        finally:
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_END,
                agent_id=AGENT_ID, run_id=rid,
                ok=error_type is None,
                error_type=error_type, error_message=error_msg,
            ))

    _target_cls.run = _patched_run  # type: ignore[assignment]

    # Also patch print_response which is the common entry point
    if _orig_print_response is not None:
        def _patched_print_response(self: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            agent_name = getattr(self, "name", "") or "phidata"
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
                attributes={"agent_name": agent_name},
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                msg = _extract_phidata_input(args, kwargs)
                if msg:
                    sync_checkpoint(guard_engine, "pre_llm", msg, AGENT_ID)

                result = _orig_print_response(self, *args, **kwargs)
                return result
            except Exception as exc:
                error_type = type(exc).__name__
                error_msg = str(exc)
                raise
            finally:
                observer.emit(AgentEvent(
                    name=EventName.LIFECYCLE_END,
                    agent_id=AGENT_ID, run_id=rid,
                    ok=error_type is None,
                    error_type=error_type, error_message=error_msg,
                ))

        _target_cls.print_response = _patched_print_response  # type: ignore[assignment]

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    if _target_cls is not None:
        if _orig_run is not None:
            _target_cls.run = _orig_run  # type: ignore[assignment]
        if _orig_print_response is not None:
            _target_cls.print_response = _orig_print_response  # type: ignore[assignment]
    _installed = False
