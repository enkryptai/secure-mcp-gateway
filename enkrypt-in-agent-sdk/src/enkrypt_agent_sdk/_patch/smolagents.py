"""Auto-patch for smolagents — wraps ``MultiStepAgent.run()`` to inject
guardrail checks at pre_llm and post_llm checkpoints, and patches
``Tool.forward()`` for pre_tool / post_tool.

Both ``CodeAgent`` and ``ToolCallingAgent`` inherit ``run()`` from
``MultiStepAgent``, so we patch it there to cover all agent types.

Checkpoints:

1. **pre_llm**:  Check user task BEFORE the agent runs.
2. **pre_tool**: Check tool input BEFORE tool forward executes.
3. **post_tool**: Check tool output AFTER tool forward completes.
4. **post_llm**: Check agent output AFTER execution completes.
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

log = logging.getLogger("enkrypt_agent_sdk.patch.smolagents")

_installed = False
_orig_run: Any = None
_orig_tool_forward: Any = None
_run_owner: Any = None  # class where run() is actually defined

AGENT_ID = "smolagents-auto"


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_run, _orig_tool_forward, _run_owner
    if _installed:
        return
    set_on_block(on_block)

    try:
        from smolagents import MultiStepAgent
        _run_owner = MultiStepAgent
    except ImportError:
        try:
            from smolagents import CodeAgent
            _run_owner = CodeAgent
        except ImportError:
            try:
                from smolagents import ToolCallingAgent
                _run_owner = ToolCallingAgent
            except ImportError:
                return

    _orig_run = _run_owner.run

    def _patched_run(self: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            task = str(args[0]) if args else str(kwargs.get("task", ""))
            if task:
                sync_checkpoint(guard_engine, "pre_llm", task, AGENT_ID)

            result = _orig_run(self, *args, **kwargs)

            output_text = extract_output(result)
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

    _run_owner.run = _patched_run  # type: ignore[assignment]

    # --- Patch Tool.forward for pre_tool / post_tool ---
    try:
        from smolagents import Tool as SmolTool
        _orig_tool_forward = SmolTool.forward
        if _orig_tool_forward is not None:
            def _patched_forward(self: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self, "name", None) or type(self).__name__
                tool_input = str(args) if args else str(kwargs)
                sync_checkpoint(guard_engine, "pre_tool", tool_input, tool_name)
                result = _orig_tool_forward(self, *args, **kwargs)
                sync_checkpoint(guard_engine, "post_tool", str(result), tool_name)
                return result

            SmolTool.forward = _patched_forward  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    if _run_owner is not None and _orig_run is not None:
        _run_owner.run = _orig_run  # type: ignore[assignment]
    try:
        from smolagents import Tool as SmolTool
        if _orig_tool_forward is not None:
            SmolTool.forward = _orig_tool_forward  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass
    _installed = False
