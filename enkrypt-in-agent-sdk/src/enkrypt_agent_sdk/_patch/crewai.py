"""Auto-patch for CrewAI — wraps ``Crew.kickoff()`` / ``kickoff_async()``
to inject guardrail checks at pre_llm and post_llm checkpoints, plus emit
lifecycle events via the observer.

Checkpoints:

1. **pre_llm**:  Check task descriptions BEFORE crew execution begins.
2. **post_llm**: Check crew output AFTER execution completes.

Additionally patches ``CrewAI Tool._run`` (if available) for pre_tool / post_tool.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import AgentEvent, EventName, new_run_id
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    async_checkpoint,
    extract_output,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.crewai")

_installed = False
_orig_kickoff: Any = None
_orig_kickoff_async: Any = None
_orig_tool_run: Any = None

AGENT_ID = "crewai-auto"


def _extract_crew_input(crew: Any) -> str:
    """Extract task descriptions from the crew's task list."""
    tasks = getattr(crew, "tasks", [])
    descriptions = []
    for t in tasks:
        desc = getattr(t, "description", "") or ""
        if desc:
            descriptions.append(desc)
    return " | ".join(descriptions)


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_kickoff, _orig_kickoff_async, _orig_tool_run
    if _installed:
        return
    set_on_block(on_block)

    try:
        from crewai import Crew
    except ImportError:
        return

    _orig_kickoff = Crew.kickoff
    _orig_kickoff_async = getattr(Crew, "kickoff_async", None)

    def _patched_kickoff(self: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        crew_name = getattr(self, "name", "") or "crew"
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
            attributes={"crew_name": crew_name},
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            # pre_llm: check task descriptions
            crew_input = _extract_crew_input(self)
            if crew_input:
                sync_checkpoint(guard_engine, "pre_llm", crew_input, AGENT_ID)

            result = _orig_kickoff(self, *args, **kwargs)

            # post_llm: check crew output
            output_text = extract_output(result) if result else ""
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

    Crew.kickoff = _patched_kickoff  # type: ignore[assignment]

    if _orig_kickoff_async is not None:
        async def _patched_kickoff_async(self: Any, *args: Any, **kwargs: Any) -> Any:
            rid = new_run_id()
            crew_name = getattr(self, "name", "") or "crew"
            observer.emit(AgentEvent(
                name=EventName.LIFECYCLE_START,
                agent_id=AGENT_ID, run_id=rid,
                attributes={"crew_name": crew_name},
            ))
            error_type: str | None = None
            error_msg: str | None = None
            try:
                crew_input = _extract_crew_input(self)
                if crew_input:
                    await async_checkpoint(guard_engine, "pre_llm", crew_input, AGENT_ID)

                result = await _orig_kickoff_async(self, *args, **kwargs)

                output_text = extract_output(result) if result else ""
                if output_text:
                    await async_checkpoint(guard_engine, "post_llm", output_text, AGENT_ID)

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

        Crew.kickoff_async = _patched_kickoff_async  # type: ignore[assignment]

    # --- Patch CrewAI Tool._run for pre_tool / post_tool ---
    try:
        from crewai.tools import BaseTool as CrewBaseTool
        _orig_tool_run = CrewBaseTool._run
        if _orig_tool_run is not None:
            def _patched_tool_run(self: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self, "name", None) or type(self).__name__
                tool_input = str(args[0]) if args else str(kwargs)
                sync_checkpoint(guard_engine, "pre_tool", tool_input, tool_name)
                result = _orig_tool_run(self, *args, **kwargs)
                sync_checkpoint(guard_engine, "post_tool", str(result), tool_name)
                return result

            CrewBaseTool._run = _patched_tool_run  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from crewai import Crew
    except ImportError:
        return
    if _orig_kickoff is not None:
        Crew.kickoff = _orig_kickoff  # type: ignore[assignment]
    if _orig_kickoff_async is not None:
        Crew.kickoff_async = _orig_kickoff_async  # type: ignore[assignment]
    try:
        from crewai.tools import BaseTool as CrewBaseTool
        if _orig_tool_run is not None:
            CrewBaseTool._run = _orig_tool_run  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass
    _installed = False
