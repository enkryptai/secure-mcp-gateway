"""Auto-patch for Haystack — wraps ``Pipeline.run()`` AND
``OpenAIChatGenerator.run()`` to inject guardrail checks at pre_llm and
post_llm checkpoints, plus emit lifecycle events.

Checkpoints:

1. **pre_llm**:  Check user input BEFORE the pipeline/generator runs.
2. **post_llm**: Check pipeline/generator output AFTER execution completes.
"""

from __future__ import annotations

import logging
from typing import Any

from enkrypt_agent_sdk.events import AgentEvent, EventName, new_run_id
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk._patch._checkpoint import (
    sync_checkpoint,
    extract_text,
    default_on_block,
    set_on_block,
)

log = logging.getLogger("enkrypt_agent_sdk.patch.haystack")

_installed = False
_orig_pipeline_run: Any = None
_orig_generator_run: Any = None

AGENT_ID = "haystack-auto"


def _extract_pipeline_input(kwargs: dict) -> str:
    """Extract user text from Haystack Pipeline.run(data={...})."""
    data = kwargs.get("data", {})
    if isinstance(data, dict):
        for component_data in data.values():
            if isinstance(component_data, dict):
                for key in ("messages", "queries", "query", "prompt", "text", "documents"):
                    val = component_data.get(key)
                    if val:
                        if isinstance(val, list) and val:
                            last = val[-1]
                            if hasattr(last, "text"):
                                return last.text
                            if hasattr(last, "content"):
                                return str(last.content)
                            return str(last)
                        return str(val)
    return ""


def _extract_pipeline_output(result: Any) -> str:
    """Extract text from Haystack pipeline output dict."""
    if isinstance(result, dict):
        for component_output in result.values():
            if isinstance(component_output, dict):
                replies = component_output.get("replies", [])
                if replies:
                    last = replies[-1]
                    if hasattr(last, "text"):
                        return last.text
                    if hasattr(last, "content"):
                        return str(last.content)
                    return str(last)
    return str(result) if result else ""


def _extract_generator_input(kwargs: dict) -> str:
    """Extract user text from ChatGenerator.run(messages=[...])."""
    messages = kwargs.get("messages", [])
    for msg in reversed(messages):
        if hasattr(msg, "text"):
            return msg.text
        if hasattr(msg, "content"):
            return str(msg.content)
        if isinstance(msg, dict):
            return str(msg.get("content", ""))
    return ""


def _extract_generator_output(result: Any) -> str:
    """Extract text from ChatGenerator output."""
    if isinstance(result, dict):
        replies = result.get("replies", [])
        if replies:
            last = replies[-1]
            if hasattr(last, "text"):
                return last.text
            if hasattr(last, "content"):
                return str(last.content)
            return str(last)
    return ""


def install(
    observer: AgentObserver,
    guard_engine: GuardEngine | None = None,
    on_block: Any = default_on_block,
) -> None:
    global _installed, _orig_pipeline_run, _orig_generator_run
    if _installed:
        return
    set_on_block(on_block)

    try:
        from haystack import Pipeline
    except ImportError:
        return

    _orig_pipeline_run = Pipeline.run

    def _patched_pipeline_run(self: Any, *args: Any, **kwargs: Any) -> Any:
        rid = new_run_id()
        observer.emit(AgentEvent(
            name=EventName.LIFECYCLE_START,
            agent_id=AGENT_ID, run_id=rid,
        ))
        error_type: str | None = None
        error_msg: str | None = None
        try:
            user_text = _extract_pipeline_input(kwargs)
            if user_text:
                sync_checkpoint(guard_engine, "pre_llm", user_text, AGENT_ID)

            result = _orig_pipeline_run(self, *args, **kwargs)

            output_text = _extract_pipeline_output(result)
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

    Pipeline.run = _patched_pipeline_run  # type: ignore[assignment]

    # --- Patch OpenAIChatGenerator.run for direct generator usage ---
    try:
        from haystack_integrations.components.generators.openai import OpenAIChatGenerator
        _orig_generator_run = OpenAIChatGenerator.run
    except ImportError:
        try:
            from haystack.components.generators.chat import OpenAIChatGenerator
            _orig_generator_run = OpenAIChatGenerator.run
        except (ImportError, AttributeError):
            _orig_generator_run = None

    if _orig_generator_run is not None:
        def _patched_generator_run(self: Any, *args: Any, **kwargs: Any) -> Any:
            user_text = _extract_generator_input(kwargs)
            if not user_text and args:
                user_text = _extract_generator_input({"messages": args[0]})
            if user_text:
                sync_checkpoint(guard_engine, "pre_llm", user_text, "haystack-generator")

            result = _orig_generator_run(self, *args, **kwargs)

            output_text = _extract_generator_output(result)
            if output_text:
                sync_checkpoint(guard_engine, "post_llm", output_text, "haystack-generator")

            return result

        try:
            from haystack_integrations.components.generators.openai import OpenAIChatGenerator
            OpenAIChatGenerator.run = _patched_generator_run  # type: ignore[assignment]
        except ImportError:
            try:
                from haystack.components.generators.chat import OpenAIChatGenerator
                OpenAIChatGenerator.run = _patched_generator_run  # type: ignore[assignment]
            except (ImportError, AttributeError):
                pass

    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    try:
        from haystack import Pipeline
    except ImportError:
        return
    if _orig_pipeline_run is not None:
        Pipeline.run = _orig_pipeline_run  # type: ignore[assignment]

    if _orig_generator_run is not None:
        try:
            from haystack_integrations.components.generators.openai import OpenAIChatGenerator
            OpenAIChatGenerator.run = _orig_generator_run  # type: ignore[assignment]
        except ImportError:
            try:
                from haystack.components.generators.chat import OpenAIChatGenerator
                OpenAIChatGenerator.run = _orig_generator_run  # type: ignore[assignment]
            except (ImportError, AttributeError):
                pass

    _installed = False
