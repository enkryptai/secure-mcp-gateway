"""Shared guardrail checkpoint infrastructure for all patch modules.

Provides ``sync_checkpoint`` and ``async_checkpoint`` that call the
``GuardEngine`` at four configurable points in the pipeline:

1. **pre_llm**:   Check user input BEFORE it reaches the LLM.
2. **pre_tool**:  Check tool input BEFORE the tool executes.
3. **post_tool**: Check tool output AFTER the tool executes.
4. **post_llm**:  Check LLM response BEFORE it reaches the user.

When a check fails, ``GuardrailBlockedError`` is raised.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from enkrypt_agent_sdk.exceptions import GuardrailBlockedError
from enkrypt_agent_sdk.guard import GuardEngine

log = logging.getLogger("enkrypt_agent_sdk.patch")

_on_block: Any = None

CHECKPOINT_LABELS = {
    "pre_llm": "PRE-LLM",
    "pre_tool": "PRE-TOOL",
    "post_tool": "POST-TOOL",
    "post_llm": "POST-LLM",
}

_LABEL_MAP = {
    "pre_llm": "before LLM",
    "pre_tool": "before tool",
    "post_tool": "after tool",
    "post_llm": "after LLM",
}


def default_on_block(checkpoint: str, name: str, violations: tuple, **kw: Any) -> None:
    """Default block handler -- prints a visible message to stdout."""
    label = CHECKPOINT_LABELS.get(checkpoint, checkpoint.upper())
    v_str = ", ".join(str(v) for v in violations)
    print(f"  >> [ENKRYPT BLOCKED] ({label}) {name}: {v_str}")
    if checkpoint == "pre_llm":
        print(f"  >> LLM was NOT called. Message never reached the model.")


def set_on_block(callback: Any) -> None:
    """Set the global block callback (called when a checkpoint blocks)."""
    global _on_block
    _on_block = callback


def get_on_block() -> Any:
    return _on_block


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------

def extract_text(data: Any) -> str:
    """Best-effort extraction of text content from various input types."""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in ("input", "query", "question", "text", "content",
                     "command", "message", "description", "sql",
                     "expression", "code", "prompt", "body", "url",
                     "search", "term", "statement", "request"):
            if key in data:
                return str(data[key])
        # For single-key dicts (common tool inputs), extract the value directly
        if len(data) == 1:
            return str(next(iter(data.values())))
        # Join all values for multi-key dicts to give the classifier real content
        vals = [str(v) for v in data.values() if v]
        return " ".join(vals) if vals else str(data)
    if isinstance(data, list):
        for msg in reversed(data):
            if hasattr(msg, "type") and msg.type == "human":
                return str(msg.content)
            if isinstance(msg, dict) and msg.get("role") == "user":
                return str(msg.get("content", ""))
        if data:
            return extract_text(data[-1])
    return str(data)


def extract_user_input(data: Any) -> str:
    """Extract user message text from LLM input (messages list, string, dict, etc.)."""
    if isinstance(data, str):
        return data
    if isinstance(data, list):
        for msg in reversed(data):
            if hasattr(msg, "type") and msg.type == "human":
                return str(msg.content)
            if isinstance(msg, dict) and msg.get("role") == "user":
                return str(msg.get("content", ""))
    if isinstance(data, dict):
        if "messages" in data:
            return extract_user_input(data["messages"])
        for key in ("input", "query", "question", "text", "content",
                     "message", "description"):
            if key in data:
                return str(data[key])
    return str(data)


def extract_output(result: Any) -> str:
    """Extract text from various framework result types."""
    if isinstance(result, str):
        return result
    for attr in ("content", "text", "data", "final_output", "output", "summary"):
        val = getattr(result, attr, None)
        if val is not None and isinstance(val, str):
            return val
    return str(result)


# ---------------------------------------------------------------------------
# Checkpoint execution
# ---------------------------------------------------------------------------

def sync_checkpoint(guard: GuardEngine | None, checkpoint: str, data: Any, name: str) -> None:
    """Run a guardrail checkpoint synchronously. Raises GuardrailBlockedError if blocked."""
    if guard is None:
        return

    enabled = getattr(guard, f"check_{checkpoint}", False)
    if not enabled:
        return

    is_input = checkpoint in ("pre_llm", "pre_tool")
    if is_input and not guard.has_input_guard:
        return
    if not is_input and not guard.has_output_guard:
        return

    if checkpoint == "pre_llm":
        text = extract_user_input(data)
    else:
        text = extract_text(data)

    if not text:
        return

    log.debug("[%s] Checking: %s (%.80s...)", checkpoint, name, text)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if is_input:
        coro = guard.check_input(text, tool_name=name)
    else:
        coro = guard.check_output(text, "", tool_name=name)

    if loop is None:
        verdict = asyncio.run(coro)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            verdict = pool.submit(asyncio.run, coro).result()

    log.debug("[%s] Verdict: safe=%s violations=%s", checkpoint, verdict.is_safe, verdict.violations)

    if not verdict.is_safe:
        _fire_on_block(checkpoint, name, verdict.violations)
        raise GuardrailBlockedError(
            f"Blocked {_LABEL_MAP.get(checkpoint, checkpoint)} for '{name}': {verdict.violations}",
            violations=[{"type": v, "checkpoint": checkpoint, "name": name} for v in verdict.violations],
        )


async def async_checkpoint(guard: GuardEngine | None, checkpoint: str, data: Any, name: str) -> None:
    """Run a guardrail checkpoint asynchronously. Raises GuardrailBlockedError if blocked."""
    if guard is None:
        return

    enabled = getattr(guard, f"check_{checkpoint}", False)
    if not enabled:
        return

    is_input = checkpoint in ("pre_llm", "pre_tool")
    if is_input and not guard.has_input_guard:
        return
    if not is_input and not guard.has_output_guard:
        return

    if checkpoint == "pre_llm":
        text = extract_user_input(data)
    else:
        text = extract_text(data)

    if not text:
        return

    log.debug("[%s] Checking: %s (%.80s...)", checkpoint, name, text)

    if is_input:
        verdict = await guard.check_input(text, tool_name=name)
    else:
        verdict = await guard.check_output(text, "", tool_name=name)

    log.debug("[%s] Verdict: safe=%s violations=%s", checkpoint, verdict.is_safe, verdict.violations)

    if not verdict.is_safe:
        _fire_on_block(checkpoint, name, verdict.violations)
        raise GuardrailBlockedError(
            f"Blocked {_LABEL_MAP.get(checkpoint, checkpoint)} for '{name}': {verdict.violations}",
            violations=[{"type": v, "checkpoint": checkpoint, "name": name} for v in verdict.violations],
        )


def _fire_on_block(checkpoint: str, name: str, violations: tuple) -> None:
    if _on_block is not None:
        try:
            _on_block(checkpoint=checkpoint, name=name, violations=violations)
        except Exception:
            pass
