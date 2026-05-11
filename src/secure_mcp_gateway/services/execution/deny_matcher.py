"""
Tool deny-list matcher using fnmatch globs.

Supports entries as plain strings (tool names / glob patterns) or objects
with ``name``, ``reason``, and ``description`` fields.

Usage:

    from secure_mcp_gateway.services.execution.deny_matcher import (
        is_tool_denied,
        filter_denied_tools,
    )

    denied_tools = ["tool3", "tool_a_*", {"name": "tool4", "reason": "policy"}]

    match = is_tool_denied("tool_a_foo", denied_tools)
    if match:
        print(match)  # {"name": "tool_a_foo", "pattern": "tool_a_*", "reason": None}

    visible = filter_denied_tools(["tool1", "tool2", "tool3"], denied_tools)
    # ["tool1", "tool2"]
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Dict, List, Optional, Sequence, Union

DenyEntry = Union[str, Dict[str, Any]]


def _entry_pattern(entry: DenyEntry) -> str:
    if isinstance(entry, str):
        return entry
    return entry.get("name", "")


def _entry_reason(entry: DenyEntry) -> Optional[str]:
    if isinstance(entry, dict):
        return entry.get("reason")
    return None


def _default_reason(pattern: str) -> str:
    """Fallback reason string used when a deny entry has no explicit reason."""
    return f"Denied by deny-list pattern: {pattern}"


def is_tool_denied(
    tool_name: str,
    denied_tools: Sequence[DenyEntry],
    allowed_tools: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Check whether ``tool_name`` is denied.

    When ``denied_tools`` contains ``"*"`` (deny-all wildcard), tools that
    appear as keys in ``allowed_tools`` are **exempt** — deny-all means
    "deny everything *not* explicitly allowed".

    Returns a dict ``{"name", "pattern", "reason"}`` on match, else ``None``.
    The ``reason`` field is always a non-empty string so callers
    (LLMs, humans, audit logs) get useful attribution even when the deny
    entry is a bare pattern string with no explicit reason. If the entry
    lacks an explicit reason, ``reason`` falls back to
    ``"Denied by deny-list pattern: <pattern>"``.
    """
    for entry in denied_tools:
        pattern = _entry_pattern(entry)
        if not pattern:
            continue

        if fnmatchcase(tool_name, pattern):
            if pattern == "*" and allowed_tools and tool_name in allowed_tools:
                continue
            reason = _entry_reason(entry) or _default_reason(pattern)
            return {
                "name": tool_name,
                "pattern": pattern,
                "reason": reason,
            }

    return None


def filter_denied_tools(
    tool_names: List[str],
    denied_tools: Sequence[DenyEntry],
    allowed_tools: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Return only those tool names that are **not** denied."""
    return [
        name
        for name in tool_names
        if is_tool_denied(name, denied_tools, allowed_tools) is None
    ]
