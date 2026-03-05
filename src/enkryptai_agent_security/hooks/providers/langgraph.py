#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Core Module for LangGraph/LangChain Agents

Uses the shared ``enkryptai_agent_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only LangGraph-specific text extraction helpers and backward-compatible
function signatures.

Configuration is loaded from guardrails_config.json
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from enkryptai_agent_security.hooks.core import (
    HooksCore,
    analyze_content,
    find_guardrails_config,
    format_violation_message,
)
from enkryptai_agent_security.hooks.core import (
    is_sensitive_tool as _is_sensitive_tool,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_FILE = find_guardrails_config("langgraph")
LOG_DIR = Path(
    os.environ.get(
        "LANGGRAPH_GUARDRAILS_LOG_DIR",
        str(Path.home() / "langgraph" / "guardrails_logs"),
    )
)

LANGGRAPH_HOOK_NAMES = [
    "pre_model_hook",
    "post_model_hook",
    "before_tool_call",
    "after_tool_call",
    "on_agent_action",
    "on_agent_finish",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="langgraph-guardrails",
    hook_names=LANGGRAPH_HOOK_NAMES,
)

SENSITIVE_TOOLS: list[str] = _core.sensitive_tools

_SOURCE_EVENT_MAP = {
    "pre_model_hook": "pre-model",
    "post_model_hook": "post-model",
    "before_tool_call": "before-tool",
    "after_tool_call": "after-tool",
    "on_agent_action": "agent-action",
    "on_agent_finish": "agent-finish",
}


# ============================================================================
# BACKWARD-COMPATIBLE API
# ============================================================================


def is_hook_enabled(hook_name: str) -> bool:
    return _core.is_enabled(hook_name)


def get_hook_block_list(hook_name: str) -> list:
    return _core.get_block_list(hook_name)


def get_hook_guardrail_name(hook_name: str) -> str:
    return _core.get_guardrail_name(hook_name)


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    return _SOURCE_EVENT_MAP.get(hook_name, hook_name.lower().replace("_", "-"))


def check_with_enkrypt_api(
    text: str, hook_name: str = "pre_model_hook"
) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
    """Check text via shared HooksCore. Returns (should_block, violations, raw)."""
    return _core.check(text, hook_name, source_event=get_source_event(hook_name))


def log_event(
    hook_name: str,
    data: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> None:
    _core.log_event(hook_name, data, result)


def log_to_combined(
    hook_name: str,
    data: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> None:
    _core.log_combined(hook_name, data, result)


def log_security_alert(
    alert_type: str,
    details: dict[str, Any],
    data: dict[str, Any] | None = None,
) -> None:
    _core.log_security_alert(alert_type, details)


def flush_logs() -> None:
    _core.flush_logs()


def get_metrics(hook_name: str | None = None) -> dict[str, Any]:
    return _core.metrics.get_metrics(hook_name)


def reset_metrics(hook_name: str | None = None) -> None:
    _core.metrics.reset(hook_name)


def is_sensitive_tool(tool_name: str) -> bool:
    return _is_sensitive_tool(tool_name, _core.sensitive_tools)


def reload_config() -> None:
    _core.reload_config(CONFIG_FILE)


# Re-export from shared core for convenience
format_violation_message = format_violation_message
analyze_content = analyze_content


# ============================================================================
# LANGGRAPH-SPECIFIC TEXT EXTRACTION HELPERS
# ============================================================================


def extract_messages_text(messages: list) -> str:
    """Extract text from LangGraph/LangChain messages list."""
    text_parts = []
    for msg in messages:
        if hasattr(msg, "content"):
            content = msg.content
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        text_parts.append(item["text"])
                    elif isinstance(item, str):
                        text_parts.append(item)
        elif isinstance(msg, dict):
            content = msg.get("content", "")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        text_parts.append(item["text"])
                    elif isinstance(item, str):
                        text_parts.append(item)
    return "\n".join(text_parts)


def extract_tool_calls_text(ai_message) -> str:
    """Extract tool call arguments as text from an AI message."""
    text_parts = []
    tool_calls = getattr(ai_message, "tool_calls", None) or []
    for tc in tool_calls:
        if isinstance(tc, dict):
            args = tc.get("args", {})
            if isinstance(args, dict):
                text_parts.append(json.dumps(args))
            elif isinstance(args, str):
                text_parts.append(args)
        elif hasattr(tc, "args"):
            args = tc.args
            if isinstance(args, dict):
                text_parts.append(json.dumps(args))
            elif isinstance(args, str):
                text_parts.append(args)
    return "\n".join(text_parts)
