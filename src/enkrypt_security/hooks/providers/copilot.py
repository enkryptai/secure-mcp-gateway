#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Shared Module for GitHub Copilot Hooks

Uses the shared ``enkrypt_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only Copilot-specific tool checking, result analysis, the BaseHook class,
and backward-compatible function signatures.

Configuration is loaded from guardrails_config.json
"""
from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from enkrypt_security.hooks.core import (
    HooksCore,
    analyze_content,
    find_guardrails_config,
    format_violation_message,
)
from enkrypt_security.hooks.core import (
    is_sensitive_tool as _is_sensitive_tool,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_FILE = find_guardrails_config("copilot")
LOG_DIR = Path(
    os.environ.get(
        "COPILOT_HOOKS_LOG_DIR",
        str(Path.home() / "copilot" / "hooks_logs"),
    )
)

COPILOT_HOOK_NAMES = [
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "errorOccurred",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="copilot-guardrails",
    hook_names=COPILOT_HOOK_NAMES,
)

SENSITIVE_TOOLS: list[str] = _core.sensitive_tools


# ============================================================================
# BACKWARD-COMPATIBLE API
# ============================================================================


def is_hook_enabled(hook_name: str) -> bool:
    return _core.is_enabled(hook_name)


def get_hook_block_list(hook_name: str) -> list:
    return _core.get_block_list(hook_name)


def get_hook_guardrail_name(hook_name: str) -> str:
    return _core.get_guardrail_name(hook_name)


def check_with_enkrypt_api(
    text: str, hook_name: str = "userPromptSubmitted"
) -> tuple[bool, list, dict]:
    """Check text via shared HooksCore. Returns (should_block, violations, raw)."""
    return _core.check(text, hook_name)


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


# Backward-compatible alias
get_hook_metrics = get_metrics


def reset_metrics(hook_name: str | None = None) -> None:
    _core.metrics.reset(hook_name)


def is_sensitive_tool(tool_name: str) -> bool:
    return _is_sensitive_tool(tool_name, _core.sensitive_tools)


def reload_config() -> None:
    _core.reload_config(CONFIG_FILE)


def get_timestamp() -> str:
    """Get ISO format timestamp."""
    import datetime

    return datetime.datetime.now().isoformat()


# Re-export with backward-compatible signature (handlers pass hook_name=...)
_format_violation_message = format_violation_message


def format_violation_message(
    violations: list, hook_name: str = "", guardrail_name: str = ""
) -> str:
    name = guardrail_name or (get_hook_guardrail_name(hook_name) if hook_name else "")
    return _format_violation_message(violations, guardrail_name=name)


analyze_content = analyze_content


# ============================================================================
# COPILOT-SPECIFIC: Source event mapping
# ============================================================================


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    event_mapping = {
        "userPromptSubmitted": "pre-prompt",
        "preToolUse": "pre-tool",
        "postToolUse": "post-tool",
        "errorOccurred": "error",
    }
    return event_mapping.get(hook_name, hook_name)


# ============================================================================
# COPILOT-SPECIFIC: Pre-compiled regex patterns for tool result analysis
# ============================================================================

SENSITIVE_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
]


# ============================================================================
# COPILOT-SPECIFIC: Tool checking
# ============================================================================


def check_tool(tool_name: str, tool_args: str) -> tuple[str, str]:
    """
    Check if a tool should be allowed, blocked, or require confirmation.

    Args:
        tool_name: The Copilot tool name (e.g., "bash", "edit", "create")
        tool_args: The tool arguments as a JSON string

    Returns:
        Tuple of (permission_decision, reason)
        permission_decision: "allow", "deny", or "ask"
    """
    tool_name_lower = tool_name.lower()

    for sensitive in SENSITIVE_TOOLS:
        if sensitive.lower() in tool_name_lower:
            return (
                "ask",
                f"Tool '{tool_name}' matches sensitive tool pattern '{sensitive}' and requires confirmation."
            )

    try:
        params = json.loads(tool_args) if tool_args else {}

        if isinstance(params, dict):
            query = params.get("query", "") or params.get("sql", "") or params.get("command", "")
            if query:
                query_upper = query.upper()
                dangerous_sql = ["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT"]
                for keyword in dangerous_sql:
                    if keyword in query_upper:
                        return (
                            "ask",
                            f"SQL operation '{keyword}' detected in tool arguments and requires confirmation."
                        )
    except (json.JSONDecodeError, TypeError):
        pass

    return "allow", ""


def analyze_tool_result(tool_name: str, result_text: str) -> dict:
    """
    Analyze tool result for potential issues.

    Uses pre-compiled regex patterns for faster analysis.
    """
    analysis = {
        "sensitive_data_hints": [],
        "result_size": len(result_text),
        "is_error": False,
    }

    for pattern, name in SENSITIVE_PATTERNS:
        if pattern.search(result_text):
            analysis["sensitive_data_hints"].append(name)

    try:
        result = json.loads(result_text)
        if isinstance(result, dict):
            if result.get("error") or result.get("Error"):
                analysis["is_error"] = True
            if result.get("status") in ["error", "failed", "failure"]:
                analysis["is_error"] = True
    except (json.JSONDecodeError, TypeError):
        pass

    return analysis


# ============================================================================
# COPILOT-SPECIFIC: Hook base class
# ============================================================================


class BaseHook:
    """
    Base class for Copilot hooks.

    Provides common functionality:
    - JSON input parsing with error handling
    - Logging and metrics
    - Guardrails integration
    - Output formatting

    Subclasses should implement:
    - process(self, data: dict) -> dict
    """

    def __init__(self, hook_name: str, default_output: dict):
        self.hook_name = hook_name
        self.default_output = default_output

    def run(self):
        """Main entry point - reads stdin, processes, writes stdout."""
        import sys
        import time

        start_time = time.time()

        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            log_event(self.hook_name, {
                "parse_error": str(e),
                "error_type": "JSONDecodeError"
            })
            print(json.dumps(self.default_output))
            return

        try:
            result = self.process(data)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            _core.metrics.record_call(self.hook_name, blocked=False, latency_ms=latency_ms, error=True)
            log_event(self.hook_name, {
                "error": str(e),
                "error_type": type(e).__name__,
                "data": data,
            })
            result = self.default_output

        log_event(self.hook_name, data, result)
        log_to_combined(self.hook_name, data, result)
        flush_logs()
        print(json.dumps(result))

    def process(self, data: dict) -> dict:
        raise NotImplementedError("Subclasses must implement process()")

    def check_guardrails(self, text: str) -> tuple[bool, list, dict]:
        return check_with_enkrypt_api(text, hook_name=self.hook_name)

    def format_block_message(self, violations: list) -> str:
        return format_violation_message(violations, guardrail_name=get_hook_guardrail_name(self.hook_name))

    def log_alert(self, alert_type: str, details: dict, data: dict):
        log_security_alert(alert_type, {
            "hook": self.hook_name,
            "guardrail_name": get_hook_guardrail_name(self.hook_name),
            **details,
        }, data)

    @property
    def is_enabled(self) -> bool:
        return is_hook_enabled(self.hook_name)
