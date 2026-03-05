#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Core Module for Claude Code Hooks

Uses the shared ``enkryptai_agent_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only Claude-specific tool checking, hook classes, and backward-compatible
function signatures.

Configuration is loaded from guardrails_config.json
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from enkryptai_agent_security.hooks.core import (
    HooksCore,
    analyze_content,
    find_guardrails_config,
    format_violation_message as _format_violation_message,
)
from enkryptai_agent_security.hooks.core import (
    is_sensitive_tool as _is_sensitive_tool,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_FILE = find_guardrails_config("claude")
LOG_DIR = Path(
    os.environ.get(
        "CLAUDE_HOOKS_LOG_DIR",
        str(Path.home() / "claude" / "hooks_logs"),
    )
)

CLAUDE_HOOK_NAMES = [
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="claude-guardrails",
    hook_names=CLAUDE_HOOK_NAMES,
)

SENSITIVE_TOOLS: list[str] = _core.sensitive_tools

# Backward-compatible aliases
metrics = _core.metrics


# ============================================================================
# BACKWARD-COMPATIBLE API
# ============================================================================


def is_hook_enabled(hook_name: str) -> bool:
    return _core.is_enabled(hook_name)


def get_hook_block_list(hook_name: str) -> list[str]:
    return _core.get_block_list(hook_name)


def get_hook_guardrail_name(hook_name: str) -> str:
    return _core.get_guardrail_name(hook_name)


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    event_mapping = {
        "UserPromptSubmit": "pre-prompt",
        "PreToolUse": "pre-tool",
        "PostToolUse": "post-tool",
    }
    return event_mapping.get(hook_name, hook_name)


def check_with_enkrypt_api(
    text: str, hook_name: str = "UserPromptSubmit"
) -> tuple[bool, list, dict]:
    """Check text via shared HooksCore. Returns (should_block, violations, raw)."""
    source_event = get_source_event(hook_name)
    return _core.check(text, hook_name, source_event=source_event)


def format_violation_message(
    violations: list, hook_name: str = "UserPromptSubmit"
) -> str:
    """Format a user-friendly message from violations."""
    guardrail_name = _core.get_guardrail_name(hook_name)
    return _format_violation_message(violations, guardrail_name)


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


def get_timestamp() -> str:
    """Get ISO format timestamp."""
    return datetime.datetime.now().isoformat()


def get_hook_metrics(hook_name: str | None = None) -> dict[str, Any]:
    return _core.metrics.get_metrics(hook_name)


def get_metrics(hook_name: str | None = None) -> dict[str, Any]:
    return _core.metrics.get_metrics(hook_name)


def reset_metrics(hook_name: str | None = None) -> None:
    _core.metrics.reset(hook_name)


def is_sensitive_tool(tool_name: str) -> bool:
    return _is_sensitive_tool(tool_name, _core.sensitive_tools)


def reload_config() -> None:
    _core.reload_config(CONFIG_FILE)


# Re-export from shared core for convenience
analyze_content = analyze_content


# ============================================================================
# CLAUDE-SPECIFIC: TOOL CHECKING
# ============================================================================


def check_tool(tool_name: str, tool_input: dict) -> tuple[str, str]:
    """
    Check if a Claude Code tool should be allowed, blocked, or require confirmation.

    Args:
        tool_name: Name of the tool (e.g., "Write", "Bash", "Edit")
        tool_input: Tool input parameters as dict

    Returns:
        Tuple of (permission_decision, reason)
        permission_decision: "allow", "deny", or "ask"
    """
    tool_name_lower = tool_name.lower()

    for sensitive in SENSITIVE_TOOLS:
        if sensitive.endswith("*"):
            prefix = sensitive[:-1].lower()
            if tool_name_lower.startswith(prefix):
                return (
                    "ask",
                    f"Tool '{tool_name}' requires confirmation "
                    f"(matches sensitive pattern '{sensitive}')",
                )
        elif sensitive.lower() in tool_name_lower:
            return ("ask", f"Tool '{tool_name}' requires confirmation")

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        command_lower = command.lower()

        dangerous_commands = [
            "rm -rf", "sudo", "chmod 777", "> /dev/", "mkfs", "dd if=",
        ]
        for dangerous in dangerous_commands:
            if dangerous in command_lower:
                return (
                    "ask",
                    f"Bash command contains potentially dangerous operation: "
                    f"{dangerous}",
                )

    elif tool_name in ["Write", "Edit"]:
        file_path = tool_input.get("file_path", "")
        sensitive_files = [
            ".env", ".ssh/", "credentials", "secrets", ".git/config",
        ]
        for sensitive in sensitive_files:
            if sensitive in file_path.lower():
                return ("ask", f"Operation on sensitive file: {file_path}")

    return "allow", ""


def analyze_tool_result(tool_name: str, tool_response: dict) -> dict:
    """Analyze Claude Code tool result for potential issues."""
    result_str = (
        json.dumps(tool_response)
        if isinstance(tool_response, dict)
        else str(tool_response)
    )

    analysis: dict[str, Any] = {
        "sensitive_data_hints": [],
        "result_size": len(result_str),
        "is_error": False,
    }

    content_info = analyze_content(result_str)
    analysis["sensitive_data_hints"] = content_info.get("sensitive_data_hints", [])

    if isinstance(tool_response, dict):
        if tool_response.get("error") or tool_response.get("Error"):
            analysis["is_error"] = True
        if tool_response.get("status") in ["error", "failed", "failure"]:
            analysis["is_error"] = True

    return analysis


# ============================================================================
# CLAUDE-SPECIFIC: HOOK BASE CLASSES
# ============================================================================


class BaseHook:
    """
    Base class for Claude Code hooks.

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
                "error_type": "JSONDecodeError",
            })
            print(json.dumps(self.default_output))
            return

        try:
            result = self.process(data)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            metrics.record_call(
                self.hook_name, blocked=False, latency_ms=latency_ms, error=True,
            )
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
        return format_violation_message(violations, hook_name=self.hook_name)

    def log_alert(self, alert_type: str, details: dict, data: dict):
        log_security_alert(alert_type, {
            "hook": self.hook_name,
            "guardrail_name": get_hook_guardrail_name(self.hook_name),
            **details,
        }, data)

    @property
    def is_enabled(self) -> bool:
        return is_hook_enabled(self.hook_name)


class InputGuardrailHook(BaseHook):
    """Base class for input guardrail hooks (UserPromptSubmit, PreToolUse)."""

    def __init__(self, hook_name: str, text_field: str = "prompt"):
        super().__init__(hook_name, {})
        self.text_field = text_field

    def get_text_to_check(self, data: dict) -> str:
        return data.get(self.text_field, "")

    def process(self, data: dict) -> dict:
        import sys
        import time

        text = self.get_text_to_check(data)

        if not text or not text.strip():
            return {}

        if not self.is_enabled:
            log_event(self.hook_name, {**data, "skipped": "guardrails disabled"})
            return {}

        start_time = time.time()
        should_block, violations, api_result = self.check_guardrails(text)

        print(
            f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
            file=sys.stderr,
        )

        if should_block:
            violation_message = self.format_block_message(violations)
            self.log_alert("input_blocked", {
                "violations": violations,
                "text_preview": text[:200] + "..." if len(text) > 200 else text,
            }, data)
            return self.create_block_response(violation_message)

        return {}

    def create_block_response(self, reason: str) -> dict:
        """Create a block response. Override in subclasses for hook-specific format."""
        return {
            "decision": "block",
            "reason": f"Blocked by Enkrypt AI Guardrails:\n\n{reason}",
        }


class OutputAuditHook(BaseHook):
    """Base class for output audit hooks (PostToolUse)."""

    def __init__(self, hook_name: str, text_field: str = "tool_response"):
        super().__init__(hook_name, {})
        self.text_field = text_field

    def get_text_to_check(self, data: dict) -> str:
        field_value = data.get(self.text_field, {})
        if isinstance(field_value, dict):
            return json.dumps(field_value)
        return str(field_value) if field_value else ""

    def process(self, data: dict) -> dict:
        text = self.get_text_to_check(data)

        if not text or not text.strip():
            return {}

        if not self.is_enabled:
            return {}

        should_block, violations, api_result = self.check_guardrails(text)

        if violations:
            self.log_alert("output_audit_alert", {
                "violations": violations,
                "text_preview": text[:200] + "..." if len(text) > 200 else text,
            }, data)

        return {}
