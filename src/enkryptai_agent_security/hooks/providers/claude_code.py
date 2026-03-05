#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - Core Module for Claude Code Hooks

Uses the shared ``enkryptai_agent_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only Claude-Code-specific text extractors, output formatters, and
backward-compatible function signatures.

Configuration is loaded from guardrails_config.json

Claude Code Hook Documentation:
https://docs.anthropic.com/en/docs/claude-code/hooks
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
# CONSTANTS
# ============================================================================

HOOK_EVENTS = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "PreCompact",
    "SessionEnd",
    "Notification",
]

DETECTOR_TYPES = [
    "injection_attack",
    "pii",
    "toxicity",
    "nsfw",
    "bias",
    "sponge_attack",
    "keyword_detector",
    "topic_detector",
    "policy_violation",
]

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_FILE = find_guardrails_config("claude_code")
LOG_DIR = Path(
    os.environ.get(
        "CLAUDE_CODE_HOOKS_LOG_DIR",
        str(Path.home() / "claude_code" / "hooks_logs"),
    )
)

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="claude-code-guardrails",
    hook_names=HOOK_EVENTS,
)

# Backward-compatible exports used by handler files
metrics = _core.metrics

# Raw config dict (session_start.py imports this directly)
_config: dict[str, Any] = {}
try:
    if CONFIG_FILE.is_file():
        with open(CONFIG_FILE, encoding="utf-8") as _f:
            _config = json.load(_f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

_api_cfg = _config.get("enkrypt_api", {})
ENKRYPT_API_KEY = os.environ.get(
    "ENKRYPT_API_KEY", _api_cfg.get("api_key", "")
).strip()


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
    """Map hook name to source event for API."""
    mapping = {
        "UserPromptSubmit": "user_prompt",
        "PreToolUse": "tool_input",
        "PostToolUse": "tool_output",
        "Stop": "agent_stop",
        "SessionStart": "session_start",
        "SessionEnd": "session_end",
    }
    return mapping.get(hook_name, hook_name.lower())


def check_with_enkrypt_api(
    text: str, hook_name: str = "UserPromptSubmit"
) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
    """Check text via shared HooksCore. Returns (should_block, violations, raw)."""
    source_event = get_source_event(hook_name)
    return _core.check(text, hook_name, source_event=source_event)


def log_event(event_type: str, data: Dict[str, Any]) -> None:
    """Log an event to the audit log."""
    _core.log_event(event_type, data)


def log_security_alert(
    alert_type: str,
    details: Dict[str, Any],
    context: Dict[str, Any] | None = None,
) -> None:
    _core.log_security_alert(alert_type, details)


def flush_logs() -> None:
    _core.flush_logs()


def is_sensitive_tool(tool_name: str) -> bool:
    return _is_sensitive_tool(tool_name, _core.sensitive_tools)


def close_http_session() -> None:
    """Close the HTTP session (session lifecycle managed by HooksCore)."""
    pass


def reload_config() -> None:
    _core.reload_config(CONFIG_FILE)


# ============================================================================
# CLAUDE CODE HOOK I/O HELPERS
# ============================================================================


def read_hook_input() -> Dict[str, Any]:
    """Read and parse hook input from stdin."""
    try:
        input_data = sys.stdin.read()
        if not input_data.strip():
            return {}
        return json.loads(input_data)
    except json.JSONDecodeError as e:
        log_event("input_parse_error", {"error": str(e)})
        return {}
    except Exception as e:
        log_event("input_read_error", {"error": str(e)})
        return {}


def output_json(data: Dict[str, Any]) -> None:
    """Output JSON to stdout."""
    print(json.dumps(data))


def output_error(message: str) -> None:
    """Output error message to stderr."""
    print(message, file=sys.stderr)


# ============================================================================
# CLAUDE CODE HOOK OUTPUT FORMATTERS
# ============================================================================


def format_blocking_error(
    violations: List[Dict[str, Any]], hook_name: str
) -> str:
    """Format violation message for stderr (used with exit code 2)."""
    if not violations:
        return ""
    detector_names = [v["detector"] for v in violations]
    return (
        f"[Enkrypt Guardrails - {hook_name}] "
        f"Blocked due to: {', '.join(detector_names)}"
    )


def create_json_output(
    hook_event_name: str,
    decision: Optional[str] = None,
    reason: Optional[str] = None,
    permission_decision: Optional[str] = None,
    permission_decision_reason: Optional[str] = None,
    additional_context: Optional[str] = None,
    updated_input: Optional[Dict[str, Any]] = None,
    continue_session: bool = True,
    stop_reason: Optional[str] = None,
    suppress_output: bool = False,
    system_message: Optional[str] = None,
) -> Dict[str, Any]:
    """Create structured JSON output for Claude Code hooks."""
    output: Dict[str, Any] = {}

    if not continue_session:
        output["continue"] = False
        if stop_reason:
            output["stopReason"] = stop_reason

    if suppress_output:
        output["suppressOutput"] = True

    if system_message:
        output["systemMessage"] = system_message

    if decision:
        output["decision"] = decision
        if reason:
            output["reason"] = reason

    hook_specific: Dict[str, Any] = {"hookEventName": hook_event_name}

    if permission_decision:
        hook_specific["permissionDecision"] = permission_decision
    if permission_decision_reason:
        hook_specific["permissionDecisionReason"] = permission_decision_reason
    if additional_context:
        hook_specific["additionalContext"] = additional_context
    if updated_input:
        hook_specific["updatedInput"] = updated_input

    if len(hook_specific) > 1:
        output["hookSpecificOutput"] = hook_specific

    return output


# ============================================================================
# CLAUDE CODE TEXT EXTRACTORS
# ============================================================================


def extract_text_from_tool_input(
    tool_name: str, tool_input: Dict[str, Any]
) -> str:
    """Extract text content from tool input for guardrails check."""
    text_parts: list[str] = []

    if tool_name == "Bash":
        if "command" in tool_input:
            text_parts.append(tool_input["command"])
        if "description" in tool_input:
            text_parts.append(tool_input["description"])

    elif tool_name == "Write":
        if "content" in tool_input:
            text_parts.append(tool_input["content"])
        if "file_path" in tool_input:
            text_parts.append(tool_input["file_path"])

    elif tool_name == "Edit":
        if "new_string" in tool_input:
            text_parts.append(tool_input["new_string"])
        if "old_string" in tool_input:
            text_parts.append(tool_input["old_string"])

    elif tool_name == "Read":
        if "file_path" in tool_input:
            text_parts.append(tool_input["file_path"])

    else:
        for key in [
            "text", "content", "message", "query", "prompt", "input", "data",
        ]:
            if key in tool_input and isinstance(tool_input[key], str):
                text_parts.append(tool_input[key])

    return "\n".join(text_parts)


def extract_text_from_tool_response(
    tool_name: str, tool_response: Dict[str, Any]
) -> str:
    """Extract text content from tool response for guardrails check."""
    text_parts: list[str] = []

    for key in [
        "output", "result", "content", "text", "data", "response",
        "stdout", "stderr",
    ]:
        if key in tool_response:
            value = tool_response[key]
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, dict):
                text_parts.append(json.dumps(value))

    if not text_parts and tool_response:
        text_parts.append(json.dumps(tool_response))

    return "\n".join(text_parts)
