#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Shared Module for Kiro Hooks

Uses the shared ``enkrypt_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only Kiro-specific file checking, hook classes, and backward-compatible
function signatures.

Configuration is loaded from guardrails_config.json

Kiro Hook Actions:
- Shell Command: Exit 0 = success (stdout to context), Other = error (stderr to agent)
- Agent Prompt: Returns prompt text that is sent to the agent
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

CONFIG_FILE = find_guardrails_config("kiro")
LOG_DIR = Path(
    os.environ.get(
        "KIRO_HOOKS_LOG_DIR",
        str(Path.home() / "kiro" / "hooks_logs"),
    )
)

KIRO_HOOK_NAMES = [
    "PromptSubmit",
    "AgentStop",
    "FileSave",
    "FileCreate",
    "FileDelete",
    "Manual",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="kiro-guardrails",
    hook_names=KIRO_HOOK_NAMES,
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
    text: str, hook_name: str = "PromptSubmit"
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


# Re-export with backward-compatible signature (handlers pass hook_name=...)
_format_violation_message = format_violation_message


def format_violation_message(
    violations: list, hook_name: str = "", guardrail_name: str = ""
) -> str:
    name = guardrail_name or (get_hook_guardrail_name(hook_name) if hook_name else "")
    return _format_violation_message(violations, guardrail_name=name)


analyze_content = analyze_content


def get_timestamp() -> str:
    """Get ISO format timestamp."""
    import datetime
    return datetime.datetime.now().isoformat()


# ============================================================================
# KIRO-SPECIFIC: Source event mapping
# ============================================================================


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    event_mapping = {
        "PromptSubmit": "pre-prompt",
        "AgentStop": "post-response",
        "FileSave": "file-save",
        "FileCreate": "file-create",
        "FileDelete": "file-delete",
        "Manual": "manual-trigger",
    }
    return event_mapping.get(hook_name, hook_name)


# ============================================================================
# KIRO-SPECIFIC: Sensitive file patterns and file checking
# ============================================================================

SENSITIVE_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
    (re.compile(r"private[_-]?key", re.IGNORECASE), "private key reference"),
    (re.compile(r"aws[_-]?(access|secret)", re.IGNORECASE), "AWS credential reference"),
]

SENSITIVE_FILE_PATTERNS = [
    re.compile(r"\.env$", re.IGNORECASE),
    re.compile(r"\.env\.", re.IGNORECASE),
    re.compile(r"secrets?\.", re.IGNORECASE),
    re.compile(r"credentials?\.", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
]

# Load user-defined sensitive file patterns from config
_config_raw = {}
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as _f:
        _config_raw = json.load(_f)
except (FileNotFoundError, json.JSONDecodeError):
    pass
SENSITIVE_FILE_PATTERN_STRINGS: list[str] = _config_raw.get("sensitive_file_patterns", [])


def is_sensitive_file(file_path: str) -> bool:
    """Check if a file path matches sensitive file patterns."""
    for pattern in SENSITIVE_FILE_PATTERNS:
        if pattern.search(file_path):
            return True

    for pattern_str in SENSITIVE_FILE_PATTERN_STRINGS:
        try:
            if re.search(pattern_str, file_path, re.IGNORECASE):
                return True
        except re.error:
            pass

    return False


def analyze_file_content(file_path: str, content: str) -> dict:
    """Analyze file content for potential security issues."""
    analysis = {
        "file_path": file_path,
        "is_sensitive_file": is_sensitive_file(file_path),
        "sensitive_data_hints": [],
        "content_size": len(content),
    }

    for pattern, name in SENSITIVE_PATTERNS:
        if pattern.search(content):
            analysis["sensitive_data_hints"].append(name)

    return analysis


def check_file_content(file_path: str, content: str, hook_name: str = "FileSave") -> tuple[bool, list, dict]:
    """
    Check file content using Enkrypt API.

    Args:
        file_path: Path to the file
        content: File content to check
        hook_name: The hook name (FileSave, FileCreate)

    Returns:
        Tuple of (should_block, violations, result)
    """
    analysis = analyze_file_content(file_path, content)

    if not analysis["is_sensitive_file"] and not analysis["sensitive_data_hints"]:
        if not is_hook_enabled(hook_name):
            return False, [], {"skipped": "No sensitive content detected, guardrails disabled"}

    should_block, violations, api_result = check_with_enkrypt_api(content, hook_name)
    api_result["local_analysis"] = analysis
    return should_block, violations, api_result


# ============================================================================
# KIRO-SPECIFIC: Hook base classes
# ============================================================================


class BaseHook:
    """
    Base class for Kiro hooks.

    Kiro Shell Command Hooks:
    - Exit code 0: Success, stdout added to agent context
    - Exit code != 0: Error, stderr sent to agent

    Subclasses should implement:
    - process(self, data: dict) -> tuple[int, str, str]
      Returns: (exit_code, stdout_message, stderr_message)
    """

    def __init__(self, hook_name: str):
        self.hook_name = hook_name

    def run(self):
        """Main entry point - reads stdin/env, processes, writes stdout/stderr."""
        import sys
        import time

        start_time = time.time()
        data = self._read_input()

        try:
            exit_code, stdout_msg, stderr_msg = self.process(data)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            _core.metrics.record_call(self.hook_name, blocked=False, latency_ms=latency_ms, error=True)
            log_event(self.hook_name, {
                "error": str(e),
                "error_type": type(e).__name__,
                "data": data,
            })
            print(f"Hook error: {str(e)}", file=sys.stderr)
            sys.exit(1)

        result = {
            "exit_code": exit_code,
            "stdout": stdout_msg[:200] if stdout_msg else "",
            "stderr": stderr_msg[:200] if stderr_msg else "",
        }
        log_event(self.hook_name, data, result)
        log_to_combined(self.hook_name, data, result)
        flush_logs()

        if stdout_msg:
            print(stdout_msg)
        if stderr_msg:
            print(stderr_msg, file=sys.stderr)
        sys.exit(exit_code)

    def _read_input(self) -> dict:
        """Read input from stdin or environment variables."""
        import sys
        data = {}

        try:
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
                if stdin_content:
                    data = json.loads(stdin_content)
        except (json.JSONDecodeError, IOError):
            pass

        data["USER_PROMPT"] = os.environ.get("USER_PROMPT", "")
        data["USER"] = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        data["PWD"] = os.environ.get("PWD", os.getcwd())
        return data

    def process(self, data: dict) -> tuple[int, str, str]:
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


class InputGuardrailHook(BaseHook):
    """
    Base class for input guardrail hooks (PromptSubmit).

    For Kiro shell command hooks, blocking means returning non-zero exit code.
    """

    def __init__(self, hook_name: str, text_field: str = "USER_PROMPT"):
        super().__init__(hook_name)
        self.text_field = text_field

    def get_text_to_check(self, data: dict) -> str:
        return data.get(self.text_field, "")

    def process(self, data: dict) -> tuple[int, str, str]:
        import time

        text = self.get_text_to_check(data)

        if not text or not text.strip():
            return 0, "", ""

        if not self.is_enabled:
            log_event(self.hook_name, {**data, "skipped": "guardrails disabled"})
            return 0, "", ""

        start_time = time.time()
        should_block, violations, api_result = self.check_guardrails(text)

        if should_block:
            violation_message = self.format_block_message(violations)
            self.log_alert("input_blocked", {
                "violations": violations,
                "text_preview": text[:200] + "..." if len(text) > 200 else text,
            }, data)
            return 1, "", f"Blocked by Enkrypt AI Guardrails:\n\n{violation_message}"

        return 0, "", ""


class OutputAuditHook(BaseHook):
    """
    Base class for output audit hooks (AgentStop).

    These hooks observe output but don't block it (audit-only).
    """

    def __init__(self, hook_name: str):
        super().__init__(hook_name)

    def process(self, data: dict) -> tuple[int, str, str]:
        log_event(self.hook_name, data)
        return 0, "", ""
