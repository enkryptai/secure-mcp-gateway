#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Core Module for Strands Agents

Uses the shared ``enkrypt_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only Strands Agents-specific configuration and backward-compatible
function signatures.

Configuration is loaded from guardrails_config.json
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
from pathlib import Path
from typing import Any, Dict, Optional

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

CONFIG_FILE = find_guardrails_config("strands")
LOG_DIR = Path(
    os.environ.get(
        "STRANDS_GUARDRAILS_LOG_DIR",
        str(Path.home() / "strands" / "guardrails_logs"),
    )
)

STRANDS_HOOK_NAMES = [
    "MessageAdded",
    "BeforeInvocation",
    "AfterInvocation",
    "BeforeModelCall",
    "AfterModelCall",
    "BeforeToolCall",
    "AfterToolCall",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="strands-guardrails",
    hook_names=STRANDS_HOOK_NAMES,
)

SENSITIVE_TOOLS: list[str] = _core.sensitive_tools

_SOURCE_EVENT_MAP = {
    "MessageAdded": "message-added",
    "BeforeInvocation": "pre-invocation",
    "AfterInvocation": "post-invocation",
    "BeforeModelCall": "pre-model",
    "AfterModelCall": "post-model",
    "BeforeToolCall": "pre-tool",
    "AfterToolCall": "post-tool",
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
    return _SOURCE_EVENT_MAP.get(hook_name, hook_name.lower())


def check_with_enkrypt_api(
    text: str, hook_name: str = "MessageAdded"
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
