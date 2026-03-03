#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Core Module for LangChain

Uses the shared ``enkrypt_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only LangChain-specific text extraction helpers and backward-compatible
function signatures.

Configuration is loaded from guardrails_config.json
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
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

CONFIG_FILE = find_guardrails_config("langchain")
LOG_DIR = Path(
    os.environ.get(
        "LANGCHAIN_GUARDRAILS_LOG_DIR",
        str(Path.home() / "langchain" / "guardrails_logs"),
    )
)

LANGCHAIN_HOOK_NAMES = [
    "on_llm_start",
    "on_llm_end",
    "on_llm_error",
    "on_chat_model_start",
    "on_chain_start",
    "on_chain_end",
    "on_chain_error",
    "on_tool_start",
    "on_tool_end",
    "on_tool_error",
    "on_agent_action",
    "on_agent_finish",
    "on_retriever_start",
    "on_retriever_end",
    "on_retriever_error",
    "on_text",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="langchain-guardrails",
    hook_names=LANGCHAIN_HOOK_NAMES,
)

SENSITIVE_TOOLS: list[str] = _core.sensitive_tools


# ============================================================================
# BACKWARD-COMPATIBLE API
# ============================================================================


def is_hook_enabled(hook_name: str) -> bool:
    return _core.is_enabled(hook_name)


def get_hook_block_list(hook_name: str) -> list[str]:
    return _core.get_block_list(hook_name)


def get_hook_guardrail_name(hook_name: str) -> str:
    return _core.get_guardrail_name(hook_name)


def check_with_enkrypt_api(
    text: str, hook_name: str = "on_llm_start"
) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
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
# LANGCHAIN-SPECIFIC TEXT EXTRACTION HELPERS
# ============================================================================


def extract_prompts_text(prompts: list) -> str:
    """Extract text from LangChain prompts list."""
    if not prompts:
        return ""
    parts: list[str] = []
    for prompt in prompts:
        if isinstance(prompt, str):
            parts.append(prompt)
        elif isinstance(prompt, list):
            for msg in prompt:
                if hasattr(msg, "content"):
                    parts.append(str(msg.content))
                elif isinstance(msg, dict) and "content" in msg:
                    parts.append(str(msg["content"]))
                elif isinstance(msg, str):
                    parts.append(msg)
    return "\n".join(parts)


def extract_messages_text(messages: list) -> str:
    """Extract text from LangChain messages list."""
    parts: list[str] = []
    for msg in messages:
        if hasattr(msg, "content"):
            content = msg.content
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(item["text"])
                    elif isinstance(item, str):
                        parts.append(item)
        elif isinstance(msg, dict):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(item["text"])
                    elif isinstance(item, str):
                        parts.append(item)
    return "\n".join(parts)


def extract_chain_inputs_text(inputs: dict) -> str:
    """Extract text from chain inputs dictionary."""
    parts: list[str] = []
    for _key, value in inputs.items():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif hasattr(item, "content"):
                    parts.append(str(item.content))
    return "\n".join(parts)


def extract_chain_outputs_text(outputs: dict) -> str:
    """Extract text from chain outputs dictionary."""
    parts: list[str] = []
    for _key, value in outputs.items():
        if isinstance(value, str):
            parts.append(value)
        elif hasattr(value, "content"):
            parts.append(str(value.content))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif hasattr(item, "content"):
                    parts.append(str(item.content))
    return "\n".join(parts)


def extract_retriever_query_text(query: str) -> str:
    """Extract text from retriever query."""
    return str(query) if query else ""


def extract_retriever_documents_text(documents: list) -> str:
    """Extract text from retriever documents."""
    parts: list[str] = []
    for doc in documents:
        if hasattr(doc, "page_content"):
            parts.append(doc.page_content)
        elif isinstance(doc, dict) and "page_content" in doc:
            parts.append(doc["page_content"])
        elif isinstance(doc, str):
            parts.append(doc)
    return "\n".join(parts)
