#!/usr/bin/env python
"""
Enkrypt AI Guardrails Integration for CrewAI Hooks

Uses the shared ``enkrypt_security.hooks`` infrastructure for API calls,
config loading, response parsing, logging, and metrics.  This module adds
only CrewAI-specific hook functions, the context manager, and
backward-compatible function signatures.

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

CONFIG_FILE = find_guardrails_config("crewai")
LOG_DIR = Path(
    os.environ.get(
        "CREWAI_GUARDRAILS_LOG_DIR",
        str(Path.home() / "crewai" / "guardrails_logs"),
    )
)

CREWAI_HOOK_NAMES = [
    "before_llm_call",
    "after_llm_call",
    "before_tool_call",
    "after_tool_call",
]

_core = HooksCore.from_config_file(
    CONFIG_FILE,
    log_dir=LOG_DIR,
    source_name="crewai-guardrails",
    hook_names=CREWAI_HOOK_NAMES,
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
    text: str, hook_name: str = "before_llm_call"
) -> tuple[bool, list, dict]:
    """Check text via shared HooksCore. Returns (should_block, violations, raw)."""
    return _core.check(text, hook_name)


def log_event(
    hook_name: str,
    data: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> None:
    _core.log_event(hook_name, data, result)


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
# CREWAI-SPECIFIC: Source event mapping
# ============================================================================


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    event_mapping = {
        "before_llm_call": "pre-llm",
        "after_llm_call": "post-llm",
        "before_tool_call": "pre-tool",
        "after_tool_call": "post-tool",
    }
    return event_mapping.get(hook_name, hook_name)


# ============================================================================
# CREWAI-SPECIFIC: Universal guardrails check
# ============================================================================


def check_guardrails(text: str, hook_name: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Universal function to check text against guardrails for any hook.

    Args:
        text: Text to check
        hook_name: Name of the hook
        context: Additional context information

    Returns:
        Dictionary with check results

    Raises:
        ValueError: If check fails and violations are blocking
    """
    should_block, violations, api_result = check_with_enkrypt_api(text, hook_name)

    if should_block:
        log_security_alert("guardrails_blocked", {
            "hook": hook_name,
            "violations": violations,
            "text_preview": text[:200] + "..." if len(text) > 200 else text,
        }, context or {})

        violation_msg = format_violation_message(violations, guardrail_name=get_hook_guardrail_name(hook_name))
        raise ValueError(
            f"Guardrails blocked operation in {hook_name}:\n{violation_msg}"
        )

    return {
        "passed": True,
        "violations": violations,
        "api_result": api_result,
        "hook": hook_name,
    }


# ============================================================================
# CREWAI-SPECIFIC: Hook functions (for programmatic registration)
# ============================================================================


def check_llm_input(context):
    """Monitor LLM calls and run guardrails checks."""
    import time
    start_time = time.time()

    try:
        text_to_check = context.task.description if hasattr(context, 'task') else str(context)
        context_dict = {
            'agent_name': getattr(context, 'agent_name', 'unknown'),
            'task': str(context.task.description) if hasattr(context, 'task') else None,
            'timestamp': get_timestamp()
        }

        log_event("before_llm_call_attempt", context_dict)
        check_guardrails(text_to_check, 'before_llm_call', context_dict)

        latency_ms = (time.time() - start_time) * 1000
        log_event("before_llm_call_passed", {**context_dict, "latency_ms": latency_ms})

    except ValueError as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Enkrypt Guardrails BLOCKED LLM call: {e}")
        log_event("before_llm_call_blocked", {**context_dict, "error": str(e), "latency_ms": latency_ms})
        return False
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Guardrails check failed: {e}")
        log_event("before_llm_call_error", {
            **context_dict, "error": str(e), "error_type": type(e).__name__, "latency_ms": latency_ms
        })

    return None


def check_llm_output(context):
    """Monitor LLM responses and run guardrails checks."""
    import time
    start_time = time.time()

    try:
        text_to_check = str(context.response) if hasattr(context, 'response') else str(context)
        context_dict = {
            'response_preview': text_to_check[:500],
            'timestamp': get_timestamp()
        }

        log_event("after_llm_call_attempt", context_dict)
        check_guardrails(text_to_check, 'after_llm_call', context_dict)

        latency_ms = (time.time() - start_time) * 1000
        log_event("after_llm_call_passed", {**context_dict, "latency_ms": latency_ms})

    except ValueError as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Enkrypt Guardrails BLOCKED LLM output: {e}")
        log_event("after_llm_call_blocked", {**context_dict, "error": str(e), "latency_ms": latency_ms})
        return False
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Guardrails check on output failed: {e}")
        log_event("after_llm_call_error", {
            **context_dict, "error": str(e), "error_type": type(e).__name__, "latency_ms": latency_ms
        })

    return None


def check_tool_input(context):
    """Monitor tool calls and run guardrails checks."""
    import time
    start_time = time.time()

    tool_name = context.tool_name
    tool_input = context.tool_input

    try:
        text_to_check = f"Tool: {tool_name}\nInput: {json.dumps(tool_input) if isinstance(tool_input, dict) else str(tool_input)}"
        context_dict = {
            'tool_name': tool_name,
            'tool_input': tool_input if isinstance(tool_input, dict) else {'input': str(tool_input)},
            'timestamp': get_timestamp()
        }

        log_event("before_tool_call_attempt", context_dict)
        check_guardrails(text_to_check, 'before_tool_call', context_dict)

        latency_ms = (time.time() - start_time) * 1000
        log_event("before_tool_call_passed", {**context_dict, "latency_ms": latency_ms})

    except ValueError as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Enkrypt Guardrails BLOCKED tool call to {tool_name}: {e}")
        log_event("before_tool_call_blocked", {**context_dict, "error": str(e), "latency_ms": latency_ms})
        return False
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Guardrails check on tool call failed: {e}")
        log_event("before_tool_call_error", {
            **context_dict, "error": str(e), "error_type": type(e).__name__, "latency_ms": latency_ms
        })

    return None


def check_tool_output(context):
    """Monitor tool responses and run guardrails checks."""
    import time
    start_time = time.time()

    try:
        text_to_check = str(context.tool_result) if hasattr(context, 'tool_result') else str(context)
        context_dict = {
            'tool_name': getattr(context, 'tool_name', 'unknown'),
            'tool_result_preview': text_to_check[:500],
            'timestamp': get_timestamp()
        }

        log_event("after_tool_call_attempt", context_dict)
        check_guardrails(text_to_check, 'after_tool_call', context_dict)

        latency_ms = (time.time() - start_time) * 1000
        log_event("after_tool_call_passed", {**context_dict, "latency_ms": latency_ms})

    except ValueError as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Enkrypt Guardrails BLOCKED tool output: {e}")
        log_event("after_tool_call_blocked", {**context_dict, "error": str(e), "latency_ms": latency_ms})
        return False
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        print(f"Guardrails check on tool output failed: {e}")
        log_event("after_tool_call_error", {
            **context_dict, "error": str(e), "error_type": type(e).__name__, "latency_ms": latency_ms
        })

    return None


# ============================================================================
# CREWAI-SPECIFIC: Context manager for automatic hook registration
# ============================================================================


class EnkryptGuardrailsContext:
    """
    Context manager for enabling Enkrypt AI guardrails with automatic hook registration.

    Usage:
        with EnkryptGuardrailsContext():
            crew = AddNumbers().crew()
            result = crew.kickoff(inputs)
    """

    def __init__(self):
        self._hooks_registered = False

    def __enter__(self):
        if not self._hooks_registered:
            self._register_hooks()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._hooks_registered:
            self._unregister_hooks()
        return False

    def _register_hooks(self):
        try:
            from crewai.hooks import (
                register_before_llm_call_hook,
                register_after_llm_call_hook,
                register_before_tool_call_hook,
                register_after_tool_call_hook
            )

            register_before_llm_call_hook(check_llm_input)
            register_after_llm_call_hook(check_llm_output)
            register_before_tool_call_hook(check_tool_input)
            register_after_tool_call_hook(check_tool_output)

            self._hooks_registered = True
            print("Enkrypt Guardrails hooks registered successfully")
            log_event("guardrails_hooks_registered", {"timestamp": get_timestamp()})

        except Exception as e:
            print(f"Failed to register guardrails hooks: {e}")
            log_event("guardrails_hooks_registration_failed", {"error": str(e), "timestamp": get_timestamp()})
            raise

    def _unregister_hooks(self):
        try:
            from crewai.hooks import (
                unregister_before_llm_call_hook,
                unregister_after_llm_call_hook,
                unregister_before_tool_call_hook,
                unregister_after_tool_call_hook
            )

            unregister_before_llm_call_hook(check_llm_input)
            unregister_after_llm_call_hook(check_llm_output)
            unregister_before_tool_call_hook(check_tool_input)
            unregister_after_tool_call_hook(check_tool_output)

            self._hooks_registered = False
            print("Enkrypt Guardrails hooks unregistered successfully")
            log_event("guardrails_hooks_unregistered", {"timestamp": get_timestamp()})

        except Exception as e:
            print(f"Failed to unregister guardrails hooks: {e}")
            log_event("guardrails_hooks_unregistration_failed", {"error": str(e), "timestamp": get_timestamp()})


# ============================================================================
# CREWAI-SPECIFIC: Convenience functions
# ============================================================================

_global_context = None


def enable_guardrails():
    """
    Enable guardrails globally by registering hooks.

    For scoped usage, prefer using the EnkryptGuardrailsContext context manager.
    """
    global _global_context
    if _global_context is None:
        _global_context = EnkryptGuardrailsContext()
        _global_context.__enter__()
        print("Enkrypt Guardrails enabled globally")
        log_event("guardrails_enabled_globally", {"timestamp": get_timestamp()})


def disable_guardrails():
    """Disable guardrails globally by unregistering hooks."""
    global _global_context
    if _global_context is not None:
        _global_context.__exit__(None, None, None)
        _global_context = None
        print("Enkrypt Guardrails disabled globally")
        log_event("guardrails_disabled_globally", {"timestamp": get_timestamp()})


def with_guardrails(func):
    """
    Decorator to run a function with guardrails enabled.

    Usage:
        @with_guardrails
        def run_crew():
            crew = AddNumbers().crew()
            return crew.kickoff(inputs)
    """
    def wrapper(*args, **kwargs):
        with EnkryptGuardrailsContext():
            return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
