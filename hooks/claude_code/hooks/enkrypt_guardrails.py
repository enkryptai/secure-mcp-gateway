#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - Core Module for Claude Code Hooks

This module provides the core Enkrypt API integration for Claude Code hooks:
- UserPromptSubmit (input guardrails)
- PreToolUse (tool input guardrails)
- PostToolUse (tool output guardrails)
- Stop (session stop control)
- SessionStart (session initialization)
- SessionEnd (session cleanup)

Configuration is loaded from guardrails_config.json

Claude Code Hook Documentation:
https://docs.anthropic.com/en/docs/claude-code/hooks
"""

import os
import re
import json
import sys
import time
import atexit
import datetime
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# Suppress warnings
import warnings
warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================================
# CONSTANTS
# ============================================================================

# Hook event names (from Claude Code documentation)
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

# Detector types from Enkrypt API
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

# Sensitive data patterns
SENSITIVE_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
]

# Header masking patterns
SENSITIVE_HEADER_KEYS = {"apikey", "authorization", "x-api-key", "bearer", "token"}


# ============================================================================
# CONNECTION POOLING
# ============================================================================

def _create_session() -> requests.Session:
    """Create a requests session with connection pooling and retry logic."""
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST", "GET"],
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


_http_session: Optional[requests.Session] = None
_session_lock = threading.Lock()


def get_http_session() -> requests.Session:
    """Get or create the global HTTP session (thread-safe)."""
    global _http_session
    if _http_session is None:
        with _session_lock:
            if _http_session is None:
                _http_session = _create_session()
    return _http_session


def close_http_session():
    """Close the HTTP session."""
    global _http_session
    if _http_session is not None:
        _http_session.close()
        _http_session = None


# Register cleanup
atexit.register(close_http_session)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Find config file
SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "guardrails_config.json"

# Alternative config locations
if not CONFIG_FILE.exists():
    alt_paths = [
        Path(os.environ.get("ENKRYPT_GUARDRAILS_CONFIG", "")),
        Path.cwd() / "guardrails_config.json",
        SCRIPT_DIR.parent / "guardrails_config.json",
    ]
    for alt in alt_paths:
        if alt.exists():
            CONFIG_FILE = alt
            break


def load_config() -> Dict[str, Any]:
    """Load configuration from JSON file."""
    try:
        if CONFIG_FILE.is_file():
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
    except Exception:
        # Can't log here - logging not set up yet
        pass
    return {}


# Log directory (create early, before config)
LOG_DIR = Path.home() / "claude_code" / "guardrails_logs"
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass  # Non-critical


def _log_early(event_type: str, data: Dict[str, Any]) -> None:
    """Early logging before full logging is set up."""
    try:
        log_file = LOG_DIR / "combined_audit.jsonl"
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event_type,
            **data
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# Load configuration
_config = load_config()

# API Configuration
ENKRYPT_API_URL = _config.get("enkrypt_api", {}).get(
    "url", os.environ.get("ENKRYPT_API_URL", "https://api.enkryptai.com/guardrails/policy/detect")
)
ENKRYPT_API_KEY = _config.get("enkrypt_api", {}).get(
    "api_key", os.environ.get("ENKRYPT_API_KEY", "")
)
ENKRYPT_SSL_VERIFY = _config.get("enkrypt_api", {}).get("ssl_verify", True)
ENKRYPT_TIMEOUT = _config.get("enkrypt_api", {}).get("timeout", 15)
ENKRYPT_FAIL_SILENTLY = _config.get("enkrypt_api", {}).get("fail_silently", True)


# ============================================================================
# LOGGING
# ============================================================================

def log_event(event_type: str, data: Dict[str, Any]) -> None:
    """Log an event to the audit log."""
    try:
        log_file = LOG_DIR / "combined_audit.jsonl"
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event_type,
            **data
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Don't fail on logging errors


def log_security_alert(alert_type: str, details: Dict[str, Any], context: Dict[str, Any] = None) -> None:
    """Log a security alert."""
    try:
        log_file = LOG_DIR / "security_alerts.jsonl"
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "alert_type": alert_type,
            "details": details,
            "context": context or {}
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ============================================================================
# METRICS
# ============================================================================

@dataclass
class HookMetrics:
    """Metrics for a specific hook."""
    total_calls: int = 0
    blocked: int = 0
    allowed: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total_calls if self.total_calls > 0 else 0


class MetricsCollector:
    """Thread-safe metrics collector."""

    def __init__(self):
        self._metrics: Dict[str, HookMetrics] = {}
        self._lock = threading.Lock()

    def record_call(self, hook_name: str, blocked: bool = False, latency_ms: float = 0, error: bool = False):
        with self._lock:
            if hook_name not in self._metrics:
                self._metrics[hook_name] = HookMetrics()
            m = self._metrics[hook_name]
            m.total_calls += 1
            m.total_latency_ms += latency_ms
            if error:
                m.errors += 1
            elif blocked:
                m.blocked += 1
            else:
                m.allowed += 1

    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                name: {
                    "total_calls": m.total_calls,
                    "blocked": m.blocked,
                    "allowed": m.allowed,
                    "errors": m.errors,
                    "avg_latency_ms": m.avg_latency_ms
                }
                for name, m in self._metrics.items()
            }

    def reset(self):
        with self._lock:
            self._metrics.clear()


metrics = MetricsCollector()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask sensitive values in headers for logging."""
    masked = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_KEYS:
            masked[key] = f"{value[:8]}..." if len(value) > 8 else "***"
        else:
            masked[key] = value
    return masked


def is_hook_enabled(hook_name: str) -> bool:
    """Check if a hook is enabled in configuration."""
    hook_config = _config.get(hook_name, {})
    return hook_config.get("enabled", False)


def get_hook_block_list(hook_name: str) -> List[str]:
    """Get the block list for a specific hook."""
    hook_config = _config.get(hook_name, {})
    return hook_config.get("block", [])


def get_hook_guardrail_name(hook_name: str) -> str:
    """Get the guardrail name for a specific hook."""
    hook_config = _config.get(hook_name, {})
    return hook_config.get("guardrail_name", "Default Policy")


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


def is_sensitive_tool(tool_name: str) -> bool:
    """Check if a tool is considered sensitive."""
    sensitive_tools = _config.get("sensitive_tools", [])
    for pattern in sensitive_tools:
        if pattern.endswith("*"):
            if tool_name.startswith(pattern[:-1]):
                return True
        elif tool_name == pattern or tool_name.startswith(pattern):
            return True
    return False


# ============================================================================
# ENKRYPT API CLIENT
# ============================================================================

def parse_enkrypt_response(result: Dict[str, Any], block_list: List[str]) -> List[Dict[str, Any]]:
    """
    Parse Enkrypt API response and extract violations.

    API Response Format:
    {
      "summary": {
        "injection_attack": 1,  // 1 = detected, 0 = not detected
        "pii": 1,
        "toxicity": ["toxicity"],  // can be a list
        ...
      },
      "details": {
        "injection_attack": { "safe": "0.01", "attack": "0.99", ... },
        ...
      }
    }
    """
    violations = []
    summary = result.get("summary", {})
    details = result.get("details", {})

    # Map summary keys to detector names
    detector_mapping = {
        "nsfw": "nsfw",
        "toxicity": "toxicity",
        "pii": "pii",
        "injection_attack": "injection_attack",
        "keyword_detected": "keyword_detector",
        "policy_violation": "policy_violation",
        "bias": "bias",
        "sponge_attack": "sponge_attack",
        "on_topic": "topic_detector",
    }

    for summary_key, detector_name in detector_mapping.items():
        summary_value = summary.get(summary_key)

        # Check if this detector triggered
        is_detected = False
        if isinstance(summary_value, int) and summary_value == 1:
            is_detected = True
        elif isinstance(summary_value, list) and len(summary_value) > 0:
            is_detected = True
        elif isinstance(summary_value, bool) and summary_value:
            is_detected = True

        # Special case: on_topic=0 means OFF topic (violation)
        if summary_key == "on_topic":
            is_detected = summary_value == 0 if isinstance(summary_value, int) else False

        if is_detected and detector_name in block_list:
            violation_info = {
                "detector": detector_name,
                "detected": True,
                "blocked": True,
            }

            # Add details
            detail = details.get(detector_name, {}) or details.get(summary_key, {})
            if detail:
                violation_info["details"] = detail

            violations.append(violation_info)

    return violations


def check_with_enkrypt_api(
    text: str,
    hook_name: str = "PreToolUse"
) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Check content with Enkrypt AI API.

    Returns:
        Tuple of (should_block, violations, raw_result)
    """
    start_time = time.time()

    # Skip if no API key
    if not ENKRYPT_API_KEY:
        log_event("api_skipped", {"reason": "no_api_key", "hook": hook_name})
        return False, [], {}

    # Skip if hook is disabled
    if not is_hook_enabled(hook_name):
        return False, [], {"skipped": f"{hook_name} guardrails disabled"}

    # Skip empty text
    if not text or not text.strip():
        return False, [], {}

    block_list = get_hook_block_list(hook_name)
    guardrail_name = get_hook_guardrail_name(hook_name)

    try:
        # Disable SSL warnings if needed
        if not ENKRYPT_SSL_VERIFY:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = get_http_session()
        resp = session.post(
            ENKRYPT_API_URL,
            headers={
                "Content-Type": "application/json",
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-Policy": guardrail_name,
                "X-Enkrypt-Source-Name": "claude-code-hooks",
                "X-Enkrypt-Source-Event": get_source_event(hook_name),
            },
            json={"text": text},
            timeout=ENKRYPT_TIMEOUT,
            verify=ENKRYPT_SSL_VERIFY,
        )

        # Log response
        log_event("enkrypt_api_response", {
            "hook": hook_name,
            "status_code": resp.status_code,
            "response_preview": resp.text[:300] if resp.text else None,
        })

        resp.raise_for_status()
        result = resp.json()

        # Parse violations
        violations = parse_enkrypt_response(result, block_list)
        should_block = len(violations) > 0

        # Record metrics
        latency_ms = (time.time() - start_time) * 1000
        metrics.record_call(hook_name, blocked=should_block, latency_ms=latency_ms)

        return should_block, violations, result

    except requests.exceptions.Timeout:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": "timeout", "hook": hook_name})
        return should_block_on_error, [], {"error": "timeout"}

    except requests.exceptions.ConnectionError:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": "connection_error", "hook": hook_name})
        return should_block_on_error, [], {"error": "connection_error"}

    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": str(e), "hook": hook_name})
        return should_block_on_error, [], {"error": str(e)}


# ============================================================================
# CLAUDE CODE HOOK OUTPUT FORMATTERS
# ============================================================================

def format_blocking_error(violations: List[Dict[str, Any]], hook_name: str) -> str:
    """Format violation message for stderr (used with exit code 2)."""
    if not violations:
        return ""

    detector_names = [v["detector"] for v in violations]
    return f"[Enkrypt Guardrails - {hook_name}] Blocked due to: {', '.join(detector_names)}"


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
    """
    Create structured JSON output for Claude Code hooks.

    This follows the Claude Code hook output specification.
    """
    output: Dict[str, Any] = {}

    # Common fields
    if not continue_session:
        output["continue"] = False
        if stop_reason:
            output["stopReason"] = stop_reason

    if suppress_output:
        output["suppressOutput"] = True

    if system_message:
        output["systemMessage"] = system_message

    # Legacy decision field (for backward compatibility)
    if decision:
        output["decision"] = decision
        if reason:
            output["reason"] = reason

    # Hook-specific output
    hook_specific: Dict[str, Any] = {"hookEventName": hook_event_name}

    if permission_decision:
        hook_specific["permissionDecision"] = permission_decision
    if permission_decision_reason:
        hook_specific["permissionDecisionReason"] = permission_decision_reason
    if additional_context:
        hook_specific["additionalContext"] = additional_context
    if updated_input:
        hook_specific["updatedInput"] = updated_input

    if len(hook_specific) > 1:  # More than just hookEventName
        output["hookSpecificOutput"] = hook_specific

    return output


def output_json(data: Dict[str, Any]) -> None:
    """Output JSON to stdout."""
    print(json.dumps(data))


def output_error(message: str) -> None:
    """Output error message to stderr."""
    print(message, file=sys.stderr)


# ============================================================================
# HOOK INPUT PARSER
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


def extract_text_from_tool_input(tool_name: str, tool_input: Dict[str, Any]) -> str:
    """Extract text content from tool input for guardrails check."""
    text_parts = []

    # Bash tool
    if tool_name == "Bash":
        if "command" in tool_input:
            text_parts.append(tool_input["command"])
        if "description" in tool_input:
            text_parts.append(tool_input["description"])

    # Write tool
    elif tool_name == "Write":
        if "content" in tool_input:
            text_parts.append(tool_input["content"])
        if "file_path" in tool_input:
            text_parts.append(tool_input["file_path"])

    # Edit tool
    elif tool_name == "Edit":
        if "new_string" in tool_input:
            text_parts.append(tool_input["new_string"])
        if "old_string" in tool_input:
            text_parts.append(tool_input["old_string"])

    # Read tool
    elif tool_name == "Read":
        if "file_path" in tool_input:
            text_parts.append(tool_input["file_path"])

    # Generic: try common field names
    else:
        for key in ["text", "content", "message", "query", "prompt", "input", "data"]:
            if key in tool_input and isinstance(tool_input[key], str):
                text_parts.append(tool_input[key])

    return "\n".join(text_parts)


def extract_text_from_tool_response(tool_name: str, tool_response: Dict[str, Any]) -> str:
    """Extract text content from tool response for guardrails check."""
    text_parts = []

    # Try common response field names
    for key in ["output", "result", "content", "text", "data", "response", "stdout", "stderr"]:
        if key in tool_response:
            value = tool_response[key]
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, dict):
                text_parts.append(json.dumps(value))

    # If nothing found, serialize the whole response
    if not text_parts and tool_response:
        text_parts.append(json.dumps(tool_response))

    return "\n".join(text_parts)
