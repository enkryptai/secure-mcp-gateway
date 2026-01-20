#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Core Module for LangGraph/LangChain Agents

This module provides the core Enkrypt API integration for LangGraph agents.
It enables guardrails protection via pre_model_hook, post_model_hook, and tool wrappers.

Supported guardrails checks:
- Prompt injection detection
- PII/secrets detection
- Toxicity filtering
- NSFW content filtering
- Keyword detection
- Policy violation detection
- Bias detection
- Topic enforcement

Configuration is loaded from guardrails_config.json
"""
import warnings
warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
import re
import json
import atexit
import datetime
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================================
# PRE-COMPILED REGEX PATTERNS
# ============================================================================

SENSITIVE_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
    (re.compile(r"private[_-]?key", re.IGNORECASE), "private key reference"),
    (re.compile(r"aws[_-]?(access|secret)", re.IGNORECASE), "AWS credential reference"),
    (re.compile(r"bearer\s+[a-zA-Z0-9\-_]+", re.IGNORECASE), "bearer token"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), "OpenAI API key pattern"),
]

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


atexit.register(close_http_session)


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class EnkryptApiConfig:
    """Configuration for Enkrypt API connection."""
    url: str = "https://api.enkryptai.com/guardrails/policy/detect"
    api_key: str = ""
    ssl_verify: bool = True
    timeout: int = 15
    fail_silently: bool = True


@dataclass
class HookPolicy:
    """Policy configuration for a specific hook event."""
    enabled: bool = False
    policy_name: str = ""
    block: List[str] = field(default_factory=list)


@dataclass
class HookMetrics:
    """Metrics for tracking hook performance."""
    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0
    last_call_timestamp: Optional[str] = None

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total_calls if self.total_calls > 0 else 0.0


# ============================================================================
# METRICS COLLECTION
# ============================================================================

class MetricsCollector:
    """Thread-safe metrics collector."""

    def __init__(self):
        self._metrics: Dict[str, HookMetrics] = {}
        self._lock = threading.Lock()

    def record_call(self, hook_name: str, blocked: bool, latency_ms: float, error: bool = False):
        with self._lock:
            if hook_name not in self._metrics:
                self._metrics[hook_name] = HookMetrics()
            m = self._metrics[hook_name]
            m.total_calls += 1
            m.total_latency_ms += latency_ms
            m.last_call_timestamp = datetime.datetime.now().isoformat()
            if error:
                m.errors += 1
            elif blocked:
                m.blocked_calls += 1
            else:
                m.allowed_calls += 1

    def get_metrics(self, hook_name: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if hook_name:
                m = self._metrics.get(hook_name, HookMetrics())
                return {
                    "total_calls": m.total_calls,
                    "blocked_calls": m.blocked_calls,
                    "allowed_calls": m.allowed_calls,
                    "errors": m.errors,
                    "avg_latency_ms": m.avg_latency_ms,
                    "last_call_timestamp": m.last_call_timestamp,
                }
            return {
                name: {
                    "total_calls": m.total_calls,
                    "blocked_calls": m.blocked_calls,
                    "allowed_calls": m.allowed_calls,
                    "errors": m.errors,
                    "avg_latency_ms": m.avg_latency_ms,
                    "last_call_timestamp": m.last_call_timestamp,
                }
                for name, m in self._metrics.items()
            }

    def reset(self, hook_name: Optional[str] = None):
        with self._lock:
            if hook_name:
                self._metrics[hook_name] = HookMetrics()
            else:
                self._metrics.clear()


metrics = MetricsCollector()


# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

CONFIG_FILE = Path(__file__).parent / "guardrails_config.json"
LOG_DIR = Path(os.environ.get("LANGGRAPH_GUARDRAILS_LOG_DIR", Path.home() / "langgraph" / "guardrails_logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_RETENTION_DAYS = int(os.environ.get("LANGGRAPH_GUARDRAILS_LOG_RETENTION_DAYS", "7"))


def validate_config(config: dict) -> List[str]:
    """Validate configuration and return list of errors."""
    errors = []

    api_config = config.get("enkrypt_api", {})
    if api_config:
        url = api_config.get("url", "")
        if url and not url.startswith(("http://", "https://")):
            errors.append(f"enkrypt_api.url must start with http:// or https://, got: {url}")

        timeout = api_config.get("timeout")
        if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
            errors.append(f"enkrypt_api.timeout must be a positive number, got: {timeout}")

        ssl_verify = api_config.get("ssl_verify")
        if ssl_verify is not None and not isinstance(ssl_verify, bool):
            errors.append(f"enkrypt_api.ssl_verify must be a boolean, got: {type(ssl_verify).__name__}")

    # Validate hook policies (LangGraph hook names)
    valid_hooks = [
        "pre_model_hook", "post_model_hook",
        "before_tool_call", "after_tool_call",
        "on_agent_action", "on_agent_finish"
    ]
    for hook_name in valid_hooks:
        policy = config.get(hook_name, {})
        if policy:
            if "enabled" in policy and not isinstance(policy["enabled"], bool):
                errors.append(f"{hook_name}.enabled must be a boolean")
            if "block" in policy and not isinstance(policy["block"], list):
                errors.append(f"{hook_name}.block must be a list")

    return errors


def load_config() -> dict:
    """Load and validate configuration from guardrails_config.json"""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        errors = validate_config(config)
        if errors:
            error_file = LOG_DIR / "config_errors.log"
            with open(error_file, "a", encoding="utf-8") as ef:
                timestamp = datetime.datetime.now().isoformat()
                ef.write(f"[{timestamp}] Config validation errors:\n")
                for error in errors:
                    ef.write(f"  - {error}\n")
        return config
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        error_file = LOG_DIR / "config_errors.log"
        with open(error_file, "a", encoding="utf-8") as ef:
            timestamp = datetime.datetime.now().isoformat()
            ef.write(f"[{timestamp}] JSON parse error: {e}\n")
        return {}


# Load config on module import
CONFIG = load_config()

# Extract configuration values
_api_config = CONFIG.get("enkrypt_api", {})
ENKRYPT_API_URL = os.environ.get(
    "ENKRYPT_API_URL",
    _api_config.get("url", "https://api.enkryptai.com/guardrails/policy/detect")
).strip()
ENKRYPT_API_KEY = os.environ.get(
    "ENKRYPT_API_KEY",
    _api_config.get("api_key", "")
).strip()
ENKRYPT_SSL_VERIFY = _api_config.get("ssl_verify", True)
ENKRYPT_TIMEOUT = _api_config.get("timeout", 15)
ENKRYPT_FAIL_SILENTLY = _api_config.get("fail_silently", True)

# Hook-specific policies (LangGraph hooks)
HOOK_POLICIES = {
    "pre_model_hook": CONFIG.get("pre_model_hook", {}),
    "post_model_hook": CONFIG.get("post_model_hook", {}),
    "before_tool_call": CONFIG.get("before_tool_call", {}),
    "after_tool_call": CONFIG.get("after_tool_call", {}),
    "on_agent_action": CONFIG.get("on_agent_action", {}),
    "on_agent_finish": CONFIG.get("on_agent_finish", {}),
}

# Sensitive tools that require extra validation
SENSITIVE_TOOLS = CONFIG.get("sensitive_tools", [])


# ============================================================================
# POLICY FUNCTIONS
# ============================================================================

def get_hook_policy(hook_name: str) -> dict:
    """Get policy config for a specific hook."""
    return HOOK_POLICIES.get(hook_name, {})


def is_hook_enabled(hook_name: str) -> bool:
    """Check if guardrails are enabled for a specific hook."""
    return get_hook_policy(hook_name).get("enabled", False)


def get_hook_block_list(hook_name: str) -> list:
    """Get list of detectors that should block for a specific hook."""
    return get_hook_policy(hook_name).get("block", [])


def get_hook_policy_name(hook_name: str) -> str:
    """Get policy name for a specific hook."""
    return get_hook_policy(hook_name).get("policy_name", f"Default {hook_name} Policy")


# ============================================================================
# LOGGING
# ============================================================================

class BufferedLogger:
    """Buffered logger for better I/O performance."""

    def __init__(self, buffer_size: int = 10, flush_interval: float = 5.0):
        self._buffers: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval
        self._last_flush: Dict[str, float] = {}
        self._closed = False

    def write(self, file_path: Path, entry: str):
        if self._closed:
            return
        key = str(file_path)
        now = datetime.datetime.now().timestamp()
        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = []
                self._last_flush[key] = now
            self._buffers[key].append(entry)
            should_flush = (
                len(self._buffers[key]) >= self._buffer_size or
                (now - self._last_flush.get(key, 0)) >= self._flush_interval
            )
            if should_flush:
                self._flush_file(key, file_path)

    def _flush_file(self, key: str, file_path: Path):
        if key in self._buffers and self._buffers[key]:
            try:
                with open(file_path, "a", encoding="utf-8") as f:
                    f.writelines(self._buffers[key])
                self._buffers[key] = []
                self._last_flush[key] = datetime.datetime.now().timestamp()
            except IOError:
                pass

    def flush_all(self):
        with self._lock:
            for key in list(self._buffers.keys()):
                self._flush_file(key, Path(key))

    def close(self):
        self._closed = True
        self.flush_all()


_buffered_logger = BufferedLogger()
atexit.register(_buffered_logger.close)


def get_timestamp():
    """Get ISO format timestamp."""
    return datetime.datetime.now().isoformat()


def log_event(hook_name: str, data: dict, result: dict = None):
    """Log a hook event."""
    log_file = LOG_DIR / f"{hook_name}.jsonl"
    entry = {
        "timestamp": get_timestamp(),
        "hook": hook_name,
        "input": data,
    }
    if result is not None:
        entry["output"] = result
    _buffered_logger.write(log_file, json.dumps(entry) + "\n")


def log_to_combined(hook_name: str, data: dict, result: dict = None):
    """Log to combined audit log."""
    log_file = LOG_DIR / "combined_audit.jsonl"
    entry = {
        "timestamp": get_timestamp(),
        "hook": hook_name,
        "data": data,
    }
    if result is not None:
        entry["result"] = result
    _buffered_logger.write(log_file, json.dumps(entry) + "\n")


def log_security_alert(alert_type: str, details: dict, data: dict):
    """Log a security alert."""
    alert_file = LOG_DIR / "security_alerts.jsonl"
    alert = {
        "timestamp": get_timestamp(),
        "type": alert_type,
        **details,
    }
    _buffered_logger.write(alert_file, json.dumps(alert) + "\n")


def flush_logs():
    """Manually flush all log buffers."""
    _buffered_logger.flush_all()


# ============================================================================
# ENKRYPT API RESPONSE PARSING
# ============================================================================

def parse_enkrypt_response(result: dict, block_list: list) -> list:
    """
    Parse Enkrypt API response and extract violations.
    """
    violations = []
    summary = result.get("summary", {})
    details = result.get("details", {})

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

        is_detected = False
        if isinstance(summary_value, int) and summary_value == 1:
            is_detected = True
        elif isinstance(summary_value, list) and len(summary_value) > 0:
            is_detected = True
        elif isinstance(summary_value, bool) and summary_value:
            is_detected = True

        # Special case: on_topic=0 means OFF topic
        if summary_key == "on_topic":
            is_detected = summary_value == 0 if isinstance(summary_value, int) else False

        if is_detected and detector_name in block_list:
            violation_info = {
                "detector": detector_name,
                "detected": True,
                "blocked": True,
            }

            detail = details.get(detector_name, {}) or details.get(summary_key, {})

            if detector_name == "pii":
                pii_detail = detail.get("pii", {})
                if pii_detail:
                    violation_info["entities"] = list(pii_detail.keys())
                    violation_info["pii_found"] = pii_detail

            elif detector_name == "toxicity":
                if isinstance(summary_value, list):
                    violation_info["toxicity_types"] = summary_value
                if "toxicity" in detail:
                    violation_info["score"] = detail.get("toxicity")

            elif detector_name == "keyword_detector":
                violation_info["matched_keywords"] = detail.get("detected_keywords", [])

            elif detector_name == "policy_violation":
                violation_info["violating_policy"] = detail.get("violating_policy", "")
                violation_info["explanation"] = detail.get("explanation", "")

            elif detector_name == "injection_attack":
                violation_info["attack_score"] = detail.get("attack", 0)

            elif detector_name == "nsfw":
                violation_info["nsfw_score"] = detail.get("nsfw", 0)

            elif detector_name == "bias":
                violation_info["bias_detected"] = detail.get("bias_detected", False)

            elif detector_name == "sponge_attack":
                violation_info["sponge_detected"] = detail.get("sponge_attack_detected", False)

            violations.append(violation_info)

    return violations


# ============================================================================
# ENKRYPT API FUNCTIONS
# ============================================================================

def mask_sensitive_headers(headers: dict) -> dict:
    """Mask sensitive values in headers for logging."""
    if not headers:
        return headers
    masked = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if any(s in key_lower for s in SENSITIVE_HEADER_KEYS):
            if value and len(value) > 4:
                masked[key] = f"****{value[-4:]}"
            else:
                masked[key] = "****"
        else:
            masked[key] = value
    return masked


def get_source_event(hook_name: str) -> str:
    """Map hook name to X-Enkrypt-Source-Event header value."""
    event_mapping = {
        "pre_model_hook": "pre-model",
        "post_model_hook": "post-model",
        "before_tool_call": "before-tool",
        "after_tool_call": "after-tool",
        "on_agent_action": "agent-action",
        "on_agent_finish": "agent-finish",
    }
    return event_mapping.get(hook_name, hook_name.lower().replace("_", "-"))


def check_with_enkrypt_api(text: str, hook_name: str = "pre_model_hook") -> tuple:
    """
    Check text using Enkrypt AI Guardrails API.

    Args:
        text: The text to check
        hook_name: The hook name for policy selection

    Returns:
        Tuple of (should_block, violations_list, full_result)
    """
    import time
    start_time = time.time()

    if not is_hook_enabled(hook_name):
        return False, [], {"skipped": f"{hook_name} guardrails disabled"}

    block_list = get_hook_block_list(hook_name)

    try:
        policy_name = get_hook_policy_name(hook_name)
        payload = {"text": text}

        log_event("enkrypt_api_debug", {
            "url": ENKRYPT_API_URL,
            "api_key_length": len(ENKRYPT_API_KEY) if ENKRYPT_API_KEY else 0,
            "payload_text_length": len(text),
            "policy_name": policy_name,
            "hook_name": hook_name,
        })

        if not ENKRYPT_SSL_VERIFY:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session = get_http_session()
        resp = session.post(
            ENKRYPT_API_URL,
            headers={
                "Content-Type": "application/json",
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-Policy": policy_name,
                "X-Enkrypt-Source-Name": "langgraph-guardrails",
                "X-Enkrypt-Source-Event": get_source_event(hook_name),
            },
            json=payload,
            timeout=ENKRYPT_TIMEOUT,
            verify=ENKRYPT_SSL_VERIFY,
        )

        log_event("enkrypt_api_response", {
            "status_code": resp.status_code,
            "response_preview": resp.text[:300] if resp.text else None,
        })

        resp.raise_for_status()
        result = resp.json()

        violations = parse_enkrypt_response(result, block_list)
        should_block = len(violations) > 0

        latency_ms = (time.time() - start_time) * 1000
        metrics.record_call(hook_name, blocked=should_block, latency_ms=latency_ms)

        return should_block, violations, result

    except requests.exceptions.Timeout:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": "timeout", "fail_silently": ENKRYPT_FAIL_SILENTLY})
        return should_block_on_error, [], {"error": "timeout", "fail_silently": ENKRYPT_FAIL_SILENTLY}

    except requests.exceptions.ConnectionError:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": "connection_error", "fail_silently": ENKRYPT_FAIL_SILENTLY})
        return should_block_on_error, [], {"error": "connection_error", "fail_silently": ENKRYPT_FAIL_SILENTLY}

    except requests.exceptions.HTTPError as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        error_info = {"error": str(e), "fail_silently": ENKRYPT_FAIL_SILENTLY}
        if e.response is not None:
            error_info["status_code"] = e.response.status_code
        log_event("enkrypt_api_error", error_info)
        return should_block_on_error, [], error_info

    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        log_event("enkrypt_api_error", {"error": str(e), "error_type": type(e).__name__})
        return should_block_on_error, [], {"error": str(e), "fail_silently": ENKRYPT_FAIL_SILENTLY}


def format_violation_message(violations: list, hook_name: str = "pre_model_hook") -> str:
    """Format a user-friendly message from violations."""
    if not violations:
        return ""

    policy_name = get_hook_policy_name(hook_name)
    messages = [f"Policy: {policy_name}\n"]

    for v in violations:
        detector = v["detector"]

        if detector == "pii":
            entities = v.get("entities", [])
            pii_found = v.get("pii_found", {})
            if pii_found:
                pii_items = [f"{k}" for k in list(pii_found.keys())[:3]]
                messages.append(f"PII/Secrets detected: {', '.join(pii_items)}")
            elif entities:
                messages.append(f"PII/Secrets detected: {', '.join(str(e) for e in entities[:5])}")
            else:
                messages.append("PII/Secrets detected")

        elif detector == "injection_attack":
            attack_score = v.get("attack_score", 0)
            try:
                score_float = float(attack_score) if attack_score else 0
                if score_float:
                    messages.append(f"Injection attack detected (confidence: {score_float:.1%})")
                else:
                    messages.append("Injection attack pattern detected")
            except (ValueError, TypeError):
                messages.append("Injection attack pattern detected")

        elif detector == "toxicity":
            toxicity_types = v.get("toxicity_types", [])
            score = v.get("score", "N/A")
            if toxicity_types:
                messages.append(f"Toxic content detected: {', '.join(toxicity_types)} (score: {score})")
            else:
                messages.append(f"Toxic content detected (score: {score})")

        elif detector == "nsfw":
            nsfw_score = v.get("nsfw_score", 0)
            try:
                score_float = float(nsfw_score) if nsfw_score else 0
                if score_float:
                    messages.append(f"NSFW content detected (confidence: {score_float:.1%})")
                else:
                    messages.append("NSFW content detected")
            except (ValueError, TypeError):
                messages.append("NSFW content detected")

        elif detector == "keyword_detector":
            keywords = v.get("matched_keywords", [])
            if keywords:
                messages.append(f"Banned keywords detected: {', '.join(keywords)}")
            else:
                messages.append("Banned keywords detected")

        elif detector == "policy_violation":
            violating_policy = v.get("violating_policy", "")
            explanation = v.get("explanation", "")
            if violating_policy:
                messages.append(f"Policy violation: {violating_policy}")
            if explanation:
                messages.append(f"   -> {explanation[:150]}")

        elif detector == "bias":
            messages.append("Bias detected in content")

        elif detector == "sponge_attack":
            messages.append("Sponge attack detected")

        elif detector == "topic_detector":
            messages.append("Off-topic or sensitive topic detected")

        else:
            messages.append(f"{detector.replace('_', ' ').title()} detected")

    return "\n".join(messages)


# ============================================================================
# TOOL CHECKING
# ============================================================================

def is_sensitive_tool(tool_name: str) -> bool:
    """Check if a tool is in the sensitive tools list."""
    tool_name_lower = tool_name.lower()
    for sensitive in SENSITIVE_TOOLS:
        if sensitive.endswith("*"):
            prefix = sensitive[:-1].lower()
            if tool_name_lower.startswith(prefix):
                return True
        elif sensitive.lower() in tool_name_lower:
            return True
    return False


def analyze_content(content: str) -> Dict[str, Any]:
    """Analyze content for sensitive data patterns."""
    analysis = {
        "sensitive_data_hints": [],
        "content_length": len(content),
    }
    for pattern, name in SENSITIVE_PATTERNS:
        if pattern.search(content):
            analysis["sensitive_data_hints"].append(name)
    return analysis


# ============================================================================
# LANGGRAPH-SPECIFIC HELPERS
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


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def reload_config():
    """Reload configuration from file."""
    global CONFIG, HOOK_POLICIES, SENSITIVE_TOOLS, ENKRYPT_SSL_VERIFY, ENKRYPT_TIMEOUT, ENKRYPT_API_URL, ENKRYPT_API_KEY, ENKRYPT_FAIL_SILENTLY

    CONFIG = load_config()
    _api_config = CONFIG.get("enkrypt_api", {})

    ENKRYPT_API_URL = os.environ.get(
        "ENKRYPT_API_URL",
        _api_config.get("url", "https://api.enkryptai.com/guardrails/policy/detect")
    ).strip()
    ENKRYPT_API_KEY = os.environ.get(
        "ENKRYPT_API_KEY",
        _api_config.get("api_key", "")
    ).strip()
    ENKRYPT_SSL_VERIFY = _api_config.get("ssl_verify", True)
    ENKRYPT_TIMEOUT = _api_config.get("timeout", 15)
    ENKRYPT_FAIL_SILENTLY = _api_config.get("fail_silently", True)

    HOOK_POLICIES = {
        "pre_model_hook": CONFIG.get("pre_model_hook", {}),
        "post_model_hook": CONFIG.get("post_model_hook", {}),
        "before_tool_call": CONFIG.get("before_tool_call", {}),
        "after_tool_call": CONFIG.get("after_tool_call", {}),
        "on_agent_action": CONFIG.get("on_agent_action", {}),
        "on_agent_finish": CONFIG.get("on_agent_finish", {}),
    }
    SENSITIVE_TOOLS = CONFIG.get("sensitive_tools", [])

    log_event("config_reloaded", {
        "hooks_enabled": {k: v.get("enabled", False) for k, v in HOOK_POLICIES.items()},
    })


def get_metrics(hook_name: Optional[str] = None) -> Dict[str, Any]:
    """Get metrics for hooks."""
    return metrics.get_metrics(hook_name)


def reset_metrics(hook_name: Optional[str] = None):
    """Reset metrics."""
    metrics.reset(hook_name)
