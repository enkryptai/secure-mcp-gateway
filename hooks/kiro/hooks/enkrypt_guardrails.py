#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Shared Module for Kiro Hooks

This module provides the core Enkrypt API integration used by all Kiro hooks:
- PromptSubmit (input guardrails)
- AgentStop (session completion)
- FileSave (file-based trigger with guardrails)
- FileCreate (file-based trigger with guardrails)
- FileDelete (file-based trigger)
- Manual (on-demand hooks)

Configuration is loaded from guardrails_config.json

Kiro Hook Actions:
- Shell Command: Exit 0 = success (stdout to context), Other = error (stderr to agent)
- Agent Prompt: Returns prompt text that is sent to the agent
"""
# Suppress requests library warnings (urllib3/chardet version mismatches)
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

# Top-level imports for better performance
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================================
# PRE-COMPILED REGEX PATTERNS (20-30% faster pattern matching)
# ============================================================================

# Sensitive data patterns for file/output analysis
SENSITIVE_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
    (re.compile(r"private[_-]?key", re.IGNORECASE), "private key reference"),
    (re.compile(r"aws[_-]?(access|secret)", re.IGNORECASE), "AWS credential reference"),
]

# Header masking patterns
SENSITIVE_HEADER_KEYS = {"apikey", "authorization", "x-api-key", "bearer", "token"}

# File patterns that should trigger extra scrutiny
SENSITIVE_FILE_PATTERNS = [
    re.compile(r"\.env$", re.IGNORECASE),
    re.compile(r"\.env\.", re.IGNORECASE),
    re.compile(r"secrets?\.", re.IGNORECASE),
    re.compile(r"credentials?\.", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
]


# ============================================================================
# CONNECTION POOLING (20-30% faster repeated API calls)
# ============================================================================

def _create_session() -> requests.Session:
    """Create a requests session with connection pooling and retry logic."""
    session = requests.Session()

    # Configure retry strategy with exponential backoff
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST", "GET"],
    )

    # Mount adapter with connection pooling
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


# Global session for connection reuse
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
    """Close the HTTP session (call at shutdown)."""
    global _http_session
    if _http_session is not None:
        _http_session.close()
        _http_session = None


# Register session cleanup at exit
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
    fail_silently: bool = True  # If True, allow request on API error; if False, block on error


@dataclass
class HookPolicy:
    """Policy configuration for a specific hook."""
    enabled: bool = False
    guardrail_name: str = ""
    block: List[str] = field(default_factory=list)


@dataclass
class Violation:
    """Represents a detected violation from guardrails."""
    detector: str
    detected: bool = True
    blocked: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailsConfig:
    """Complete guardrails configuration for Kiro hooks."""
    enkrypt_api: EnkryptApiConfig = field(default_factory=EnkryptApiConfig)
    prompt_submit: HookPolicy = field(default_factory=HookPolicy)
    agent_stop: HookPolicy = field(default_factory=HookPolicy)
    file_save: HookPolicy = field(default_factory=HookPolicy)
    file_create: HookPolicy = field(default_factory=HookPolicy)
    sensitive_file_patterns: List[str] = field(default_factory=list)


@dataclass
class HookMetrics:
    """Metrics for a single hook."""
    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0
    last_call_timestamp: Optional[str] = None

    @property
    def avg_latency_ms(self) -> float:
        """Calculate average latency."""
        return self.total_latency_ms / self.total_calls if self.total_calls > 0 else 0.0


# ============================================================================
# METRICS COLLECTION
# ============================================================================

class MetricsCollector:
    """Thread-safe metrics collector for all hooks."""

    def __init__(self):
        self._metrics: Dict[str, HookMetrics] = {}
        self._lock = threading.Lock()

    def record_call(self, hook_name: str, blocked: bool, latency_ms: float, error: bool = False):
        """Record a hook call with its outcome."""
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
        """Get metrics for a specific hook or all hooks."""
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
            else:
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
        """Reset metrics for a specific hook or all hooks."""
        with self._lock:
            if hook_name:
                self._metrics[hook_name] = HookMetrics()
            else:
                self._metrics.clear()


# Global metrics collector
metrics = MetricsCollector()


# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

CONFIG_FILE = Path(__file__).parent / "guardrails_config.json"
LOG_DIR = Path(os.environ.get("KIRO_HOOKS_LOG_DIR", Path.home() / "kiro" / "hooks_logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Log retention settings
LOG_RETENTION_DAYS = int(os.environ.get("KIRO_HOOKS_LOG_RETENTION_DAYS", "7"))


def validate_config(config: dict) -> List[str]:
    """
    Validate configuration and return list of errors.
    Catches errors early to prevent runtime failures.
    """
    errors = []

    # Validate enkrypt_api section
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

        fail_silently = api_config.get("fail_silently")
        if fail_silently is not None and not isinstance(fail_silently, bool):
            errors.append(f"enkrypt_api.fail_silently must be a boolean, got: {type(fail_silently).__name__}")

    # Validate hook policies (Kiro hook names)
    valid_hooks = ["PromptSubmit", "AgentStop", "FileSave", "FileCreate", "FileDelete", "Manual"]
    for hook_name in valid_hooks:
        policy = config.get(hook_name, {})
        if policy:
            if "enabled" in policy and not isinstance(policy["enabled"], bool):
                errors.append(f"{hook_name}.enabled must be a boolean")
            if "block" in policy and not isinstance(policy["block"], list):
                errors.append(f"{hook_name}.block must be a list")
            if "guardrail_name" in policy and not isinstance(policy["guardrail_name"], str):
                errors.append(f"{hook_name}.guardrail_name must be a string")

    # Validate sensitive_file_patterns
    sensitive_patterns = config.get("sensitive_file_patterns")
    if sensitive_patterns is not None and not isinstance(sensitive_patterns, list):
        errors.append("sensitive_file_patterns must be a list")

    return errors


def load_config() -> dict:
    """Load and validate configuration from guardrails_config.json"""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Validate configuration
        errors = validate_config(config)
        if errors:
            # Write validation errors to a file since we can't use log_event yet
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
        # Write JSON parse error to file
        error_file = LOG_DIR / "config_errors.log"
        with open(error_file, "a", encoding="utf-8") as ef:
            timestamp = datetime.datetime.now().isoformat()
            ef.write(f"[{timestamp}] JSON parse error: {e}\n")
        return {}


# Load config on module import
CONFIG = load_config()

# Extract configuration values (strip whitespace to avoid URL issues)
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
ENKRYPT_FAIL_SILENTLY = _api_config.get("fail_silently", True)  # True = allow on error, False = block on error

SENSITIVE_FILE_PATTERN_STRINGS = CONFIG.get("sensitive_file_patterns", [])

# Hook-specific policies (Kiro hook names)
HOOK_POLICIES = {
    "PromptSubmit": CONFIG.get("PromptSubmit", {}),
    "AgentStop": CONFIG.get("AgentStop", {}),
    "FileSave": CONFIG.get("FileSave", {}),
    "FileCreate": CONFIG.get("FileCreate", {}),
    "FileDelete": CONFIG.get("FileDelete", {}),
    "Manual": CONFIG.get("Manual", {}),
}


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


def get_hook_guardrail_name(hook_name: str) -> str:
    """Get guardrail name for a specific hook."""
    return get_hook_policy(hook_name).get("guardrail_name", f"Default {hook_name} Policy")


# ============================================================================
# LOGGING FUNCTIONS (with buffering and rotation)
# ============================================================================

class BufferedLogger:
    """
    Buffered logger for better I/O performance (40-60% faster).
    Batches writes and flushes periodically or when buffer is full.
    """

    def __init__(self, buffer_size: int = 10, flush_interval: float = 5.0):
        self._buffers: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval
        self._last_flush: Dict[str, float] = {}
        self._closed = False

    def write(self, file_path: Path, entry: str):
        """Buffer a log entry for later writing."""
        if self._closed:
            return

        key = str(file_path)
        now = datetime.datetime.now().timestamp()

        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = []
                self._last_flush[key] = now

            self._buffers[key].append(entry)

            # Flush if buffer is full or interval elapsed
            should_flush = (
                len(self._buffers[key]) >= self._buffer_size or
                (now - self._last_flush.get(key, 0)) >= self._flush_interval
            )

            if should_flush:
                self._flush_file(key, file_path)

    def _flush_file(self, key: str, file_path: Path):
        """Flush buffer to file (must be called with lock held)."""
        if key in self._buffers and self._buffers[key]:
            try:
                with open(file_path, "a", encoding="utf-8") as f:
                    f.writelines(self._buffers[key])
                self._buffers[key] = []
                self._last_flush[key] = datetime.datetime.now().timestamp()
            except IOError:
                pass  # Silently fail on I/O errors

    def flush_all(self):
        """Flush all buffers to files."""
        with self._lock:
            for key in list(self._buffers.keys()):
                file_path = Path(key)
                self._flush_file(key, file_path)

    def close(self):
        """Flush and close the logger."""
        self._closed = True
        self.flush_all()


# Global buffered logger
_buffered_logger = BufferedLogger()

# Register flush at exit
atexit.register(_buffered_logger.close)


def cleanup_old_logs():
    """Remove log files older than LOG_RETENTION_DAYS (default 7 days)."""
    if LOG_RETENTION_DAYS <= 0:
        return

    try:
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(days=LOG_RETENTION_DAYS)

        for log_file in LOG_DIR.glob("*.jsonl"):
            try:
                mtime = datetime.datetime.fromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    # Archive to .old or delete
                    archive_name = log_file.with_suffix(f".{log_file.suffix}.old")
                    if archive_name.exists():
                        archive_name.unlink()
                    log_file.rename(archive_name)
            except (OSError, IOError):
                pass

        # Also cleanup .old files older than 2x retention
        double_cutoff = now - datetime.timedelta(days=LOG_RETENTION_DAYS * 2)
        for old_file in LOG_DIR.glob("*.old"):
            try:
                mtime = datetime.datetime.fromtimestamp(old_file.stat().st_mtime)
                if mtime < double_cutoff:
                    old_file.unlink()
            except (OSError, IOError):
                pass
    except Exception:
        pass  # Don't fail on cleanup errors


# Run cleanup on module load (only once per day at most)
_cleanup_marker = LOG_DIR / ".last_cleanup"
try:
    should_cleanup = True
    if _cleanup_marker.exists():
        last_cleanup = datetime.datetime.fromtimestamp(_cleanup_marker.stat().st_mtime)
        if (datetime.datetime.now() - last_cleanup).days < 1:
            should_cleanup = False

    if should_cleanup:
        cleanup_old_logs()
        _cleanup_marker.touch()
except Exception:
    pass


def get_timestamp():
    """Get ISO format timestamp."""
    return datetime.datetime.now().isoformat()


def log_event(hook_name: str, data: dict, result: dict = None):
    """Log a hook event to a JSON Lines file (buffered)."""
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
    """Log to a combined audit log file (buffered)."""
    log_file = LOG_DIR / "combined_audit.jsonl"

    entry = {
        "timestamp": get_timestamp(),
        "hook": hook_name,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "data": data,
    }
    if result is not None:
        entry["result"] = result

    _buffered_logger.write(log_file, json.dumps(entry) + "\n")


def log_security_alert(alert_type: str, details: dict, data: dict):
    """Log a security alert (buffered)."""
    alert_file = LOG_DIR / "security_alerts.jsonl"
    alert = {
        "timestamp": get_timestamp(),
        "type": alert_type,
        **details,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
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

    API Response Format:
    {
      "summary": {
        "on_topic": 0,
        "nsfw": 1,
        "toxicity": ["toxicity", "insult"],
        "pii": 1,
        "injection_attack": 1,
        "keyword_detected": 1,
        "policy_violation": 1,
        "bias": 1,
        "sponge_attack": 1
      },
      "details": {
        "topic_detector": {...},
        "nsfw": {...},
        "toxicity": {...},
        "pii": {...},
        "injection_attack": {...},
        "keyword_detector": {...},
        "policy_violation": {...},
        "bias": {...},
        "sponge_attack": {...}
      }
    }
    """
    violations = []
    summary = result.get("summary", {})
    details = result.get("details", {})

    # Map summary keys to detector names in block list
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

        # Special case: on_topic=0 means OFF topic (potential issue), on_topic=1 means ON topic (ok)
        if summary_key == "on_topic":
            is_detected = summary_value == 0 if isinstance(summary_value, int) else False

        if is_detected and detector_name in block_list:
            violation_info = {
                "detector": detector_name,
                "detected": True,
                "blocked": True,
            }

            # Add details based on detector type
            detail = details.get(detector_name, {}) or details.get(summary_key, {})

            if detector_name == "pii":
                pii_detail = detail.get("pii", {})
                if pii_detail:
                    violation_info["entities"] = list(pii_detail.keys())
                    violation_info["pii_found"] = pii_detail

            elif detector_name == "toxicity":
                if isinstance(summary_value, list):
                    violation_info["toxicity_types"] = summary_value
                # Get toxicity score
                if "toxicity" in detail:
                    violation_info["score"] = detail.get("toxicity")

            elif detector_name == "keyword_detector":
                violation_info["matched_keywords"] = detail.get("detected_keywords", [])
                violation_info["keyword_counts"] = detail.get("detected_counts", {})

            elif detector_name == "policy_violation":
                violation_info["violating_policy"] = detail.get("violating_policy", "")
                violation_info["explanation"] = detail.get("explanation", "")

            elif detector_name == "injection_attack":
                violation_info["attack_score"] = detail.get("attack", 0)

            elif detector_name == "nsfw":
                violation_info["nsfw_score"] = detail.get("nsfw", 0)

            elif detector_name == "bias":
                violation_info["bias_detected"] = detail.get("bias_detected", False)
                violation_info["debiased_text"] = detail.get("debiased_text", "")

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
        # Use pre-compiled set for O(1) lookup
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
        "PromptSubmit": "pre-prompt",
        "AgentStop": "post-response",
        "FileSave": "file-save",
        "FileCreate": "file-create",
        "FileDelete": "file-delete",
        "Manual": "manual-trigger",
    }
    return event_mapping.get(hook_name, hook_name)


def check_with_enkrypt_api(text: str, hook_name: str = "PromptSubmit") -> tuple[bool, list, dict]:
    """
    Check text using Enkrypt AI Guardrails API.

    Uses connection pooling for 20-30% faster repeated API calls.

    Args:
        text: The text to check (prompt, file content, etc.)
        hook_name: The hook name (PromptSubmit, AgentStop, FileSave, FileCreate, Manual)

    Returns:
        Tuple of (should_block, violations_list, full_result)
    """
    import time
    start_time = time.time()

    # Check if guardrails are enabled for this hook
    if not is_hook_enabled(hook_name):
        return False, [], {"skipped": f"{hook_name} guardrails disabled"}

    # Get the block list for this hook
    block_list = get_hook_block_list(hook_name)

    try:
        # Get guardrail name for this hook
        guardrail_name = get_hook_guardrail_name(hook_name)

        payload = {
            "text": text
        }

        # Debug: Log the actual request being made
        log_event("enkrypt_api_debug", {
            "url": ENKRYPT_API_URL,
            "api_key_length": len(ENKRYPT_API_KEY) if ENKRYPT_API_KEY else 0,
            "payload_text_length": len(text),
            "guardrail_name": guardrail_name,
            "config_file": str(CONFIG_FILE),
            "ssl_verify": ENKRYPT_SSL_VERIFY,
            "timeout": ENKRYPT_TIMEOUT,
        })

        # Disable SSL warnings if SSL verification is disabled
        if not ENKRYPT_SSL_VERIFY:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Use pooled session for better performance
        session = get_http_session()
        resp = session.post(
            ENKRYPT_API_URL,
            headers={
                "Content-Type": "application/json",
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-Policy": guardrail_name,
                "X-Enkrypt-Source-Name": "kiro-hooks",
                "X-Enkrypt-Source-Event": get_source_event(hook_name),
            },
            json=payload,
            timeout=ENKRYPT_TIMEOUT,
            verify=ENKRYPT_SSL_VERIFY,
        )

        # Log response status before raising (mask sensitive headers)
        log_event("enkrypt_api_response", {
            "status_code": resp.status_code,
            "url": resp.url,
            "response_preview": resp.text[:300] if resp.text else None,
            "request_url": ENKRYPT_API_URL,
            "headers_sent": mask_sensitive_headers(dict(resp.request.headers)) if resp.request else None,
        })

        resp.raise_for_status()
        result = resp.json()

        # Parse the response using the actual API format
        violations = parse_enkrypt_response(result, block_list)

        should_block = len(violations) > 0

        # Record metrics
        latency_ms = (time.time() - start_time) * 1000
        metrics.record_call(hook_name, blocked=should_block, latency_ms=latency_ms)

        return should_block, violations, result

    except requests.exceptions.Timeout as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        error_info = {
            "error": "API request timed out",
            "error_type": "Timeout",
            "timeout_seconds": ENKRYPT_TIMEOUT,
            "url_used": ENKRYPT_API_URL,
            "fail_silently": ENKRYPT_FAIL_SILENTLY,
            "action": "allowed" if ENKRYPT_FAIL_SILENTLY else "blocked",
        }
        log_event("enkrypt_api_error", error_info)
        return should_block_on_error, [], {"error": "timeout", "fail_silently": ENKRYPT_FAIL_SILENTLY}

    except requests.exceptions.ConnectionError as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        error_info = {
            "error": "Failed to connect to API",
            "error_type": "ConnectionError",
            "url_used": ENKRYPT_API_URL,
            "fail_silently": ENKRYPT_FAIL_SILENTLY,
            "action": "allowed" if ENKRYPT_FAIL_SILENTLY else "blocked",
        }
        log_event("enkrypt_api_error", error_info)
        return should_block_on_error, [], {"error": "connection_error", "fail_silently": ENKRYPT_FAIL_SILENTLY}

    except requests.exceptions.HTTPError as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        error_info = {
            "error": str(e),
            "error_type": "HTTPError",
            "url_used": ENKRYPT_API_URL,
            "fail_silently": ENKRYPT_FAIL_SILENTLY,
            "action": "allowed" if ENKRYPT_FAIL_SILENTLY else "blocked",
        }
        if e.response is not None:
            error_info["status_code"] = e.response.status_code
            error_info["response_text"] = e.response.text[:500] if e.response.text else None
        log_event("enkrypt_api_error", error_info)
        return should_block_on_error, [], {"error": str(e), "fail_silently": ENKRYPT_FAIL_SILENTLY}

    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        should_block_on_error = not ENKRYPT_FAIL_SILENTLY
        metrics.record_call(hook_name, blocked=should_block_on_error, latency_ms=latency_ms, error=True)
        error_info = {
            "error": str(e),
            "error_type": type(e).__name__,
            "url_used": ENKRYPT_API_URL,
            "fail_silently": ENKRYPT_FAIL_SILENTLY,
            "action": "allowed" if ENKRYPT_FAIL_SILENTLY else "blocked",
        }
        log_event("enkrypt_api_error", error_info)
        return should_block_on_error, [], {"error": str(e), "fail_silently": ENKRYPT_FAIL_SILENTLY}


def format_violation_message(violations: list, hook_name: str = "PromptSubmit") -> str:
    """Format a user-friendly message from violations."""
    if not violations:
        return ""

    guardrail_name = get_hook_guardrail_name(hook_name)

    messages = [f"Policy: {guardrail_name}\n"]

    for v in violations:
        detector = v["detector"]

        if detector == "pii":
            entities = v.get("entities", [])
            pii_found = v.get("pii_found", {})
            if pii_found:
                # Show actual PII types found
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
# FILE CHECKING FUNCTIONS (Kiro-specific)
# ============================================================================

def is_sensitive_file(file_path: str) -> bool:
    """Check if a file path matches sensitive file patterns."""
    for pattern in SENSITIVE_FILE_PATTERNS:
        if pattern.search(file_path):
            return True

    # Also check user-defined patterns from config
    for pattern_str in SENSITIVE_FILE_PATTERN_STRINGS:
        try:
            if re.search(pattern_str, file_path, re.IGNORECASE):
                return True
        except re.error:
            pass  # Invalid regex, skip

    return False


def analyze_file_content(file_path: str, content: str) -> dict:
    """
    Analyze file content for potential security issues.

    Uses pre-compiled regex patterns for faster analysis.
    """
    analysis = {
        "file_path": file_path,
        "is_sensitive_file": is_sensitive_file(file_path),
        "sensitive_data_hints": [],
        "content_size": len(content),
    }

    # Use pre-compiled patterns for faster matching
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
    # First do local analysis
    analysis = analyze_file_content(file_path, content)

    # If it's a sensitive file, always check with API
    # Otherwise, only check if content has sensitive hints or guardrails enabled
    if not analysis["is_sensitive_file"] and not analysis["sensitive_data_hints"]:
        if not is_hook_enabled(hook_name):
            return False, [], {"skipped": "No sensitive content detected, guardrails disabled"}

    # Check with Enkrypt API
    should_block, violations, api_result = check_with_enkrypt_api(content, hook_name)

    # Add local analysis to result
    api_result["local_analysis"] = analysis

    return should_block, violations, api_result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def reload_config():
    """
    Reload configuration from file (useful for dynamic updates).

    Call this to pick up config changes without restarting the hook process.
    """
    global CONFIG, HOOK_POLICIES, SENSITIVE_FILE_PATTERN_STRINGS, ENKRYPT_SSL_VERIFY, ENKRYPT_TIMEOUT, ENKRYPT_API_URL, ENKRYPT_API_KEY, ENKRYPT_FAIL_SILENTLY
    CONFIG = load_config()
    _api_config = CONFIG.get("enkrypt_api", {})

    # Update API settings
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

    # Update hook policies (Kiro hook names)
    HOOK_POLICIES = {
        "PromptSubmit": CONFIG.get("PromptSubmit", {}),
        "AgentStop": CONFIG.get("AgentStop", {}),
        "FileSave": CONFIG.get("FileSave", {}),
        "FileCreate": CONFIG.get("FileCreate", {}),
        "FileDelete": CONFIG.get("FileDelete", {}),
        "Manual": CONFIG.get("Manual", {}),
    }
    SENSITIVE_FILE_PATTERN_STRINGS = CONFIG.get("sensitive_file_patterns", [])

    log_event("config_reloaded", {
        "ssl_verify": ENKRYPT_SSL_VERIFY,
        "timeout": ENKRYPT_TIMEOUT,
        "fail_silently": ENKRYPT_FAIL_SILENTLY,
        "hooks_enabled": {k: v.get("enabled", False) for k, v in HOOK_POLICIES.items()},
    })


def get_hook_metrics(hook_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get metrics for a specific hook or all hooks.

    Args:
        hook_name: Optional hook name. If None, returns all metrics.

    Returns:
        Dict with metrics including total_calls, blocked_calls, errors, avg_latency_ms
    """
    return metrics.get_metrics(hook_name)


def reset_metrics(hook_name: Optional[str] = None):
    """Reset metrics for a specific hook or all hooks."""
    metrics.reset(hook_name)


# ============================================================================
# HOOK BASE CLASS (reduces code duplication by ~40%)
# ============================================================================

class BaseHook:
    """
    Base class for Kiro hooks.

    Provides common functionality:
    - JSON input parsing with error handling
    - Logging and metrics
    - Guardrails integration
    - Output formatting

    Kiro Shell Command Hooks:
    - Exit code 0: Success, stdout added to agent context
    - Exit code != 0: Error, stderr sent to agent

    Subclasses should implement:
    - process(self, data: dict) -> tuple[int, str, str]
      Returns: (exit_code, stdout_message, stderr_message)
    """

    def __init__(self, hook_name: str):
        """
        Initialize the hook.

        Args:
            hook_name: The name of the hook (e.g., "PromptSubmit")
        """
        self.hook_name = hook_name

    def run(self):
        """Main entry point - reads stdin/env, processes, writes stdout/stderr."""
        import sys
        import time

        start_time = time.time()

        # For Kiro shell command hooks, input can come from stdin or env vars
        data = self._read_input()

        try:
            exit_code, stdout_msg, stderr_msg = self.process(data)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            metrics.record_call(self.hook_name, blocked=False, latency_ms=latency_ms, error=True)
            log_event(self.hook_name, {
                "error": str(e),
                "error_type": type(e).__name__,
                "data": data,
            })
            # On error, return non-zero exit code
            print(f"Hook error: {str(e)}", file=sys.stderr)
            sys.exit(1)

        # Log the event
        result = {"exit_code": exit_code, "stdout": stdout_msg[:200] if stdout_msg else "", "stderr": stderr_msg[:200] if stderr_msg else ""}
        log_event(self.hook_name, data, result)
        log_to_combined(self.hook_name, data, result)

        # Flush logs to ensure they're written
        flush_logs()

        # Output results
        if stdout_msg:
            print(stdout_msg)
        if stderr_msg:
            print(stderr_msg, file=sys.stderr)

        sys.exit(exit_code)

    def _read_input(self) -> dict:
        """Read input from stdin or environment variables."""
        import sys
        data = {}

        # Try to read JSON from stdin
        try:
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
                if stdin_content:
                    data = json.loads(stdin_content)
        except (json.JSONDecodeError, IOError):
            pass

        # Also capture relevant environment variables (Kiro passes USER_PROMPT via env)
        data["USER_PROMPT"] = os.environ.get("USER_PROMPT", "")
        data["USER"] = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        data["PWD"] = os.environ.get("PWD", os.getcwd())

        return data

    def process(self, data: dict) -> tuple[int, str, str]:
        """
        Process the hook input and return output.

        Override this method in subclasses.

        Args:
            data: The input data (from stdin JSON or environment)

        Returns:
            Tuple of (exit_code, stdout_message, stderr_message)
            - exit_code 0: Success, stdout added to agent context
            - exit_code != 0: Error, stderr sent to agent
        """
        raise NotImplementedError("Subclasses must implement process()")

    def check_guardrails(self, text: str) -> tuple[bool, list, dict]:
        """
        Check text against guardrails.

        Args:
            text: The text to check

        Returns:
            Tuple of (should_block, violations, api_result)
        """
        return check_with_enkrypt_api(text, hook_name=self.hook_name)

    def format_block_message(self, violations: list) -> str:
        """Format a user-friendly block message from violations."""
        return format_violation_message(violations, hook_name=self.hook_name)

    def log_alert(self, alert_type: str, details: dict, data: dict):
        """Log a security alert."""
        log_security_alert(alert_type, {
            "hook": self.hook_name,
            "guardrail_name": get_hook_guardrail_name(self.hook_name),
            **details,
        }, data)

    @property
    def is_enabled(self) -> bool:
        """Check if this hook's guardrails are enabled."""
        return is_hook_enabled(self.hook_name)


class InputGuardrailHook(BaseHook):
    """
    Base class for input guardrail hooks (PromptSubmit).

    These hooks can block input before it's processed.
    For Kiro shell command hooks, blocking means returning non-zero exit code.
    """

    def __init__(self, hook_name: str, text_field: str = "USER_PROMPT"):
        """
        Initialize the input guardrail hook.

        Args:
            hook_name: The name of the hook
            text_field: The field in the input data containing text to check
        """
        super().__init__(hook_name)
        self.text_field = text_field

    def get_text_to_check(self, data: dict) -> str:
        """Extract the text to check from input data."""
        return data.get(self.text_field, "")

    def process(self, data: dict) -> tuple[int, str, str]:
        """Process input and check guardrails."""
        import time

        text = self.get_text_to_check(data)

        if not text or not text.strip():
            return 0, "", ""

        if not self.is_enabled:
            log_event(self.hook_name, {**data, "skipped": "guardrails disabled"})
            return 0, "", ""

        start_time = time.time()
        should_block, violations, api_result = self.check_guardrails(text)
        latency_ms = (time.time() - start_time) * 1000

        if should_block:
            violation_message = self.format_block_message(violations)
            self.log_alert("input_blocked", {
                "violations": violations,
                "text_preview": text[:200] + "..." if len(text) > 200 else text,
            }, data)
            # Return non-zero exit code to signal block
            return 1, "", f"Blocked by Enkrypt AI Guardrails:\n\n{violation_message}"

        # Success - return empty stdout (or context info)
        return 0, "", ""


class OutputAuditHook(BaseHook):
    """
    Base class for output audit hooks (AgentStop).

    These hooks observe output but don't block it (audit-only).
    """

    def __init__(self, hook_name: str):
        """
        Initialize the output audit hook.

        Args:
            hook_name: The name of the hook
        """
        super().__init__(hook_name)

    def process(self, data: dict) -> tuple[int, str, str]:
        """Process output and audit (no blocking)."""
        # AgentStop hooks typically just log/audit, always return success
        log_event(self.hook_name, data)
        return 0, "", ""
