"""Shared hooks infrastructure — config, API client, parsing, logging, metrics.

Replaces ~600 lines of boilerplate duplicated in every hook provider.
Each provider creates a :class:`HooksCore` instance and calls
``core.check(text, hook_name)`` instead of hand-rolling HTTP + parsing.
"""

from __future__ import annotations

import atexit
import datetime
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from enkrypt_security.guardrails.client import EnkryptGuardrailClient
from enkrypt_security.guardrails.types import (
    GuardrailResult,  # noqa: TC001 — used at runtime
)
from enkrypt_security.telemetry.redaction import mask_sensitive_headers

log = logging.getLogger("enkrypt_security.hooks")

# ============================================================================
# Pre-compiled regex patterns for content analysis
# ============================================================================

SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"password", re.IGNORECASE), "password reference"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key reference"),
    (re.compile(r"secret", re.IGNORECASE), "secret reference"),
    (re.compile(r"token", re.IGNORECASE), "token reference"),
    (re.compile(r"credential", re.IGNORECASE), "credential reference"),
    (re.compile(r"private[_-]?key", re.IGNORECASE), "private key reference"),
    (
        re.compile(r"aws[_-]?(access|secret)", re.IGNORECASE),
        "AWS credential reference",
    ),
    (re.compile(r"bearer\s+[a-zA-Z0-9\-_]+", re.IGNORECASE), "bearer token"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), "OpenAI API key pattern"),
]


# ============================================================================
# Config file discovery
# ============================================================================


def find_guardrails_config(platform: str = "") -> Path:
    """Search for a guardrails config file in standard locations.

    Order:
        1. ``ENKRYPT_GUARDRAILS_CONFIG`` environment variable
        2. Current working directory ``guardrails_config.json``
        3. ``~/.enkrypt/hooks/<platform>/guardrails_config.json``
        4. ``~/.enkrypt/enkrypt_config.json``  (unified config)
        5. Falls back to a non-existent path (handled by ``from_config_file``)
    """
    env = os.environ.get("ENKRYPT_GUARDRAILS_CONFIG")
    if env:
        p = Path(env)
        if p.exists():
            return p

    cwd_config = Path.cwd() / "guardrails_config.json"
    if cwd_config.exists():
        return cwd_config

    if platform:
        home_config = (
            Path.home() / ".enkrypt" / "hooks" / platform / "guardrails_config.json"
        )
        if home_config.exists():
            return home_config

    unified = Path.home() / ".enkrypt" / "enkrypt_config.json"
    if unified.exists():
        return unified

    return Path("guardrails_config.json")


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class HookPolicy:
    """Policy configuration for a specific hook event."""

    enabled: bool = False
    guardrail_name: str = ""
    block: list[str] = field(default_factory=list)


@dataclass
class HookMetrics:
    """Metrics for tracking hook performance."""

    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0
    last_call_timestamp: str | None = None

    @property
    def avg_latency_ms(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_latency_ms / self.total_calls


# ============================================================================
# Metrics collector
# ============================================================================


class MetricsCollector:
    """Thread-safe metrics collector."""

    def __init__(self) -> None:
        self._metrics: dict[str, HookMetrics] = {}
        self._lock = threading.Lock()

    def record_call(
        self,
        hook_name: str,
        blocked: bool,
        latency_ms: float,
        error: bool = False,
    ) -> None:
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

    def get_metrics(self, hook_name: str | None = None) -> dict[str, Any]:
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

    def reset(self, hook_name: str | None = None) -> None:
        with self._lock:
            if hook_name:
                self._metrics[hook_name] = HookMetrics()
            else:
                self._metrics.clear()


# ============================================================================
# Buffered JSONL logger
# ============================================================================


class BufferedLogger:
    """Buffered JSONL logger for better I/O performance."""

    def __init__(
        self, buffer_size: int = 10, flush_interval: float = 5.0
    ) -> None:
        self._buffers: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval
        self._last_flush: dict[str, float] = {}
        self._closed = False

    def write(self, file_path: Path, entry: str) -> None:
        if self._closed:
            return
        key = str(file_path)
        now = datetime.datetime.now().timestamp()
        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = []
                self._last_flush[key] = now
            self._buffers[key].append(entry)
            should_flush = len(
                self._buffers[key]
            ) >= self._buffer_size or (
                now - self._last_flush.get(key, 0)
            ) >= self._flush_interval
            if should_flush:
                self._flush_file(key, file_path)

    def _flush_file(self, key: str, file_path: Path) -> None:
        if self._buffers.get(key):
            try:
                with open(file_path, "a", encoding="utf-8") as f:
                    f.writelines(self._buffers[key])
                self._buffers[key] = []
                self._last_flush[key] = datetime.datetime.now().timestamp()
            except OSError:
                pass

    def flush_all(self) -> None:
        with self._lock:
            for key in list(self._buffers.keys()):
                self._flush_file(key, Path(key))

    def close(self) -> None:
        self._closed = True
        self.flush_all()


# ============================================================================
# Violation message formatting
# ============================================================================


def format_violation_message(
    violations: list[dict[str, Any]], guardrail_name: str = ""
) -> str:
    """Format a user-friendly message from violations."""
    if not violations:
        return ""

    messages: list[str] = []
    if guardrail_name:
        messages.append(f"Policy: {guardrail_name}\n")

    for v in violations:
        detector = v.get("detector", "unknown")

        if detector == "pii":
            pii_found = v.get("pii_found", {})
            entities = v.get("entities", [])
            if pii_found:
                pii_items = list(pii_found.keys())[:3]
                messages.append(f"PII/Secrets detected: {', '.join(pii_items)}")
            elif entities:
                messages.append(
                    f"PII/Secrets detected: "
                    f"{', '.join(str(e) for e in entities[:5])}"
                )
            else:
                messages.append("PII/Secrets detected")

        elif detector == "injection_attack":
            score = v.get("attack_score", 0)
            try:
                sf = float(score) if score else 0
                if sf:
                    messages.append(
                        f"Injection attack detected (confidence: {sf:.1%})"
                    )
                else:
                    messages.append("Injection attack pattern detected")
            except (ValueError, TypeError):
                messages.append("Injection attack pattern detected")

        elif detector == "toxicity":
            types = v.get("toxicity_types", [])
            score = v.get("score", "N/A")
            if types:
                messages.append(
                    f"Toxic content detected: {', '.join(types)} "
                    f"(score: {score})"
                )
            else:
                messages.append(f"Toxic content detected (score: {score})")

        elif detector == "nsfw":
            score = v.get("nsfw_score", 0)
            try:
                sf = float(score) if score else 0
                if sf:
                    messages.append(
                        f"NSFW content detected (confidence: {sf:.1%})"
                    )
                else:
                    messages.append("NSFW content detected")
            except (ValueError, TypeError):
                messages.append("NSFW content detected")

        elif detector == "keyword_detector":
            kws = v.get("matched_keywords", [])
            if kws:
                messages.append(f"Banned keywords detected: {', '.join(kws)}")
            else:
                messages.append("Banned keywords detected")

        elif detector == "policy_violation":
            policy = v.get("violating_policy", "")
            explanation = v.get("explanation", "")
            if policy:
                messages.append(f"Policy violation: {policy}")
            if explanation:
                messages.append(f"   -> {explanation[:150]}")

        elif detector == "bias":
            messages.append("Bias detected in content")

        elif detector == "sponge_attack":
            messages.append("Sponge attack detected")

        elif detector == "topic_detector":
            messages.append("Off-topic or sensitive topic detected")

        else:
            messages.append(
                f"{detector.replace('_', ' ').title()} detected"
            )

    return "\n".join(messages)


# ============================================================================
# Content analysis utility
# ============================================================================


def analyze_content(content: str) -> dict[str, Any]:
    """Analyze content for sensitive data patterns."""
    hints: list[str] = []
    for pattern, name in SENSITIVE_PATTERNS:
        if pattern.search(content):
            hints.append(name)
    return {"sensitive_data_hints": hints, "content_length": len(content)}


def is_sensitive_tool(tool_name: str, sensitive_tools: list[str]) -> bool:
    """Check if a tool is in the sensitive tools list."""
    tool_lower = tool_name.lower()
    for s in sensitive_tools:
        if s.endswith("*"):
            if tool_lower.startswith(s[:-1].lower()):
                return True
        elif s.lower() in tool_lower:
            return True
    return False


# ============================================================================
# Parse API response into hook-style violation dicts
# ============================================================================


def _guardrail_result_to_violations(
    result: GuardrailResult,
) -> list[dict[str, Any]]:
    """Convert shared GuardrailResult into the legacy hook violations format.

    Hook providers historically expect a list of dicts with keys like
    ``detector``, ``detected``, ``blocked``, plus detector-specific fields.
    """
    violations: list[dict[str, Any]] = []
    for v in result.violations:
        if v.action.value != "allow":
            info: dict[str, Any] = {
                "detector": v.detector,
                "detected": True,
                "blocked": v.action.value == "block",
            }
            if v.details:
                info.update(v.details)
            violations.append(info)
    return violations


# ============================================================================
# HooksCore — the main entry point
# ============================================================================


class HooksCore:
    """Shared core for all hook providers.

    Owns the :class:`EnkryptGuardrailClient`, :class:`MetricsCollector`,
    :class:`BufferedLogger`, and per-hook policy lookup.

    Usage::

        core = HooksCore.from_config_file("guardrails_config.json", log_dir=log_dir)
        should_block, violations, raw = core.check(text, "on_llm_start")
    """

    def __init__(
        self,
        *,
        client: EnkryptGuardrailClient,
        hook_policies: dict[str, dict[str, Any]],
        sensitive_tools: list[str] | None = None,
        log_dir: Path | None = None,
        source_name: str = "enkrypt-hooks",
    ) -> None:
        self.client = client
        self.hook_policies = hook_policies
        self.sensitive_tools = sensitive_tools or []
        self.source_name = source_name

        self.metrics = MetricsCollector()
        self.log_dir = log_dir or Path.home() / "platform" / "hooks_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._logger = BufferedLogger()
        atexit.register(self._logger.close)

        # Optional OTel context (set via init_telemetry)
        self._telemetry_ctx: Any = None

    # ----------------------------------------------------------------
    # Factory
    # ----------------------------------------------------------------

    @classmethod
    def from_config_file(
        cls,
        config_path: str | Path,
        *,
        log_dir: Path | None = None,
        source_name: str = "enkrypt-hooks",
        hook_names: list[str] | None = None,
    ) -> HooksCore:
        """Create a HooksCore from a config file.

        Detects two formats:
          - **Unified** (has ``"api"`` key): passes through ``load_config``
          - **Legacy hooks** (has ``"enkrypt_api"`` key): old flat layout

        Falls back to shared ``load_config()`` when the file doesn't exist.
        """
        config = _load_json_config(Path(config_path))

        # Unified config detection — the file has a top-level "api" key
        if config and "api" in config:
            try:
                from enkrypt_security.config.loader import _config_from_dict

                ec = _config_from_dict(config)
                return cls.from_enkrypt_config(
                    ec,
                    log_dir=log_dir,
                    source_name=source_name,
                    hook_names=hook_names,
                )
            except Exception:
                log.debug("Unified config parsing failed — falling through")

        if not config:
            try:
                from enkrypt_security.config import load_config as _load_shared

                ec = _load_shared()
                if ec.api.api_key:
                    return cls.from_enkrypt_config(
                        ec,
                        log_dir=log_dir,
                        source_name=source_name,
                        hook_names=hook_names,
                    )
            except Exception:
                log.debug("Shared config fallback failed — using env vars")

        api_cfg = config.get("enkrypt_api", {})

        api_key = os.environ.get(
            "ENKRYPT_API_KEY", api_cfg.get("api_key", "")
        ).strip()
        base_url = os.environ.get(
            "ENKRYPT_API_URL",
            api_cfg.get("url", "https://api.enkryptai.com"),
        ).strip()
        # Strip /guardrails/policy/detect suffix if present in legacy configs
        for suffix in (
            "/guardrails/policy/detect",
            "/guardrails/policy",
            "/guardrails",
        ):
            if base_url.endswith(suffix):
                base_url = base_url[: -len(suffix)]
                break

        client = EnkryptGuardrailClient(
            api_key=api_key,
            base_url=base_url,
            fail_open=api_cfg.get("fail_silently", True),
            timeout=api_cfg.get("timeout", 15),
            ssl_verify=api_cfg.get("ssl_verify", True),
            source_name=source_name,
        )

        policies: dict[str, dict[str, Any]] = {}
        if hook_names:
            for name in hook_names:
                policies[name] = config.get(name, {})

        return cls(
            client=client,
            hook_policies=policies,
            sensitive_tools=config.get("sensitive_tools", []),
            log_dir=log_dir,
            source_name=source_name,
        )

    @classmethod
    def from_enkrypt_config(
        cls,
        config: "EnkryptConfig",
        *,
        log_dir: Path | None = None,
        source_name: str = "enkrypt-hooks",
        hook_names: list[str] | None = None,
    ) -> HooksCore:
        """Build a HooksCore from a shared EnkryptConfig.

        Per-hook policies come from ``config.extra["hooks"]["<platform>"]``
        where ``<platform>`` is matched via ``source_name``.
        """
        from enkrypt_security.config.models import HookPlatformConfig as _HPC

        client = EnkryptGuardrailClient(
            api_key=config.api.api_key,
            base_url=config.api.base_url,
            guardrail_name=config.input_guardrails.guardrail_name,
            block=config.input_guardrails.block,
            fail_open=config.api.fail_open,
            timeout=config.api.timeout,
            ssl_verify=config.api.ssl_verify,
        )

        # Resolve the platform section for this provider
        hooks_raw = config.extra.get("hooks", {})
        platform_key = _resolve_platform_key(source_name, hooks_raw)

        hook_policies: dict[str, dict[str, Any]] = {}
        sensitive_tools_list: list[str] = []

        platform_data = hooks_raw.get(platform_key) if platform_key else None
        if isinstance(platform_data, _HPC):
            sensitive_tools_list = list(platform_data.sensitive_tools)
            if hook_names:
                for name in hook_names:
                    hp = platform_data.policies.get(name)
                    if hp:
                        hook_policies[name] = {
                            "enabled": hp.enabled,
                            "guardrail_name": hp.guardrail_name,
                            "block": hp.block,
                        }
        elif isinstance(platform_data, dict):
            sensitive_tools_list = list(platform_data.get("sensitive_tools", []))
            if hook_names:
                for name in hook_names:
                    val = platform_data.get(name, {})
                    if isinstance(val, dict):
                        hook_policies[name] = val

        # Fallback for flat hooks structure (e.g. legacy config without platform nesting)
        if not hook_policies and hook_names and isinstance(hooks_raw, dict):
            for name in hook_names:
                val = hooks_raw.get(name, {})
                if isinstance(val, dict) and "enabled" in val:
                    hook_policies[name] = val
            if not sensitive_tools_list:
                sensitive_tools_list = list(hooks_raw.get("sensitive_tools", []))

        return cls(
            client=client,
            hook_policies=hook_policies,
            sensitive_tools=sensitive_tools_list,
            log_dir=log_dir,
            source_name=source_name,
        )

    # ----------------------------------------------------------------
    # Policy helpers
    # ----------------------------------------------------------------

    def get_policy(self, hook_name: str) -> dict[str, Any]:
        return self.hook_policies.get(hook_name, {})

    def is_enabled(self, hook_name: str) -> bool:
        return self.get_policy(hook_name).get("enabled", False)

    def get_block_list(self, hook_name: str) -> list[str]:
        return self.get_policy(hook_name).get("block", [])

    def get_guardrail_name(self, hook_name: str) -> str:
        return self.get_policy(hook_name).get(
            "guardrail_name", f"Default {hook_name} Policy"
        )

    # ----------------------------------------------------------------
    # Core guardrail check
    # ----------------------------------------------------------------

    def check(
        self,
        text: str,
        hook_name: str,
        *,
        source_event: str = "",
    ) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
        """Check text using the Enkrypt guardrails API.

        Returns the legacy ``(should_block, violations, raw_result)`` tuple
        for backward compatibility with existing hook providers.
        """
        t0 = time.time()

        if not self.is_enabled(hook_name):
            return False, [], {"skipped": f"{hook_name} guardrails disabled"}

        block_list = self.get_block_list(hook_name)
        guardrail_name = self.get_guardrail_name(hook_name)
        event = source_event or hook_name.lower().replace("_", "-")

        # Temporarily override client's block list and guardrail name
        orig_block = self.client.block
        orig_name = self.client.guardrail_name
        self.client.block = block_list
        self.client.guardrail_name = guardrail_name

        try:
            result: GuardrailResult = self.client.check_input(
                text, source_event=event
            )
            violations = _guardrail_result_to_violations(result)
            should_block = not result.is_safe

            latency_ms = (time.time() - t0) * 1000
            self.metrics.record_call(
                hook_name, blocked=should_block, latency_ms=latency_ms
            )

            self.log_event(
                hook_name,
                {
                    "text_length": len(text),
                    "guardrail_name": guardrail_name,
                },
                {
                    "should_block": should_block,
                    "violation_count": len(violations),
                    "latency_ms": round(latency_ms, 1),
                },
            )

            return should_block, violations, result.raw_response

        except Exception as exc:
            latency_ms = (time.time() - t0) * 1000
            fail_open = self.client.fail_open
            should_block = not fail_open
            self.metrics.record_call(
                hook_name,
                blocked=should_block,
                latency_ms=latency_ms,
                error=True,
            )
            self.log_event(
                "api_error",
                {
                    "hook": hook_name,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            return (
                should_block,
                [],
                {"error": str(exc), "fail_open": fail_open},
            )
        finally:
            self.client.block = orig_block
            self.client.guardrail_name = orig_name

    # ----------------------------------------------------------------
    # Logging
    # ----------------------------------------------------------------

    def log_event(
        self,
        hook_name: str,
        data: dict[str, Any],
        result: dict[str, Any] | None = None,
    ) -> None:
        log_file = self.log_dir / f"{hook_name}.jsonl"
        entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hook": hook_name,
            "input": data,
        }
        if result is not None:
            entry["output"] = result
        self._logger.write(log_file, json.dumps(entry) + "\n")

    def log_combined(
        self,
        hook_name: str,
        data: dict[str, Any],
        result: dict[str, Any] | None = None,
    ) -> None:
        log_file = self.log_dir / "combined_audit.jsonl"
        entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hook": hook_name,
            "data": data,
        }
        if result is not None:
            entry["result"] = result
        self._logger.write(log_file, json.dumps(entry) + "\n")

    def log_security_alert(
        self, alert_type: str, details: dict[str, Any]
    ) -> None:
        alert_file = self.log_dir / "security_alerts.jsonl"
        alert: dict[str, Any] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": alert_type,
            **details,
        }
        self._logger.write(alert_file, json.dumps(alert) + "\n")

    def flush_logs(self) -> None:
        self._logger.flush_all()

    # ----------------------------------------------------------------
    # Optional OTel integration
    # ----------------------------------------------------------------

    def enable_telemetry(
        self,
        *,
        service_name: str = "",
        exporter: str = "none",
        endpoint: str = "",
    ) -> None:
        """Optionally enable OTel tracing/metrics for hook calls."""
        try:
            from enkrypt_security.telemetry.setup import init_telemetry

            self._telemetry_ctx = init_telemetry(
                service_name=service_name or self.source_name,
                exporter=exporter,
                endpoint=endpoint,
            )
        except Exception:
            log.debug("Telemetry init failed — continuing without OTel")

    # ----------------------------------------------------------------
    # Reload config
    # ----------------------------------------------------------------

    def reload_config(self, config_path: str | Path) -> None:
        """Hot-reload configuration from file."""
        config = _load_json_config(Path(config_path))
        for name in list(self.hook_policies.keys()):
            self.hook_policies[name] = config.get(name, {})
        self.sensitive_tools = config.get("sensitive_tools", [])

        api_cfg = config.get("enkrypt_api", {})
        new_key = os.environ.get(
            "ENKRYPT_API_KEY", api_cfg.get("api_key", "")
        ).strip()
        if new_key and new_key != self.client.api_key:
            self.client.api_key = new_key

        self.log_event(
            "config_reloaded",
            {
                "hooks_enabled": {
                    k: v.get("enabled", False)
                    for k, v in self.hook_policies.items()
                },
            },
        )


# ============================================================================
# Platform key resolution
# ============================================================================

_SOURCE_TO_PLATFORM: dict[str, str] = {
    "cursor": "cursor",
    "claude": "claude",
    "claude-code": "claude_code",
    "claude_code": "claude_code",
    "copilot": "copilot",
    "kiro": "kiro",
    "langchain": "langchain",
    "langgraph": "langgraph",
    "openai": "openai",
    "strands": "strands",
    "crewai": "crewai",
}


def _resolve_platform_key(source_name: str, hooks: dict[str, Any]) -> str | None:
    """Map a ``source_name`` like ``"enkrypt-cursor-hooks"`` to a platform key."""
    sn = source_name.lower().replace("enkrypt-", "").replace("-hooks", "").replace("_hooks", "").strip()
    direct = _SOURCE_TO_PLATFORM.get(sn)
    if direct and direct in hooks:
        return direct
    for key in hooks:
        if sn in key.lower() or key.lower() in sn:
            return key
    return None


# ============================================================================
# Config file loading
# ============================================================================


def _load_json_config(path: Path) -> dict[str, Any]:
    """Load and return a JSON config file, returning {} on failure."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        log.warning("Failed to parse %s: %s", path, exc)
        return {}
