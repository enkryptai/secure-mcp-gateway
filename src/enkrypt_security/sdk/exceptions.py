"""Exception hierarchy for the Enkrypt Agent SDK.

Follows the Secure MCP Gateway pattern: typed exceptions with error codes,
severity levels, and recovery strategies baked in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ErrorCode(str, Enum):
    GUARDRAIL_INPUT_BLOCKED = "GUARD_001"
    GUARDRAIL_OUTPUT_BLOCKED = "GUARD_002"
    GUARDRAIL_TIMEOUT = "GUARD_003"
    GUARDRAIL_API_ERROR = "GUARD_004"
    PII_DETECTION_ERROR = "PII_001"
    PII_REDACTION_ERROR = "PII_002"
    CONFIG_INVALID = "CFG_001"
    CONFIG_MISSING = "CFG_002"
    TELEMETRY_INIT_ERROR = "TELEM_001"
    PATCH_INSTALL_ERROR = "PATCH_001"
    PATCH_UNINSTALL_ERROR = "PATCH_002"
    NETWORK_ERROR = "NET_001"
    NETWORK_TIMEOUT = "NET_002"
    UNKNOWN = "UNKNOWN"


class ErrorSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(str, Enum):
    RETRY = "retry"
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    SKIP = "skip"


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ErrorContext:
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str | None = None
    run_id: str | None = None
    step_id: str | None = None
    tool_name: str | None = None
    model_name: str | None = None
    operation: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Base exception
# ---------------------------------------------------------------------------

class EnkryptSDKError(Exception):
    """Root exception for every error raised by the SDK."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recovery: RecoveryStrategy = RecoveryStrategy.FAIL_CLOSED,
        context: ErrorContext | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.severity = severity
        self.recovery = recovery
        self.context = context or ErrorContext()
        self.__cause__ = cause

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": str(self),
            "severity": self.severity.value,
            "recovery": self.recovery.value,
            "correlation_id": self.context.correlation_id,
        }


# ---------------------------------------------------------------------------
# Specific exceptions
# ---------------------------------------------------------------------------

class GuardrailBlockedError(EnkryptSDKError):
    """Raised when a guardrail blocks the request/response."""

    def __init__(self, message: str, *, violations: list[dict[str, Any]] | None = None, **kw: Any):
        super().__init__(ErrorCode.GUARDRAIL_INPUT_BLOCKED, message, severity=ErrorSeverity.HIGH, **kw)
        self.violations = violations or []


class GuardrailTimeoutError(EnkryptSDKError):
    def __init__(self, message: str, *, timeout_seconds: float = 0, **kw: Any):
        super().__init__(
            ErrorCode.GUARDRAIL_TIMEOUT, message,
            severity=ErrorSeverity.MEDIUM,
            recovery=RecoveryStrategy.FAIL_OPEN,
            **kw,
        )
        self.timeout_seconds = timeout_seconds


class GuardrailAPIError(EnkryptSDKError):
    def __init__(self, message: str, *, status_code: int | None = None, **kw: Any):
        super().__init__(
            ErrorCode.GUARDRAIL_API_ERROR, message,
            severity=ErrorSeverity.MEDIUM,
            recovery=RecoveryStrategy.RETRY,
            **kw,
        )
        self.status_code = status_code


class ConfigError(EnkryptSDKError):
    def __init__(self, message: str, **kw: Any):
        super().__init__(ErrorCode.CONFIG_INVALID, message, severity=ErrorSeverity.HIGH, **kw)


class PatchError(EnkryptSDKError):
    def __init__(self, message: str, **kw: Any):
        super().__init__(
            ErrorCode.PATCH_INSTALL_ERROR, message,
            severity=ErrorSeverity.LOW,
            recovery=RecoveryStrategy.SKIP,
            **kw,
        )
