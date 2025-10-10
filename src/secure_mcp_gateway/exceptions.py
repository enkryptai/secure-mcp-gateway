"""Standardized error handling system."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class ErrorCode(Enum):
    """Standardized error codes for the MCP Gateway."""

    # Authentication Errors (1000-1099)
    AUTH_INVALID_CREDENTIALS = "AUTH_001"
    AUTH_TOKEN_EXPIRED = "AUTH_002"
    AUTH_INSUFFICIENT_PERMISSIONS = "AUTH_003"
    AUTH_RATE_LIMITED = "AUTH_004"
    AUTH_PROVIDER_ERROR = "AUTH_005"
    AUTH_TIMEOUT = "AUTH_006"
    AUTH_NETWORK_ERROR = "AUTH_007"
    AUTH_CONFIG_ERROR = "AUTH_008"
    AUTH_UNAUTHORIZED = "AUTH_009"

    # Guardrail Errors (1100-1199)
    GUARDRAIL_API_ERROR = "GUARD_001"
    GUARDRAIL_VALIDATION_FAILED = "GUARD_002"
    GUARDRAIL_PII_DETECTED = "GUARD_003"
    GUARDRAIL_POLICY_VIOLATION = "GUARD_004"
    GUARDRAIL_TIMEOUT = "GUARD_005"
    GUARDRAIL_PROVIDER_ERROR = "GUARD_006"
    GUARDRAIL_VALIDATION_ERROR = "GUARD_007"
    GUARDRAIL_UNAUTHORIZED = "GUARD_008"
    GUARDRAIL_NETWORK_ERROR = "GUARD_009"

    # Tool Execution Errors (1200-1299)
    TOOL_EXECUTION_FAILED = "TOOL_001"
    TOOL_NOT_FOUND = "TOOL_002"
    TOOL_INVALID_ARGS = "TOOL_003"
    TOOL_TIMEOUT = "TOOL_004"
    TOOL_PERMISSION_DENIED = "TOOL_005"
    TOOL_SERVER_UNAVAILABLE = "TOOL_006"

    # Discovery Errors (1300-1399)
    DISCOVERY_FAILED = "DISC_001"
    DISCOVERY_SERVER_UNAVAILABLE = "DISC_002"
    DISCOVERY_TOOL_VALIDATION_FAILED = "DISC_003"
    DISCOVERY_CONFIG_ERROR = "DISC_004"
    DISCOVERY_TIMEOUT = "DISC_005"
    DISCOVERY_NETWORK_ERROR = "DISC_006"
    DISCOVERY_AUTH_FAILED = "DISC_007"

    # Configuration Errors (1400-1499)
    CONFIG_INVALID = "CONFIG_001"
    CONFIG_MISSING_REQUIRED = "CONFIG_002"
    CONFIG_PROVIDER_ERROR = "CONFIG_003"
    CONFIG_VALIDATION_FAILED = "CONFIG_004"

    # Network Errors (1500-1599)
    NETWORK_TIMEOUT = "NET_001"
    NETWORK_CONNECTION_FAILED = "NET_002"
    NETWORK_SSL_ERROR = "NET_003"
    NETWORK_DNS_ERROR = "NET_004"
    NETWORK_UNREACHABLE = "NET_005"
    NETWORK_PROTOCOL_ERROR = "NET_006"

    # System Errors (1600-1699)
    SYSTEM_INTERNAL_ERROR = "SYS_001"
    SYSTEM_RESOURCE_EXHAUSTED = "SYS_002"
    SYSTEM_MAINTENANCE = "SYS_003"
    SYSTEM_UNAVAILABLE = "SYS_004"
    SYSTEM_OPERATION_FAILED = "SYS_005"

    # Telemetry Errors (1700-1799)
    TELEMETRY_PROVIDER_ERROR = "TELEM_001"
    TELEMETRY_EXPORT_FAILED = "TELEM_002"
    TELEMETRY_CONFIG_ERROR = "TELEM_003"

    # Cache Errors (1800-1899)
    CACHE_CONNECTION_FAILED = "CACHE_001"
    CACHE_OPERATION_FAILED = "CACHE_002"
    CACHE_SERIALIZATION_ERROR = "CACHE_003"


class ErrorSeverity(Enum):
    """Error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Error recovery strategies."""

    RETRY = "retry"
    FALLBACK = "fallback"
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    ESCALATE = "escalate"
    IGNORE = "ignore"


@dataclass
class ErrorContext:
    """Contextual information for error tracking."""

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    server_name: Optional[str] = None
    tool_name: Optional[str] = None
    operation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorDetails:
    """Structured error details."""

    code: ErrorCode
    message: str
    severity: ErrorSeverity
    recovery_strategy: RecoveryStrategy
    retry_after: Optional[int] = None  # seconds
    user_message: Optional[str] = None
    technical_details: Optional[Dict[str, Any]] = None
    suggested_actions: Optional[List[str]] = None


class MCPGatewayError(Exception):
    """Base exception for MCP Gateway errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.FAIL_CLOSED,
        context: Optional[ErrorContext] = None,
        details: Optional[ErrorDetails] = None,
        cause: Optional[Exception] = None,
    ):
        self.code = code
        self.message = message
        self.severity = severity
        self.recovery_strategy = recovery_strategy
        self.context = context or ErrorContext()
        self.details = details
        self.cause = cause

        # Build user-friendly message
        if details and details.user_message:
            user_msg = details.user_message
        else:
            user_msg = self._build_user_message()

        super().__init__(user_msg)

    def _build_user_message(self) -> str:
        """Build user-friendly error message."""
        if self.severity == ErrorSeverity.CRITICAL:
            return f"Critical system error: {self.message}"
        elif self.severity == ErrorSeverity.HIGH:
            return f"Error: {self.message}"
        else:
            return self.message

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for API responses."""
        return {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "severity": self.severity.value,
                "recovery_strategy": self.recovery_strategy.value,
                "correlation_id": self.context.correlation_id,
                "timestamp": self.context.timestamp.isoformat(),
                "context": {
                    "request_id": self.context.request_id,
                    "user_id": self.context.user_id,
                    "session_id": self.context.session_id,
                    "server_name": self.context.server_name,
                    "tool_name": self.context.tool_name,
                    "operation": self.context.operation,
                },
                "details": {
                    "retry_after": self.details.retry_after if self.details else None,
                    "user_message": self.details.user_message if self.details else None,
                    "technical_details": self.details.technical_details
                    if self.details
                    else None,
                    "suggested_actions": self.details.suggested_actions
                    if self.details
                    else None,
                },
                "cause": str(self.cause) if self.cause else None,
            }
        }


# Specific Exception Classes
class AuthenticationError(MCPGatewayError):
    """Authentication-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.HIGH,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FAIL_CLOSED,
            context=context,
            cause=cause,
        )


class GuardrailError(MCPGatewayError):
    """Guardrail-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FAIL_OPEN,
            context=context,
            cause=cause,
        )


class ToolExecutionError(MCPGatewayError):
    """Tool execution-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            cause=cause,
        )


class DiscoveryError(MCPGatewayError):
    """Discovery-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FALLBACK,
            context=context,
            cause=cause,
        )


class ConfigurationError(MCPGatewayError):
    """Configuration-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.HIGH,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FAIL_CLOSED,
            context=context,
            cause=cause,
        )


class NetworkError(MCPGatewayError):
    """Network-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            cause=cause,
        )


class SystemError(MCPGatewayError):
    """System-related errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.CRITICAL,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.ESCALATE,
            context=context,
            cause=cause,
        )


class TimeoutError(MCPGatewayError):
    """Timeout-related errors with specific timeout handling."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        timeout_duration: float,
        timeout_type: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
    ):
        self.timeout_duration = timeout_duration
        self.timeout_type = timeout_type

        # Build timeout-specific details
        details = ErrorDetails(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FAIL_CLOSED,
            user_message=f"Operation timed out after {timeout_duration}s",
            technical_details={
                "timeout_duration": timeout_duration,
                "timeout_type": timeout_type,
                "escalation_level": self._get_escalation_level(
                    timeout_duration, timeout_type
                ),
            },
            suggested_actions=[
                f"Check if the {timeout_type} service is responding",
                f"Consider increasing the timeout value (current: {timeout_duration}s)",
                "Verify network connectivity and service availability",
            ],
        )

        super().__init__(
            code=code,
            message=message,
            severity=severity,
            recovery_strategy=RecoveryStrategy.FAIL_CLOSED,
            context=context,
            details=details,
            cause=cause,
        )

    def _get_escalation_level(self, duration: float, timeout_type: str) -> str:
        """Determine escalation level based on timeout duration and type."""
        # Define escalation thresholds by timeout type
        thresholds = {
            "guardrail": {"warn": 5.0, "critical": 10.0},
            "tool_execution": {"warn": 30.0, "critical": 60.0},
            "network": {"warn": 10.0, "critical": 30.0},
            "auth": {"warn": 5.0, "critical": 15.0},
            "discovery": {"warn": 15.0, "critical": 30.0},
        }

        type_thresholds = thresholds.get(timeout_type, {"warn": 10.0, "critical": 30.0})

        if duration >= type_thresholds["critical"]:
            return "critical"
        elif duration >= type_thresholds["warn"]:
            return "warning"
        else:
            return "normal"


# Error Factory Functions
def create_auth_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> AuthenticationError:
    """Create an authentication error."""
    return AuthenticationError(code, message, context=context, cause=cause)


def create_guardrail_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> GuardrailError:
    """Create a guardrail error."""
    return GuardrailError(code, message, context=context, cause=cause)


def create_tool_execution_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> ToolExecutionError:
    """Create a tool execution error."""
    return ToolExecutionError(code, message, context=context, cause=cause)


def create_discovery_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> DiscoveryError:
    """Create a discovery error."""
    return DiscoveryError(code, message, context=context, cause=cause)


def create_configuration_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> ConfigurationError:
    """Create a configuration error."""
    return ConfigurationError(code, message, context=context, cause=cause)


def create_network_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> NetworkError:
    """Create a network error."""
    return NetworkError(code, message, context=context, cause=cause)


def create_system_error(
    code: ErrorCode,
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> SystemError:
    """Create a system error."""
    return SystemError(code, message, context=context, cause=cause)


def create_timeout_error(
    code: ErrorCode,
    message: str,
    timeout_duration: float,
    timeout_type: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> TimeoutError:
    """Create a timeout error with specific timeout details."""
    return TimeoutError(
        code=code,
        message=message,
        timeout_duration=timeout_duration,
        timeout_type=timeout_type,
        context=context,
        cause=cause,
    )


def create_guardrail_timeout_error(
    timeout_duration: float,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> TimeoutError:
    """Create a guardrail timeout error."""
    return create_timeout_error(
        code=ErrorCode.GUARDRAIL_TIMEOUT,
        message=f"Guardrail validation timed out after {timeout_duration}s",
        timeout_duration=timeout_duration,
        timeout_type="guardrail",
        context=context,
        cause=cause,
    )


def create_tool_timeout_error(
    timeout_duration: float,
    tool_name: Optional[str] = None,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> TimeoutError:
    """Create a tool execution timeout error."""
    message = f"Tool execution timed out after {timeout_duration}s"
    if tool_name:
        message += f" for tool '{tool_name}'"

    return create_timeout_error(
        code=ErrorCode.TOOL_TIMEOUT,
        message=message,
        timeout_duration=timeout_duration,
        timeout_type="tool_execution",
        context=context,
        cause=cause,
    )


def create_network_timeout_error(
    timeout_duration: float,
    endpoint: Optional[str] = None,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> TimeoutError:
    """Create a network timeout error."""
    message = f"Network request timed out after {timeout_duration}s"
    if endpoint:
        message += f" to endpoint '{endpoint}'"

    return create_timeout_error(
        code=ErrorCode.NETWORK_TIMEOUT,
        message=message,
        timeout_duration=timeout_duration,
        timeout_type="network",
        context=context,
        cause=cause,
    )


# Auth-specific error helpers
def create_auth_timeout_error(
    timeout_duration: float,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> TimeoutError:
    """Create an authentication timeout error."""
    return create_timeout_error(
        code=ErrorCode.AUTH_TIMEOUT,
        message=f"Authentication timed out after {timeout_duration}s",
        timeout_duration=timeout_duration,
        timeout_type="auth",
        context=context,
        cause=cause,
    )


def create_auth_network_error(
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> AuthenticationError:
    """Create an authentication network error."""
    return create_auth_error(
        code=ErrorCode.AUTH_NETWORK_ERROR,
        message=message,
        context=context,
        cause=cause,
    )


def create_auth_unauthorized_error(
    message: str = "Unauthorized access",
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> AuthenticationError:
    """Create an authentication unauthorized error."""
    return create_auth_error(
        code=ErrorCode.AUTH_UNAUTHORIZED,
        message=message,
        context=context,
        cause=cause,
    )


def create_auth_config_error(
    message: str,
    context: Optional[ErrorContext] = None,
    cause: Optional[Exception] = None,
) -> AuthenticationError:
    """Create an authentication configuration error."""
    return create_auth_error(
        code=ErrorCode.AUTH_CONFIG_ERROR,
        message=message,
        context=context,
        cause=cause,
    )
