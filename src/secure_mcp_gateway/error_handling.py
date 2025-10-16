"""Error handling and recovery system."""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type, Union

from .exceptions import (
    ErrorCode,
    ErrorContext,
    ErrorSeverity,
    MCPGatewayError,
    RecoveryStrategy,
)
from .utils import logger


class ErrorRecoveryManager:
    """Manages error recovery strategies and retry logic."""

    def __init__(self):
        self.retry_configs = {
            RecoveryStrategy.RETRY: {
                "max_attempts": 3,
                "base_delay": 1.0,
                "max_delay": 10.0,
                "exponential_backoff": True,
            },
            RecoveryStrategy.FALLBACK: {
                "max_attempts": 1,
                "fallback_function": None,
            },
            RecoveryStrategy.FAIL_OPEN: {
                "max_attempts": 1,
                "default_result": True,
            },
            RecoveryStrategy.FAIL_CLOSED: {
                "max_attempts": 1,
                "default_result": False,
            },
        }

    async def execute_with_recovery(
        self,
        operation: Callable,
        error_types: List[Type[Exception]],
        recovery_strategy: RecoveryStrategy,
        context: Optional[ErrorContext] = None,
        **kwargs,
    ) -> Any:
        """Execute operation with appropriate recovery strategy."""

        if recovery_strategy == RecoveryStrategy.RETRY:
            return await self._execute_with_retry(
                operation, error_types, context, **kwargs
            )
        elif recovery_strategy == RecoveryStrategy.FALLBACK:
            return await self._execute_with_fallback(
                operation, error_types, context, **kwargs
            )
        elif recovery_strategy == RecoveryStrategy.FAIL_OPEN:
            return await self._execute_fail_open(
                operation, error_types, context, **kwargs
            )
        elif recovery_strategy == RecoveryStrategy.FAIL_CLOSED:
            return await self._execute_fail_closed(
                operation, error_types, context, **kwargs
            )
        else:
            # Default to fail closed
            return await self._execute_fail_closed(
                operation, error_types, context, **kwargs
            )

    async def _execute_with_retry(
        self,
        operation: Callable,
        error_types: List[Type[Exception]],
        context: Optional[ErrorContext] = None,
        **kwargs,
    ) -> Any:
        """Execute operation with retry logic."""
        config = self.retry_configs[RecoveryStrategy.RETRY]
        max_attempts = config["max_attempts"]
        base_delay = config["base_delay"]
        max_delay = config["max_delay"]
        exponential_backoff = config["exponential_backoff"]

        last_exception = None

        for attempt in range(max_attempts):
            try:
                return await operation(**kwargs)
            except Exception as e:
                last_exception = e

                # Check if this is a retryable error
                if not any(isinstance(e, error_type) for error_type in error_types):
                    raise e

                # If this is the last attempt, raise the exception
                if attempt == max_attempts - 1:
                    break

                # Calculate delay for next attempt
                if exponential_backoff:
                    delay = min(base_delay * (2**attempt), max_delay)
                else:
                    delay = base_delay

                logger.error(
                    f"[ErrorRecovery] Retry attempt {attempt + 1}/{max_attempts} after {delay}s delay. Error: {e}"
                )

                await asyncio.sleep(delay)

        # If we get here, all retries failed
        raise last_exception

    async def _execute_with_fallback(
        self,
        operation: Callable,
        error_types: List[Type[Exception]],
        context: Optional[ErrorContext] = None,
        **kwargs,
    ) -> Any:
        """Execute operation with fallback strategy."""
        try:
            return await operation(**kwargs)
        except Exception as e:
            if any(isinstance(e, error_type) for error_type in error_types):
                logger.error(f"[ErrorRecovery] Operation failed, using fallback: {e}")
                # Return fallback result (this would need to be configured per operation)
                return None
            else:
                raise e

    async def _execute_fail_open(
        self,
        operation: Callable,
        error_types: List[Type[Exception]],
        context: Optional[ErrorContext] = None,
        **kwargs,
    ) -> Any:
        """Execute operation with fail-open strategy."""
        try:
            return await operation(**kwargs)
        except Exception as e:
            if any(isinstance(e, error_type) for error_type in error_types):
                logger.error(f"[ErrorRecovery] Operation failed, failing open: {e}")
                # Return safe default (allow operation to continue)
                return True
            else:
                raise e

    async def _execute_fail_closed(
        self,
        operation: Callable,
        error_types: List[Type[Exception]],
        context: Optional[ErrorContext] = None,
        **kwargs,
    ) -> Any:
        """Execute operation with fail-closed strategy."""
        try:
            return await operation(**kwargs)
        except Exception as e:
            if any(isinstance(e, error_type) for error_type in error_types):
                logger.error(f"[ErrorRecovery] Operation failed, failing closed: {e}")
                # Block operation
                return False
            else:
                raise e


class ErrorLogger:
    """Enhanced error logging with correlation IDs and structured data."""

    def __init__(self, logger_name: str = "mcp_gateway"):
        self.logger = logging.getLogger(logger_name)
        self._setup_logger()

    def _setup_logger(self):
        """Setup structured logging."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_error(
        self,
        error: MCPGatewayError,
        additional_context: Optional[Dict[str, Any]] = None,
    ):
        """Log error with full context and correlation ID."""
        log_data = {
            "correlation_id": error.context.correlation_id,
            "error_code": error.code.value,
            "severity": error.severity.value,
            "recovery_strategy": error.recovery_strategy.value,
            "error_message": error.message,
            "timestamp": error.context.timestamp.isoformat(),
            "context": {
                "request_id": error.context.request_id,
                "user_id": error.context.user_id,
                "session_id": error.context.session_id,
                "server_name": error.context.server_name,
                "tool_name": error.context.tool_name,
                "operation": error.context.operation,
            },
            "additional_context": additional_context or {},
        }

        if error.cause:
            log_data["cause"] = str(error.cause)

        if error.details:
            log_data["details"] = {
                "retry_after": error.details.retry_after,
                "user_message": error.details.user_message,
                "technical_details": error.details.technical_details,
                "suggested_actions": error.details.suggested_actions,
            }

        # Log based on severity
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"CRITICAL ERROR: {error.message}", extra=log_data)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(f"HIGH SEVERITY ERROR: {error.message}", extra=log_data)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(
                f"MEDIUM SEVERITY ERROR: {error.message}", extra=log_data
            )
        else:
            self.logger.info(f"LOW SEVERITY ERROR: {error.message}", extra=log_data)

    def log_recovery_attempt(
        self,
        error: MCPGatewayError,
        attempt: int,
        max_attempts: int,
        delay: Optional[float] = None,
    ):
        """Log recovery attempt."""
        log_data = {
            "correlation_id": error.context.correlation_id,
            "error_code": error.code.value,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "delay": delay,
            "recovery_strategy": error.recovery_strategy.value,
        }

        self.logger.info(
            f"Recovery attempt {attempt}/{max_attempts} for error {error.code.value}",
            extra=log_data,
        )


class ErrorMonitor:
    """Monitor and track error patterns for alerting."""

    def __init__(self):
        self.error_counts = {}
        self.error_rates = {}
        self.alert_thresholds = {
            ErrorSeverity.CRITICAL: 1,  # Alert immediately
            ErrorSeverity.HIGH: 5,  # Alert after 5 occurrences
            ErrorSeverity.MEDIUM: 10,  # Alert after 10 occurrences
            ErrorSeverity.LOW: 50,  # Alert after 50 occurrences
        }

    def track_error(self, error: MCPGatewayError):
        """Track error occurrence."""
        error_key = f"{error.code.value}_{error.severity.value}"

        if error_key not in self.error_counts:
            self.error_counts[error_key] = 0

        self.error_counts[error_key] += 1

        # Check if we should alert
        threshold = self.alert_thresholds.get(error.severity, 10)
        if self.error_counts[error_key] >= threshold:
            self._trigger_alert(error, self.error_counts[error_key])

    def _trigger_alert(self, error: MCPGatewayError, count: int):
        """Trigger alert for error pattern."""
        alert_message = (
            f"ALERT: Error {error.code.value} has occurred {count} times. "
            f"Severity: {error.severity.value}, "
            f"Recovery Strategy: {error.recovery_strategy.value}"
        )

        logger.critical(alert_message)

        # In a production system, this would send to monitoring service
        # For now, we just log it
        logging.getLogger("mcp_gateway.alerts").critical(alert_message)


# Global instances
error_recovery_manager = ErrorRecoveryManager()
error_logger = ErrorLogger()
error_monitor = ErrorMonitor()


@asynccontextmanager
async def error_handling_context(
    operation_name: str,
    context: Optional[ErrorContext] = None,
    recovery_strategy: Optional[RecoveryStrategy] = None,
):
    """Context manager for error handling with automatic logging and recovery."""
    if context is None:
        context = ErrorContext()

    context.operation = operation_name

    try:
        yield context
    except MCPGatewayError as e:
        # Log the error
        error_logger.log_error(e)

        # Track for monitoring
        error_monitor.track_error(e)

        # Re-raise the error
        raise e
    except Exception as e:
        # Convert generic exception to MCPGatewayError
        mcp_error = MCPGatewayError(
            code=ErrorCode.SYSTEM_INTERNAL_ERROR,
            message=f"Unexpected error in {operation_name}: {e!s}",
            severity=ErrorSeverity.HIGH,
            context=context,
            cause=e,
        )

        # Log the error
        error_logger.log_error(mcp_error)

        # Track for monitoring
        error_monitor.track_error(mcp_error)

        # Re-raise as MCPGatewayError
        raise mcp_error


def create_error_response(error: MCPGatewayError) -> Dict[str, Any]:
    """Create standardized error response for API endpoints."""
    return {
        "status": "error",
        "error": error.to_dict()["error"],
        "timestamp": error.context.timestamp.isoformat(),
        "correlation_id": error.context.correlation_id,
    }


def create_success_response(
    data: Any, correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create standardized success response for API endpoints."""
    return {
        "status": "success",
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
        "correlation_id": correlation_id,
    }
