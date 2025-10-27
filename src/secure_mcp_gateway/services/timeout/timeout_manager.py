"""
Timeout Management Service

This module provides comprehensive timeout management for the Enkrypt Secure MCP Gateway,
including configurable timeouts, request cancellation support, and timeout escalation policies.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union

from secure_mcp_gateway.utils import logger


class TimeoutEscalationLevel(Enum):
    """Timeout escalation levels."""

    NORMAL = "normal"
    WARN = "warn"
    TIMEOUT = "timeout"
    FAIL = "fail"


@dataclass
class TimeoutConfig:
    """Configuration for timeout settings."""

    default_timeout: int = 30
    guardrail_timeout: int = 1
    auth_timeout: int = 10
    tool_execution_timeout: int = 60
    discovery_timeout: int = 120  # Increased to 120s to accommodate OAuth flows
    cache_timeout: int = 5
    connectivity_timeout: int = 2
    escalation_policies: Dict[str, float] = None

    def __post_init__(self):
        if self.escalation_policies is None:
            self.escalation_policies = {
                "warn_threshold": 0.8,
                "timeout_threshold": 1.0,
                "fail_threshold": 1.2,
            }


@dataclass
class TimeoutResult:
    """Result of a timeout operation."""

    success: bool
    result: Any = None
    error: Optional[Exception] = None
    elapsed_time: float = 0.0
    escalation_level: TimeoutEscalationLevel = TimeoutEscalationLevel.NORMAL
    cancelled: bool = False


class TimeoutManager:
    """
    Manages timeouts for all external API calls and long-running operations.

    Features:
    - Configurable timeouts for different operation types
    - Request cancellation support
    - Timeout escalation policies (warn, timeout, fail)
    - Timeout monitoring and metrics
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the TimeoutManager.

        Args:
            config: Timeout configuration dictionary
        """
        self.config = TimeoutConfig()
        if config:
            self._load_config(config)

        self._active_operations: Dict[str, asyncio.Task] = {}
        self._timeout_metrics: Dict[str, Any] = {
            "total_operations": 0,
            "successful_operations": 0,
            "timeout_operations": 0,
            "cancelled_operations": 0,
            "escalation_counts": {level.value: 0 for level in TimeoutEscalationLevel},
        }

    def _load_config(self, config: Dict[str, Any]) -> None:
        """Load timeout configuration from dictionary."""
        timeout_settings = config.get("timeout_settings", {})

        self.config.default_timeout = timeout_settings.get("default_timeout", 30)
        self.config.guardrail_timeout = timeout_settings.get("guardrail_timeout", 15)
        self.config.auth_timeout = timeout_settings.get("auth_timeout", 10)
        self.config.tool_execution_timeout = timeout_settings.get(
            "tool_execution_timeout", 60
        )
        self.config.discovery_timeout = timeout_settings.get("discovery_timeout", 120)
        self.config.cache_timeout = timeout_settings.get("cache_timeout", 5)
        self.config.connectivity_timeout = timeout_settings.get(
            "connectivity_timeout", 2
        )

        escalation_policies = timeout_settings.get("escalation_policies", {})
        self.config.escalation_policies.update(escalation_policies)

    def get_timeout(self, operation_type: str) -> int:
        """
        Get timeout value for a specific operation type.

        Args:
            operation_type: Type of operation (guardrail, auth, tool_execution, etc.)

        Returns:
            Timeout value in seconds
        """
        timeout_map = {
            "guardrail": self.config.guardrail_timeout,
            "auth": self.config.auth_timeout,
            "tool_execution": self.config.tool_execution_timeout,
            "discovery": self.config.discovery_timeout,
            "cache": self.config.cache_timeout,
            "connectivity": self.config.connectivity_timeout,
        }

        return timeout_map.get(operation_type, self.config.default_timeout)

    async def execute_with_timeout(
        self,
        operation: Callable,
        operation_type: str = "default",
        operation_id: Optional[str] = None,
        *args,
        **kwargs,
    ) -> TimeoutResult:
        """
        Execute an operation with configurable timeout and cancellation support.

        Args:
            operation: Async operation to execute
            operation_type: Type of operation for timeout configuration
            operation_id: Unique identifier for the operation
            *args: Arguments to pass to the operation
            **kwargs: Keyword arguments to pass to the operation

        Returns:
            TimeoutResult with operation result and metadata
        """
        start_time = time.time()
        timeout_value = self.get_timeout(operation_type)
        operation_id = operation_id or f"{operation_type}_{int(start_time)}"

        # Track active operation
        self._active_operations[operation_id] = None
        self._timeout_metrics["total_operations"] += 1

        try:
            # Create the operation task
            task = asyncio.create_task(operation(*args, **kwargs))
            self._active_operations[operation_id] = task

            # Execute with timeout
            result = await asyncio.wait_for(task, timeout=timeout_value)

            # Calculate elapsed time and escalation level
            elapsed_time = time.time() - start_time
            escalation_level = self._calculate_escalation_level(
                elapsed_time, timeout_value
            )

            # Update metrics
            self._timeout_metrics["successful_operations"] += 1
            self._timeout_metrics["escalation_counts"][escalation_level.value] += 1

            # Update telemetry metrics
            self._update_telemetry_metrics(
                operation_type, elapsed_time, escalation_level, success=True
            )

            # Log escalation if needed
            if escalation_level != TimeoutEscalationLevel.NORMAL:
                self._log_escalation(
                    operation_id, elapsed_time, timeout_value, escalation_level
                )

            return TimeoutResult(
                success=True,
                result=result,
                elapsed_time=elapsed_time,
                escalation_level=escalation_level,
            )

        except asyncio.TimeoutError:
            elapsed_time = time.time() - start_time
            self._timeout_metrics["timeout_operations"] += 1
            self._timeout_metrics["escalation_counts"][
                TimeoutEscalationLevel.TIMEOUT.value
            ] += 1

            # Update telemetry metrics
            self._update_telemetry_metrics(
                operation_type,
                elapsed_time,
                TimeoutEscalationLevel.TIMEOUT,
                success=False,
            )

            logger.error(
                f"[TimeoutManager] Operation {operation_id} timed out after {elapsed_time:.2f}s "
                f"(timeout: {timeout_value}s)",
            )

            return TimeoutResult(
                success=False,
                error=asyncio.TimeoutError(
                    f"Operation timed out after {timeout_value}s"
                ),
                elapsed_time=elapsed_time,
                escalation_level=TimeoutEscalationLevel.TIMEOUT,
            )

        except asyncio.CancelledError:
            elapsed_time = time.time() - start_time
            self._timeout_metrics["cancelled_operations"] += 1

            # Update telemetry metrics
            self._update_telemetry_metrics(
                operation_type,
                elapsed_time,
                TimeoutEscalationLevel.NORMAL,
                success=False,
                cancelled=True,
            )

            logger.debug(
                f"[TimeoutManager] Operation {operation_id} was cancelled after {elapsed_time:.2f}s"
            )

            return TimeoutResult(
                success=False,
                error=asyncio.CancelledError("Operation was cancelled"),
                elapsed_time=elapsed_time,
                cancelled=True,
            )

        except Exception as e:
            elapsed_time = time.time() - start_time

            # Use standardized error handling
            from secure_mcp_gateway.error_handling import error_logger
            from secure_mcp_gateway.exceptions import (
                ErrorCode,
                ErrorContext,
                create_system_error,
            )

            # Create error context
            context = ErrorContext(
                operation=f"timeout_manager.{operation_type}",
                request_id=operation_id,
                additional_context={
                    "operation_type": operation_type,
                    "timeout_value": timeout_value,
                    "elapsed_time": elapsed_time,
                },
            )

            # Create standardized error
            error = create_system_error(
                code=ErrorCode.SYSTEM_OPERATION_FAILED,
                message=f"Timeout-managed operation {operation_id} failed: {e}",
                context=context,
                cause=e,
            )

            # Log the error
            error_logger.log_error(error)

            logger.error(
                f"[TimeoutManager] Operation {operation_id} failed with error: {e}"
            )

            return TimeoutResult(success=False, error=error, elapsed_time=elapsed_time)

        finally:
            # Clean up active operation
            self._active_operations.pop(operation_id, None)

    def _calculate_escalation_level(
        self, elapsed_time: float, timeout_value: int
    ) -> TimeoutEscalationLevel:
        """Calculate escalation level based on elapsed time vs timeout."""
        ratio = elapsed_time / timeout_value

        if ratio >= self.config.escalation_policies["fail_threshold"]:
            return TimeoutEscalationLevel.FAIL
        elif ratio >= self.config.escalation_policies["timeout_threshold"]:
            return TimeoutEscalationLevel.TIMEOUT
        elif ratio >= self.config.escalation_policies["warn_threshold"]:
            return TimeoutEscalationLevel.WARN
        else:
            return TimeoutEscalationLevel.NORMAL

    def _log_escalation(
        self,
        operation_id: str,
        elapsed_time: float,
        timeout_value: int,
        escalation_level: TimeoutEscalationLevel,
    ) -> None:
        """Log timeout escalation."""
        ratio = elapsed_time / timeout_value

        if escalation_level == TimeoutEscalationLevel.WARN:
            logger.warning(
                f"[TimeoutManager] WARNING: Operation {operation_id} is approaching timeout "
                f"({elapsed_time:.2f}s / {timeout_value}s, {ratio:.1%})",
            )
        elif escalation_level == TimeoutEscalationLevel.TIMEOUT:
            logger.error(
                f"[TimeoutManager] TIMEOUT: Operation {operation_id} exceeded timeout "
                f"({elapsed_time:.2f}s / {timeout_value}s, {ratio:.1%})",
            )
        elif escalation_level == TimeoutEscalationLevel.FAIL:
            logger.critical(
                f"[TimeoutManager] FAIL: Operation {operation_id} severely exceeded timeout "
                f"({elapsed_time:.2f}s / {timeout_value}s, {ratio:.1%})",
            )

    async def cancel_operation(self, operation_id: str) -> bool:
        """
        Cancel a specific operation.

        Args:
            operation_id: ID of the operation to cancel

        Returns:
            True if operation was cancelled, False if not found
        """
        task = self._active_operations.get(operation_id)
        if task and not task.done():
            task.cancel()
            logger.info(f"[TimeoutManager] Cancelled operation {operation_id}")
            return True
        return False

    async def cancel_all_operations(self) -> int:
        """
        Cancel all active operations.

        Returns:
            Number of operations cancelled
        """
        cancelled_count = 0
        for operation_id, task in self._active_operations.items():
            if task and not task.done():
                task.cancel()
                cancelled_count += 1

        logger.info(f"[TimeoutManager] Cancelled {cancelled_count} active operations")
        return cancelled_count

    def get_active_operations(self) -> Dict[str, str]:
        """Get list of active operations."""
        return {
            op_id: "running" if not task.done() else "completed"
            for op_id, task in self._active_operations.items()
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get timeout metrics."""
        total = self._timeout_metrics["total_operations"]
        if total == 0:
            success_rate = 0.0
        else:
            success_rate = self._timeout_metrics["successful_operations"] / total

        return {
            **self._timeout_metrics,
            "success_rate": success_rate,
            "active_operations": len(self._active_operations),
        }

    @asynccontextmanager
    async def timeout_context(
        self, operation_type: str = "default", operation_id: Optional[str] = None
    ):
        """
        Context manager for timeout operations.

        Usage:
            async with timeout_manager.timeout_context("guardrail", "guardrail_123") as ctx:
                result = await some_operation()
        """
        timeout_value = self.get_timeout(operation_type)
        operation_id = operation_id or f"{operation_type}_{int(time.time())}"

        start_time = time.time()

        try:
            yield {
                "operation_id": operation_id,
                "timeout_value": timeout_value,
                "start_time": start_time,
            }
        finally:
            # Context cleanup if needed
            pass

    def _update_telemetry_metrics(
        self,
        operation_type: str,
        elapsed_time: float,
        escalation_level: TimeoutEscalationLevel,
        success: bool,
        cancelled: bool = False,
    ) -> None:
        """Update telemetry metrics for timeout operations."""
        try:
            from secure_mcp_gateway.plugins.telemetry import (
                get_telemetry_config_manager,
            )

            telemetry_manager = get_telemetry_config_manager()
            provider = telemetry_manager.get_active_provider()

            if provider and hasattr(provider, "timeout_operations_total"):
                # Update basic counters
                provider.timeout_operations_total.add(1)

                if success:
                    provider.timeout_operations_successful.add(1)
                elif cancelled:
                    provider.timeout_operations_cancelled.add(1)
                else:
                    provider.timeout_operations_timed_out.add(1)

                # Update escalation counters
                if escalation_level == TimeoutEscalationLevel.WARN:
                    provider.timeout_escalation_warn.add(1)
                elif escalation_level == TimeoutEscalationLevel.TIMEOUT:
                    provider.timeout_escalation_timeout.add(1)
                elif escalation_level == TimeoutEscalationLevel.FAIL:
                    provider.timeout_escalation_fail.add(1)

                # Update duration histogram
                provider.timeout_operation_duration.record(elapsed_time)

                # Update active operations gauge
                active_count = len(self._active_operations)
                provider.timeout_active_operations.add(
                    active_count - self._last_active_count
                    if hasattr(self, "_last_active_count")
                    else active_count
                )
                self._last_active_count = active_count

        except Exception as e:
            # Don't let telemetry errors break timeout functionality
            logger.debug(f"[TimeoutManager] Failed to update telemetry metrics: {e}")


# Global timeout manager instance
_timeout_manager: Optional[TimeoutManager] = None


def get_timeout_manager() -> TimeoutManager:
    """Get the global timeout manager instance."""
    global _timeout_manager
    if _timeout_manager is None:
        from secure_mcp_gateway.utils import get_common_config

        config = get_common_config()
        _timeout_manager = TimeoutManager(config)
    return _timeout_manager


def initialize_timeout_manager(config: Dict[str, Any]) -> TimeoutManager:
    """Initialize the global timeout manager with configuration."""
    global _timeout_manager
    _timeout_manager = TimeoutManager(config)
    return _timeout_manager
