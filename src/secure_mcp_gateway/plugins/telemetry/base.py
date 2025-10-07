"""
Telemetry Plugin System - Base Classes

SOLID Principles Applied:
- Single Responsibility: Each class has one clear purpose
- Open/Closed: Open for extension (new providers), closed for modification
- Liskov Substitution: All providers are interchangeable
- Interface Segregation: Minimal, focused interfaces
- Dependency Inversion: Depend on abstractions, not implementations
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Union


class TelemetryLevel(Enum):
    """Telemetry logging levels"""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class TelemetryResult:
    """Standardized result from telemetry operations"""

    success: bool
    provider_name: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)


class TelemetryProvider(ABC):
    """Abstract base class for all telemetry providers"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the provider name"""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Get the provider version"""
        pass

    @abstractmethod
    def initialize(self, config: dict[str, Any]) -> TelemetryResult:
        """Initialize the telemetry provider"""
        pass

    @abstractmethod
    def create_logger(self, name: str) -> Any:
        """Create a logger instance"""
        pass

    @abstractmethod
    def create_tracer(self, name: str) -> Any:
        """Create a tracer instance"""
        pass

    # Optional methods with default implementations
    def create_meter(self, name: str) -> Any:
        """Create a meter instance (optional)"""
        return None

    def shutdown(self) -> TelemetryResult:
        """Shutdown the provider (optional)"""
        return TelemetryResult(
            success=True, provider_name=self.name, message="Shutdown successful"
        )


class TelemetryRegistry:
    """Registry for managing telemetry providers"""

    def __init__(self):
        self._provider: TelemetryProvider | None = None

    def register(self, provider: TelemetryProvider) -> None:
        """Register a telemetry provider"""
        self._provider = provider

    def unregister(self, name: str = None) -> None:
        """Unregister the telemetry provider"""
        self._provider = None

    def get(self, name: str | None = None) -> TelemetryProvider | None:
        """Get the registered provider"""
        return self._provider

    def list_providers(self) -> list[str]:
        """Get list of registered provider names"""
        if self._provider:
            return [self._provider.name]
        return []


__all__ = [
    "TelemetryProvider",
    "TelemetryResult",
    "TelemetryRegistry",
    "TelemetryLevel",
]
