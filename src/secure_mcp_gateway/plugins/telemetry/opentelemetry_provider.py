"""
OpenTelemetry Provider for Telemetry Plugin System

This provider implements OpenTelemetry-based logging, tracing, and metrics
for the Enkrypt Secure MCP Gateway.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys

# Avoid circular import by defining sys_print locally
import sys as python_sys
from typing import Any
from urllib.parse import urlparse

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DEFAULT_COMMON_CONFIG,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    EXAMPLE_CONFIG_PATH,
)
from secure_mcp_gateway.plugins.telemetry.base import TelemetryProvider, TelemetryResult
from secure_mcp_gateway.version import __version__


def sys_print(message: str, is_error: bool = False, is_debug: bool = False):
    """Local sys_print to avoid circular imports."""
    if is_error:
        print(f"[ERROR] {message}", file=python_sys.stderr)
    elif is_debug:
        print(f"[DEBUG] {message}", file=python_sys.stderr)
    else:
        print(message, file=python_sys.stderr)


class OpenTelemetryProvider(TelemetryProvider):
    """
    OpenTelemetry telemetry provider.

    Provides full OpenTelemetry implementation with logging, tracing, and metrics.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the OpenTelemetry provider.

        Args:
            config: Provider configuration (optional, can initialize later)
        """
        self._initialized = False
        self._logger = None
        self._tracer = None
        self._meter = None
        self._resource = None
        self._is_telemetry_enabled = None

        # Initialize all metrics as None
        self._initialize_metric_vars()

        if config:
            self.initialize(config)

    def _initialize_metric_vars(self):
        """Initialize all metric variables as None."""
        self.list_servers_call_count = None
        self.servers_discovered_count = None
        self.cache_hit_counter = None
        self.cache_miss_counter = None
        self.tool_call_counter = None
        self.guardrail_api_request_counter = None
        self.guardrail_api_request_duration = None
        self.guardrail_violation_counter = None
        self.tool_call_duration = None
        self.tool_call_success_counter = None
        self.tool_call_failure_counter = None
        self.tool_call_error_counter = None
        self.auth_success_counter = None
        self.auth_failure_counter = None
        self.active_sessions_gauge = None
        self.active_users_gauge = None
        self.pii_redactions_counter = None
        self.tool_call_blocked_counter = None
        self.input_guardrail_violation_counter = None
        self.output_guardrail_violation_counter = None
        self.relevancy_violation_counter = None
        self.adherence_violation_counter = None
        self.hallucination_violation_counter = None

    @property
    def name(self) -> str:
        """Provider name"""
        return "opentelemetry"

    @property
    def version(self) -> str:
        """Provider version"""
        return "1.0.0"

    def _check_docker(self) -> bool:
        """Check if running inside a Docker container."""
        docker_env_indicators = ["/.dockerenv", "/run/.containerenv"]
        for indicator in docker_env_indicators:
            if os.path.exists(indicator):
                return True

        try:
            with open("/proc/1/cgroup", encoding="utf-8") as f:
                for line in f:
                    if any(
                        keyword in line
                        for keyword in ["docker", "kubepods", "containerd"]
                    ):
                        return True
        except FileNotFoundError:
            pass

        return False

    def _get_common_config(self) -> dict[str, Any]:
        """Get the common configuration for the gateway."""
        config = {}

        is_running_in_docker = self._check_docker()
        sys_print(
            f"[{self.name}] is_running_in_docker: {is_running_in_docker}", is_debug=True
        )

        picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH

        if os.path.exists(picked_config_path):
            sys_print(
                f"[{self.name}] Loading {picked_config_path} file...", is_debug=True
            )
            with open(picked_config_path, encoding="utf-8") as f:
                config = json.load(f)
        else:
            sys_print(
                f"[{self.name}] No config file found. Loading example config.",
                is_debug=True,
            )
            if os.path.exists(EXAMPLE_CONFIG_PATH):
                sys_print(
                    f"[{self.name}] Loading {EXAMPLE_CONFIG_NAME} file...",
                    is_debug=True,
                )
                with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                    config = json.load(f)
            else:
                sys_print(
                    f"[{self.name}] Example config file not found. Using default common config.",
                    is_debug=True,
                )

        common_config = config.get("common_mcp_gateway_config", {})
        return {**DEFAULT_COMMON_CONFIG, **common_config}

    def _check_telemetry_enabled(self, config: dict[str, Any]) -> bool:
        """Check if telemetry is enabled and endpoint is reachable."""
        if self._is_telemetry_enabled is not None:
            return self._is_telemetry_enabled

        if not config.get("enabled", False):
            self._is_telemetry_enabled = False
            return False

        endpoint = config.get("endpoint", "http://localhost:4317")

        try:
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname
            port = parsed_url.port
            if not hostname or not port:
                sys_print(
                    f"[{self.name}] Invalid OTLP endpoint URL: {endpoint}",
                    is_error=True,
                )
                self._is_telemetry_enabled = False
                return False

            with socket.create_connection((hostname, port), timeout=1):
                self._is_telemetry_enabled = True
                return True
        except (OSError, AttributeError, TypeError, ValueError) as e:
            sys_print(
                f"[{self.name}] Telemetry enabled in config, but endpoint {endpoint} is not accessible. "
                f"Disabling telemetry. Error: {e}",
                is_error=True,
            )
            self._is_telemetry_enabled = False
            return False

    def initialize(self, config: dict[str, Any]) -> TelemetryResult:
        """
        Initialize OpenTelemetry.

        Args:
            config: Configuration dict with:
                - enabled: Whether telemetry is enabled
                - endpoint: OTLP endpoint URL
                - insecure: Whether to use insecure connection
                - service_name: Name of the service (optional)
                - job_name: Job name for metrics (optional)

        Returns:
            TelemetryResult: Initialization result
        """
        try:
            sys_print(
                f"[{self.name}] Initializing OpenTelemetry provider v{__version__}..."
            )

            # Get config from common config if not provided
            if not config or "enabled" not in config:
                common_config = self._get_common_config()
                config = common_config.get("enkrypt_telemetry", {})

            # Extract configuration
            enabled = self._check_telemetry_enabled(config)
            endpoint = config.get("endpoint", "http://localhost:4317")
            insecure = config.get("insecure", True)
            service_name = config.get("service_name", "secure-mcp-gateway")
            job_name = config.get("job_name", "enkryptai")

            if enabled:
                sys_print(
                    f"[{self.name}] OpenTelemetry enabled - initializing components"
                )
                self._setup_enabled_telemetry(
                    endpoint, insecure, service_name, job_name
                )
            else:
                sys_print(
                    f"[{self.name}] OpenTelemetry disabled - using no-op components"
                )
                self._setup_disabled_telemetry()

            self._initialized = True

            sys_print(f"[{self.name}] ✓ Initialized OpenTelemetry provider")

            return TelemetryResult(
                success=True,
                provider_name=self.name,
                message="OpenTelemetry initialized successfully",
                data={
                    "endpoint": endpoint,
                    "enabled": enabled,
                    "service_name": service_name,
                },
            )

        except Exception as e:
            sys_print(f"[{self.name}] ✗ Failed to initialize: {e}", is_error=True)
            return TelemetryResult(
                success=False,
                provider_name=self.name,
                message="Failed to initialize OpenTelemetry",
                error=str(e),
            )

    def _setup_enabled_telemetry(
        self, endpoint: str, insecure: bool, service_name: str, job_name: str
    ):
        """Setup telemetry when enabled."""
        # Common resource
        self._resource = Resource(
            attributes={"service.name": service_name, "job": job_name}
        )

        # ---------- LOGGING SETUP ----------
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        json_formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}'
        )
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        otlp_exporter = OTLPLogExporter(endpoint=endpoint, insecure=insecure)
        logger_provider = LoggerProvider(resource=self._resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_exporter))

        otlp_handler = LoggingHandler(
            level=logging.INFO, logger_provider=logger_provider
        )
        otlp_handler.setFormatter(json_formatter)
        root_logger.addHandler(otlp_handler)

        self._logger = logging.getLogger(service_name)

        # ---------- TRACING SETUP ----------
        trace.set_tracer_provider(TracerProvider(resource=self._resource))
        self._tracer = trace.get_tracer(__name__)

        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
        span_processor = BatchSpanProcessor(otlp_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)

        # ---------- METRICS SETUP ----------
        otlp_exporter = OTLPMetricExporter(endpoint=endpoint, insecure=insecure)
        reader = PeriodicExportingMetricReader(
            otlp_exporter, export_interval_millis=5000
        )
        provider = MeterProvider(resource=self._resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)

        self._meter = metrics.get_meter("enkrypt.meter")

        # Create all metrics
        self._create_metrics()

    def _create_metrics(self):
        """Create all metrics."""
        # Basic Counters
        self.list_servers_call_count = self._meter.create_counter(
            "enkrypt_list_all_servers_calls",
            description="Number of times enkrypt_list_all_servers was called",
        )
        self.servers_discovered_count = self._meter.create_counter(
            "enkrypt_servers_discovered",
            description="Total number of servers discovered with tools",
        )
        self.cache_hit_counter = self._meter.create_counter(
            name="enkrypt_cache_hits_total",
            description="Total number of cache hits",
            unit="1",
        )
        self.cache_miss_counter = self._meter.create_counter(
            name="enkrypt_cache_misses_total",
            description="Total number of cache misses",
            unit="1",
        )
        self.tool_call_counter = self._meter.create_counter(
            name="enkrypt_tool_calls_total",
            description="Total number of tool calls",
            unit="1",
        )
        self.guardrail_api_request_counter = self._meter.create_counter(
            name="enkrypt_api_requests_total",
            description="Total number of API requests",
            unit="1",
        )
        self.guardrail_api_request_duration = self._meter.create_histogram(
            name="enkrypt_api_request_duration_seconds",
            description="Duration of API requests in seconds",
            unit="s",
        )
        self.guardrail_violation_counter = self._meter.create_counter(
            name="enkrypt_guardrail_violations_total",
            description="Total number of guardrail violations",
            unit="1",
        )
        self.tool_call_duration = self._meter.create_histogram(
            name="enkrypt_tool_call_duration_seconds",
            description="Duration of tool calls in seconds",
            unit="s",
        )

        # Advanced Metrics
        self.tool_call_success_counter = self._meter.create_counter(
            "enkrypt_tool_call_success_total",
            description="Total successful tool calls",
            unit="1",
        )
        self.tool_call_failure_counter = self._meter.create_counter(
            "enkrypt_tool_call_failure_total",
            description="Total failed tool calls",
            unit="1",
        )
        self.tool_call_error_counter = self._meter.create_counter(
            "enkrypt_tool_call_errors_total",
            description="Total tool call errors",
            unit="1",
        )
        self.auth_success_counter = self._meter.create_counter(
            "enkrypt_auth_success_total",
            description="Total successful authentications",
            unit="1",
        )
        self.auth_failure_counter = self._meter.create_counter(
            "enkrypt_auth_failure_total",
            description="Total failed authentications",
            unit="1",
        )
        self.active_sessions_gauge = self._meter.create_up_down_counter(
            "enkrypt_active_sessions", description="Current active sessions", unit="1"
        )
        self.active_users_gauge = self._meter.create_up_down_counter(
            "enkrypt_active_users", description="Current active users", unit="1"
        )
        self.pii_redactions_counter = self._meter.create_counter(
            "enkrypt_pii_redactions_total", description="Total PII redactions", unit="1"
        )
        self.tool_call_blocked_counter = self._meter.create_counter(
            "enkrypt_tool_call_blocked_total",
            description="Total blocked tool calls (guardrail blocks)",
            unit="1",
        )
        self.input_guardrail_violation_counter = self._meter.create_counter(
            "enkrypt_input_guardrail_violations_total",
            description="Input guardrail violations",
            unit="1",
        )
        self.output_guardrail_violation_counter = self._meter.create_counter(
            "enkrypt_output_guardrail_violations_total",
            description="Output guardrail violations",
            unit="1",
        )
        self.relevancy_violation_counter = self._meter.create_counter(
            "enkrypt_relevancy_violations_total",
            description="Relevancy guardrail violations",
            unit="1",
        )
        self.adherence_violation_counter = self._meter.create_counter(
            "enkrypt_adherence_violations_total",
            description="Adherence guardrail violations",
            unit="1",
        )
        self.hallucination_violation_counter = self._meter.create_counter(
            "enkrypt_hallucination_violations_total",
            description="Hallucination guardrail violations",
            unit="1",
        )

    def _setup_disabled_telemetry(self):
        """Setup no-op telemetry when disabled."""

        # No-op logger
        class NoOpLogger:
            def info(self, msg, *args, **kwargs):
                pass

            def debug(self, msg, *args, **kwargs):
                pass

            def warning(self, msg, *args, **kwargs):
                pass

            def error(self, msg, *args, **kwargs):
                pass

            def critical(self, msg, *args, **kwargs):
                pass

        # No-op tracer components
        class NoOpSpan:
            def set_attribute(self, key, value):
                pass

            def set_attributes(self, attributes):
                pass

            def add_event(self, name, attributes=None):
                pass

            def set_status(self, status):
                pass

            def record_exception(self, exception):
                pass

            def end(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        class NoOpTracer:
            def start_as_current_span(self, name, **kwargs):
                return NoOpSpan()

            def start_span(self, name, **kwargs):
                return NoOpSpan()

            def get_current_span(self):
                return NoOpSpan()

        class NoOpMeter:
            def create_counter(self, name, **kwargs):
                return NoOpCounter()

            def create_histogram(self, name, **kwargs):
                return NoOpHistogram()

            def create_up_down_counter(self, name, **kwargs):
                return NoOpCounter()

        class NoOpCounter:
            def add(self, amount, attributes=None):
                pass

        class NoOpHistogram:
            def record(self, amount, attributes=None):
                pass

        self._logger = NoOpLogger()
        self._tracer = NoOpTracer()
        self._meter = NoOpMeter()
        self._resource = None

        # Create all no-op metrics
        self.list_servers_call_count = NoOpCounter()
        self.servers_discovered_count = NoOpCounter()
        self.cache_hit_counter = NoOpCounter()
        self.cache_miss_counter = NoOpCounter()
        self.tool_call_counter = NoOpCounter()
        self.tool_call_duration = NoOpHistogram()
        self.guardrail_api_request_counter = NoOpCounter()
        self.guardrail_api_request_duration = NoOpHistogram()
        self.guardrail_violation_counter = NoOpCounter()
        self.tool_call_success_counter = NoOpCounter()
        self.tool_call_failure_counter = NoOpCounter()
        self.tool_call_error_counter = NoOpCounter()
        self.tool_call_blocked_counter = NoOpCounter()
        self.input_guardrail_violation_counter = NoOpCounter()
        self.output_guardrail_violation_counter = NoOpCounter()
        self.relevancy_violation_counter = NoOpCounter()
        self.adherence_violation_counter = NoOpCounter()
        self.hallucination_violation_counter = NoOpCounter()
        self.auth_success_counter = NoOpCounter()
        self.auth_failure_counter = NoOpCounter()
        self.active_sessions_gauge = NoOpCounter()
        self.active_users_gauge = NoOpCounter()
        self.pii_redactions_counter = NoOpCounter()

    def create_logger(self, name: str) -> Any:
        """Create a logger instance."""
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._logger

    def create_tracer(self, name: str) -> Any:
        """Create a tracer instance."""
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._tracer

    def create_meter(self, name: str) -> Any:
        """Create a meter instance."""
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._meter

    def is_initialized(self) -> bool:
        """Check if provider is initialized"""
        return self._initialized


__all__ = ["OpenTelemetryProvider"]
