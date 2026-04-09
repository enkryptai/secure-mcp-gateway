"""OpenTelemetry telemetry provider."""

from __future__ import annotations

import atexit
import json
import logging
import os
import socket
import sys
from typing import Any
from urllib.parse import urlparse

import structlog

from secure_mcp_gateway.log import get_logger
from secure_mcp_gateway.plugins.telemetry.conventions import (
    METRIC_DESCRIPTIONS,
    MetricNames,
)

logger = get_logger("enkrypt.telemetry")

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
        self._tracer_provider = None
        self._meter_provider = None

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
        # logger.debug(f"[{self.name}] is_running_in_docker: {is_running_in_docker}")

        picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH

        if os.path.exists(picked_config_path):
            logger.debug(f"[{self.name}] Loading {picked_config_path} file...")
            with open(picked_config_path, encoding="utf-8") as f:
                config = json.load(f)
        else:
            logger.debug(f"[{self.name}] No config file found. Loading example config.")
            if os.path.exists(EXAMPLE_CONFIG_PATH):
                logger.debug(f"[{self.name}] Loading {EXAMPLE_CONFIG_NAME} file...")
                with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                    config = json.load(f)
            else:
                logger.debug(
                    f"[{self.name}] Example config file not found. Using default common config."
                )

        common_config = config.get("common_mcp_gateway_config", {})
        plugins_config = config.get("plugins", {})
        return {**DEFAULT_COMMON_CONFIG, **common_config, "plugins": plugins_config}

    def _check_telemetry_enabled(self, config: dict[str, Any]) -> bool:
        """Check if telemetry is enabled and endpoint is reachable."""
        if self._is_telemetry_enabled is not None:
            return self._is_telemetry_enabled

        if not config.get("enabled", False):
            self._is_telemetry_enabled = False
            return False

        endpoint = config.get("url", "http://localhost:4317")

        try:
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname
            port = parsed_url.port
            if not hostname or not port:
                logger.error(f"[{self.name}] Invalid OTLP endpoint URL: {endpoint}")
                self._is_telemetry_enabled = False
                return False

            # For gRPC endpoints (port 4317), use socket connection test
            if parsed_url.port == 4317:
                logger.debug(f"[{self.name}] Testing gRPC connectivity to {endpoint}")
                # Get configurable timeout from TimeoutManager
                from secure_mcp_gateway.services.timeout import get_timeout_manager

                timeout_manager = get_timeout_manager()
                timeout_value = timeout_manager.get_timeout("connectivity")

                with socket.create_connection((hostname, port), timeout=timeout_value):
                    logger.debug(f"[{self.name}] gRPC endpoint {endpoint} is reachable")
                    self._is_telemetry_enabled = True
                    return True
            # For HTTP endpoints, test HTTP connectivity instead of just TCP
            elif parsed_url.scheme == "http" or parsed_url.scheme == "https":
                import urllib.error
                import urllib.request

                try:
                    logger.debug(
                        f"[{self.name}] Testing HTTP connectivity to {endpoint}"
                    )
                    # Test HTTP connectivity with a simple HEAD request
                    req = urllib.request.Request(endpoint, method="HEAD")
                    with urllib.request.urlopen(req, timeout=timeout_value) as response:
                        # Any HTTP response (even 404, 405) means the endpoint is reachable
                        logger.debug(
                            f"[{self.name}] HTTP endpoint {endpoint} is reachable (status: {response.status})"
                        )
                        self._is_telemetry_enabled = True
                        return True
                except urllib.error.HTTPError as e:
                    # HTTP errors (404, 405, etc.) mean the service is running
                    if e.code in [404, 405, 400, 500]:
                        logger.debug(
                            f"[{self.name}] HTTP endpoint {endpoint} is reachable (status: {e.code})"
                        )
                        self._is_telemetry_enabled = True
                        return True
                    else:
                        logger.error(
                            f"[{self.name}] Telemetry enabled in config, but HTTP endpoint {endpoint} returned error {e.code}. "
                            "Disabling telemetry."
                        )
                        self._is_telemetry_enabled = False
                        return False
                except urllib.error.URLError as e:
                    logger.error(
                        f"[{self.name}] Telemetry enabled in config, but HTTP endpoint {endpoint} is not accessible. "
                        f"Disabling telemetry. Error: {e}"
                    )
                    self._is_telemetry_enabled = False
                    return False
            else:
                # For non-HTTP endpoints, use socket connection test
                with socket.create_connection((hostname, port), timeout=timeout_value):
                    self._is_telemetry_enabled = True
                    return True
        except (OSError, AttributeError, TypeError, ValueError) as e:
            logger.error(
                f"[{self.name}] Telemetry enabled in config, but endpoint {endpoint} is not accessible. "
                f"Disabling telemetry. Error: {e}"
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
            logger.info(
                f"[{self.name}] Initializing OpenTelemetry provider v{__version__}..."
            )

            # Get config from common config if not provided
            if not config or "enabled" not in config:
                common_config = self._get_common_config()
                telemetry_plugin_config = common_config.get("plugins", {}).get(
                    "telemetry", {}
                )
                config = telemetry_plugin_config.get("config", {})
                logger.debug(f"[{self.name}] Loaded telemetry config: {config}")

            # Extract configuration
            enabled = self._check_telemetry_enabled(config)
            endpoint = config.get("url", "http://localhost:4317")
            insecure = config.get("insecure", True)
            service_name = config.get("service_name", "secure-mcp-gateway")
            job_name = config.get("job_name", "enkryptai")

            if enabled:
                logger.info(
                    f"[{self.name}] OpenTelemetry enabled - initializing components"
                )
                self._setup_enabled_telemetry(
                    endpoint, insecure, service_name, job_name, config
                )
            else:
                logger.info(
                    f"[{self.name}] OpenTelemetry disabled - using no-op components"
                )
                self._setup_disabled_telemetry()

            self._initialized = True

            logger.info(f"[{self.name}] ✓ Initialized OpenTelemetry provider")

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
            logger.error(f"[{self.name}] ✗ Failed to initialize: {e}")
            return TelemetryResult(
                success=False,
                provider_name=self.name,
                message="Failed to initialize OpenTelemetry",
                error=str(e),
            )

    def _setup_enabled_telemetry(
        self,
        endpoint: str,
        insecure: bool,
        service_name: str,
        job_name: str,
        config: dict[str, Any] = None,
    ):
        """Setup telemetry when enabled."""
        # Common resource
        self._resource = Resource(
            attributes={"service.name": service_name, "job": job_name}
        )

        # ---------- LOGGING SETUP ----------
        # Attach OTLP log handler to the stdlib *root* logger so that all
        # structlog events (which are bridged through stdlib) are exported.
        otlp_exporter = OTLPLogExporter(endpoint=endpoint, insecure=insecure)
        logger_provider = LoggerProvider(resource=self._resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_exporter))

        otlp_handler = LoggingHandler(
            level=logging.DEBUG, logger_provider=logger_provider
        )
        logging.getLogger().addHandler(otlp_handler)
        self._logger = get_logger(service_name)

        # ---------- TRACING SETUP ----------
        self._tracer_provider = TracerProvider(resource=self._resource)
        trace.set_tracer_provider(self._tracer_provider)
        self._tracer = trace.get_tracer(__name__)

        otlp_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
        span_processor = BatchSpanProcessor(otlp_exporter)
        self._tracer_provider.add_span_processor(span_processor)

        # ---------- METRICS SETUP ----------
        otlp_exporter = OTLPMetricExporter(endpoint=endpoint, insecure=insecure)
        reader = PeriodicExportingMetricReader(
            otlp_exporter, export_interval_millis=5000
        )
        self._meter_provider = MeterProvider(
            resource=self._resource, metric_readers=[reader]
        )
        metrics.set_meter_provider(self._meter_provider)

        self._meter = metrics.get_meter("enkrypt.meter")

        # Flush buffered spans/metrics on process exit
        atexit.register(self.shutdown)

        # Create all metrics
        self._create_metrics()

        # Create timeout-specific metrics
        self._create_timeout_metrics()

    def _create_metrics(self):
        """Create all metrics using canonical names from conventions."""
        M = MetricNames
        D = METRIC_DESCRIPTIONS

        self.list_servers_call_count = self._meter.create_counter(
            M.DISCOVERY_LIST, description=D[M.DISCOVERY_LIST],
        )
        self.servers_discovered_count = self._meter.create_counter(
            M.DISCOVERY_FOUND, description=D[M.DISCOVERY_FOUND],
        )
        self.cache_hit_counter = self._meter.create_counter(
            M.CACHE_HITS, description=D[M.CACHE_HITS], unit="1",
        )
        self.cache_miss_counter = self._meter.create_counter(
            M.CACHE_MISSES, description=D[M.CACHE_MISSES], unit="1",
        )
        self.tool_call_counter = self._meter.create_counter(
            M.TOOL_CALLS, description=D[M.TOOL_CALLS], unit="1",
        )
        self.guardrail_api_request_counter = self._meter.create_counter(
            M.GUARDRAIL_CHECKS, description=D[M.GUARDRAIL_CHECKS], unit="1",
        )
        self.guardrail_api_request_duration = self._meter.create_histogram(
            M.GUARDRAIL_DURATION, description=D[M.GUARDRAIL_DURATION], unit="s",
        )
        self.guardrail_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_BLOCKS, description=D[M.GUARDRAIL_BLOCKS], unit="1",
        )
        self.tool_call_duration = self._meter.create_histogram(
            M.TOOL_DURATION, description=D[M.TOOL_DURATION], unit="s",
        )
        self.tool_call_success_counter = self._meter.create_counter(
            M.TOOL_SUCCESS, description=D[M.TOOL_SUCCESS], unit="1",
        )
        self.tool_call_failure_counter = self._meter.create_counter(
            M.TOOL_FAILURES, description=D[M.TOOL_FAILURES], unit="1",
        )
        self.tool_call_error_counter = self._meter.create_counter(
            M.TOOL_ERRORS, description=D[M.TOOL_ERRORS], unit="1",
        )
        self.auth_success_counter = self._meter.create_counter(
            M.AUTH_SUCCESS, description=D[M.AUTH_SUCCESS], unit="1",
        )
        self.auth_failure_counter = self._meter.create_counter(
            M.AUTH_FAILURE, description=D[M.AUTH_FAILURE], unit="1",
        )
        self.active_sessions_gauge = self._meter.create_up_down_counter(
            M.SESSION_ACTIVE, description=D[M.SESSION_ACTIVE], unit="1",
        )
        self.active_users_gauge = self._meter.create_up_down_counter(
            M.USERS_ACTIVE, description=D[M.USERS_ACTIVE], unit="1",
        )
        self.pii_redactions_counter = self._meter.create_counter(
            M.PII_REDACTIONS, description=D[M.PII_REDACTIONS], unit="1",
        )
        self.tool_call_blocked_counter = self._meter.create_counter(
            M.TOOL_BLOCKED, description=D[M.TOOL_BLOCKED], unit="1",
        )
        self.input_guardrail_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_INPUT_BLOCKS, description=D[M.GUARDRAIL_INPUT_BLOCKS], unit="1",
        )
        self.output_guardrail_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_OUTPUT_BLOCKS, description=D[M.GUARDRAIL_OUTPUT_BLOCKS], unit="1",
        )
        self.relevancy_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_RELEVANCY_BLOCKS, description=D[M.GUARDRAIL_RELEVANCY_BLOCKS], unit="1",
        )
        self.adherence_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_ADHERENCE_BLOCKS, description=D[M.GUARDRAIL_ADHERENCE_BLOCKS], unit="1",
        )
        self.hallucination_violation_counter = self._meter.create_counter(
            M.GUARDRAIL_HALLUCINATION_BLOCKS, description=D[M.GUARDRAIL_HALLUCINATION_BLOCKS], unit="1",
        )

    def _setup_disabled_telemetry(self):
        """Setup no-op telemetry when disabled.

        The logger is still a real structlog logger routed to the console
        handler set up by ``configure_logging()``.  Only OTLP export is
        skipped.
        """
        self._logger = get_logger("secure-mcp-gateway")

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
        """Create a logger instance (structlog-backed)."""
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return get_logger(name)

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

    def _create_timeout_metrics(self):
        """Create timeout-specific metrics using canonical names."""
        M = MetricNames
        D = METRIC_DESCRIPTIONS

        self.timeout_operations_total = self._meter.create_counter(
            M.TIMEOUT_OPERATIONS, description=D[M.TIMEOUT_OPERATIONS],
        )
        self.timeout_operations_successful = self._meter.create_counter(
            M.TIMEOUT_SUCCESS, description=D[M.TIMEOUT_SUCCESS],
        )
        self.timeout_operations_timed_out = self._meter.create_counter(
            M.TIMEOUT_TIMED_OUT, description=D[M.TIMEOUT_TIMED_OUT],
        )
        self.timeout_operations_cancelled = self._meter.create_counter(
            M.TIMEOUT_CANCELLED, description=D[M.TIMEOUT_CANCELLED],
        )
        self.timeout_escalation_warn = self._meter.create_counter(
            M.TIMEOUT_ESCALATION_WARN, description=D[M.TIMEOUT_ESCALATION_WARN],
        )
        self.timeout_escalation_timeout = self._meter.create_counter(
            M.TIMEOUT_ESCALATION_TIMEOUT, description=D[M.TIMEOUT_ESCALATION_TIMEOUT],
        )
        self.timeout_escalation_fail = self._meter.create_counter(
            M.TIMEOUT_ESCALATION_FAIL, description=D[M.TIMEOUT_ESCALATION_FAIL],
        )
        self.timeout_operation_duration = self._meter.create_histogram(
            M.TIMEOUT_DURATION, description=D[M.TIMEOUT_DURATION],
        )
        self.timeout_active_operations = self._meter.create_up_down_counter(
            M.TIMEOUT_ACTIVE, description=D[M.TIMEOUT_ACTIVE],
        )

    def shutdown(self) -> None:
        """Flush and shut down OTel providers so buffered data is not lost."""
        if self._tracer_provider and hasattr(self._tracer_provider, "shutdown"):
            self._tracer_provider.shutdown()
        if self._meter_provider and hasattr(self._meter_provider, "shutdown"):
            self._meter_provider.shutdown()

    def is_initialized(self) -> bool:
        """Check if provider is initialized"""
        return self._initialized


__all__ = ["OpenTelemetryProvider"]
