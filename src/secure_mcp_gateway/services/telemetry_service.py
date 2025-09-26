# telemetry_service.py

import json
import logging
import os
import socket
import sys
import time
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
from secure_mcp_gateway.version import __version__


class TelemetryService:
    """
    Telemetry service for Enkrypt Secure MCP Gateway.
    Handles OpenTelemetry setup, logging, tracing, and metrics.
    """

    def __init__(self):
        """Initialize the telemetry service."""
        # TODO: Fix error and use stdout
        print(
            f"[otel] Initializing Enkrypt Secure MCP Gateway Telemetry Service v{__version__}",
            file=sys.stderr,
        )

        self.is_telemetry_enabled = None
        self.tracer = None
        self.logger = None
        self.meter = None
        self.resource = None

        # Initialize all metrics as None
        self._initialize_metrics()

        # Setup telemetry
        self._setup_telemetry()

    def _initialize_metrics(self):
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

    def get_absolute_path(self, file_name):
        """Get the absolute path of a file."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(current_dir, file_name)

    def does_file_exist(self, file_name_or_path, is_absolute_path=None):
        """Check if a file exists in the current directory."""
        if is_absolute_path is None:
            # Try to determine if it's an absolute path
            is_absolute_path = os.path.isabs(file_name_or_path)

        if is_absolute_path:
            return os.path.exists(file_name_or_path)
        else:
            return os.path.exists(self.get_absolute_path(file_name_or_path))

    def is_docker(self):
        """Check if the code is running inside a Docker container."""
        # Check for Docker environment markers
        docker_env_indicators = ["/.dockerenv", "/run/.containerenv"]
        for indicator in docker_env_indicators:
            if os.path.exists(indicator):
                return True

        # Check cgroup for any containerization system entries
        try:
            with open("/proc/1/cgroup", encoding="utf-8") as f:
                for line in f:
                    if any(
                        keyword in line
                        for keyword in ["docker", "kubepods", "containerd"]
                    ):
                        return True
        except FileNotFoundError:
            # /proc/1/cgroup doesn't exist, which is common outside of Linux
            pass

        return False

    def get_common_config(self, print_debug=False):
        """Get the common configuration for the Enkrypt Secure MCP Gateway."""
        config = {}

        if print_debug:
            print("[otel] Getting Enkrypt Common Configuration", file=sys.stderr)
            print(f"[otel] config_path: {CONFIG_PATH}", file=sys.stderr)
            print(f"[otel] docker_config_path: {DOCKER_CONFIG_PATH}", file=sys.stderr)
            print(f"[otel] example_config_path: {EXAMPLE_CONFIG_PATH}", file=sys.stderr)

        is_running_in_docker = self.is_docker()
        print(f"[otel] is_running_in_docker: {is_running_in_docker}", file=sys.stderr)
        picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
        if self.does_file_exist(picked_config_path):
            print(f"[otel] Loading {picked_config_path} file...", file=sys.stderr)
            with open(picked_config_path, encoding="utf-8") as f:
                config = json.load(f)
        else:
            print(
                "[otel] No config file found. Loading example config.", file=sys.stderr
            )
            if self.does_file_exist(EXAMPLE_CONFIG_PATH):
                if print_debug:
                    print(
                        f"[otel] Loading {EXAMPLE_CONFIG_NAME} file...", file=sys.stderr
                    )
                with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                    config = json.load(f)
            else:
                print(
                    "[otel] Example config file not found. Using default common config.",
                    file=sys.stderr,
                )

        if print_debug and config:
            print(f"[otel] config: {config}", file=sys.stderr)

        common_config = config.get("common_mcp_gateway_config", {})
        # Merge with defaults to ensure all required fields exist
        return {**DEFAULT_COMMON_CONFIG, **common_config}

    def _check_telemetry_enabled(self):
        """Check if telemetry is enabled."""
        if self.is_telemetry_enabled is not None:
            return self.is_telemetry_enabled

        config = self.get_common_config()
        telemetry_config = config.get("enkrypt_telemetry", {})
        if not telemetry_config.get("enabled", False):
            self.is_telemetry_enabled = False
            return False

        endpoint = telemetry_config.get("endpoint", "http://localhost:4317")

        try:
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname
            port = parsed_url.port
            if not hostname or not port:
                print(f"[otel] Invalid OTLP endpoint URL: {endpoint}", file=sys.stderr)
                self.is_telemetry_enabled = False
                return False

            with socket.create_connection((hostname, port), timeout=1):
                self.is_telemetry_enabled = True
                return True
        except (OSError, AttributeError, TypeError, ValueError) as e:
            print(
                f"[otel] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}",
                file=sys.stderr,
            )
            self.is_telemetry_enabled = False
            return False

    def _setup_telemetry(self):
        """Setup telemetry components."""
        common_config = self.get_common_config()
        otel_config = common_config.get("enkrypt_telemetry", {})

        self._check_telemetry_enabled()
        self.telemetry_insecure = otel_config.get(
            "insecure", True
        )  # True for local development
        self.telemetry_endpoint = otel_config.get("endpoint", "http://localhost:4317")

        self.service_name = "secure-mcp-gateway"
        self.job_name = "enkryptai"

        if self._check_telemetry_enabled():
            print(
                "[otel] OpenTelemetry enabled - initializing components",
                file=sys.stderr,
            )
            self._setup_enabled_telemetry()
        else:
            print("[otel] OpenTelemetry disabled - using no-op logger", file=sys.stderr)
            self._setup_disabled_telemetry()

    def _setup_enabled_telemetry(self):
        """Setup telemetry when enabled."""
        # ---------- COMMON RESOURCE ----------
        self.resource = Resource(
            attributes={"service.name": self.service_name, "job": self.job_name}
        )

        # ---------- LOGGING SETUP ----------
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        # Create formatters
        json_formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}'
        )
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # OTLP gRPC log exporter
        otlp_exporter = OTLPLogExporter(
            endpoint=self.telemetry_endpoint, insecure=self.telemetry_insecure
        )
        logger_provider = LoggerProvider(resource=self.resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_exporter))

        otlp_handler = LoggingHandler(
            level=logging.INFO, logger_provider=logger_provider
        )
        otlp_handler.setFormatter(json_formatter)
        root_logger.addHandler(otlp_handler)

        # Get logger for this service
        self.logger = logging.getLogger(self.service_name)

        # ---------- TRACING SETUP -------------------------------------------------------
        # Set up tracer provider with proper resource
        trace.set_tracer_provider(
            TracerProvider(
                resource=self.resource  # Use the common resource
            )
        )

        # Get tracer
        self.tracer = trace.get_tracer(__name__)

        # Set up OTLP exporter using gRPC
        otlp_exporter = OTLPSpanExporter(
            endpoint=self.telemetry_endpoint,  # Use gRPC port
            insecure=self.telemetry_insecure,
        )

        # Add span processor
        span_processor = BatchSpanProcessor(otlp_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)

        # ---------- METRICS SETUP -----------------------------------------------------
        # Step 1: Set up OTLP gRPC Exporter
        otlp_exporter = OTLPMetricExporter(
            endpoint=self.telemetry_endpoint,  # Use gRPC port
            insecure=self.telemetry_insecure,
        )

        # Step 2: Metric reader
        reader = PeriodicExportingMetricReader(
            otlp_exporter, export_interval_millis=5000
        )

        # Step 3: Set global MeterProvider with common resource
        provider = MeterProvider(resource=self.resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)

        # Step 4: Create a meter and a counter
        self.meter = metrics.get_meter("enkrypt.meter")

        # Initialize all metrics
        self._create_metrics()

    def _create_metrics(self):
        """Create all metrics."""
        # Basic Counters
        self.list_servers_call_count = self.meter.create_counter(
            "enkrypt_list_all_servers_calls",
            description="Number of times enkrypt_list_all_servers was called",
        )
        self.servers_discovered_count = self.meter.create_counter(
            "enkrypt_servers_discovered",
            description="Total number of servers discovered with tools",
        )
        self.cache_hit_counter = self.meter.create_counter(
            name="enkrypt_cache_hits_total",
            description="Total number of cache hits",
            unit="1",
        )
        self.cache_miss_counter = self.meter.create_counter(
            name="enkrypt_cache_misses_total",
            description="Total number of cache misses",
            unit="1",
        )
        self.tool_call_counter = self.meter.create_counter(
            name="enkrypt_tool_calls_total",
            description="Total number of tool calls",
            unit="1",
        )
        self.guardrail_api_request_counter = self.meter.create_counter(
            name="enkrypt_api_requests_total",
            description="Total number of API requests",
            unit="1",
        )
        self.guardrail_api_request_duration = self.meter.create_histogram(
            name="enkrypt_api_request_duration_seconds",
            description="Duration of API requests in seconds",
            unit="s",
        )
        self.guardrail_violation_counter = self.meter.create_counter(
            name="enkrypt_guardrail_violations_total",
            description="Total number of guardrail violations",
            unit="1",
        )
        self.tool_call_duration = self.meter.create_histogram(
            name="enkrypt_tool_call_duration_seconds",
            description="Duration of tool calls in seconds",
            unit="s",
        )

        # --- Advanced Metrics ---
        # Tool call success/failure/error counters
        self.tool_call_success_counter = self.meter.create_counter(
            "enkrypt_tool_call_success_total",
            description="Total successful tool calls",
            unit="1",
        )
        self.tool_call_failure_counter = self.meter.create_counter(
            "enkrypt_tool_call_failure_total",
            description="Total failed tool calls",
            unit="1",
        )
        self.tool_call_error_counter = self.meter.create_counter(
            "enkrypt_tool_call_errors_total",
            description="Total tool call errors",
            unit="1",
        )
        # Authentication
        self.auth_success_counter = self.meter.create_counter(
            "enkrypt_auth_success_total",
            description="Total successful authentications",
            unit="1",
        )
        self.auth_failure_counter = self.meter.create_counter(
            "enkrypt_auth_failure_total",
            description="Total failed authentications",
            unit="1",
        )
        # Active sessions/users (UpDownCounter = gauge)
        self.active_sessions_gauge = self.meter.create_up_down_counter(
            "enkrypt_active_sessions", description="Current active sessions", unit="1"
        )
        self.active_users_gauge = self.meter.create_up_down_counter(
            "enkrypt_active_users", description="Current active users", unit="1"
        )
        # PII redactions
        self.pii_redactions_counter = self.meter.create_counter(
            "enkrypt_pii_redactions_total", description="Total PII redactions", unit="1"
        )
        # Blocked tool calls (for block rate calculation)
        self.tool_call_blocked_counter = self.meter.create_counter(
            "enkrypt_tool_call_blocked_total",
            description="Total blocked tool calls (guardrail blocks)",
            unit="1",
        )
        # Per-violation-type counters (optional, for direct Prometheus queries)
        self.input_guardrail_violation_counter = self.meter.create_counter(
            "enkrypt_input_guardrail_violations_total",
            description="Input guardrail violations",
            unit="1",
        )
        self.output_guardrail_violation_counter = self.meter.create_counter(
            "enkrypt_output_guardrail_violations_total",
            description="Output guardrail violations",
            unit="1",
        )
        self.relevancy_violation_counter = self.meter.create_counter(
            "enkrypt_relevancy_violations_total",
            description="Relevancy guardrail violations",
            unit="1",
        )
        self.adherence_violation_counter = self.meter.create_counter(
            "enkrypt_adherence_violations_total",
            description="Adherence guardrail violations",
            unit="1",
        )
        self.hallucination_violation_counter = self.meter.create_counter(
            "enkrypt_hallucination_violations_total",
            description="Hallucination guardrail violations",
            unit="1",
        )

    def _setup_disabled_telemetry(self):
        """Setup no-op telemetry when disabled."""

        # Create a simple no-op logger when telemetry is disabled
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

        self.logger = NoOpLogger()
        self.resource = None

        # Create no-op telemetry objects when telemetry is disabled
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
                return NoOpCounter()  # Using NoOpCounter for up_down_counter as well

        class NoOpCounter:
            def add(self, amount, attributes=None):
                pass

        class NoOpHistogram:
            def record(self, amount, attributes=None):
                pass

        self.tracer = NoOpTracer()
        self.meter = NoOpMeter()

        # Create all the no-op metrics
        self.list_servers_call_count = NoOpCounter()
        self.servers_discovered_count = NoOpCounter()
        self.cache_hit_counter = NoOpCounter()
        self.cache_miss_counter = NoOpCounter()
        self.tool_call_counter = NoOpCounter()
        self.tool_call_duration = NoOpHistogram()
        self.guardrail_api_request_counter = NoOpCounter()
        self.guardrail_api_request_duration = NoOpHistogram()
        self.guardrail_violation_counter = NoOpCounter()

        # --- Advanced Metrics (No-op versions) ---
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
        self.active_sessions_gauge = NoOpCounter()  # Using NoOpCounter for gauge
        self.active_users_gauge = NoOpCounter()  # Using NoOpCounter for gauge
        self.pii_redactions_counter = NoOpCounter()

    def get_tracer(self):
        """Get the tracer instance."""
        return self.tracer

    def get_logger(self):
        """Get the logger instance."""
        return self.logger

    def get_meter(self):
        """Get the meter instance."""
        return self.meter

    def test_telemetry(self):
        """Test telemetry functionality."""
        print("[otel] Emitting test telemetry...", file=sys.stderr)

        # Emit test log
        print("[otel] test log emit", file=sys.stderr)
        self.logger.info("This is a test log from Enkrypt Gateway")

        # Test trace
        # Start a span
        with self.tracer.start_as_current_span(f"{self.job_name}.tracing.test") as span:
            span.set_attribute("component", "test")
            span.set_attribute("job", self.job_name)
            print("[otel-trace] Test span created.", file=sys.stderr)

        # Test metrics
        print("[otel-metrics] Emitting metrics...", file=sys.stderr)
        for i in range(10):
            self.list_servers_call_count.add(1)
            self.servers_discovered_count.add(1)
            self.cache_hit_counter.add(1)
            self.cache_miss_counter.add(1)
            self.tool_call_counter.add(1)
            self.guardrail_api_request_counter.add(1)
            self.guardrail_api_request_duration.record(1)
            time.sleep(0.1)


# Global telemetry service instance
telemetry_service = TelemetryService()

# Export the components for backward compatibility
tracer = telemetry_service.get_tracer()
logger = telemetry_service.get_logger()
meter = telemetry_service.get_meter()

# Export all metrics for backward compatibility
list_servers_call_count = telemetry_service.list_servers_call_count
servers_discovered_count = telemetry_service.servers_discovered_count
cache_hit_counter = telemetry_service.cache_hit_counter
cache_miss_counter = telemetry_service.cache_miss_counter
tool_call_counter = telemetry_service.tool_call_counter
tool_call_duration = telemetry_service.tool_call_duration
guardrail_api_request_counter = telemetry_service.guardrail_api_request_counter
guardrail_api_request_duration = telemetry_service.guardrail_api_request_duration
guardrail_violation_counter = telemetry_service.guardrail_violation_counter
tool_call_success_counter = telemetry_service.tool_call_success_counter
tool_call_failure_counter = telemetry_service.tool_call_failure_counter
tool_call_error_counter = telemetry_service.tool_call_error_counter
tool_call_blocked_counter = telemetry_service.tool_call_blocked_counter
input_guardrail_violation_counter = telemetry_service.input_guardrail_violation_counter
output_guardrail_violation_counter = (
    telemetry_service.output_guardrail_violation_counter
)
relevancy_violation_counter = telemetry_service.relevancy_violation_counter
adherence_violation_counter = telemetry_service.adherence_violation_counter
hallucination_violation_counter = telemetry_service.hallucination_violation_counter
auth_success_counter = telemetry_service.auth_success_counter
auth_failure_counter = telemetry_service.auth_failure_counter
active_sessions_gauge = telemetry_service.active_sessions_gauge
active_users_gauge = telemetry_service.active_users_gauge
pii_redactions_counter = telemetry_service.pii_redactions_counter


# ---------- TEST EXECUTION ----------
if __name__ == "__main__":
    telemetry_service.test_telemetry()
