# telemetry.py

import os
import sys
import json
import time
import socket
import logging
from urllib.parse import urlparse


from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import Resource

from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.consts import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    DEFAULT_COMMON_CONFIG
)

# TODO: Fix error and use stdout
print(f"[otel] Initializing Enkrypt Secure MCP Gateway Telemetry Module v{__version__}", file=sys.stderr)

IS_TELEMETRY_ENABLED = None

# --------------------------------------------------------------------------
# Redefining functions from utils.py here to avoid circular imports
# If logic changes, please make changes in both files
# --------------------------------------------------------------------------

def get_absolute_path(file_name):
    """
    Get the absolute path of a file
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, file_name)


def does_file_exist(file_name_or_path, is_absolute_path=None):
    """
    Check if a file exists in the current directory
    """
    if is_absolute_path is None:
        # Try to determine if it's an absolute path
        is_absolute_path = os.path.isabs(file_name_or_path)
    
    if is_absolute_path:
        return os.path.exists(file_name_or_path)
    else:
        return os.path.exists(get_absolute_path(file_name_or_path))


def is_docker():
    """
    Check if the code is running inside a Docker container.
    """
    # Check for Docker environment markers
    docker_env_indicators = ['/.dockerenv', '/run/.containerenv']
    for indicator in docker_env_indicators:
        if os.path.exists(indicator):
            return True

    # Check cgroup for any containerization system entries
    try:
        with open('/proc/1/cgroup', 'rt', encoding='utf-8') as f:
            for line in f:
                if any(keyword in line for keyword in ['docker', 'kubepods', 'containerd']):
                    return True
    except FileNotFoundError:
        # /proc/1/cgroup doesn't exist, which is common outside of Linux
        pass

    return False


def get_common_config(print_debug=False):
    """
    Get the common configuration for the Enkrypt Secure MCP Gateway
    """
    config = {}

    if print_debug:
        print("[otel] Getting Enkrypt Common Configuration", file=sys.stderr)
        print(f"[otel] config_path: {CONFIG_PATH}", file=sys.stderr)
        print(f"[otel] docker_config_path: {DOCKER_CONFIG_PATH}", file=sys.stderr)
        print(f"[otel] example_config_path: {EXAMPLE_CONFIG_PATH}", file=sys.stderr)

    is_running_in_docker = is_docker()
    print(f"[otel] is_running_in_docker: {is_running_in_docker}", file=sys.stderr)
    picked_config_path = DOCKER_CONFIG_PATH if is_running_in_docker else CONFIG_PATH
    if does_file_exist(picked_config_path):
        print(f"[otel] Loading {picked_config_path} file...", file=sys.stderr)
        with open(picked_config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    else:
        print("[otel] No config file found. Loading example config.", file=sys.stderr)
        if does_file_exist(EXAMPLE_CONFIG_PATH):
            if print_debug:
                print(f"[otel] Loading {EXAMPLE_CONFIG_NAME} file...", file=sys.stderr)
            with open(EXAMPLE_CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            print("[otel] Example config file not found. Using default common config.", file=sys.stderr)

    if print_debug and config:
        print(f"[otel] config: {config}", file=sys.stderr)

    common_config = config.get("common_mcp_gateway_config", {})
    # Merge with defaults to ensure all required fields exist
    return {**DEFAULT_COMMON_CONFIG, **common_config}


def is_telemetry_enabled():
    """
    Check if telemetry is enabled
    """
    global IS_TELEMETRY_ENABLED
    if IS_TELEMETRY_ENABLED:
        return True
    elif IS_TELEMETRY_ENABLED is not None:
        return False

    config = get_common_config()
    telemetry_config = config.get("enkrypt_telemetry", {})
    if not telemetry_config.get("enabled", False):
        IS_TELEMETRY_ENABLED = False
        return False

    endpoint = telemetry_config.get("endpoint", "http://localhost:4317")

    try:
        parsed_url = urlparse(endpoint)
        hostname = parsed_url.hostname
        port = parsed_url.port
        if not hostname or not port:
            print(f"[otel] Invalid OTLP endpoint URL: {endpoint}", file=sys.stderr)
            IS_TELEMETRY_ENABLED = False
            return False
        
        with socket.create_connection((hostname, port), timeout=1):
            IS_TELEMETRY_ENABLED = True
            return True
    except (socket.error, AttributeError, TypeError, ValueError) as e:
        print(f"[otel] Telemetry is enabled in config, but endpoint {endpoint} is not accessible. So, disabling telemetry. Error: {e}", file=sys.stderr)
        IS_TELEMETRY_ENABLED = False
        return False


# --------------------------------------------------------------------------

common_config = get_common_config()
otel_config = common_config.get("enkrypt_telemetry", {})

is_telemetry_enabled()
TELEMETRY_INSECURE = otel_config.get("insecure", True) # True for local development
TELEMETRY_ENDPOINT = otel_config.get("endpoint", "http://localhost:4317")

SERVICE_NAME = "secure-mcp-gateway"
JOB_NAME = "enkryptai"

if IS_TELEMETRY_ENABLED:
    print(f"[otel] OpenTelemetry enabled - initializing components", file=sys.stderr)

    # ---------- COMMON RESOURCE ----------
    resource = Resource(attributes={
        "service.name": SERVICE_NAME,
        "job": JOB_NAME
    })

    # ---------- LOGGING SETUP ----------
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Create formatters
    json_formatter = logging.Formatter(
        '{"timestamp":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # OTLP gRPC log exporter
    otlp_exporter = OTLPLogExporter(
        endpoint=TELEMETRY_ENDPOINT,
        insecure=TELEMETRY_INSECURE
    )
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_exporter))

    otlp_handler = LoggingHandler(
        level=logging.INFO,
        logger_provider=logger_provider
    )
    otlp_handler.setFormatter(json_formatter)
    root_logger.addHandler(otlp_handler)

    # Get logger for this service
    logger = logging.getLogger(SERVICE_NAME)
else:
    print(f"[otel] OpenTelemetry disabled - using no-op logger", file=sys.stderr)
    
    # Create a simple no-op logger when telemetry is disabled
    class NoOpLogger:
        def info(self, msg, *args, **kwargs): pass
        def debug(self, msg, *args, **kwargs): pass
        def warning(self, msg, *args, **kwargs): pass
        def error(self, msg, *args, **kwargs): pass
        def critical(self, msg, *args, **kwargs): pass
    
    logger = NoOpLogger()
    resource = None

if IS_TELEMETRY_ENABLED:
    # ---------- TRACING SETUP -------------------------------------------------------
    # Set up tracer provider with proper resource
    trace.set_tracer_provider(
        TracerProvider(
            resource=resource  # Use the common resource
        )
    )

    # Get tracer
    tracer = trace.get_tracer(__name__)

    # Set up OTLP exporter using gRPC
    otlp_exporter = OTLPSpanExporter(
        endpoint=TELEMETRY_ENDPOINT,  # Use gRPC port
        insecure=TELEMETRY_INSECURE
    )

    # Add span processor
    span_processor = BatchSpanProcessor(otlp_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)

    # ---------- METRICS SETUP -----------------------------------------------------
    # Step 1: Set up OTLP gRPC Exporter
    otlp_exporter = OTLPMetricExporter(
        endpoint=TELEMETRY_ENDPOINT,  # Use gRPC port
        insecure=TELEMETRY_INSECURE
    )

    # Step 2: Metric reader
    reader = PeriodicExportingMetricReader(otlp_exporter, export_interval_millis=5000)

    # Step 3: Set global MeterProvider with common resource
    provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(provider)

    # Step 4: Create a meter and a counter
    meter = metrics.get_meter("enkrypt.meter")

    #############################
    list_servers_call_count = meter.create_counter(
        "enkrypt_list_all_servers_calls",
        description="Number of times enkrypt_list_all_servers was called"
    )
    servers_discovered_count = meter.create_counter(
        "enkrypt_servers_discovered",
        description="Total number of servers discovered with tools"
    )
    cache_hit_counter = meter.create_counter(
                name="enkrypt_cache_hits_total",
                description="Total number of cache hits",
                unit="1"
            )
    cache_miss_counter = meter.create_counter(
                name="enkrypt_cache_misses_total",
                description="Total number of cache misses",
                unit="1"
            )
    tool_call_counter = meter.create_counter(
        name="enkrypt_tool_calls_total",
        description="Total number of tool calls",
        unit="1"
    )
    guardrail_api_request_counter = meter.create_counter(
        name="enkrypt_api_requests_total",
        description="Total number of API requests",
        unit="1"
    )
    guardrail_api_request_duration = meter.create_histogram(
        name="enkrypt_api_request_duration_seconds",
        description="Duration of API requests in seconds",
        unit="s"
    )
    guardrail_violation_counter = meter.create_counter(
        name="enkrypt_guardrail_violations_total",
        description="Total number of guardrail violations",
        unit="1"
    )
    tool_call_duration = meter.create_histogram(
        name="enkrypt_tool_call_duration_seconds",
        description="Duration of tool calls in seconds",
        unit="s"
    )
    ################################################

    # request_counter = meter.create_counter(
    #     name="enkrypt_request_count",
    #     unit="requests",
    #     description="Counts number of processed requests"
    # )

    # #----------------------------------------------------
    # # Request/Response metrics
    # request_duration = meter.create_histogram(
    #     name="enkrypt_request_duration_seconds",
    #     description="Request latency by endpoint",
    #     unit="s"
    # )

    # # request_size = meter.create_histogram(
    # #     name="enkrypt_request_size_bytes",
    # #     description="Size of incoming requests",
    # #     unit="bytes"
    # # )

    # # response_size = meter.create_histogram(
    # #     name="enkrypt_response_size_bytes",
    # #     description="Size of outgoing responses",
    # #     unit="bytes"
    # # )

    # # request_errors = meter.create_counter(
    # #     name="enkrypt_request_errors_total",
    # #     description="Total error count by error type/code",
    # #     unit="1"
    # # )





    #-----------------------------------------------------------------
else:
    # Create no-op telemetry objects when telemetry is disabled
    class NoOpSpan:
        def set_attribute(self, key, value): pass
        def set_attributes(self, attributes): pass
        def add_event(self, name, attributes=None): pass
        def set_status(self, status): pass
        def record_exception(self, exception): pass
        def end(self): pass
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb): pass

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
    
    class NoOpCounter:
        def add(self, amount, attributes=None): pass
    
    class NoOpHistogram:
        def record(self, amount, attributes=None): pass
    
    tracer = NoOpTracer()
    meter = NoOpMeter()
    
    # Create all the no-op metrics
    list_servers_call_count = NoOpCounter()
    servers_discovered_count = NoOpCounter()
    cache_hit_counter = NoOpCounter()
    cache_miss_counter = NoOpCounter()
    tool_call_counter = NoOpCounter()
    tool_call_duration = NoOpHistogram()
    guardrail_api_request_counter = NoOpCounter()
    guardrail_api_request_duration = NoOpHistogram()
    guardrail_violation_counter = NoOpCounter()

# ---------- TEST EXECUTION ----------
if __name__ == "__main__":
    print("[otel] Emitting test telemetry...", file=sys.stderr)

    # Emit test log
    logger = logging.getLogger(SERVICE_NAME)
    print("[otel] test log emit", file=sys.stderr)

    logger.info("This is a test log from Enkrypt Gateway")

    # Test trace
    # Start a span
    with tracer.start_as_current_span(f"{JOB_NAME}.tracing.test") as span:
        span.set_attribute("component", "test")
        span.set_attribute("job", JOB_NAME)
        print("[otel-trace] Test span created.", file=sys.stderr)

    # Test metrics
    print("[otel-metrics] Emitting metrics...", file=sys.stderr)
    for i in range(10):
        list_servers_call_count.add(1)
        servers_discovered_count.add(1)
        cache_hit_counter.add(1)
        cache_miss_counter.add(1)
        tool_call_counter.add(1)
        guardrail_api_request_counter.add(1)
        guardrail_api_request_duration.record(1)
        time.sleep(0.1)

