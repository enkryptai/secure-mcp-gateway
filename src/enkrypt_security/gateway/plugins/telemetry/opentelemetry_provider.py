"""OpenTelemetry telemetry provider — backed by enkrypt_security.telemetry.

This is a thin adapter that satisfies the Gateway's ``TelemetryProvider``
interface by delegating to ``init_telemetry()`` for OTel setup and using
shared ``MetricNames`` for all metric definitions.

The full OTel initialisation (tracer / meter providers, exporters, no-op
fallbacks) lives in ``enkrypt_security.telemetry.setup`` — this file only
adds gateway-specific concerns:
  1. Endpoint connectivity check before enabling telemetry
  2. OTLP log export (optional, sends Python logs to OTel collector)
  3. Metric instance variables consumed by ``TelemetryConfigManager``
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any
from urllib.parse import urlparse

from enkrypt_security.telemetry import (
    MetricNames,
    TelemetryContext,
    init_telemetry,
)
from enkrypt_security.gateway.consts import (
    CONFIG_PATH,
    DEFAULT_COMMON_CONFIG,
    DOCKER_CONFIG_PATH,
    EXAMPLE_CONFIG_NAME,
    EXAMPLE_CONFIG_PATH,
)
from enkrypt_security.gateway.plugins.telemetry.base import TelemetryProvider, TelemetryResult
from enkrypt_security.gateway.version import __version__

logger = logging.getLogger("enkrypt.telemetry")


class OpenTelemetryProvider(TelemetryProvider):
    """Gateway telemetry provider backed by shared ``init_telemetry()``."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._initialized = False
        self._ctx: TelemetryContext | None = None
        self._logger: Any = None
        self._tracer: Any = None
        self._meter: Any = None
        self._resource: Any = None
        self._is_telemetry_enabled: bool | None = None

        self._initialize_metric_vars()

        if config:
            self.initialize(config)

    def _initialize_metric_vars(self) -> None:
        """Set all metric instance variables to ``None``."""
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

    # ------------------------------------------------------------------
    # TelemetryProvider interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "opentelemetry"

    @property
    def version(self) -> str:
        return "1.0.0"

    def create_logger(self, name: str) -> Any:
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._logger

    def create_tracer(self, name: str) -> Any:
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._tracer

    def create_meter(self, name: str) -> Any:
        if not self._initialized:
            raise RuntimeError("Provider not initialized. Call initialize() first.")
        return self._meter

    def shutdown(self) -> TelemetryResult:
        if self._ctx:
            self._ctx.shutdown()
        return TelemetryResult(
            success=True, provider_name=self.name, message="Shutdown successful"
        )

    def is_initialized(self) -> bool:
        return self._initialized

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialize(self, config: dict[str, Any]) -> TelemetryResult:
        try:
            logger.info(
                "[%s] Initializing OpenTelemetry provider v%s...",
                self.name,
                __version__,
            )

            if not config or "enabled" not in config:
                common_config = self._get_common_config()
                telemetry_plugin_config = common_config.get("plugins", {}).get(
                    "telemetry", {}
                )
                config = telemetry_plugin_config.get("config", {})

            enabled = self._check_telemetry_enabled(config)
            endpoint = config.get("url", "http://localhost:4317")
            insecure = config.get("insecure", True)
            service_name = config.get("service_name", "secure-mcp-gateway")

            if enabled:
                logger.info(
                    "[%s] OpenTelemetry enabled — initializing components",
                    self.name,
                )
                self._ctx = init_telemetry(
                    service_name=service_name,
                    exporter="otlp_grpc",
                    endpoint=endpoint,
                    insecure=insecure,
                    metric_export_interval_ms=5000,
                )
                self._setup_otlp_logging(endpoint, insecure, service_name, config)
            else:
                logger.info(
                    "[%s] OpenTelemetry disabled — using no-op components",
                    self.name,
                )
                self._ctx = init_telemetry()  # no-op

            self._tracer = self._ctx.tracer
            self._meter = self._ctx.meter
            self._logger = self._ctx.log

            self._create_metrics()
            self._create_timeout_metrics()
            self._initialized = True

            logger.info("[%s] Initialized OpenTelemetry provider", self.name)

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
            logger.error("[%s] Failed to initialize: %s", self.name, e)
            return TelemetryResult(
                success=False,
                provider_name=self.name,
                message="Failed to initialize OpenTelemetry",
                error=str(e),
            )

    # ------------------------------------------------------------------
    # OTLP log export (gateway-specific, sends Python logs to collector)
    # ------------------------------------------------------------------

    def _setup_otlp_logging(
        self,
        endpoint: str,
        insecure: bool,
        service_name: str,
        config: dict[str, Any],
    ) -> None:
        """Attach an OTLP log handler so gateway logs reach the collector."""
        try:
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
                OTLPLogExporter,
            )
            from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
            from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
            from opentelemetry.sdk.resources import Resource

            resource = Resource(attributes={"service.name": service_name})
            log_exporter = OTLPLogExporter(endpoint=endpoint, insecure=insecure)
            log_provider = LoggerProvider(resource=resource)
            log_provider.add_log_record_processor(
                BatchLogRecordProcessor(log_exporter)
            )

            svc_logger = logging.getLogger(service_name)
            from enkrypt_security.gateway.utils import get_common_config

            common_config = get_common_config()
            log_level = common_config.get("enkrypt_log_level", "INFO").upper()
            svc_logger.setLevel(getattr(logging, log_level, logging.INFO))

            handler = LoggingHandler(
                level=logging.INFO, logger_provider=log_provider
            )
            svc_logger.addHandler(handler)
            self._logger = svc_logger
        except ImportError:
            logger.debug(
                "[%s] OTLP log exporter not available, using default logger",
                self.name,
            )

    # ------------------------------------------------------------------
    # Metrics (shared names, backward-compatible instance variables)
    # ------------------------------------------------------------------

    def _create_metrics(self) -> None:
        """Create metrics using shared ``MetricNames`` constants."""
        m = self._meter

        # Guardrail metrics
        self.guardrail_api_request_counter = m.create_counter(
            MetricNames.GUARDRAIL_CHECKS,
            description="Total guardrail API calls",
            unit="1",
        )
        self.guardrail_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS,
            description="Total guardrail blocks",
            unit="1",
        )
        self.guardrail_api_request_duration = m.create_histogram(
            MetricNames.GUARDRAIL_DURATION,
            description="Guardrail check duration in seconds",
            unit="s",
        )

        # Granular violation counters (all map to guardrail.blocks with labels)
        self.input_guardrail_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".input",
            description="Input guardrail violations",
            unit="1",
        )
        self.output_guardrail_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".output",
            description="Output guardrail violations",
            unit="1",
        )
        self.relevancy_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".relevancy",
            description="Relevancy guardrail violations",
            unit="1",
        )
        self.adherence_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".adherence",
            description="Adherence guardrail violations",
            unit="1",
        )
        self.hallucination_violation_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".hallucination",
            description="Hallucination guardrail violations",
            unit="1",
        )
        self.tool_call_blocked_counter = m.create_counter(
            MetricNames.GUARDRAIL_BLOCKS + ".tool_blocked",
            description="Total blocked tool calls (guardrail blocks)",
            unit="1",
        )

        # Tool metrics
        self.tool_call_counter = m.create_counter(
            MetricNames.TOOL_CALLS,
            description="Total tool executions",
            unit="1",
        )
        self.tool_call_duration = m.create_histogram(
            MetricNames.TOOL_DURATION,
            description="Tool execution duration in seconds",
            unit="s",
        )
        self.tool_call_error_counter = m.create_counter(
            MetricNames.TOOL_ERRORS,
            description="Total tool execution errors",
            unit="1",
        )
        self.tool_call_success_counter = m.create_counter(
            MetricNames.TOOL_CALLS + ".success",
            description="Total successful tool calls",
            unit="1",
        )
        self.tool_call_failure_counter = m.create_counter(
            MetricNames.TOOL_CALLS + ".failure",
            description="Total failed tool calls",
            unit="1",
        )

        # Auth metrics
        self.auth_success_counter = m.create_counter(
            MetricNames.AUTH_SUCCESS,
            description="Successful authentications",
            unit="1",
        )
        self.auth_failure_counter = m.create_counter(
            MetricNames.AUTH_FAILURE,
            description="Failed authentications",
            unit="1",
        )

        # Cache metrics
        self.cache_hit_counter = m.create_counter(
            MetricNames.CACHE_HITS,
            description="Cache hits",
            unit="1",
        )
        self.cache_miss_counter = m.create_counter(
            MetricNames.CACHE_MISSES,
            description="Cache misses",
            unit="1",
        )

        # PII metrics
        self.pii_redactions_counter = m.create_counter(
            MetricNames.PII_REDACTIONS,
            description="PII redaction operations",
            unit="1",
        )

        # Session metrics
        self.active_sessions_gauge = m.create_up_down_counter(
            MetricNames.SESSION_ACTIVE,
            description="Currently active sessions",
            unit="1",
        )
        self.active_users_gauge = m.create_up_down_counter(
            MetricNames.SESSION_ACTIVE + ".users",
            description="Current active users",
            unit="1",
        )

        # Gateway-specific discovery metrics
        self.list_servers_call_count = m.create_counter(
            MetricNames.DISCOVERY_LIST,
            description="Number of list-servers calls",
        )
        self.servers_discovered_count = m.create_counter(
            MetricNames.DISCOVERY_FOUND,
            description="Total servers discovered with tools",
        )

    def _create_timeout_metrics(self) -> None:
        """Create timeout-specific metrics."""
        m = self._meter

        self.timeout_operations_total = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS,
            description="Total timeout operations",
        )
        self.timeout_operations_successful = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".success",
            description="Successful timeout operations",
        )
        self.timeout_operations_timed_out = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".timed_out",
            description="Operations that timed out",
        )
        self.timeout_operations_cancelled = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".cancelled",
            description="Operations that were cancelled",
        )
        self.timeout_escalation_warn = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".escalation_warn",
            description="Timeout escalation warnings",
        )
        self.timeout_escalation_timeout = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".escalation_timeout",
            description="Timeout escalations",
        )
        self.timeout_escalation_fail = m.create_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".escalation_fail",
            description="Timeout escalation failures",
        )
        self.timeout_operation_duration = m.create_histogram(
            MetricNames.TIMEOUT_OPERATIONS + ".duration",
            description="Duration of timeout operations in seconds",
        )
        self.timeout_active_operations = m.create_up_down_counter(
            MetricNames.TIMEOUT_OPERATIONS + ".active",
            description="Currently active timeout operations",
        )

    # ------------------------------------------------------------------
    # Gateway-specific helpers
    # ------------------------------------------------------------------

    def _check_docker(self) -> bool:
        docker_env_indicators = ["/.dockerenv", "/run/.containerenv"]
        for indicator in docker_env_indicators:
            if os.path.exists(indicator):
                return True
        try:
            with open("/proc/1/cgroup", encoding="utf-8") as f:
                for line in f:
                    if any(k in line for k in ("docker", "kubepods", "containerd")):
                        return True
        except FileNotFoundError:
            pass
        return False

    def _get_common_config(self) -> dict[str, Any]:
        import json

        picked = DOCKER_CONFIG_PATH if self._check_docker() else CONFIG_PATH
        config: dict[str, Any] = {}
        if os.path.exists(picked):
            with open(picked, encoding="utf-8") as f:
                config = json.load(f)
        elif os.path.exists(EXAMPLE_CONFIG_PATH):
            with open(EXAMPLE_CONFIG_PATH, encoding="utf-8") as f:
                config = json.load(f)
        common = config.get("common_mcp_gateway_config", {})
        plugins = config.get("plugins", {})
        return {**DEFAULT_COMMON_CONFIG, **common, "plugins": plugins}

    def _check_telemetry_enabled(self, config: dict[str, Any]) -> bool:
        if self._is_telemetry_enabled is not None:
            return self._is_telemetry_enabled

        if not config.get("enabled", False):
            self._is_telemetry_enabled = False
            return False

        endpoint = config.get("url", "http://localhost:4317")
        try:
            parsed = urlparse(endpoint)
            hostname, port = parsed.hostname, parsed.port
            if not hostname or not port:
                self._is_telemetry_enabled = False
                return False

            from enkrypt_security.gateway.services.timeout import get_timeout_manager

            timeout_value = get_timeout_manager().get_timeout("connectivity")

            if parsed.port == 4317:
                with socket.create_connection(
                    (hostname, port), timeout=timeout_value
                ):
                    self._is_telemetry_enabled = True
                    return True
            elif parsed.scheme in ("http", "https"):
                return self._check_http_endpoint(endpoint, timeout_value)
            else:
                with socket.create_connection(
                    (hostname, port), timeout=timeout_value
                ):
                    self._is_telemetry_enabled = True
                    return True
        except (OSError, AttributeError, TypeError, ValueError) as e:
            logger.error(
                "[%s] Endpoint %s not accessible, disabling telemetry: %s",
                self.name,
                endpoint,
                e,
            )
            self._is_telemetry_enabled = False
            return False

    def _check_http_endpoint(self, endpoint: str, timeout: float) -> bool:
        import urllib.error
        import urllib.request

        try:
            req = urllib.request.Request(endpoint, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout):
                self._is_telemetry_enabled = True
                return True
        except urllib.error.HTTPError as e:
            if e.code in (400, 404, 405, 500):
                self._is_telemetry_enabled = True
                return True
            self._is_telemetry_enabled = False
            return False
        except urllib.error.URLError:
            self._is_telemetry_enabled = False
            return False


__all__ = ["OpenTelemetryProvider"]
