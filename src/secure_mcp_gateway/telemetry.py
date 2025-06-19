"""
Enkrypt Secure MCP Gateway OpenTelemetry Module

This module provides comprehensive observability for the Enkrypt Secure MCP Gateway, including:
1. Distributed Tracing:
   - Tool call tracing
   - Guardrail operation tracing  
   - Cache operation tracing
   - API call tracing

2. Metrics Collection:
   - Performance metrics
   - Error rates
   - Guardrail violation rates
   - Cache hit/miss rates

3. Structured Logging:
   - Audit trails
   - Security events
   - Performance logs
   - Error logs

Configuration Variables:
    enkrypt_telemetry_enabled: Enable/disable telemetry
    enkrypt_telemetry_service_name: Service name for tracing
    enkrypt_telemetry_endpoint: OTLP endpoint URL
    enkrypt_telemetry_headers: Authentication headers for telemetry
    enkrypt_metrics_enabled: Enable/disable metrics collection
    enkrypt_jaeger_enabled: Enable/disable Jaeger tracing
    enkrypt_prometheus_enabled: Enable/disable Prometheus metrics
"""

import os
import sys
import time
import logging
import asyncio
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager, contextmanager

# OpenTelemetry imports
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.semantic_conventions.trace import SpanAttributes
from opentelemetry.trace import Status, StatusCode

# Structured logging
import structlog

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__

# Configuration
common_config = get_common_config()

ENKRYPT_TELEMETRY_ENABLED = common_config.get("enkrypt_telemetry_enabled", False)
ENKRYPT_TELEMETRY_SERVICE_NAME = common_config.get("enkrypt_telemetry_service_name", "enkrypt-mcp-gateway")
ENKRYPT_TELEMETRY_ENDPOINT = common_config.get("enkrypt_telemetry_endpoint", "http://localhost:4317")
ENKRYPT_TELEMETRY_HEADERS = common_config.get("enkrypt_telemetry_headers", {})
ENKRYPT_METRICS_ENABLED = common_config.get("enkrypt_metrics_enabled", True)
ENKRYPT_JAEGER_ENABLED = common_config.get("enkrypt_jaeger_enabled", False)
ENKRYPT_PROMETHEUS_ENABLED = common_config.get("enkrypt_prometheus_enabled", True)
ENKRYPT_JAEGER_ENDPOINT = common_config.get("enkrypt_jaeger_endpoint", "http://localhost:14268/api/traces")

# Global telemetry objects
tracer = None
meter = None
audit_logger = None

# Metrics
tool_call_counter = None
tool_call_duration = None
guardrail_violation_counter = None
cache_hit_counter = None
cache_miss_counter = None
api_request_counter = None
api_request_duration = None


def setup_telemetry():
    """Initialize OpenTelemetry tracing, metrics, and structured logging."""
    global tracer, meter, audit_logger
    global tool_call_counter, tool_call_duration, guardrail_violation_counter
    global cache_hit_counter, cache_miss_counter, api_request_counter, api_request_duration
    
    if not ENKRYPT_TELEMETRY_ENABLED:
        sys_print("OpenTelemetry is disabled")
        return
    
    sys_print(f"Initializing OpenTelemetry for {ENKRYPT_TELEMETRY_SERVICE_NAME}")
    
    # Setup Tracing
    trace_provider = TracerProvider(
        resource=trace.Resource.create({
            "service.name": ENKRYPT_TELEMETRY_SERVICE_NAME,
            "service.version": __version__
        })
    )
    
    # Add exporters
    if ENKRYPT_TELEMETRY_ENDPOINT:
        otlp_exporter = OTLPSpanExporter(
            endpoint=ENKRYPT_TELEMETRY_ENDPOINT,
            headers=ENKRYPT_TELEMETRY_HEADERS
        )
        trace_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
    
    if ENKRYPT_JAEGER_ENABLED:
        jaeger_exporter = JaegerExporter(
            agent_host_name="localhost",
            agent_port=6831,
            collector_endpoint=ENKRYPT_JAEGER_ENDPOINT,
        )
        trace_provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
    
    trace.set_tracer_provider(trace_provider)
    tracer = trace.get_tracer(__name__)
    
    # Setup Metrics
    if ENKRYPT_METRICS_ENABLED:
        metric_readers = []
        
        if ENKRYPT_TELEMETRY_ENDPOINT:
            otlp_metric_exporter = OTLPMetricExporter(
                endpoint=ENKRYPT_TELEMETRY_ENDPOINT,
                headers=ENKRYPT_TELEMETRY_HEADERS
            )
            metric_readers.append(PeriodicExportingMetricReader(otlp_metric_exporter))
        
        if ENKRYPT_PROMETHEUS_ENABLED:
            metric_readers.append(PrometheusMetricReader())
        
        meter_provider = MeterProvider(metric_readers=metric_readers)
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter(__name__)
        
        # Create metrics
        tool_call_counter = meter.create_counter(
            name="mcp_tool_calls_total",
            description="Total number of tool calls",
            unit="1"
        )
        
        tool_call_duration = meter.create_histogram(
            name="mcp_tool_call_duration_seconds",
            description="Duration of tool calls in seconds",
            unit="s"
        )
        
        guardrail_violation_counter = meter.create_counter(
            name="mcp_guardrail_violations_total",
            description="Total number of guardrail violations",
            unit="1"
        )
        
        cache_hit_counter = meter.create_counter(
            name="mcp_cache_hits_total",
            description="Total number of cache hits",
            unit="1"
        )
        
        cache_miss_counter = meter.create_counter(
            name="mcp_cache_misses_total",
            description="Total number of cache misses",
            unit="1"
        )
        
        api_request_counter = meter.create_counter(
            name="mcp_api_requests_total",
            description="Total number of API requests",
            unit="1"
        )
        
        api_request_duration = meter.create_histogram(
            name="mcp_api_request_duration_seconds",
            description="Duration of API requests in seconds",
            unit="s"
        )
    
    # Setup Structured Logging for Audit Trails
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    audit_logger = structlog.get_logger("audit")
    
    # Auto-instrument libraries
    RequestsInstrumentor().instrument()
    AioHttpClientInstrumentor().instrument()
    RedisInstrumentor().instrument()
    
    sys_print("OpenTelemetry initialization completed")


@asynccontextmanager
async def trace_tool_call(server_name: str, tool_name: str, gateway_id: str, user_id: str = None):
    """Async context manager for tracing tool calls with comprehensive attributes."""
    if not tracer:
        yield None
        return
    
    with tracer.start_as_current_span(
        name=f"mcp.tool.call",
        attributes={
            SpanAttributes.RPC_SERVICE: server_name,
            SpanAttributes.RPC_METHOD: tool_name,
            "mcp.gateway.id": gateway_id,
            "mcp.user.id": user_id or "unknown",
            "mcp.server.name": server_name,
            "mcp.tool.name": tool_name
        }
    ) as span:
        start_time = time.time()
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
            # Record metrics asynchronously to avoid blocking
            asyncio.create_task(_record_tool_call_metric(server_name, tool_name, "success"))
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            # Record metrics asynchronously to avoid blocking
            asyncio.create_task(_record_tool_call_metric(server_name, tool_name, "error"))
            raise
        finally:
            duration = time.time() - start_time
            # Record duration asynchronously to avoid blocking
            asyncio.create_task(_record_tool_call_duration(server_name, tool_name, duration))


@asynccontextmanager
async def trace_guardrail_check(guardrail_type: str, policy_name: str, direction: str):
    """Async context manager for tracing guardrail checks."""
    if not tracer:
        yield None
        return
    
    with tracer.start_as_current_span(
        name=f"mcp.guardrail.check",
        attributes={
            "mcp.guardrail.type": guardrail_type,
            "mcp.guardrail.policy": policy_name,
            "mcp.guardrail.direction": direction
        }
    ) as span:
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


@asynccontextmanager
async def trace_cache_operation(operation: str, cache_key: str):
    """Async context manager for tracing cache operations."""
    if not tracer:
        yield None
        return
    
    with tracer.start_as_current_span(
        name=f"mcp.cache.{operation}",
        attributes={
            "mcp.cache.operation": operation,
            "mcp.cache.key": cache_key
        }
    ) as span:
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise


async def _record_tool_call_metric(server_name: str, tool_name: str, status: str):
    """Async helper to record tool call metrics."""
    try:
        if tool_call_counter:
            tool_call_counter.add(1, {
                "server_name": server_name,
                "tool_name": tool_name,
                "status": status
            })
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record tool call metric: {e}")


async def _record_tool_call_duration(server_name: str, tool_name: str, duration: float):
    """Async helper to record tool call duration."""
    try:
        if tool_call_duration:
            tool_call_duration.record(duration, {
                "server_name": server_name,
                "tool_name": tool_name
            })
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record tool call duration: {e}")


def record_cache_hit(cache_type: str, server_name: str = None):
    """Record a cache hit metric."""
    try:
        if cache_hit_counter:
            attributes = {"cache_type": cache_type}
            if server_name:
                attributes["server_name"] = server_name
            cache_hit_counter.add(1, attributes)
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record cache hit: {e}")


def record_cache_miss(cache_type: str, server_name: str = None):
    """Record a cache miss metric."""
    try:
        if cache_miss_counter:
            attributes = {"cache_type": cache_type}
            if server_name:
                attributes["server_name"] = server_name
            cache_miss_counter.add(1, attributes)
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record cache miss: {e}")


async def record_guardrail_violation(
    violation_type: str, 
    policy_name: str, 
    direction: str,
    server_name: str,
    tool_name: str,
    gateway_id: str,
    user_id: str = None,
    violation_details: Dict[str, Any] = None
):
    """Record a guardrail violation for both metrics and audit logging asynchronously."""
    try:
        # Metrics
        if guardrail_violation_counter:
            guardrail_violation_counter.add(1, {
                "violation_type": violation_type,
                "policy_name": policy_name,
                "direction": direction,
                "server_name": server_name,
                "tool_name": tool_name
            })
        
        # Audit logging (run in background to avoid blocking)
        if audit_logger:
            asyncio.create_task(_log_guardrail_violation_async(
                violation_type, policy_name, direction, server_name, tool_name,
                gateway_id, user_id, violation_details
            ))
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record guardrail violation: {e}")


async def _log_guardrail_violation_async(
    violation_type: str, policy_name: str, direction: str, server_name: str,
    tool_name: str, gateway_id: str, user_id: str = None,
    violation_details: Dict[str, Any] = None
):
    """Async helper for audit logging guardrail violations."""
    try:
        if audit_logger:
            audit_logger.warning(
                "Guardrail violation detected",
                event_type="guardrail_violation",
                violation_type=violation_type,
                policy_name=policy_name,
                direction=direction,
                server_name=server_name,
                tool_name=tool_name,
                gateway_id=gateway_id,
                user_id=user_id,
                violation_details=violation_details or {},
                timestamp=time.time()
            )
    except Exception as e:
        sys_print(f"Failed to log guardrail violation: {e}")


async def record_api_request(endpoint: str, method: str, status_code: int, duration: float):
    """Record API request metrics asynchronously."""
    try:
        if api_request_counter:
            api_request_counter.add(1, {
                "endpoint": endpoint,
                "method": method,
                "status_code": str(status_code)
            })
        
        if api_request_duration:
            api_request_duration.record(duration, {
                "endpoint": endpoint,
                "method": method
            })
    except Exception as e:
        # Log error but don't fail the main operation
        sys_print(f"Failed to record API request metrics: {e}")


async def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    gateway_id: str,
    user_id: str = None,
    additional_data: Dict[str, Any] = None
):
    """Log security events for audit trails asynchronously."""
    try:
        if audit_logger:
            # Run logging in background to avoid blocking
            asyncio.create_task(_log_security_event_async(
                event_type, severity, description, gateway_id, user_id, additional_data
            ))
    except Exception as e:
        sys_print(f"Failed to log security event: {e}")


async def _log_security_event_async(
    event_type: str, severity: str, description: str, gateway_id: str,
    user_id: str = None, additional_data: Dict[str, Any] = None
):
    """Async helper for security event logging."""
    try:
        if audit_logger:
            log_method = getattr(audit_logger, severity.lower(), audit_logger.info)
            log_method(
                description,
                event_type=event_type,
                severity=severity,
                gateway_id=gateway_id,
                user_id=user_id,
                additional_data=additional_data or {},
                timestamp=time.time()
            )
    except Exception as e:
        sys_print(f"Failed to log security event async: {e}")


async def log_compliance_event(
    event_type: str,
    policy_name: str,
    compliance_status: str,
    gateway_id: str,
    user_id: str = None,
    details: Dict[str, Any] = None
):
    """Log compliance events for regulatory requirements asynchronously."""
    try:
        if audit_logger:
            # Run logging in background to avoid blocking
            asyncio.create_task(_log_compliance_event_async(
                event_type, policy_name, compliance_status, gateway_id, user_id, details
            ))
    except Exception as e:
        sys_print(f"Failed to log compliance event: {e}")


async def _log_compliance_event_async(
    event_type: str, policy_name: str, compliance_status: str, gateway_id: str,
    user_id: str = None, details: Dict[str, Any] = None
):
    """Async helper for compliance event logging."""
    try:
        if audit_logger:
            audit_logger.info(
                "Compliance event",
                event_type=event_type,
                policy_name=policy_name,
                compliance_status=compliance_status,
                gateway_id=gateway_id,
                user_id=user_id,
                details=details or {},
                timestamp=time.time()
            )
    except Exception as e:
        sys_print(f"Failed to log compliance event async: {e}")


# Initialize telemetry on module import
if ENKRYPT_TELEMETRY_ENABLED:
    setup_telemetry() 