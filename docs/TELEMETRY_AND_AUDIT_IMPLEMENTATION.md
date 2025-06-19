# OpenTelemetry and Audit Trail Implementation Guide

This guide provides comprehensive instructions for implementing OpenTelemetry observability and audit trails in the Enkrypt Secure MCP Gateway.

## Table of Contents

1. [Overview](#overview)
2. [OpenTelemetry Integration](#opentelemetry-integration)
3. [Audit Trail Implementation](#audit-trail-implementation)
4. [Configuration](#configuration)
5. [Deployment](#deployment)
6. [Monitoring and Alerting](#monitoring-and-alerting)
7. [Compliance Features](#compliance-features)
8. [Troubleshooting](#troubleshooting)

## Overview

The enhanced MCP Gateway includes comprehensive observability and audit capabilities:

### OpenTelemetry Features
- **Distributed Tracing**: End-to-end tracing of tool calls, guardrail checks, and cache operations
- **Metrics Collection**: Performance metrics, error rates, and business metrics
- **Structured Logging**: Consistent, searchable log format with correlation IDs
- **Auto-instrumentation**: Automatic instrumentation of HTTP clients, Redis, and other libraries

### Audit Trail Features
- **Comprehensive Event Logging**: All security-relevant events with detailed context
- **Compliance Support**: GDPR, SOX, HIPAA, PCI-DSS compliance logging
- **Encryption**: Encrypted audit logs with tamper-proof mechanisms
- **Risk Scoring**: Automatic risk assessment for security events
- **Retention Management**: Configurable retention policies with secure archival

## OpenTelemetry Integration

### 1. Dependencies

The following OpenTelemetry packages are required:

```txt
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
opentelemetry-instrumentation>=0.41b0
opentelemetry-instrumentation-requests>=0.41b0
opentelemetry-instrumentation-aiohttp-client>=0.41b0
opentelemetry-instrumentation-redis>=0.41b0
opentelemetry-exporter-otlp>=1.20.0
opentelemetry-exporter-jaeger>=1.20.0
opentelemetry-exporter-prometheus>=1.12.0rc1
opentelemetry-semantic-conventions>=0.41b0
structlog>=23.1.0
```

### 2. Configuration

Enable telemetry in your configuration:

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_telemetry_enabled": true,
    "enkrypt_telemetry_service_name": "enkrypt-mcp-gateway",
    "enkrypt_telemetry_endpoint": "http://otel-collector:4317",
    "enkrypt_telemetry_headers": {
      "api-key": "your-telemetry-api-key"
    },
    "enkrypt_metrics_enabled": true,
    "enkrypt_jaeger_enabled": true,
    "enkrypt_prometheus_enabled": true
  }
}
```

### 3. Tracing Implementation

#### Tool Call Tracing (Async)

```python
from secure_mcp_gateway.telemetry import trace_tool_call

async def execute_tool_with_tracing(server_name, tool_name, gateway_id, user_id, args):
    async with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
        if span:
            span.set_attribute("mcp.tool.args_count", len(args))
            span.set_attribute("mcp.tool.server_type", "external")
        
        try:
            result = await session.call_tool(tool_name, arguments=args)
            
            if span:
                span.set_attribute("mcp.tool.success", True)
                span.set_attribute("mcp.tool.response_size", len(str(result)))
            
            return result
        except Exception as e:
            if span:
                span.record_exception(e)
                span.set_attribute("mcp.tool.success", False)
            raise
```

#### Guardrail Tracing (Async)

```python
from secure_mcp_gateway.telemetry import trace_guardrail_check

async def check_guardrails_with_tracing(text, blocks, policy_name, direction):
    async with trace_guardrail_check("policy", policy_name, direction) as span:
        if span:
            span.set_attribute("mcp.guardrail.text_length", len(text))
            span.set_attribute("mcp.guardrail.blocks", json.dumps(blocks))
        
        violations_detected, violation_types, response = await call_guardrail(
            text, blocks, policy_name
        )
        
        if span:
            span.set_attribute("mcp.guardrail.violations_detected", violations_detected)
            span.set_attribute("mcp.guardrail.violation_types", json.dumps(violation_types))
        
        return violations_detected, violation_types, response
```

### 4. Metrics Collection

Key metrics automatically collected:

- `mcp_tool_calls_total`: Total number of tool calls (by server, tool, status)
- `mcp_tool_call_duration_seconds`: Tool call duration histogram
- `mcp_guardrail_violations_total`: Guardrail violations (by type, policy, direction)
- `mcp_cache_hits_total` / `mcp_cache_misses_total`: Cache performance
- `mcp_api_requests_total`: API request metrics

#### Custom Metrics (Async)

```python
from secure_mcp_gateway.telemetry import record_guardrail_violation
import asyncio

# Record a guardrail violation (async)
await record_guardrail_violation(
    violation_type="pii",
    policy_name="github-input-policy",
    direction="input",
    server_name="github",
    tool_name="search_repositories",
    gateway_id="gateway-001",
    user_id="user-001",
    violation_details={"confidence": 0.95, "entities": ["email"]}
)

# For fire-and-forget logging in sync contexts
asyncio.create_task(record_guardrail_violation(
    violation_type="pii",
    policy_name="github-input-policy",
    direction="input",
    server_name="github",
    tool_name="search_repositories",
    gateway_id="gateway-001",
    user_id="user-001",
    violation_details={"confidence": 0.95, "entities": ["email"]}
))
```

## Audit Trail Implementation

### 1. Audit Event Types

The system logs the following event types:

- **Authentication Events**: Login attempts, failures, session management
- **Tool Execution Events**: All tool calls with sanitized parameters
- **Guardrail Violation Events**: Policy violations with risk scoring
- **Security Alert Events**: Suspicious activities and threats
- **Data Access Events**: Access to sensitive data with classification
- **Configuration Changes**: Gateway and policy modifications
- **Cache Operations**: Cache access patterns for security analysis

### 2. Comprehensive Logging Example (Async)

```python
from secure_mcp_gateway.audit import (
    log_guardrail_violation_event,
    log_tool_execution_event,
    log_security_alert_event,
    AuditSeverity
)
import asyncio

# Log a guardrail violation with comprehensive details (async)
await log_guardrail_violation_event(
    gateway_id="gateway-001",
    user_id="user-001",
    server_name="github",
    tool_name="search_repositories",
    violation_type="pii",
    policy_name="github-input-policy",
    direction="input",
    violation_details={
        "detected_entities": ["email_address"],
        "confidence_score": 0.95,
        "original_text_hash": "sha256:abc123...",
        "policy_version": "v1.2",
        "detection_method": "ml_model"
    },
    blocked=True
)

# Log tool execution with performance metrics (async)
await log_tool_execution_event(
    gateway_id="gateway-001",
    user_id="user-001",
    server_name="github",
    tool_name="search_repositories",
    args={"query": "machine learning", "sort": "stars"},
    success=True,
    execution_time=1.234,
    response_size=4096
)

# Log security alerts for suspicious patterns (async)
await log_security_alert_event(
    gateway_id="gateway-001",
    user_id="user-001",
    alert_type="unusual_access_pattern",
    description="User accessing multiple sensitive repositories in short time",
    severity=AuditSeverity.HIGH,
    details={
        "repositories_accessed": 15,
        "time_window": "5 minutes",
        "risk_score": 85,
        "previous_baseline": 3
    }
)

# For fire-and-forget logging in sync contexts
asyncio.create_task(log_security_alert_event(
    gateway_id="gateway-001",
    user_id="user-001",
    alert_type="rate_limiting_triggered",
    description="Rate limit exceeded for user",
    severity=AuditSeverity.MEDIUM,
    details={"requests_per_minute": 150, "limit": 100}
))
```

### 3. Audit Log Encryption

Audit logs are automatically encrypted when enabled:

```json
{
  "enkrypt_audit_encryption_enabled": true,
  "enkrypt_audit_encryption_key": "base64-encoded-key"
}
```

The encryption uses Fernet (AES 128) with PBKDF2 key derivation for security.

### 4. Risk Scoring

Automatic risk scoring for violations:

```python
def calculate_risk_score(violation_type: str, violation_details: Dict[str, Any]) -> int:
    base_scores = {
        "pii": 80,
        "malware": 95,
        "toxicity": 60,
        "bias": 50,
        "hallucination": 70
    }
    
    base_score = base_scores.get(violation_type.lower(), 50)
    
    # Adjust based on confidence and severity
    if violation_details.get("confidence", 0) > 0.9:
        base_score += 10
    if violation_details.get("severity") == "high":
        base_score += 15
    
    return min(base_score, 100)
```

## Configuration

### Complete Configuration Example

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_telemetry_enabled": true,
    "enkrypt_telemetry_service_name": "enkrypt-mcp-gateway-prod",
    "enkrypt_telemetry_endpoint": "http://otel-collector:4317",
    "enkrypt_telemetry_headers": {
      "authorization": "Bearer your-token"
    },
    "enkrypt_metrics_enabled": true,
    "enkrypt_jaeger_enabled": true,
    "enkrypt_prometheus_enabled": true,
    
    "enkrypt_audit_enabled": true,
    "enkrypt_audit_encryption_enabled": true,
    "enkrypt_audit_retention_days": 2555,
    "enkrypt_audit_log_path": "/var/log/enkrypt/audit",
    "enkrypt_audit_remote_endpoint": "https://audit-collector.company.com/api/events"
  }
}
```

### Environment Variables

```bash
# OpenTelemetry
export ENKRYPT_TELEMETRY_ENABLED=true
export ENKRYPT_TELEMETRY_ENDPOINT=http://otel-collector:4317
export ENKRYPT_JAEGER_ENABLED=true

# Audit
export ENKRYPT_AUDIT_ENABLED=true
export ENKRYPT_AUDIT_ENCRYPTION_ENABLED=true
export ENKRYPT_AUDIT_ENCRYPTION_KEY=your-base64-key
```

## Deployment

### 1. Docker Compose Example

```yaml
version: '3.8'
services:
  mcp-gateway:
    image: enkrypt/mcp-gateway:latest
    environment:
      - ENKRYPT_TELEMETRY_ENABLED=true
      - ENKRYPT_TELEMETRY_ENDPOINT=http://otel-collector:4317
      - ENKRYPT_AUDIT_ENABLED=true
    volumes:
      - audit-logs:/var/log/enkrypt/audit
    depends_on:
      - otel-collector
      - jaeger
      - prometheus
  
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otel-collector-config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    ports:
      - "4317:4317"
      - "4318:4318"
  
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
  
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

volumes:
  audit-logs:
```

### 2. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-gateway
  template:
    metadata:
      labels:
        app: mcp-gateway
    spec:
      containers:
      - name: mcp-gateway
        image: enkrypt/mcp-gateway:latest
        env:
        - name: ENKRYPT_TELEMETRY_ENABLED
          value: "true"
        - name: ENKRYPT_TELEMETRY_ENDPOINT
          value: "http://otel-collector:4317"
        - name: ENKRYPT_AUDIT_ENABLED
          value: "true"
        volumeMounts:
        - name: audit-logs
          mountPath: /var/log/enkrypt/audit
        - name: config
          mountPath: /app/.enkrypt/
      volumes:
      - name: audit-logs
        persistentVolumeClaim:
          claimName: audit-logs-pvc
      - name: config
        configMap:
          name: mcp-gateway-config
```

## Monitoring and Alerting

### 1. Prometheus Alerts

```yaml
groups:
- name: mcp-gateway-alerts
  rules:
  - alert: HighGuardrailViolationRate
    expr: rate(mcp_guardrail_violations_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High guardrail violation rate detected"
      description: "Guardrail violations are occurring at {{ $value }} per second"
  
  - alert: ToolCallFailureRate
    expr: rate(mcp_tool_calls_total{status="error"}[5m]) / rate(mcp_tool_calls_total[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High tool call failure rate"
      description: "{{ $value | humanizePercentage }} of tool calls are failing"
  
  - alert: SecurityViolationDetected
    expr: increase(mcp_guardrail_violations_total{violation_type=~"malware|pii"}[1m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Security violation detected"
      description: "{{ $labels.violation_type }} violation detected on {{ $labels.server_name }}"
```

### 2. Grafana Dashboard

Key dashboard panels:

- **Tool Call Performance**: Request rate, latency percentiles, error rate
- **Guardrail Effectiveness**: Violation rates by type and policy
- **Security Overview**: Risk score distribution, threat detection
- **Cache Performance**: Hit/miss ratios, cache size trends
- **Audit Events**: Event volume, compliance coverage

### 3. Log Analysis with ELK Stack

```yaml
# Logstash pipeline for audit logs
input {
  file {
    path => "/var/log/enkrypt/audit/*.log"
    codec => "json"
    tags => ["audit", "enkrypt"]
  }
}

filter {
  if "audit" in [tags] {
    # Parse structured audit events
    json {
      source => "message"
    }
    
    # Add compliance tags
    if [event_type] == "guardrail_violation" {
      mutate {
        add_tag => ["compliance", "security"]
      }
    }
    
    # Calculate risk metrics
    if [risk_score] {
      range {
        ranges => [
          "low", 0, 30,
          "medium", 31, 70,
          "high", 71, 100
        ]
        field => "risk_score"
        target => "risk_level"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "enkrypt-audit-%{+YYYY.MM.dd}"
  }
}
```

## Compliance Features

### 1. GDPR Compliance

- **Data Subject Rights**: Audit logs support data subject identification and deletion
- **Purpose Limitation**: Clear logging of data processing purposes
- **Data Minimization**: Sensitive data sanitization in logs
- **Retention Policies**: Configurable retention with automatic deletion

### 2. SOX Compliance

- **Internal Controls**: Comprehensive audit trail of all financial data access
- **Change Management**: Configuration change logging with approval workflows
- **Access Controls**: User access patterns and privilege escalation detection
- **Data Integrity**: Tamper-proof audit logs with cryptographic verification

### 3. HIPAA Compliance

- **PHI Access Logging**: All access to protected health information
- **Risk Assessment**: Automatic risk scoring for PHI-related violations
- **Breach Detection**: Real-time alerts for potential PHI breaches
- **Audit Log Protection**: Encrypted storage with access controls

### 4. PCI-DSS Compliance

- **Cardholder Data Protection**: Detection and blocking of credit card information
- **Access Monitoring**: Real-time monitoring of payment system access
- **Network Security**: Network-level security event correlation
- **Regular Auditing**: Automated compliance reporting

## Async Best Practices

### 1. Async Context Managers

All telemetry tracing functions now use async context managers for better performance:

```python
# ✅ Correct async usage
async with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
    # Async operations here
    result = await some_async_operation()

# ❌ Incorrect - don't use sync context managers
with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
    result = sync_operation()
```

### 2. Fire-and-Forget Logging

For performance-critical paths, use fire-and-forget logging:

```python
import asyncio

# Fire-and-forget - won't block the main execution
asyncio.create_task(log_tool_execution_event(
    gateway_id="gateway-001",
    user_id="user-001",
    server_name="github",
    tool_name="search_repositories",
    args=args,
    success=True,
    execution_time=1.234
))

# Continue with main logic immediately
return result
```

### 3. Error Handling

All async telemetry and audit functions include built-in error handling:

```python
# Telemetry failures won't crash your application
try:
    async with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
        result = await execute_tool()
        # Even if audit logging fails, this won't raise an exception
        await log_tool_execution_event(...)
        return result
except ToolExecutionError as e:
    # Only tool execution errors are propagated
    raise
```

### 4. Performance Considerations

- **Tracing**: Minimal overhead, uses background tasks for metrics
- **Audit Logging**: Buffered writes, encrypted in background
- **Metrics**: Fire-and-forget recording with error suppression
- **Network Calls**: All telemetry exports are async and non-blocking

### 5. Integration Patterns

#### Pattern 1: Comprehensive Async Integration

```python
async def secure_tool_execution(server_name, tool_name, args, gateway_id, user_id):
    """Complete async integration with tracing, metrics, and audit logging."""
    
    async with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
        start_time = time.time()
        
        try:
            # Execute the actual tool
            result = await execute_tool(server_name, tool_name, args)
            
            # Log successful execution (async, non-blocking)
            asyncio.create_task(log_tool_execution_event(
                gateway_id=gateway_id,
                user_id=user_id,
                server_name=server_name,
                tool_name=tool_name,
                args=args,
                success=True,
                execution_time=time.time() - start_time,
                response_size=len(str(result))
            ))
            
            return result
            
        except Exception as e:
            # Log failure (async, non-blocking)
            asyncio.create_task(log_tool_execution_event(
                gateway_id=gateway_id,
                user_id=user_id,
                server_name=server_name,
                tool_name=tool_name,
                args=args,
                success=False,
                execution_time=time.time() - start_time,
                error_message=str(e)
            ))
            
            # Log security alert for suspicious failures
            asyncio.create_task(log_security_alert_event(
                gateway_id=gateway_id,
                user_id=user_id,
                alert_type="tool_execution_failure",
                description=f"Tool execution failed: {server_name}.{tool_name}",
                severity=AuditSeverity.MEDIUM,
                details={"error": str(e), "args_hash": hash(str(args))}
            ))
            
            raise
```

#### Pattern 2: Guardrail Integration with Async

```python
async def async_guardrail_check_with_logging(content, direction, server_name, tool_name, gateway_id, user_id):
    """Async guardrail check with comprehensive logging."""
    
    async with trace_guardrail_check("content_policy", "default", direction) as span:
        try:
            # Perform guardrail check
            violations_detected, violation_types, response = await check_guardrails(content)
            
            if violations_detected:
                # Record violation metrics and audit logs (async, non-blocking)
                asyncio.create_task(record_guardrail_violation(
                    violation_type=violation_types[0],
                    policy_name="default",
                    direction=direction,
                    server_name=server_name,
                    tool_name=tool_name,
                    gateway_id=gateway_id,
                    user_id=user_id,
                    violation_details={"detected_types": violation_types}
                ))
                
                asyncio.create_task(log_guardrail_violation_event(
                    gateway_id=gateway_id,
                    user_id=user_id,
                    server_name=server_name,
                    tool_name=tool_name,
                    violation_type=violation_types[0],
                    policy_name="default",
                    direction=direction,
                    violation_details={"content_length": len(content)},
                    blocked=True
                ))
            
            return not violations_detected, violation_types, response
            
        except Exception as e:
            # Log guardrail system failure
            asyncio.create_task(log_security_alert_event(
                gateway_id=gateway_id,
                user_id=user_id,
                alert_type="guardrail_system_failure",
                description="Guardrail system encountered an error",
                severity=AuditSeverity.CRITICAL,
                details={"error": str(e)}
            ))
            raise
```

## Troubleshooting

### 1. Common Issues

#### Telemetry Not Working

```bash
# Check telemetry configuration
curl -f http://localhost:8080/metrics || echo "Prometheus metrics not available"

# Verify OTLP endpoint connectivity
telnet otel-collector 4317

# Check Jaeger traces
curl http://jaeger:16686/api/traces?service=enkrypt-mcp-gateway
```

#### Audit Logs Missing

```bash
# Check audit configuration
grep -i audit /app/.enkrypt/enkrypt_mcp_config.json

# Verify log directory permissions
ls -la /var/log/enkrypt/audit/

# Check for encryption errors
tail -f /var/log/enkrypt/gateway.log | grep -i encryption
```

#### High Memory Usage

```bash
# Check telemetry buffer sizes
ps aux | grep mcp-gateway
cat /proc/$(pgrep mcp-gateway)/status | grep -i mem

# Reduce batch sizes in configuration
{
  "enkrypt_telemetry_batch_size": 100,
  "enkrypt_audit_buffer_size": 50
}
```

### 2. Performance Tuning

#### Optimize Telemetry

```json
{
  "enkrypt_telemetry_sampling_ratio": 0.1,
  "enkrypt_metrics_collection_interval": 30,
  "enkrypt_trace_batch_timeout": 5000
}
```

#### Optimize Audit Logging

```json
{
  "enkrypt_audit_async_enabled": true,
  "enkrypt_audit_batch_size": 100,
  "enkrypt_audit_flush_interval": 10
}
```

### 3. Security Considerations

- **Encryption Keys**: Use strong, randomly generated encryption keys
- **Network Security**: Secure telemetry and audit endpoints with TLS
- **Access Controls**: Restrict access to audit logs and telemetry data
- **Key Rotation**: Implement regular rotation of encryption keys
- **Monitoring**: Monitor the monitoring systems for tampering

## Best Practices

1. **Start Small**: Enable basic telemetry first, then add comprehensive audit logging
2. **Test Thoroughly**: Verify all telemetry and audit features in staging environment
3. **Monitor Performance**: Watch for performance impact of observability features
4. **Regular Reviews**: Regularly review audit logs and telemetry data for insights
5. **Compliance Alignment**: Ensure configuration meets your specific compliance requirements
6. **Documentation**: Maintain documentation of your observability and audit configuration
7. **Incident Response**: Integrate audit logs into your incident response procedures
8. **Training**: Train your team on using the telemetry and audit features effectively

This implementation provides enterprise-grade observability and audit capabilities for the MCP Gateway, ensuring comprehensive security monitoring and compliance support. 