"""
Telemetry Integration Example - Async Version

This module demonstrates how to integrate OpenTelemetry tracing and audit logging
into the MCP Gateway functions using async patterns for better performance.

Key features demonstrated:
- Async telemetry tracing with context managers
- Async audit logging for compliance
- Error handling with comprehensive logging
- Performance monitoring with metrics
- Guardrail violation handling with risk assessment
"""

import asyncio
import time
from typing import Dict, Any, Optional

# Import async telemetry and audit functions
from .telemetry import (
    trace_tool_call,
    trace_guardrail_check,
    trace_cache_operation,
    record_guardrail_violation,
    log_security_event,
    record_cache_hit,
    record_cache_miss,
    record_api_request
)
from .audit import (
    log_authentication_event,
    log_tool_execution_event,
    log_guardrail_violation_event,
    log_security_alert_event,
    log_data_access_event
)


async def enhanced_tool_execution_with_telemetry(
    server_name: str,
    tool_name: str,
    args: Dict[str, Any],
    gateway_id: str,
    user_id: str = None
) -> Dict[str, Any]:
    """
    Enhanced tool execution with comprehensive telemetry and audit logging (async).
    
    This function demonstrates how to integrate tracing, metrics, and audit logging
    into tool execution with proper error handling and performance monitoring.
    """
    execution_start = time.time()
    
    # Start distributed tracing
    async with trace_tool_call(server_name, tool_name, gateway_id, user_id) as span:
        try:
            # Add custom attributes to span
            if span:
                span.set_attribute("mcp.tool.args_count", len(args))
                span.set_attribute("mcp.tool.execution_mode", "async")
            
            # Simulate tool execution (replace with actual tool call)
            await asyncio.sleep(0.1)  # Simulate async work
            
            # Mock successful result
            result = {
                "status": "success",
                "data": f"Tool {tool_name} executed successfully",
                "execution_time": time.time() - execution_start
            }
            
            # Log successful tool execution
            await log_tool_execution_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                server_name=server_name,
                tool_name=tool_name,
                args=args,
                success=True,
                execution_time=result["execution_time"],
                response_size=len(str(result))
            )
            
            # Add success attributes to span
            if span:
                span.set_attribute("mcp.tool.success", True)
                span.set_attribute("mcp.tool.response_size", len(str(result)))
            
            return result
            
        except Exception as e:
            # Log failed tool execution
            await log_tool_execution_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                server_name=server_name,
                tool_name=tool_name,
                args=args,
                success=False,
                execution_time=time.time() - execution_start,
                error_message=str(e)
            )
            
            # Log security alert for suspicious failures
            await log_security_event(
                event_type="tool_execution_failure",
                severity="warning",
                description=f"Tool execution failed: {server_name}.{tool_name}",
                gateway_id=gateway_id,
                user_id=user_id,
                additional_data={"error": str(e), "tool_name": tool_name}
            )
            
            # Add error attributes to span
            if span:
                span.set_attribute("mcp.tool.success", False)
                span.set_attribute("mcp.tool.error", str(e))
            
            raise


async def enhanced_guardrail_check_with_telemetry(
    content: str,
    direction: str,
    server_name: str,
    tool_name: str,
    gateway_id: str,
    user_id: str = None
) -> Dict[str, Any]:
    """
    Enhanced guardrail check with comprehensive telemetry and audit logging (async).
    
    This function demonstrates how to integrate tracing and audit logging
    into guardrail checks with proper violation handling.
    """
    
    # Start guardrail tracing
    async with trace_guardrail_check("content_policy", "default_policy", direction) as span:
        try:
            # Add custom attributes to span
            if span:
                span.set_attribute("mcp.guardrail.content_length", len(content))
                span.set_attribute("mcp.guardrail.server_name", server_name)
                span.set_attribute("mcp.guardrail.tool_name", tool_name)
            
            # Simulate guardrail check (replace with actual guardrail logic)
            await asyncio.sleep(0.05)  # Simulate async work
            
            # Mock violation detection (for demonstration)
            has_violation = "sensitive" in content.lower()
            
            if has_violation:
                violation_details = {
                    "violation_reason": "Sensitive content detected",
                    "content_snippet": content[:100] + "..." if len(content) > 100 else content,
                    "detection_method": "keyword_matching"
                }
                
                # Record guardrail violation in telemetry
                await record_guardrail_violation(
                    violation_type="content_policy",
                    policy_name="default_policy",
                    direction=direction,
                    server_name=server_name,
                    tool_name=tool_name,
                    gateway_id=gateway_id,
                    user_id=user_id,
                    violation_details=violation_details
                )
                
                # Log detailed audit event for compliance
                await log_guardrail_violation_event(
                    gateway_id=gateway_id,
                    user_id=user_id or "unknown",
                    server_name=server_name,
                    tool_name=tool_name,
                    violation_type="content_policy",
                    policy_name="default_policy",
                    direction=direction,
                    violation_details=violation_details,
                    blocked=True
                )
                
                # Log security alert for high-risk violations
                await log_security_alert_event(
                    gateway_id=gateway_id,
                    user_id=user_id or "unknown",
                    alert_type="guardrail_violation",
                    description=f"High-risk content violation detected in {direction}",
                    severity="HIGH",
                    details={
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "violation_type": "content_policy"
                    }
                )
                
                # Add violation attributes to span
                if span:
                    span.set_attribute("mcp.guardrail.violation", True)
                    span.set_attribute("mcp.guardrail.violation_type", "content_policy")
                    span.set_attribute("mcp.guardrail.blocked", True)
                
                return {
                    "allowed": False,
                    "violation_type": "content_policy",
                    "reason": "Sensitive content detected",
                    "details": violation_details
                }
            
            # No violation detected
            if span:
                span.set_attribute("mcp.guardrail.violation", False)
                span.set_attribute("mcp.guardrail.allowed", True)
            
            return {
                "allowed": True,
                "reason": "Content passed all guardrail checks"
            }
            
        except Exception as e:
            # Log guardrail system failure
            await log_security_alert_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                alert_type="guardrail_system_failure",
                description=f"Guardrail system failed during {direction} check",
                severity="CRITICAL",
                details={
                    "error": str(e),
                    "server_name": server_name,
                    "tool_name": tool_name
                }
            )
            
            # Add error attributes to span
            if span:
                span.set_attribute("mcp.guardrail.system_error", True)
                span.set_attribute("mcp.guardrail.error", str(e))
            
            raise


async def enhanced_cache_operation_with_telemetry(
    operation: str,
    cache_key: str,
    server_name: str = None,
    data: Any = None
) -> Dict[str, Any]:
    """
    Enhanced cache operation with comprehensive telemetry (async).
    
    This function demonstrates how to integrate tracing and metrics
    into cache operations with proper performance monitoring.
    """
    
    # Start cache operation tracing
    async with trace_cache_operation(operation, cache_key) as span:
        try:
            # Add custom attributes to span
            if span:
                span.set_attribute("mcp.cache.server_name", server_name or "unknown")
                span.set_attribute("mcp.cache.data_size", len(str(data)) if data else 0)
            
            # Simulate cache operation (replace with actual cache logic)
            await asyncio.sleep(0.01)  # Simulate async work
            
            if operation == "get":
                # Mock cache hit/miss
                cache_hit = cache_key in ["cached_key_1", "cached_key_2"]
                
                if cache_hit:
                    record_cache_hit("tool_cache", server_name)
                    result = {"status": "hit", "data": f"cached_data_for_{cache_key}"}
                    
                    if span:
                        span.set_attribute("mcp.cache.hit", True)
                else:
                    record_cache_miss("tool_cache", server_name)
                    result = {"status": "miss", "data": None}
                    
                    if span:
                        span.set_attribute("mcp.cache.hit", False)
                
                return result
                
            elif operation == "set":
                # Mock cache set operation
                result = {"status": "success", "key": cache_key}
                
                if span:
                    span.set_attribute("mcp.cache.operation_success", True)
                
                return result
                
            elif operation == "delete":
                # Mock cache delete operation
                result = {"status": "success", "key": cache_key}
                
                if span:
                    span.set_attribute("mcp.cache.operation_success", True)
                
                return result
            
            else:
                raise ValueError(f"Unsupported cache operation: {operation}")
                
        except Exception as e:
            # Add error attributes to span
            if span:
                span.set_attribute("mcp.cache.operation_success", False)
                span.set_attribute("mcp.cache.error", str(e))
            
            raise


async def enhanced_authentication_with_telemetry(
    gateway_key: str,
    user_id: str = None,
    source_ip: str = None,
    user_agent: str = None
) -> Dict[str, Any]:
    """
    Enhanced authentication with comprehensive audit logging (async).
    
    This function demonstrates how to integrate audit logging
    into authentication with proper security event tracking.
    """
    
    try:
        # Simulate authentication logic (replace with actual auth logic)
        await asyncio.sleep(0.02)  # Simulate async work
        
        # Mock authentication result
        auth_success = gateway_key.startswith("valid_")
        gateway_id = gateway_key[:8] if gateway_key else "unknown"
        
        if auth_success:
            # Log successful authentication
            await log_authentication_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                success=True,
                source_ip=source_ip,
                user_agent=user_agent
            )
            
            # Log data access event for compliance
            await log_data_access_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                data_type="gateway_configuration",
                access_type="read",
                data_classification="internal",
                success=True,
                details={"authentication_method": "api_key"}
            )
            
            return {
                "status": "success",
                "gateway_id": gateway_id,
                "user_id": user_id,
                "authenticated": True
            }
        
        else:
            # Log failed authentication
            await log_authentication_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                success=False,
                source_ip=source_ip,
                user_agent=user_agent,
                failure_reason="Invalid gateway key"
            )
            
            # Log security alert for authentication failure
            await log_security_alert_event(
                gateway_id=gateway_id,
                user_id=user_id or "unknown",
                alert_type="authentication_failure",
                description="Failed authentication attempt",
                severity="MEDIUM",
                details={
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "failure_reason": "Invalid gateway key"
                }
            )
            
            return {
                "status": "error",
                "error": "Authentication failed",
                "authenticated": False
            }
            
    except Exception as e:
        # Log authentication system failure
        await log_security_alert_event(
            gateway_id="unknown",
            user_id=user_id or "unknown",
            alert_type="authentication_system_failure",
            description="Authentication system encountered an error",
            severity="CRITICAL",
            details={
                "error": str(e),
                "source_ip": source_ip,
                "user_agent": user_agent
            }
        )
        
        raise


async def comprehensive_telemetry_example():
    """
    Comprehensive example demonstrating all telemetry and audit features (async).
    
    This function shows how to use all the telemetry and audit functions
    together in a realistic scenario.
    """
    
    print("=== Comprehensive Telemetry Example (Async) ===")
    
    # Example 1: Authentication with telemetry
    print("\n1. Testing authentication with telemetry...")
    auth_result = await enhanced_authentication_with_telemetry(
        gateway_key="valid_test_key_123",
        user_id="user123",
        source_ip="192.168.1.100",
        user_agent="MCP-Client/1.0"
    )
    print(f"Auth result: {auth_result}")
    
    # Example 2: Tool execution with comprehensive telemetry
    print("\n2. Testing tool execution with telemetry...")
    tool_result = await enhanced_tool_execution_with_telemetry(
        server_name="github_server",
        tool_name="create_issue",
        args={"title": "Test issue", "body": "This is a test"},
        gateway_id="test_key",
        user_id="user123"
    )
    print(f"Tool result: {tool_result}")
    
    # Example 3: Guardrail check with violation detection
    print("\n3. Testing guardrail check with violation...")
    guardrail_result = await enhanced_guardrail_check_with_telemetry(
        content="This contains sensitive information",
        direction="request",
        server_name="github_server",
        tool_name="create_issue",
        gateway_id="test_key",
        user_id="user123"
    )
    print(f"Guardrail result: {guardrail_result}")
    
    # Example 4: Cache operations with telemetry
    print("\n4. Testing cache operations with telemetry...")
    
    # Cache miss
    cache_result1 = await enhanced_cache_operation_with_telemetry(
        operation="get",
        cache_key="non_existent_key",
        server_name="github_server"
    )
    print(f"Cache miss result: {cache_result1}")
    
    # Cache hit
    cache_result2 = await enhanced_cache_operation_with_telemetry(
        operation="get",
        cache_key="cached_key_1",
        server_name="github_server"
    )
    print(f"Cache hit result: {cache_result2}")
    
    # Cache set
    cache_result3 = await enhanced_cache_operation_with_telemetry(
        operation="set",
        cache_key="new_key",
        server_name="github_server",
        data={"some": "data"}
    )
    print(f"Cache set result: {cache_result3}")
    
    print("\n=== Telemetry Example Complete ===")
    print("Check your telemetry backend (Jaeger, Prometheus) for traces and metrics!")
    print("Check your audit logs for compliance and security events!")


# Example usage
if __name__ == "__main__":
    # Run the comprehensive example
    asyncio.run(comprehensive_telemetry_example()) 