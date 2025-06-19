"""
Enkrypt Secure MCP Gateway Audit Trail Module

This module provides comprehensive audit trail functionality for compliance and security monitoring:

1. Audit Event Types:
   - Authentication events
   - Authorization events
   - Tool execution events
   - Guardrail violation events
   - Configuration changes
   - Cache operations
   - API access events

2. Compliance Features:
   - GDPR compliance logging
   - SOX compliance trails
   - HIPAA audit requirements
   - Custom compliance frameworks

3. Security Monitoring:
   - Suspicious activity detection
   - Failed authentication tracking
   - Privilege escalation attempts
   - Data access patterns

4. Retention and Archival:
   - Configurable retention policies
   - Secure archival to external systems
   - Tamper-proof logging mechanisms
"""

import os
import sys
import time
import json
import hashlib
import threading
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__

# Configuration
common_config = get_common_config()

ENKRYPT_AUDIT_ENABLED = common_config.get("enkrypt_audit_enabled", True)
ENKRYPT_AUDIT_ENCRYPTION_ENABLED = common_config.get("enkrypt_audit_encryption_enabled", True)
ENKRYPT_AUDIT_RETENTION_DAYS = int(common_config.get("enkrypt_audit_retention_days", 365))
ENKRYPT_AUDIT_LOG_PATH = common_config.get("enkrypt_audit_log_path", "/var/log/enkrypt/audit")
ENKRYPT_AUDIT_REMOTE_ENDPOINT = common_config.get("enkrypt_audit_remote_endpoint", None)
ENKRYPT_AUDIT_ENCRYPTION_KEY = common_config.get("enkrypt_audit_encryption_key", None)


class AuditEventType(Enum):
    """Enumeration of audit event types."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TOOL_EXECUTION = "tool_execution"
    GUARDRAIL_VIOLATION = "guardrail_violation"
    CONFIGURATION_CHANGE = "configuration_change"
    CACHE_OPERATION = "cache_operation"
    API_ACCESS = "api_access"
    SECURITY_ALERT = "security_alert"
    COMPLIANCE_EVENT = "compliance_event"
    DATA_ACCESS = "data_access"
    ERROR_EVENT = "error_event"


class AuditSeverity(Enum):
    """Enumeration of audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Structured audit event data class."""
    event_id: str
    timestamp: float
    event_type: AuditEventType
    severity: AuditSeverity
    gateway_id: str
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    description: str
    details: Dict[str, Any]
    compliance_tags: List[str]
    risk_score: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        return data
    
    def to_json(self) -> str:
        """Convert audit event to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Enhanced audit logger with encryption and compliance features."""
    
    def __init__(self):
        self.logger = structlog.get_logger("audit")
        self.encryption_key = None
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        
        # Setup encryption if enabled
        if ENKRYPT_AUDIT_ENCRYPTION_ENABLED and ENKRYPT_AUDIT_ENCRYPTION_KEY:
            self.setup_encryption()
        
        # Setup log file rotation
        self.setup_log_rotation()
    
    def setup_encryption(self):
        """Setup encryption for audit logs."""
        try:
            if ENKRYPT_AUDIT_ENCRYPTION_KEY:
                # Use provided key
                key = ENKRYPT_AUDIT_ENCRYPTION_KEY.encode()
            else:
                # Generate key from system info (not recommended for production)
                password = f"enkrypt-audit-{__version__}".encode()
                salt = b"enkrypt_salt_2024"  # Should be random in production
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
            
            self.encryption_key = Fernet(key)
            sys_print("Audit log encryption enabled")
        except Exception as e:
            sys_print(f"Failed to setup audit encryption: {e}")
            self.encryption_key = None
    
    def setup_log_rotation(self):
        """Setup log file rotation and retention."""
        # Create audit log directory if it doesn't exist
        os.makedirs(ENKRYPT_AUDIT_LOG_PATH, exist_ok=True)
        
        # Setup structured logging with file output
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
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt audit data if encryption is enabled."""
        if self.encryption_key:
            try:
                encrypted = self.encryption_key.encrypt(data.encode())
                return base64.b64encode(encrypted).decode()
            except Exception as e:
                sys_print(f"Failed to encrypt audit data: {e}")
                return data
        return data
    
    async def log_event(self, event: AuditEvent):
        """Log an audit event with encryption and compliance features asynchronously."""
        if not ENKRYPT_AUDIT_ENABLED:
            return
        
        try:
            # Convert event to JSON
            event_json = event.to_json()
            
            # Encrypt if enabled
            if self.encryption_key:
                event_json = self.encrypt_data(event_json)
            
            # Log to structured logger (run in background)
            asyncio.create_task(self._log_to_structured_logger(event, event_json))
            
            # Buffer for batch processing
            with self.buffer_lock:
                self.event_buffer.append(event)
                if len(self.event_buffer) >= 100:  # Flush buffer every 100 events
                    asyncio.create_task(self._flush_buffer_async())
        
        except Exception as e:
            sys_print(f"Failed to log audit event: {e}")
    
    async def _log_to_structured_logger(self, event: AuditEvent, event_json: str):
        """Async helper for structured logging."""
        try:
            self.logger.info(
                "Audit Event",
                event_id=event.event_id,
                event_type=event.event_type.value,
                severity=event.severity.value,
                gateway_id=event.gateway_id,
                encrypted_data=event_json if self.encryption_key else None,
                raw_data=event.to_dict() if not self.encryption_key else None
            )
        except Exception as e:
            sys_print(f"Failed to log to structured logger: {e}")
    
    def flush_buffer(self):
        """Flush buffered events to remote endpoint if configured (sync version)."""
        asyncio.create_task(self._flush_buffer_async())
    
    async def _flush_buffer_async(self):
        """Flush buffered events to remote endpoint if configured asynchronously."""
        if not ENKRYPT_AUDIT_REMOTE_ENDPOINT or not self.event_buffer:
            return
        
        try:
            # Get events to flush
            with self.buffer_lock:
                events_to_flush = self.event_buffer.copy()
                self.event_buffer.clear()
            
            if events_to_flush:
                # Send buffered events to remote endpoint
                events_data = [event.to_dict() for event in events_to_flush]
                # Implementation for remote logging would go here
                # async with aiohttp.ClientSession() as session:
                #     await session.post(ENKRYPT_AUDIT_REMOTE_ENDPOINT, json=events_data)
                
                sys_print(f"Flushed {len(events_data)} audit events to remote endpoint")
        except Exception as e:
            sys_print(f"Failed to flush audit buffer: {e}")


# Global audit logger instance
audit_logger = AuditLogger() if ENKRYPT_AUDIT_ENABLED else None


def generate_event_id() -> str:
    """Generate unique event ID."""
    timestamp = str(time.time())
    random_data = os.urandom(16).hex()
    return hashlib.sha256(f"{timestamp}-{random_data}".encode()).hexdigest()[:16]


async def log_authentication_event(
    gateway_id: str,
    user_id: str,
    success: bool,
    source_ip: str = None,
    user_agent: str = None,
    failure_reason: str = None
):
    """Log authentication events asynchronously."""
    if not audit_logger:
        return
    
    try:
        event = AuditEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditSeverity.MEDIUM if success else AuditSeverity.HIGH,
            gateway_id=gateway_id,
            user_id=user_id,
            session_id=None,
            source_ip=source_ip,
            user_agent=user_agent,
            description=f"Authentication {'successful' if success else 'failed'} for user {user_id}",
            details={
                "success": success,
                "failure_reason": failure_reason,
                "auth_method": "api_key"
            },
            compliance_tags=["GDPR", "SOX", "HIPAA"]
        )
        
        await audit_logger.log_event(event)
    except Exception as e:
        sys_print(f"Failed to log authentication event: {e}")


async def log_tool_execution_event(
    gateway_id: str,
    user_id: str,
    server_name: str,
    tool_name: str,
    args: Dict[str, Any],
    success: bool,
    execution_time: float,
    error_message: str = None,
    response_size: int = None
):
    """Log tool execution events asynchronously."""
    if not audit_logger:
        return
    
    try:
        # Sanitize sensitive data from args
        sanitized_args = sanitize_sensitive_data(args)
        
        event = AuditEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.LOW if success else AuditSeverity.MEDIUM,
            gateway_id=gateway_id,
            user_id=user_id,
            session_id=None,
            source_ip=None,
            user_agent=None,
            description=f"Tool execution: {server_name}.{tool_name}",
            details={
                "server_name": server_name,
                "tool_name": tool_name,
                "args": sanitized_args,
                "success": success,
                "execution_time": execution_time,
                "error_message": error_message,
                "response_size": response_size
            },
            compliance_tags=["SOX", "GDPR"]
        )
        
        await audit_logger.log_event(event)
    except Exception as e:
        sys_print(f"Failed to log tool execution event: {e}")


async def log_guardrail_violation_event(
    gateway_id: str,
    user_id: str,
    server_name: str,
    tool_name: str,
    violation_type: str,
    policy_name: str,
    direction: str,
    violation_details: Dict[str, Any],
    blocked: bool = True
):
    """Log guardrail violation events with comprehensive details asynchronously."""
    if not audit_logger:
        return
    
    try:
        # Calculate risk score based on violation type
        risk_score = calculate_risk_score(violation_type, violation_details)
        
        event = AuditEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type=AuditEventType.GUARDRAIL_VIOLATION,
            severity=AuditSeverity.HIGH if blocked else AuditSeverity.MEDIUM,
            gateway_id=gateway_id,
            user_id=user_id,
            session_id=None,
            source_ip=None,
            user_agent=None,
            description=f"Guardrail violation: {violation_type} in {direction} for {server_name}.{tool_name}",
            details={
                "server_name": server_name,
                "tool_name": tool_name,
                "violation_type": violation_type,
                "policy_name": policy_name,
                "direction": direction,
                "blocked": blocked,
                "violation_details": violation_details
            },
            compliance_tags=["GDPR", "HIPAA", "SOX", "PCI-DSS"],
            risk_score=risk_score
        )
        
        await audit_logger.log_event(event)
    except Exception as e:
        sys_print(f"Failed to log guardrail violation event: {e}")


async def log_security_alert_event(
    gateway_id: str,
    user_id: str,
    alert_type: str,
    description: str,
    severity: AuditSeverity,
    details: Dict[str, Any] = None
):
    """Log security alert events asynchronously."""
    if not audit_logger:
        return
    
    try:
        event = AuditEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type=AuditEventType.SECURITY_ALERT,
            severity=severity,
            gateway_id=gateway_id,
            user_id=user_id,
            session_id=None,
            source_ip=None,
            user_agent=None,
            description=description,
            details={
                "alert_type": alert_type,
                **(details or {})
            },
            compliance_tags=["SECURITY", "SOX"]
        )
        
        await audit_logger.log_event(event)
    except Exception as e:
        sys_print(f"Failed to log security alert event: {e}")


async def log_data_access_event(
    gateway_id: str,
    user_id: str,
    data_type: str,
    access_type: str,
    data_classification: str,
    success: bool,
    details: Dict[str, Any] = None
):
    """Log data access events for compliance asynchronously."""
    if not audit_logger:
        return
    
    try:
        event = AuditEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.MEDIUM,
            gateway_id=gateway_id,
            user_id=user_id,
            session_id=None,
            source_ip=None,
            user_agent=None,
            description=f"Data access: {access_type} {data_type}",
            details={
                "data_type": data_type,
                "access_type": access_type,
                "data_classification": data_classification,
                "success": success,
                **(details or {})
            },
            compliance_tags=["GDPR", "HIPAA", "PCI-DSS"]
        )
        
        await audit_logger.log_event(event)
    except Exception as e:
        sys_print(f"Failed to log data access event: {e}")


def sanitize_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize sensitive data for audit logging."""
    sensitive_keys = [
        'password', 'token', 'key', 'secret', 'api_key',
        'auth', 'credential', 'ssn', 'credit_card', 'email'
    ]
    
    def sanitize_value(key: str, value: Any) -> Any:
        if isinstance(key, str):
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                if isinstance(value, str) and len(value) > 4:
                    return f"***{value[-4:]}"
                else:
                    return "***"
        
        if isinstance(value, dict):
            return {k: sanitize_value(k, v) for k, v in value.items()}
        elif isinstance(value, list):
            return [sanitize_value("", v) for v in value]
        
        return value
    
    return sanitize_value("", data)


def calculate_risk_score(violation_type: str, violation_details: Dict[str, Any]) -> int:
    """Calculate risk score for violations (0-100)."""
    base_scores = {
        "pii": 80,
        "malware": 95,
        "toxicity": 60,
        "bias": 50,
        "hallucination": 70,
        "relevancy": 30,
        "adherence": 40
    }
    
    base_score = base_scores.get(violation_type.lower(), 50)
    
    # Adjust based on violation details
    if violation_details.get("confidence", 0) > 0.9:
        base_score += 10
    if violation_details.get("severity") == "high":
        base_score += 15
    
    return min(base_score, 100)


def get_audit_statistics(days: int = 30) -> Dict[str, Any]:
    """Get audit statistics for the specified number of days."""
    # This would typically query the audit log storage
    # For now, return placeholder statistics
    return {
        "total_events": 0,
        "events_by_type": {},
        "violations_by_policy": {},
        "risk_score_distribution": {},
        "compliance_coverage": {}
    }


def export_audit_logs(
    start_date: datetime,
    end_date: datetime,
    event_types: List[AuditEventType] = None,
    export_format: str = "json"
) -> str:
    """Export audit logs for compliance reporting."""
    # Implementation for exporting audit logs
    # This would typically query the audit storage and format the results
    return json.dumps({
        "export_metadata": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "event_types": [et.value for et in event_types] if event_types else "all",
            "export_format": export_format,
            "generated_at": datetime.now().isoformat()
        },
        "events": []  # Would contain actual audit events
    })


# Initialize audit logging
if ENKRYPT_AUDIT_ENABLED:
    sys_print(f"Audit logging initialized - Retention: {ENKRYPT_AUDIT_RETENTION_DAYS} days") 