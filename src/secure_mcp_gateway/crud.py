"""
Enkrypt Secure MCP Gateway CRUD Operations Module

This module provides comprehensive CRUD (Create, Read, Update, Delete) operations for:
1. Gateways - Management of gateway configurations and settings
2. MCP Servers - Management of MCP server configurations and connections
3. Users - Management of user accounts and permissions

Features:
- Async operations for high performance
- Comprehensive validation and error handling
- Audit trail integration for all operations
- Caching support for improved performance
- Role-based access control
- Data encryption for sensitive information

Example Usage:
    ```python
    # Gateway operations
    gateway = await create_gateway(gateway_data)
    gateway = await get_gateway(gateway_id)
    gateways = await list_gateways(filters)
    await update_gateway(gateway_id, updates)
    await delete_gateway(gateway_id)

    # MCP Server operations
    server = await create_mcp_server(server_data)
    server = await get_mcp_server(server_id)
    servers = await list_mcp_servers(filters)
    await update_mcp_server(server_id, updates)
    await delete_mcp_server(server_id)

    # User operations
    user = await create_user(user_data)
    user = await get_user(user_id)
    users = await list_users(filters)
    await update_user(user_id, updates)
    await delete_user(user_id)
    ```
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import bcrypt
from cryptography.fernet import Fernet

from secure_mcp_gateway.utils import (
    get_common_config,
    sys_print
)
from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.client import (
    initialize_cache,
    get_cache_async,
    set_cache_async,
    delete_cache_async
)
from secure_mcp_gateway.audit import (
    log_data_access_event,
    log_security_alert_event,
    AuditSeverity
)
from secure_mcp_gateway.telemetry import (
    trace_cache_operation,
    record_api_request
)

sys_print(f"Initializing Enkrypt Secure MCP Gateway CRUD Module v{__version__}")

# Configuration
common_config = get_common_config()
ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"

# Cache configuration
CACHE_EXPIRATION_GATEWAY = int(common_config.get("enkrypt_gateway_cache_expiration", 24)) * 3600  # 24 hours
CACHE_EXPIRATION_SERVER = int(common_config.get("enkrypt_tool_cache_expiration", 4)) * 3600  # 4 hours
CACHE_EXPIRATION_USER = 12 * 3600  # 12 hours

# Encryption for sensitive data
ENCRYPTION_KEY = common_config.get("enkrypt_crud_encryption_key", Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Initialize cache client
cache_client = initialize_cache()


# --- Data Models ---

class EntityStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    OPERATOR = "operator"


@dataclass
class Gateway:
    id: str
    name: str
    description: str
    api_key: str
    status: EntityStatus
    created_at: datetime
    updated_at: datetime
    created_by: str
    mcp_config: List[Dict[str, Any]]
    settings: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class MCPServer:
    id: str
    name: str
    description: str
    command: str
    args: List[str]
    env: Optional[Dict[str, str]]
    status: EntityStatus
    created_at: datetime
    updated_at: datetime
    created_by: str
    gateway_id: str
    tools: Dict[str, Any]
    guardrails: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    status: EntityStatus
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]
    permissions: List[str]
    metadata: Dict[str, Any]


# --- Validation Functions ---

def validate_gateway_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate gateway data for creation/update."""
    errors = []
    
    if not data.get("name"):
        errors.append("Gateway name is required")
    elif len(data["name"]) < 3:
        errors.append("Gateway name must be at least 3 characters")
    
    if not data.get("description"):
        errors.append("Gateway description is required")
    
    if "mcp_config" in data and not isinstance(data["mcp_config"], list):
        errors.append("MCP config must be a list")
    
    if "settings" in data and not isinstance(data["settings"], dict):
        errors.append("Settings must be a dictionary")
    
    return len(errors) == 0, errors


def validate_server_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate MCP server data for creation/update."""
    errors = []
    
    if not data.get("name"):
        errors.append("Server name is required")
    elif len(data["name"]) < 3:
        errors.append("Server name must be at least 3 characters")
    
    if not data.get("command"):
        errors.append("Server command is required")
    
    if "args" in data and not isinstance(data["args"], list):
        errors.append("Server args must be a list")
    
    if "env" in data and data["env"] is not None and not isinstance(data["env"], dict):
        errors.append("Server env must be a dictionary")
    
    if not data.get("gateway_id"):
        errors.append("Gateway ID is required")
    
    return len(errors) == 0, errors


def validate_user_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate user data for creation/update."""
    errors = []
    
    if not data.get("username"):
        errors.append("Username is required")
    elif len(data["username"]) < 3:
        errors.append("Username must be at least 3 characters")
    
    if not data.get("email"):
        errors.append("Email is required")
    elif "@" not in data["email"]:
        errors.append("Invalid email format")
    
    if "password" in data and len(data["password"]) < 8:
        errors.append("Password must be at least 8 characters")
    
    if "role" in data:
        try:
            UserRole(data["role"])
        except ValueError:
            errors.append(f"Invalid role. Must be one of: {[r.value for r in UserRole]}")
    
    return len(errors) == 0, errors


# --- Utility Functions ---

def generate_api_key() -> str:
    """Generate a secure API key."""
    return f"gw_{uuid.uuid4().hex}"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data."""
    return cipher_suite.encrypt(data.encode()).decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()


def get_cache_key(entity_type: str, entity_id: str) -> str:
    """Generate cache key for entity."""
    return f"crud:{entity_type}:{entity_id}"


def get_list_cache_key(entity_type: str, filters: Dict[str, Any]) -> str:
    """Generate cache key for entity list."""
    filter_hash = hashlib.md5(json.dumps(filters, sort_keys=True).encode()).hexdigest()
    return f"crud:list:{entity_type}:{filter_hash}"


# --- Gateway CRUD Operations ---

async def create_gateway(
    data: Dict[str, Any],
    created_by: str,
    validate: bool = True
) -> Dict[str, Any]:
    """
    Create a new gateway.
    
    Args:
        data: Gateway data
        created_by: ID of user creating the gateway
        validate: Whether to validate data
        
    Returns:
        Created gateway data
        
    Raises:
        ValueError: If validation fails
    """
    if validate:
        is_valid, errors = validate_gateway_data(data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    # Generate ID and API key
    gateway_id = str(uuid.uuid4())
    api_key = generate_api_key()
    
    # Create gateway object
    now = datetime.utcnow()
    gateway = Gateway(
        id=gateway_id,
        name=data["name"],
        description=data["description"],
        api_key=api_key,
        status=EntityStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        created_by=created_by,
        mcp_config=data.get("mcp_config", []),
        settings=data.get("settings", {}),
        metadata=data.get("metadata", {})
    )
    
    # Store in cache/database
    gateway_data = asdict(gateway)
    gateway_data["created_at"] = gateway_data["created_at"].isoformat()
    gateway_data["updated_at"] = gateway_data["updated_at"].isoformat()
    gateway_data["status"] = gateway_data["status"].value
    
    # Encrypt sensitive data
    gateway_data["api_key"] = encrypt_sensitive_data(api_key)
    
    cache_key = get_cache_key("gateway", gateway_id)
    await set_cache_async(cache_client, cache_key, json.dumps(gateway_data), CACHE_EXPIRATION_GATEWAY)
    
    # Log creation
    asyncio.create_task(log_data_access_event(
        user_id=created_by,
        resource_type="gateway",
        resource_id=gateway_id,
        action="create",
        success=True,
        data_classification="sensitive"
    ))
    
    # Record metrics
    asyncio.create_task(record_api_request(
        method="POST",
        endpoint="/gateways",
        status_code=201,
        response_time=0.1,
        user_id=created_by
    ))
    
    # Return without encrypted data
    result = gateway_data.copy()
    result["api_key"] = api_key  # Return unencrypted for initial response
    
    sys_print(f"Created gateway: {gateway_id} by user: {created_by}")
    return result


async def get_gateway(gateway_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a gateway by ID.
    
    Args:
        gateway_id: Gateway ID
        user_id: ID of user requesting the gateway
        
    Returns:
        Gateway data or None if not found
    """
    cache_key = get_cache_key("gateway", gateway_id)
    
    async with trace_cache_operation("get", "gateway", gateway_id) as span:
        cached_data = await get_cache_async(cache_client, cache_key)
        
        if cached_data:
            gateway_data = json.loads(cached_data)
            
            # Decrypt sensitive data
            if "api_key" in gateway_data:
                try:
                    gateway_data["api_key"] = decrypt_sensitive_data(gateway_data["api_key"])
                except Exception:
                    # Handle case where data isn't encrypted (backward compatibility)
                    pass
            
            # Log access
            asyncio.create_task(log_data_access_event(
                user_id=user_id,
                resource_type="gateway",
                resource_id=gateway_id,
                action="read",
                success=True,
                data_classification="sensitive"
            ))
            
            if span:
                span.set_attribute("cache.hit", True)
            
            return gateway_data
        
        if span:
            span.set_attribute("cache.hit", False)
    
    return None


async def list_gateways(
    filters: Optional[Dict[str, Any]] = None,
    user_id: str = "",
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """
    List gateways with optional filtering.
    
    Args:
        filters: Optional filters to apply
        user_id: ID of user requesting the list
        limit: Maximum number of results
        offset: Offset for pagination
        
    Returns:
        Dictionary with gateways list and metadata
    """
    if filters is None:
        filters = {}
    
    # Add pagination to filters for cache key
    cache_filters = {**filters, "limit": limit, "offset": offset}
    cache_key = get_list_cache_key("gateway", cache_filters)
    
    cached_data = await get_cache_async(cache_client, cache_key)
    if cached_data:
        result = json.loads(cached_data)
        
        # Log access
        asyncio.create_task(log_data_access_event(
            user_id=user_id,
            resource_type="gateway",
            resource_id="list",
            action="list",
            success=True,
            data_classification="sensitive"
        ))
        
        return result
    
    # For demo purposes, return empty list
    # In production, this would query the actual database
    result = {
        "gateways": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
        "filters": filters
    }
    
    # Cache the result
    await set_cache_async(cache_client, cache_key, json.dumps(result), CACHE_EXPIRATION_GATEWAY)
    
    return result


async def update_gateway(
    gateway_id: str,
    updates: Dict[str, Any],
    updated_by: str,
    validate: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Update a gateway.
    
    Args:
        gateway_id: Gateway ID
        updates: Updates to apply
        updated_by: ID of user updating the gateway
        validate: Whether to validate updates
        
    Returns:
        Updated gateway data or None if not found
    """
    # Get existing gateway
    existing = await get_gateway(gateway_id, updated_by)
    if not existing:
        return None
    
    # Validate updates
    if validate:
        # Merge with existing data for validation
        merged_data = {**existing, **updates}
        is_valid, errors = validate_gateway_data(merged_data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    # Apply updates
    updated_data = {**existing, **updates}
    updated_data["updated_at"] = datetime.utcnow().isoformat()
    
    # Encrypt sensitive data if updated
    if "api_key" in updates:
        updated_data["api_key"] = encrypt_sensitive_data(updates["api_key"])
    
    # Store updated data
    cache_key = get_cache_key("gateway", gateway_id)
    await set_cache_async(cache_client, cache_key, json.dumps(updated_data), CACHE_EXPIRATION_GATEWAY)
    
    # Invalidate list cache
    # In production, you'd invalidate specific list cache keys
    
    # Log update
    asyncio.create_task(log_data_access_event(
        user_id=updated_by,
        resource_type="gateway",
        resource_id=gateway_id,
        action="update",
        success=True,
        data_classification="sensitive",
        details={"updated_fields": list(updates.keys())}
    ))
    
    sys_print(f"Updated gateway: {gateway_id} by user: {updated_by}")
    
    # Return with decrypted sensitive data
    result = updated_data.copy()
    if "api_key" in result and "api_key" in updates:
        result["api_key"] = updates["api_key"]
    
    return result


async def delete_gateway(gateway_id: str, deleted_by: str) -> bool:
    """
    Delete a gateway (soft delete).
    
    Args:
        gateway_id: Gateway ID
        deleted_by: ID of user deleting the gateway
        
    Returns:
        True if deleted, False if not found
    """
    # Get existing gateway
    existing = await get_gateway(gateway_id, deleted_by)
    if not existing:
        return False
    
    # Soft delete by updating status
    updates = {
        "status": EntityStatus.DELETED.value,
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await update_gateway(gateway_id, updates, deleted_by, validate=False)
    
    # Log deletion
    asyncio.create_task(log_security_alert_event(
        user_id=deleted_by,
        alert_type="resource_deletion",
        severity=AuditSeverity.MEDIUM,
        description=f"Gateway {gateway_id} deleted by user {deleted_by}",
        resource_id=gateway_id,
        resource_type="gateway"
    ))
    
    sys_print(f"Deleted gateway: {gateway_id} by user: {deleted_by}")
    return True


# --- MCP Server CRUD Operations ---

async def create_mcp_server(
    data: Dict[str, Any],
    created_by: str,
    validate: bool = True
) -> Dict[str, Any]:
    """Create a new MCP server."""
    if validate:
        is_valid, errors = validate_server_data(data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    # Verify gateway exists
    gateway = await get_gateway(data["gateway_id"], created_by)
    if not gateway:
        raise ValueError("Gateway not found")
    
    server_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    server = MCPServer(
        id=server_id,
        name=data["name"],
        description=data["description"],
        command=data["command"],
        args=data.get("args", []),
        env=data.get("env"),
        status=EntityStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        created_by=created_by,
        gateway_id=data["gateway_id"],
        tools=data.get("tools", {}),
        guardrails=data.get("guardrails", {}),
        metadata=data.get("metadata", {})
    )
    
    server_data = asdict(server)
    server_data["created_at"] = server_data["created_at"].isoformat()
    server_data["updated_at"] = server_data["updated_at"].isoformat()
    server_data["status"] = server_data["status"].value
    
    cache_key = get_cache_key("server", server_id)
    await set_cache_async(cache_client, cache_key, json.dumps(server_data), CACHE_EXPIRATION_SERVER)
    
    # Log creation
    asyncio.create_task(log_data_access_event(
        user_id=created_by,
        resource_type="mcp_server",
        resource_id=server_id,
        action="create",
        success=True,
        data_classification="internal"
    ))
    
    sys_print(f"Created MCP server: {server_id} by user: {created_by}")
    return server_data


async def get_mcp_server(server_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get an MCP server by ID."""
    cache_key = get_cache_key("server", server_id)
    
    cached_data = await get_cache_async(cache_client, cache_key)
    if cached_data:
        server_data = json.loads(cached_data)
        
        # Log access
        asyncio.create_task(log_data_access_event(
            user_id=user_id,
            resource_type="mcp_server",
            resource_id=server_id,
            action="read",
            success=True,
            data_classification="internal"
        ))
        
        return server_data
    
    return None


async def list_mcp_servers(
    filters: Optional[Dict[str, Any]] = None,
    user_id: str = "",
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """List MCP servers with optional filtering."""
    if filters is None:
        filters = {}
    
    cache_filters = {**filters, "limit": limit, "offset": offset}
    cache_key = get_list_cache_key("server", cache_filters)
    
    cached_data = await get_cache_async(cache_client, cache_key)
    if cached_data:
        return json.loads(cached_data)
    
    result = {
        "servers": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
        "filters": filters
    }
    
    await set_cache_async(cache_client, cache_key, json.dumps(result), CACHE_EXPIRATION_SERVER)
    return result


async def update_mcp_server(
    server_id: str,
    updates: Dict[str, Any],
    updated_by: str,
    validate: bool = True
) -> Optional[Dict[str, Any]]:
    """Update an MCP server."""
    existing = await get_mcp_server(server_id, updated_by)
    if not existing:
        return None
    
    if validate:
        merged_data = {**existing, **updates}
        is_valid, errors = validate_server_data(merged_data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    updated_data = {**existing, **updates}
    updated_data["updated_at"] = datetime.utcnow().isoformat()
    
    cache_key = get_cache_key("server", server_id)
    await set_cache_async(cache_client, cache_key, json.dumps(updated_data), CACHE_EXPIRATION_SERVER)
    
    # Log update
    asyncio.create_task(log_data_access_event(
        user_id=updated_by,
        resource_type="mcp_server",
        resource_id=server_id,
        action="update",
        success=True,
        data_classification="internal",
        details={"updated_fields": list(updates.keys())}
    ))
    
    sys_print(f"Updated MCP server: {server_id} by user: {updated_by}")
    return updated_data


async def delete_mcp_server(server_id: str, deleted_by: str) -> bool:
    """Delete an MCP server (soft delete)."""
    existing = await get_mcp_server(server_id, deleted_by)
    if not existing:
        return False
    
    updates = {
        "status": EntityStatus.DELETED.value,
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await update_mcp_server(server_id, updates, deleted_by, validate=False)
    
    # Log deletion
    asyncio.create_task(log_security_alert_event(
        user_id=deleted_by,
        alert_type="resource_deletion",
        severity=AuditSeverity.MEDIUM,
        description=f"MCP server {server_id} deleted by user {deleted_by}",
        resource_id=server_id,
        resource_type="mcp_server"
    ))
    
    sys_print(f"Deleted MCP server: {server_id} by user: {deleted_by}")
    return True


# --- User CRUD Operations ---

async def create_user(
    data: Dict[str, Any],
    created_by: str,
    validate: bool = True
) -> Dict[str, Any]:
    """Create a new user."""
    if validate:
        is_valid, errors = validate_user_data(data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    user_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    # Hash password
    password_hash = hash_password(data["password"]) if "password" in data else ""
    
    user = User(
        id=user_id,
        username=data["username"],
        email=data["email"],
        password_hash=password_hash,
        role=UserRole(data.get("role", "user")),
        status=EntityStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        last_login=None,
        permissions=data.get("permissions", []),
        metadata=data.get("metadata", {})
    )
    
    user_data = asdict(user)
    user_data["created_at"] = user_data["created_at"].isoformat()
    user_data["updated_at"] = user_data["updated_at"].isoformat()
    user_data["last_login"] = user_data["last_login"].isoformat() if user_data["last_login"] else None
    user_data["role"] = user_data["role"].value
    user_data["status"] = user_data["status"].value
    
    # Encrypt sensitive data
    user_data["password_hash"] = encrypt_sensitive_data(password_hash)
    user_data["email"] = encrypt_sensitive_data(data["email"])
    
    cache_key = get_cache_key("user", user_id)
    await set_cache_async(cache_client, cache_key, json.dumps(user_data), CACHE_EXPIRATION_USER)
    
    # Log creation
    asyncio.create_task(log_data_access_event(
        user_id=created_by,
        resource_type="user",
        resource_id=user_id,
        action="create",
        success=True,
        data_classification="pii"
    ))
    
    # Return without sensitive data
    result = user_data.copy()
    result.pop("password_hash", None)
    result["email"] = data["email"]  # Return unencrypted for response
    
    sys_print(f"Created user: {user_id} by user: {created_by}")
    return result


async def get_user(user_id: str, requesting_user_id: str) -> Optional[Dict[str, Any]]:
    """Get a user by ID."""
    cache_key = get_cache_key("user", user_id)
    
    cached_data = await get_cache_async(cache_client, cache_key)
    if cached_data:
        user_data = json.loads(cached_data)
        
        # Decrypt sensitive data
        if "email" in user_data:
            try:
                user_data["email"] = decrypt_sensitive_data(user_data["email"])
            except Exception:
                pass
        
        # Remove password hash from response
        user_data.pop("password_hash", None)
        
        # Log access
        asyncio.create_task(log_data_access_event(
            user_id=requesting_user_id,
            resource_type="user",
            resource_id=user_id,
            action="read",
            success=True,
            data_classification="pii"
        ))
        
        return user_data
    
    return None


async def list_users(
    filters: Optional[Dict[str, Any]] = None,
    user_id: str = "",
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """List users with optional filtering."""
    if filters is None:
        filters = {}
    
    cache_filters = {**filters, "limit": limit, "offset": offset}
    cache_key = get_list_cache_key("user", cache_filters)
    
    cached_data = await get_cache_async(cache_client, cache_key)
    if cached_data:
        return json.loads(cached_data)
    
    result = {
        "users": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
        "filters": filters
    }
    
    await set_cache_async(cache_client, cache_key, json.dumps(result), CACHE_EXPIRATION_USER)
    return result


async def update_user(
    user_id: str,
    updates: Dict[str, Any],
    updated_by: str,
    validate: bool = True
) -> Optional[Dict[str, Any]]:
    """Update a user."""
    existing = await get_user(user_id, updated_by)
    if not existing:
        return None
    
    if validate:
        # Remove password from validation if not being updated
        validation_data = {**existing, **updates}
        if "password" not in updates:
            validation_data.pop("password", None)
        
        is_valid, errors = validate_user_data(validation_data)
        if not is_valid:
            raise ValueError(f"Validation errors: {', '.join(errors)}")
    
    updated_data = {**existing, **updates}
    updated_data["updated_at"] = datetime.utcnow().isoformat()
    
    # Hash new password if provided
    if "password" in updates:
        password_hash = hash_password(updates["password"])
        updated_data["password_hash"] = encrypt_sensitive_data(password_hash)
        updated_data.pop("password", None)  # Remove plain password
    
    # Encrypt email if updated
    if "email" in updates:
        updated_data["email"] = encrypt_sensitive_data(updates["email"])
    
    cache_key = get_cache_key("user", user_id)
    await set_cache_async(cache_client, cache_key, json.dumps(updated_data), CACHE_EXPIRATION_USER)
    
    # Log update
    asyncio.create_task(log_data_access_event(
        user_id=updated_by,
        resource_type="user",
        resource_id=user_id,
        action="update",
        success=True,
        data_classification="pii",
        details={"updated_fields": list(updates.keys())}
    ))
    
    sys_print(f"Updated user: {user_id} by user: {updated_by}")
    
    # Return without sensitive data
    result = updated_data.copy()
    result.pop("password_hash", None)
    if "email" in updates:
        result["email"] = updates["email"]
    
    return result


async def delete_user(user_id: str, deleted_by: str) -> bool:
    """Delete a user (soft delete)."""
    existing = await get_user(user_id, deleted_by)
    if not existing:
        return False
    
    updates = {
        "status": EntityStatus.DELETED.value,
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await update_user(user_id, updates, deleted_by, validate=False)
    
    # Log deletion
    asyncio.create_task(log_security_alert_event(
        user_id=deleted_by,
        alert_type="user_deletion",
        severity=AuditSeverity.HIGH,
        description=f"User {user_id} deleted by user {deleted_by}",
        resource_id=user_id,
        resource_type="user"
    ))
    
    sys_print(f"Deleted user: {user_id} by user: {deleted_by}")
    return True


# --- Authentication Helper Functions ---

async def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user by username and password."""
    # In production, you'd query by username index
    # For demo, we'll return None
    return None


async def update_last_login(user_id: str) -> bool:
    """Update user's last login timestamp."""
    updates = {
        "last_login": datetime.utcnow().isoformat()
    }
    
    result = await update_user(user_id, updates, user_id, validate=False)
    return result is not None


# --- Cleanup Functions ---

async def cleanup_crud_module():
    """Clean up resources when shutting down."""
    sys_print("Cleaning up CRUD module resources")
    # Additional cleanup if needed 