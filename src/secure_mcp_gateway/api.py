"""
Enkrypt Secure MCP Gateway REST API Module

This module provides a comprehensive REST API for managing gateways, MCP servers, and users.
Built with FastAPI for high performance and automatic OpenAPI documentation.

Features:
- RESTful endpoints for all CRUD operations
- JWT-based authentication and authorization
- Request validation with Pydantic models
- Comprehensive error handling
- Rate limiting and security headers
- Audit trail integration
- OpenAPI/Swagger documentation
- Health checks and monitoring endpoints

API Endpoints:
    # Gateway Management
    POST   /api/v1/gateways              - Create gateway
    GET    /api/v1/gateways              - List gateways
    GET    /api/v1/gateways/{id}         - Get gateway
    PUT    /api/v1/gateways/{id}         - Update gateway
    DELETE /api/v1/gateways/{id}         - Delete gateway
    
    # MCP Server Management
    POST   /api/v1/servers               - Create MCP server
    GET    /api/v1/servers               - List MCP servers
    GET    /api/v1/servers/{id}          - Get MCP server
    PUT    /api/v1/servers/{id}          - Update MCP server
    DELETE /api/v1/servers/{id}          - Delete MCP server
    
    # User Management
    POST   /api/v1/users                 - Create user
    GET    /api/v1/users                 - List users
    GET    /api/v1/users/{id}            - Get user
    PUT    /api/v1/users/{id}            - Update user
    DELETE /api/v1/users/{id}            - Delete user
    
    # Authentication
    POST   /api/v1/auth/login            - User login
    POST   /api/v1/auth/logout           - User logout
    POST   /api/v1/auth/refresh          - Refresh token
    
    # Health & Monitoring
    GET    /api/v1/health                - Health check
    GET    /api/v1/metrics               - System metrics
    GET    /docs                         - API documentation

Example Usage:
    ```bash
    # Start the API server
    python -m secure_mcp_gateway.api --host 0.0.0.0 --port 8000
    
    # Create a gateway
    curl -X POST "http://localhost:8000/api/v1/gateways" \
         -H "Authorization: Bearer <token>" \
         -H "Content-Type: application/json" \
         -d '{"name": "My Gateway", "description": "Test gateway"}'
    
    # List gateways
    curl -X GET "http://localhost:8000/api/v1/gateways" \
         -H "Authorization: Bearer <token>"
    ```
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, HTTPException, Depends, Security, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import uvicorn

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.crud import (
    create_gateway, get_gateway, list_gateways, update_gateway, delete_gateway,
    create_mcp_server, get_mcp_server, list_mcp_servers, update_mcp_server, delete_mcp_server,
    create_user, get_user, list_users, update_user, delete_user,
    authenticate_user, update_last_login, EntityStatus, UserRole
)
from secure_mcp_gateway.audit import log_authentication_event, log_security_alert_event, AuditSeverity
from secure_mcp_gateway.telemetry import record_api_request, trace_tool_call

# Configuration
common_config = get_common_config()
JWT_SECRET_KEY = common_config.get("enkrypt_jwt_secret", "your-secret-key-change-this")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(common_config.get("enkrypt_jwt_expiration_hours", 24))

# Security
security = HTTPBearer()

# Rate limiting (simple in-memory implementation)
request_counts = {}
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 3600  # 1 hour

sys_print(f"Initializing Enkrypt Secure MCP Gateway API v{__version__}")


# --- Pydantic Models ---

class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SuccessResponse(BaseModel):
    """Standard success response model."""
    success: bool = True
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PaginatedResponse(BaseModel):
    """Paginated response model."""
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    has_next: bool
    has_prev: bool


# Gateway Models
class GatewayCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    mcp_config: Optional[List[Dict[str, Any]]] = []
    settings: Optional[Dict[str, Any]] = {}
    metadata: Optional[Dict[str, Any]] = {}


class GatewayUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    mcp_config: Optional[List[Dict[str, Any]]] = None
    settings: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


# MCP Server Models
class MCPServerCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    command: str = Field(..., min_length=1)
    args: Optional[List[str]] = []
    env: Optional[Dict[str, str]] = None
    gateway_id: str = Field(..., min_length=1)
    tools: Optional[Dict[str, Any]] = {}
    guardrails: Optional[Dict[str, Any]] = {}
    metadata: Optional[Dict[str, Any]] = {}


class MCPServerUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    command: Optional[str] = Field(None, min_length=1)
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    tools: Optional[Dict[str, Any]] = None
    guardrails: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


# User Models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: str = Field(..., min_length=8)
    role: Optional[str] = "user"
    permissions: Optional[List[str]] = []
    metadata: Optional[Dict[str, Any]] = {}
    
    @validator('role')
    def validate_role(cls, v):
        if v not in [role.value for role in UserRole]:
            raise ValueError(f'Invalid role. Must be one of: {[r.value for r in UserRole]}')
        return v


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[str] = Field(None, regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: Optional[str] = Field(None, min_length=8)
    role: Optional[str] = None
    permissions: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('role')
    def validate_role(cls, v):
        if v is not None and v not in [role.value for role in UserRole]:
            raise ValueError(f'Invalid role. Must be one of: {[r.value for r in UserRole]}')
        return v


# Authentication Models
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    uptime: float
    components: Dict[str, str]


# --- Authentication & Authorization ---

def create_access_token(data: dict) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """Get current authenticated user."""
    payload = verify_token(credentials.credentials)
    user_id = payload.get("user_id")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    user = await get_user(user_id, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if user.get("status") != EntityStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is not active"
        )
    
    return user


async def require_role(required_role: UserRole):
    """Dependency to require specific user role."""
    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role = UserRole(current_user.get("role", "user"))
        
        # Admin can access everything
        if user_role == UserRole.ADMIN:
            return current_user
        
        # Check specific role requirement
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role.value}"
            )
        
        return current_user
    
    return role_checker


# --- Rate Limiting ---

async def rate_limit_check(request: Request):
    """Simple rate limiting middleware."""
    client_ip = request.client.host
    current_time = time.time()
    
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    
    # Clean old requests
    request_counts[client_ip] = [
        req_time for req_time in request_counts[client_ip]
        if current_time - req_time < RATE_LIMIT_WINDOW
    ]
    
    # Check rate limit
    if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    # Add current request
    request_counts[client_ip].append(current_time)


# --- FastAPI App Setup ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    sys_print("Starting Enkrypt Secure MCP Gateway API")
    yield
    sys_print("Shutting down Enkrypt Secure MCP Gateway API")


app = FastAPI(
    title="Enkrypt Secure MCP Gateway API",
    description="Comprehensive REST API for managing MCP gateways, servers, and users",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

# Global exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    asyncio.create_task(record_api_request(
        method=request.method,
        endpoint=str(request.url.path),
        status_code=exc.status_code,
        response_time=0.0,
        user_id=getattr(request.state, 'user_id', 'anonymous')
    ))
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.__class__.__name__,
            message=exc.detail
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    sys_print(f"Unhandled exception: {exc}")
    
    asyncio.create_task(log_security_alert_event(
        user_id=getattr(request.state, 'user_id', 'system'),
        alert_type="api_error",
        severity=AuditSeverity.HIGH,
        description=f"Unhandled API exception: {str(exc)}",
        metadata={"endpoint": str(request.url.path), "method": request.method}
    ))
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="InternalServerError",
            message="An internal server error occurred"
        ).dict()
    )


# --- Authentication Endpoints ---

@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: Request, login_data: LoginRequest):
    """Authenticate user and return access token."""
    start_time = time.time()
    
    try:
        # Authenticate user
        user = await authenticate_user(login_data.username, login_data.password)
        
        if not user:
            # Log failed login
            asyncio.create_task(log_authentication_event(
                user_id=login_data.username,
                action="login",
                success=False,
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent", ""),
                failure_reason="Invalid credentials"
            ))
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Update last login
        await update_last_login(user["id"])
        
        # Create access token
        token_data = {"user_id": user["id"], "username": user["username"]}
        access_token = create_access_token(token_data)
        
        # Log successful login
        asyncio.create_task(log_authentication_event(
            user_id=user["id"],
            action="login",
            success=True,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", "")
        ))
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="POST",
            endpoint="/api/v1/auth/login",
            status_code=200,
            response_time=response_time,
            user_id=user["id"]
        ))
        
        return LoginResponse(
            access_token=access_token,
            expires_in=JWT_EXPIRATION_HOURS * 3600,
            user=user
        )
        
    except HTTPException:
        raise
    except Exception as e:
        sys_print(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@app.post("/api/v1/auth/logout")
async def logout(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Logout user (token invalidation would be handled by client)."""
    asyncio.create_task(log_authentication_event(
        user_id=current_user["id"],
        action="logout",
        success=True,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "")
    ))
    
    return SuccessResponse(message="Logged out successfully")


# --- Gateway Management Endpoints ---

@app.post("/api/v1/gateways", response_model=SuccessResponse, status_code=status.HTTP_201_CREATED)
async def create_gateway_endpoint(
    request: Request,
    gateway_data: GatewayCreate,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """Create a new gateway."""
    start_time = time.time()
    
    try:
        async with trace_tool_call("create_gateway", {"name": gateway_data.name}) as span:
            gateway = await create_gateway(
                data=gateway_data.dict(),
                created_by=current_user["id"]
            )
            
            if span:
                span.set_attribute("gateway.id", gateway["id"])
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="POST",
            endpoint="/api/v1/gateways",
            status_code=201,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="Gateway created successfully",
            data=gateway
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.get("/api/v1/gateways", response_model=PaginatedResponse)
async def list_gateways_endpoint(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List gateways with optional filtering."""
    start_time = time.time()
    
    filters = {}
    if status_filter:
        filters["status"] = status_filter
    
    result = await list_gateways(
        filters=filters,
        user_id=current_user["id"],
        limit=limit,
        offset=offset
    )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint="/api/v1/gateways",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return PaginatedResponse(
        items=result["gateways"],
        total=result["total"],
        limit=limit,
        offset=offset,
        has_next=offset + limit < result["total"],
        has_prev=offset > 0
    )


@app.get("/api/v1/gateways/{gateway_id}", response_model=SuccessResponse)
async def get_gateway_endpoint(
    request: Request,
    gateway_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a gateway by ID."""
    start_time = time.time()
    
    gateway = await get_gateway(gateway_id, current_user["id"])
    
    if not gateway:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint=f"/api/v1/gateways/{gateway_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(
        message="Gateway retrieved successfully",
        data=gateway
    )


@app.put("/api/v1/gateways/{gateway_id}", response_model=SuccessResponse)
async def update_gateway_endpoint(
    request: Request,
    gateway_id: str,
    gateway_data: GatewayUpdate,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """Update a gateway."""
    start_time = time.time()
    
    try:
        # Only include non-None values
        updates = {k: v for k, v in gateway_data.dict().items() if v is not None}
        
        gateway = await update_gateway(
            gateway_id=gateway_id,
            updates=updates,
            updated_by=current_user["id"]
        )
        
        if not gateway:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Gateway not found"
            )
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="PUT",
            endpoint=f"/api/v1/gateways/{gateway_id}",
            status_code=200,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="Gateway updated successfully",
            data=gateway
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.delete("/api/v1/gateways/{gateway_id}", response_model=SuccessResponse)
async def delete_gateway_endpoint(
    request: Request,
    gateway_id: str,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """Delete a gateway."""
    start_time = time.time()
    
    success = await delete_gateway(gateway_id, current_user["id"])
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Gateway not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="DELETE",
        endpoint=f"/api/v1/gateways/{gateway_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(message="Gateway deleted successfully")


# --- MCP Server Management Endpoints ---

@app.post("/api/v1/servers", response_model=SuccessResponse, status_code=status.HTTP_201_CREATED)
async def create_server_endpoint(
    request: Request,
    server_data: MCPServerCreate,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.OPERATOR))
):
    """Create a new MCP server."""
    start_time = time.time()
    
    try:
        server = await create_mcp_server(
            data=server_data.dict(),
            created_by=current_user["id"]
        )
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="POST",
            endpoint="/api/v1/servers",
            status_code=201,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="MCP server created successfully",
            data=server
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.get("/api/v1/servers", response_model=PaginatedResponse)
async def list_servers_endpoint(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    gateway_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List MCP servers with optional filtering."""
    start_time = time.time()
    
    filters = {}
    if gateway_id:
        filters["gateway_id"] = gateway_id
    if status_filter:
        filters["status"] = status_filter
    
    result = await list_mcp_servers(
        filters=filters,
        user_id=current_user["id"],
        limit=limit,
        offset=offset
    )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint="/api/v1/servers",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return PaginatedResponse(
        items=result["servers"],
        total=result["total"],
        limit=limit,
        offset=offset,
        has_next=offset + limit < result["total"],
        has_prev=offset > 0
    )


@app.get("/api/v1/servers/{server_id}", response_model=SuccessResponse)
async def get_server_endpoint(
    request: Request,
    server_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get an MCP server by ID."""
    start_time = time.time()
    
    server = await get_mcp_server(server_id, current_user["id"])
    
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="MCP server not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint=f"/api/v1/servers/{server_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(
        message="MCP server retrieved successfully",
        data=server
    )


@app.put("/api/v1/servers/{server_id}", response_model=SuccessResponse)
async def update_server_endpoint(
    request: Request,
    server_id: str,
    server_data: MCPServerUpdate,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.OPERATOR))
):
    """Update an MCP server."""
    start_time = time.time()
    
    try:
        updates = {k: v for k, v in server_data.dict().items() if v is not None}
        
        server = await update_mcp_server(
            server_id=server_id,
            updates=updates,
            updated_by=current_user["id"]
        )
        
        if not server:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="MCP server not found"
            )
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="PUT",
            endpoint=f"/api/v1/servers/{server_id}",
            status_code=200,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="MCP server updated successfully",
            data=server
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.delete("/api/v1/servers/{server_id}", response_model=SuccessResponse)
async def delete_server_endpoint(
    request: Request,
    server_id: str,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.OPERATOR))
):
    """Delete an MCP server."""
    start_time = time.time()
    
    success = await delete_mcp_server(server_id, current_user["id"])
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="MCP server not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="DELETE",
        endpoint=f"/api/v1/servers/{server_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(message="MCP server deleted successfully")


# --- User Management Endpoints ---

@app.post("/api/v1/users", response_model=SuccessResponse, status_code=status.HTTP_201_CREATED)
async def create_user_endpoint(
    request: Request,
    user_data: UserCreate,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """Create a new user."""
    start_time = time.time()
    
    try:
        user = await create_user(
            data=user_data.dict(),
            created_by=current_user["id"]
        )
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="POST",
            endpoint="/api/v1/users",
            status_code=201,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="User created successfully",
            data=user
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.get("/api/v1/users", response_model=PaginatedResponse)
async def list_users_endpoint(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    role_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """List users with optional filtering."""
    start_time = time.time()
    
    filters = {}
    if role_filter:
        filters["role"] = role_filter
    if status_filter:
        filters["status"] = status_filter
    
    result = await list_users(
        filters=filters,
        user_id=current_user["id"],
        limit=limit,
        offset=offset
    )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint="/api/v1/users",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return PaginatedResponse(
        items=result["users"],
        total=result["total"],
        limit=limit,
        offset=offset,
        has_next=offset + limit < result["total"],
        has_prev=offset > 0
    )


@app.get("/api/v1/users/{user_id}", response_model=SuccessResponse)
async def get_user_endpoint(
    request: Request,
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a user by ID."""
    start_time = time.time()
    
    # Users can only view their own profile unless they're admin
    if current_user["id"] != user_id and current_user.get("role") != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    user = await get_user(user_id, current_user["id"])
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="GET",
        endpoint=f"/api/v1/users/{user_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(
        message="User retrieved successfully",
        data=user
    )


@app.put("/api/v1/users/{user_id}", response_model=SuccessResponse)
async def update_user_endpoint(
    request: Request,
    user_id: str,
    user_data: UserUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update a user."""
    start_time = time.time()
    
    # Users can only update their own profile unless they're admin
    if current_user["id"] != user_id and current_user.get("role") != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        updates = {k: v for k, v in user_data.dict().items() if v is not None}
        
        # Non-admin users cannot change their role
        if current_user.get("role") != UserRole.ADMIN.value and "role" in updates:
            del updates["role"]
        
        user = await update_user(
            user_id=user_id,
            updates=updates,
            updated_by=current_user["id"]
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        response_time = time.time() - start_time
        asyncio.create_task(record_api_request(
            method="PUT",
            endpoint=f"/api/v1/users/{user_id}",
            status_code=200,
            response_time=response_time,
            user_id=current_user["id"]
        ))
        
        return SuccessResponse(
            message="User updated successfully",
            data=user
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.delete("/api/v1/users/{user_id}", response_model=SuccessResponse)
async def delete_user_endpoint(
    request: Request,
    user_id: str,
    current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))
):
    """Delete a user."""
    start_time = time.time()
    
    # Prevent self-deletion
    if current_user["id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    success = await delete_user(user_id, current_user["id"])
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    response_time = time.time() - start_time
    asyncio.create_task(record_api_request(
        method="DELETE",
        endpoint=f"/api/v1/users/{user_id}",
        status_code=200,
        response_time=response_time,
        user_id=current_user["id"]
    ))
    
    return SuccessResponse(message="User deleted successfully")


# --- Health & Monitoring Endpoints ---

@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow(),
        uptime=time.time(),  # Simplified uptime
        components={
            "api": "healthy",
            "cache": "healthy",
            "database": "healthy"
        }
    )


@app.get("/api/v1/metrics")
async def get_metrics(current_user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN))):
    """Get system metrics (admin only)."""
    return {
        "requests_total": len(request_counts),
        "active_users": 1,  # Simplified
        "gateways_total": 0,  # Would query actual data
        "servers_total": 0,
        "timestamp": datetime.utcnow().isoformat()
    }


# --- CLI Runner ---

def run_api(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Run the API server."""
    sys_print(f"Starting Enkrypt Secure MCP Gateway API on {host}:{port}")
    uvicorn.run(
        "secure_mcp_gateway.api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enkrypt Secure MCP Gateway API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    run_api(host=args.host, port=args.port, reload=args.reload)