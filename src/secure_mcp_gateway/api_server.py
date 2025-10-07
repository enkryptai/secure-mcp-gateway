"""
Enkrypt Secure MCP Gateway REST API Server

This module provides a REST API interface for all CLI commands, allowing programmatic
access to configuration management, project management, user management, and system operations.

The API server uses FastAPI and provides comprehensive endpoints for:
- MCP Configuration Management
- Project Management
- User Management
- System Operations
- API Key Management

Authentication is handled via API keys in the Authorization header.
"""

import json
import os
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import all CLI functions
from secure_mcp_gateway.cli import (
    add_config,
    add_server_to_config,
    copy_config,
    export_config,
    get_config,
    get_config_server,
    # Utility functions
    import_config,
    list_config_projects,
    list_config_servers,
    # Config functions
    list_configs,
    remove_all_servers_from_config,
    remove_config,
    remove_server_from_config,
    rename_config,
    search_configs,
    update_config_server,
    update_server_guardrails,
    update_server_input_guardrails,
    update_server_output_guardrails,
    validate_config,
)
from secure_mcp_gateway.utils import (
    CONFIG_PATH,
    DOCKER_CONFIG_PATH,
    is_docker,
    sys_print,
)
from secure_mcp_gateway.version import __version__

sys_print(f"Initializing Enkrypt Secure MCP Gateway REST API Server v{__version__}")

# Configuration
is_docker_running = is_docker()
PICKED_CONFIG_PATH = DOCKER_CONFIG_PATH if is_docker_running else CONFIG_PATH

# FastAPI app
app = FastAPI(
    title="Enkrypt Secure MCP Gateway API",
    description="REST API for managing MCP configurations, projects, users, and system operations",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)


# Add security scheme for Swagger UI
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Enkrypt Secure MCP Gateway API",
        version=__version__,
        description="REST API for managing MCP configurations, projects, users, and system operations",
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }

    # Add security to all endpoints except health check
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method != "parameters" and path != "/health":
                openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# PYDANTIC MODELS
# =============================================================================


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class SuccessResponse(BaseModel):
    message: str
    data: Optional[Any] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


# Config Models
class ConfigCreateRequest(BaseModel):
    config_name: str


class ConfigCopyRequest(BaseModel):
    source_config: str
    target_config: str


class ConfigRenameRequest(BaseModel):
    new_name: str


class ServerAddRequest(BaseModel):
    server_name: str
    server_command: str
    args: Optional[List[str]] = []
    env: Optional[Dict[str, Any]] = None
    tools: Optional[Dict[str, Any]] = None
    description: str = ""
    input_guardrails_policy: Optional[Dict[str, Any]] = None
    output_guardrails_policy: Optional[Dict[str, Any]] = None


class ServerUpdateRequest(BaseModel):
    server_command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, Any]] = None
    tools: Optional[Dict[str, Any]] = None
    description: Optional[str] = None


class GuardrailsUpdateRequest(BaseModel):
    policy_file: Optional[str] = None
    policy: Optional[Dict[str, Any]] = None


class CombinedGuardrailsUpdateRequest(BaseModel):
    input_policy_file: Optional[str] = None
    input_policy: Optional[Dict[str, Any]] = None
    output_policy_file: Optional[str] = None
    output_policy: Optional[Dict[str, Any]] = None


class ConfigExportRequest(BaseModel):
    output_file: str


class ConfigImportRequest(BaseModel):
    input_file: str
    config_name: str


class ConfigSearchRequest(BaseModel):
    search_term: str


# Project Models
class ProjectCreateRequest(BaseModel):
    project_name: str


class ProjectAssignConfigRequest(BaseModel):
    config_name: Optional[str] = None
    config_id: Optional[str] = None


class ProjectAddUserRequest(BaseModel):
    user_id: Optional[str] = None
    email: Optional[str] = None


class ProjectExportRequest(BaseModel):
    output_file: str


class ProjectSearchRequest(BaseModel):
    search_term: str


# User Models
class UserCreateRequest(BaseModel):
    email: EmailStr


class UserUpdateRequest(BaseModel):
    new_email: EmailStr


class UserDeleteRequest(BaseModel):
    force: bool = False


class UserGenerateApiKeyRequest(BaseModel):
    project_name: Optional[str] = None
    project_id: Optional[str] = None


class ApiKeyRotateRequest(BaseModel):
    api_key: str


class ApiKeyDeleteRequest(BaseModel):
    api_key: str


class UserSearchRequest(BaseModel):
    search_term: str


# System Models
class SystemBackupRequest(BaseModel):
    output_file: str


class SystemRestoreRequest(BaseModel):
    input_file: str


class SystemResetRequest(BaseModel):
    confirm: bool = False


# =============================================================================
# AUTHENTICATION
# =============================================================================


def get_api_key(authorization: Optional[str] = Header(None)) -> str:
    """Extract and validate API key from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format. Use 'Bearer <api_key>'",
        )

    api_key = authorization[7:]  # Remove "Bearer " prefix

    # Validate API key exists in config
    try:
        with open(PICKED_CONFIG_PATH) as f:
            config = json.load(f)

        if api_key not in config.get("apikeys", {}):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
            )

        # Check if API key is disabled
        if config["apikeys"][api_key].get("disabled", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="API key is disabled"
            )

        return api_key
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration file not found",
        )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid configuration file",
        )


# =============================================================================
# ERROR HANDLING
# =============================================================================


def run_cli_function_with_error_handling(func, *args, **kwargs):
    """Run a CLI function and capture its output and errors properly."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
        try:
            func(*args, **kwargs)
            return stdout_capture.getvalue().strip(), None
        except SystemExit:
            # Extract error message from stderr
            error_msg = stderr_capture.getvalue().strip()
            if error_msg:
                return None, error_msg
            else:
                return None, "Operation failed"
        except Exception as e:
            return None, str(e)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    sys_print(f"Unhandled exception: {exc}", is_error=True)
    sys_print(f"Traceback: {traceback.format_exc()}", is_error=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(error="Internal server error", detail=str(exc)).dict(),
    )


# =============================================================================
# HEALTH CHECK
# =============================================================================


@app.get("/health", response_model=SuccessResponse)
async def health_check():
    """Health check endpoint."""
    return SuccessResponse(
        message="API server is healthy",
        data={"version": __version__, "config_path": PICKED_CONFIG_PATH},
    )


# =============================================================================
# CONFIG ENDPOINTS
# =============================================================================


@app.get("/api/v1/configs", response_model=SuccessResponse)
async def get_configs(api_key: str = Depends(get_api_key)):
    """List all MCP configurations."""
    try:
        # Capture stdout to get JSON response
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            list_configs(PICKED_CONFIG_PATH)

        configs = json.loads(f.getvalue())
        return SuccessResponse(
            message="Configurations retrieved successfully", data=configs
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/configs", response_model=SuccessResponse)
async def create_config(
    request: ConfigCreateRequest, api_key: str = Depends(get_api_key)
):
    """Create a new MCP configuration."""
    result, error = run_cli_function_with_error_handling(
        add_config, PICKED_CONFIG_PATH, request.config_name
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    config_id = result.split(": ")[1] if ": " in result else result

    return SuccessResponse(
        message="Configuration created successfully",
        data={"config_id": config_id, "config_name": request.config_name},
    )


@app.post("/api/v1/configs/copy", response_model=SuccessResponse)
async def copy_config_endpoint(
    request: ConfigCopyRequest, api_key: str = Depends(get_api_key)
):
    """Copy an MCP configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            copy_config(
                PICKED_CONFIG_PATH, request.source_config, request.target_config
            )

        return SuccessResponse(message="Configuration copied successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration copy failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/v1/configs/{config_identifier}/rename", response_model=SuccessResponse)
async def rename_config_endpoint(
    config_identifier: str,
    request: ConfigRenameRequest,
    api_key: str = Depends(get_api_key),
):
    """Rename an MCP configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            rename_config(PICKED_CONFIG_PATH, config_identifier, request.new_name)

        return SuccessResponse(message="Configuration renamed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration rename failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/configs/{config_identifier}", response_model=SuccessResponse)
async def get_config_endpoint(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """Get a specific MCP configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            get_config(PICKED_CONFIG_PATH, config_identifier)

        config_data = json.loads(f.getvalue())
        return SuccessResponse(
            message="Configuration retrieved successfully", data=config_data
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="Configuration not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/configs/{config_identifier}", response_model=SuccessResponse)
async def delete_config_endpoint(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """Delete an MCP configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            remove_config(PICKED_CONFIG_PATH, config_identifier)

        return SuccessResponse(message="Configuration deleted successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration deletion failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/configs/{config_identifier}/projects", response_model=SuccessResponse)
async def get_config_projects(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """List projects using a specific configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            list_config_projects(PICKED_CONFIG_PATH, config_identifier)

        projects = json.loads(f.getvalue())
        return SuccessResponse(message="Projects retrieved successfully", data=projects)
    except SystemExit:
        raise HTTPException(status_code=404, detail="Configuration not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/configs/{config_identifier}/servers", response_model=SuccessResponse)
async def get_config_servers(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """List servers in a specific configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            list_config_servers(PICKED_CONFIG_PATH, config_identifier)

        servers = json.loads(f.getvalue())
        return SuccessResponse(message="Servers retrieved successfully", data=servers)
    except SystemExit:
        raise HTTPException(status_code=404, detail="Configuration not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/api/v1/configs/{config_identifier}/servers/{server_name}",
    response_model=SuccessResponse,
)
async def get_config_server_endpoint(
    config_identifier: str, server_name: str, api_key: str = Depends(get_api_key)
):
    """Get specific server details from a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            get_config_server(PICKED_CONFIG_PATH, config_identifier, server_name)

        server_data = json.loads(f.getvalue())
        return SuccessResponse(
            message="Server details retrieved successfully", data=server_data
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="Server not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/configs/{config_identifier}/servers", response_model=SuccessResponse)
async def add_server_to_config_endpoint(
    config_identifier: str,
    request: ServerAddRequest,
    api_key: str = Depends(get_api_key),
):
    """Add a server to a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            add_server_to_config(
                PICKED_CONFIG_PATH,
                config_identifier,
                request.server_name,
                request.server_command,
                request.args,
                json.dumps(request.env) if request.env else None,
                json.dumps(request.tools) if request.tools else None,
                request.description,
                json.dumps(request.input_guardrails_policy)
                if request.input_guardrails_policy
                else None,
                json.dumps(request.output_guardrails_policy)
                if request.output_guardrails_policy
                else None,
            )

        return SuccessResponse(message="Server added successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Server addition failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put(
    "/api/v1/configs/{config_identifier}/servers/{server_name}",
    response_model=SuccessResponse,
)
async def update_server_in_config_endpoint(
    config_identifier: str,
    server_name: str,
    request: ServerUpdateRequest,
    api_key: str = Depends(get_api_key),
):
    """Update a server in a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            update_config_server(
                PICKED_CONFIG_PATH,
                config_identifier,
                server_name,
                request.server_command,
                request.args,
                json.dumps(request.env) if request.env else None,
                json.dumps(request.tools) if request.tools else None,
                request.description,
            )

        return SuccessResponse(message="Server updated successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Server update failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete(
    "/api/v1/configs/{config_identifier}/servers/{server_name}",
    response_model=SuccessResponse,
)
async def delete_server_from_config_endpoint(
    config_identifier: str, server_name: str, api_key: str = Depends(get_api_key)
):
    """Remove a server from a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            remove_server_from_config(
                PICKED_CONFIG_PATH, config_identifier, server_name
            )

        return SuccessResponse(message="Server removed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Server removal failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete(
    "/api/v1/configs/{config_identifier}/servers", response_model=SuccessResponse
)
async def delete_all_servers_from_config_endpoint(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """Remove all servers from a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            remove_all_servers_from_config(PICKED_CONFIG_PATH, config_identifier)

        return SuccessResponse(message="All servers removed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Server removal failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/api/v1/configs/{config_identifier}/validate", response_model=SuccessResponse
)
async def validate_config_endpoint(
    config_identifier: str, api_key: str = Depends(get_api_key)
):
    """Validate a configuration."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            validate_config(PICKED_CONFIG_PATH, config_identifier)

        return SuccessResponse(message="Configuration is valid")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration validation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/configs/{config_identifier}/export", response_model=SuccessResponse)
async def export_config_endpoint(
    config_identifier: str,
    request: ConfigExportRequest,
    api_key: str = Depends(get_api_key),
):
    """Export a configuration to file."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            export_config(PICKED_CONFIG_PATH, config_identifier, request.output_file)

        return SuccessResponse(message="Configuration exported successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration export failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/configs/import", response_model=SuccessResponse)
async def import_config_endpoint(
    request: ConfigImportRequest, api_key: str = Depends(get_api_key)
):
    """Import a configuration from file."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            import_config(PICKED_CONFIG_PATH, request.input_file, request.config_name)

        return SuccessResponse(message="Configuration imported successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration import failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/configs/search", response_model=SuccessResponse)
async def search_configs_endpoint(
    request: ConfigSearchRequest, api_key: str = Depends(get_api_key)
):
    """Search configurations."""
    try:
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            search_configs(PICKED_CONFIG_PATH, request.search_term)

        results = json.loads(f.getvalue())
        return SuccessResponse(message="Search completed successfully", data=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put(
    "/api/v1/configs/{config_identifier}/servers/{server_name}/input-guardrails",
    response_model=SuccessResponse,
)
async def update_server_input_guardrails_endpoint(
    config_identifier: str,
    server_name: str,
    request: GuardrailsUpdateRequest,
    api_key: str = Depends(get_api_key),
):
    """Update server input guardrails policy."""
    result, error = run_cli_function_with_error_handling(
        update_server_input_guardrails,
        PICKED_CONFIG_PATH,
        config_identifier,
        server_name,
        request.policy_file,
        json.dumps(request.policy) if request.policy else None,
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    return SuccessResponse(message="Input guardrails updated successfully")


@app.put(
    "/api/v1/configs/{config_identifier}/servers/{server_name}/output-guardrails",
    response_model=SuccessResponse,
)
async def update_server_output_guardrails_endpoint(
    config_identifier: str,
    server_name: str,
    request: GuardrailsUpdateRequest,
    api_key: str = Depends(get_api_key),
):
    """Update server output guardrails policy."""
    result, error = run_cli_function_with_error_handling(
        update_server_output_guardrails,
        PICKED_CONFIG_PATH,
        config_identifier,
        server_name,
        request.policy_file,
        json.dumps(request.policy) if request.policy else None,
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    return SuccessResponse(message="Output guardrails updated successfully")


@app.put(
    "/api/v1/configs/{config_identifier}/servers/{server_name}/guardrails",
    response_model=SuccessResponse,
)
async def update_server_guardrails_endpoint(
    config_identifier: str,
    server_name: str,
    request: CombinedGuardrailsUpdateRequest,
    api_key: str = Depends(get_api_key),
):
    """Update server guardrails policies (both input and output)."""
    result, error = run_cli_function_with_error_handling(
        update_server_guardrails,
        PICKED_CONFIG_PATH,
        config_identifier,
        server_name,
        request.input_policy_file,
        json.dumps(request.input_policy) if request.input_policy else None,
        request.output_policy_file,
        json.dumps(request.output_policy) if request.output_policy else None,
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    return SuccessResponse(message="Guardrails updated successfully")


# =============================================================================
# INCLUDE ADDITIONAL ROUTES
# =============================================================================

# Import and include additional routes
from secure_mcp_gateway.api_routes import router as additional_routes

app.include_router(additional_routes)

# =============================================================================
# MAIN FUNCTION
# =============================================================================


def main():
    """Run the API server."""
    sys_print("Starting Enkrypt Secure MCP Gateway REST API Server")
    sys_print(f"Config path: {PICKED_CONFIG_PATH}")
    sys_print("API documentation available at: http://localhost:8001/docs")

    uvicorn.run(
        "secure_mcp_gateway.api_server:app",
        host="0.0.0.0",
        port=8001,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
