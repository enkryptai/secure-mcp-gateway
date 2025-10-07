"""
Additional API routes for the Enkrypt Secure MCP Gateway REST API Server

This module contains the remaining API endpoints for projects, users, and system operations.
"""

import io
import json
from contextlib import redirect_stdout
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from secure_mcp_gateway.api_server import (
    PICKED_CONFIG_PATH,
    ApiKeyRotateRequest,
    ProjectAddUserRequest,
    ProjectAssignConfigRequest,
    ProjectCreateRequest,
    ProjectExportRequest,
    ProjectSearchRequest,
    SuccessResponse,
    SystemBackupRequest,
    SystemResetRequest,
    SystemRestoreRequest,
    UserCreateRequest,
    UserDeleteRequest,
    UserGenerateApiKeyRequest,
    UserSearchRequest,
    UserUpdateRequest,
    get_api_key,
)
from secure_mcp_gateway.cli import (
    add_user_to_project,
    assign_config_to_project,
    create_project,
    create_user,
    delete_all_user_api_keys,
    delete_user,
    delete_user_api_key,
    disable_user_api_key,
    enable_user_api_key,
    export_project,
    generate_user_api_key,
    get_project,
    get_project_config,
    get_user,
    list_all_api_keys,
    list_project_users,
    # Project functions
    list_projects,
    list_user_api_keys,
    list_user_projects,
    # User functions
    list_users,
    remove_all_users_from_project,
    remove_project,
    remove_user_from_project,
    rotate_user_api_key,
    search_projects,
    search_users,
    system_backup,
    # System functions
    system_health_check,
    system_reset,
    system_restore,
    unassign_config_from_project,
    update_user,
)

# Create router for additional routes
router = APIRouter()

# =============================================================================
# PROJECT ENDPOINTS
# =============================================================================


@router.get("/api/v1/projects", response_model=SuccessResponse)
async def get_projects(api_key: str = Depends(get_api_key)):
    """List all projects."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_projects(PICKED_CONFIG_PATH)

        projects = json.loads(f.getvalue())
        return SuccessResponse(message="Projects retrieved successfully", data=projects)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/projects", response_model=SuccessResponse)
async def create_project_endpoint(
    request: ProjectCreateRequest, api_key: str = Depends(get_api_key)
):
    """Create a new project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            create_project(PICKED_CONFIG_PATH, request.project_name)

        result = f.getvalue().strip()
        project_id = result.split(": ")[1] if ": " in result else result

        return SuccessResponse(
            message="Project created successfully",
            data={"project_id": project_id, "project_name": request.project_name},
        )
    except SystemExit:
        raise HTTPException(status_code=400, detail="Project creation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/projects/{project_identifier}", response_model=SuccessResponse)
async def get_project_endpoint(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """Get a specific project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            get_project(PICKED_CONFIG_PATH, project_identifier)

        project_data = json.loads(f.getvalue())
        return SuccessResponse(
            message="Project retrieved successfully", data=project_data
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="Project not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/v1/projects/{project_identifier}", response_model=SuccessResponse)
async def delete_project_endpoint(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """Delete a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            remove_project(PICKED_CONFIG_PATH, project_identifier)

        return SuccessResponse(message="Project deleted successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Project deletion failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/api/v1/projects/{project_identifier}/assign-config",
    response_model=SuccessResponse,
)
async def assign_config_to_project_endpoint(
    project_identifier: str,
    request: ProjectAssignConfigRequest,
    api_key: str = Depends(get_api_key),
):
    """Assign a configuration to a project."""
    try:
        config_identifier = request.config_name or request.config_id
        if not config_identifier:
            raise HTTPException(
                status_code=400, detail="Either config_name or config_id is required"
            )

        f = io.StringIO()
        with redirect_stdout(f):
            assign_config_to_project(
                PICKED_CONFIG_PATH, project_identifier, config_identifier
            )

        return SuccessResponse(message="Configuration assigned to project successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration assignment failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/api/v1/projects/{project_identifier}/unassign-config",
    response_model=SuccessResponse,
)
async def unassign_config_from_project_endpoint(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """Unassign configuration from a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            unassign_config_from_project(PICKED_CONFIG_PATH, project_identifier)

        return SuccessResponse(
            message="Configuration unassigned from project successfully"
        )
    except SystemExit:
        raise HTTPException(status_code=400, detail="Configuration unassignment failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/api/v1/projects/{project_identifier}/config", response_model=SuccessResponse
)
async def get_project_config_endpoint(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """Get configuration assigned to a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            get_project_config(PICKED_CONFIG_PATH, project_identifier)

        config_data = json.loads(f.getvalue())
        return SuccessResponse(
            message="Project configuration retrieved successfully", data=config_data
        )
    except SystemExit:
        raise HTTPException(
            status_code=404, detail="Project or configuration not found"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/api/v1/projects/{project_identifier}/users", response_model=SuccessResponse
)
async def get_project_users(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """List users in a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_project_users(PICKED_CONFIG_PATH, project_identifier)

        users = json.loads(f.getvalue())
        return SuccessResponse(
            message="Project users retrieved successfully", data=users
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="Project not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/api/v1/projects/{project_identifier}/users", response_model=SuccessResponse
)
async def add_user_to_project_endpoint(
    project_identifier: str,
    request: ProjectAddUserRequest,
    api_key: str = Depends(get_api_key),
):
    """Add a user to a project."""
    try:
        user_identifier = request.user_id or request.email
        if not user_identifier:
            raise HTTPException(
                status_code=400, detail="Either user_id or email is required"
            )

        f = io.StringIO()
        with redirect_stdout(f):
            add_user_to_project(PICKED_CONFIG_PATH, project_identifier, user_identifier)

        return SuccessResponse(message="User added to project successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="User addition failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/api/v1/projects/{project_identifier}/users/{user_identifier}",
    response_model=SuccessResponse,
)
async def remove_user_from_project_endpoint(
    project_identifier: str, user_identifier: str, api_key: str = Depends(get_api_key)
):
    """Remove a user from a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            remove_user_from_project(
                PICKED_CONFIG_PATH, project_identifier, user_identifier
            )

        return SuccessResponse(message="User removed from project successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="User removal failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/api/v1/projects/{project_identifier}/users", response_model=SuccessResponse
)
async def remove_all_users_from_project_endpoint(
    project_identifier: str, api_key: str = Depends(get_api_key)
):
    """Remove all users from a project."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            remove_all_users_from_project(PICKED_CONFIG_PATH, project_identifier)

        return SuccessResponse(message="All users removed from project successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="User removal failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/api/v1/projects/{project_identifier}/export", response_model=SuccessResponse
)
async def export_project_endpoint(
    project_identifier: str,
    request: ProjectExportRequest,
    api_key: str = Depends(get_api_key),
):
    """Export a project to file."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            export_project(PICKED_CONFIG_PATH, project_identifier, request.output_file)

        return SuccessResponse(message="Project exported successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="Project export failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/projects/search", response_model=SuccessResponse)
async def search_projects_endpoint(
    request: ProjectSearchRequest, api_key: str = Depends(get_api_key)
):
    """Search projects."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            search_projects(PICKED_CONFIG_PATH, request.search_term)

        results = json.loads(f.getvalue())
        return SuccessResponse(message="Search completed successfully", data=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# USER ENDPOINTS
# =============================================================================


@router.get("/api/v1/users", response_model=SuccessResponse)
async def get_users(api_key: str = Depends(get_api_key)):
    """List all users."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_users(PICKED_CONFIG_PATH)

        users = json.loads(f.getvalue())
        return SuccessResponse(message="Users retrieved successfully", data=users)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/users", response_model=SuccessResponse)
async def create_user_endpoint(
    request: UserCreateRequest, api_key: str = Depends(get_api_key)
):
    """Create a new user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            create_user(PICKED_CONFIG_PATH, request.email)

        result = f.getvalue().strip()
        user_id = result.split(": ")[1] if ": " in result else result

        return SuccessResponse(
            message="User created successfully",
            data={"user_id": user_id, "email": request.email},
        )
    except SystemExit:
        raise HTTPException(status_code=400, detail="User creation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/users/{user_identifier}", response_model=SuccessResponse)
async def get_user_endpoint(user_identifier: str, api_key: str = Depends(get_api_key)):
    """Get a specific user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            get_user(PICKED_CONFIG_PATH, user_identifier)

        user_data = json.loads(f.getvalue())
        return SuccessResponse(message="User retrieved successfully", data=user_data)
    except SystemExit:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/api/v1/users/{user_identifier}", response_model=SuccessResponse)
async def update_user_endpoint(
    user_identifier: str,
    request: UserUpdateRequest,
    api_key: str = Depends(get_api_key),
):
    """Update a user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            update_user(PICKED_CONFIG_PATH, user_identifier, request.new_email)

        return SuccessResponse(message="User updated successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="User update failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/v1/users/{user_identifier}", response_model=SuccessResponse)
async def delete_user_endpoint(
    user_identifier: str,
    request: UserDeleteRequest,
    api_key: str = Depends(get_api_key),
):
    """Delete a user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            delete_user(PICKED_CONFIG_PATH, user_identifier, request.force)

        return SuccessResponse(message="User deleted successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="User deletion failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/users/{user_identifier}/projects", response_model=SuccessResponse)
async def get_user_projects(user_identifier: str, api_key: str = Depends(get_api_key)):
    """List projects for a specific user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_user_projects(PICKED_CONFIG_PATH, user_identifier)

        projects = json.loads(f.getvalue())
        return SuccessResponse(
            message="User projects retrieved successfully", data=projects
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/users/{user_identifier}/api-keys", response_model=SuccessResponse)
async def generate_user_api_key_endpoint(
    user_identifier: str,
    request: UserGenerateApiKeyRequest,
    api_key: str = Depends(get_api_key),
):
    """Generate an API key for a user."""
    try:
        project_identifier = request.project_name or request.project_id
        if not project_identifier:
            raise HTTPException(
                status_code=400, detail="Either project_name or project_id is required"
            )

        f = io.StringIO()
        with redirect_stdout(f):
            generate_user_api_key(
                PICKED_CONFIG_PATH, user_identifier, project_identifier
            )

        result = f.getvalue().strip()
        new_api_key = result.split(": ")[1] if ": " in result else result

        return SuccessResponse(
            message="API key generated successfully", data={"api_key": new_api_key}
        )
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key generation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/users/{user_identifier}/api-keys", response_model=SuccessResponse)
async def get_user_api_keys(
    user_identifier: str,
    project_identifier: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    """List API keys for a user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_user_api_keys(PICKED_CONFIG_PATH, user_identifier, project_identifier)

        api_keys = json.loads(f.getvalue())
        return SuccessResponse(
            message="User API keys retrieved successfully", data=api_keys
        )
    except SystemExit:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/api/v1/users/{user_identifier}/api-keys", response_model=SuccessResponse
)
async def delete_all_user_api_keys_endpoint(
    user_identifier: str, api_key: str = Depends(get_api_key)
):
    """Delete all API keys for a user."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            delete_all_user_api_keys(PICKED_CONFIG_PATH, user_identifier)

        return SuccessResponse(message="All user API keys deleted successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key deletion failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/api-keys", response_model=SuccessResponse)
async def get_all_api_keys(api_key: str = Depends(get_api_key)):
    """List all API keys across all users."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            list_all_api_keys(PICKED_CONFIG_PATH)

        all_keys = json.loads(f.getvalue())
        return SuccessResponse(
            message="All API keys retrieved successfully", data=all_keys
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/api-keys/rotate", response_model=SuccessResponse)
async def rotate_api_key_endpoint(
    request: ApiKeyRotateRequest, api_key: str = Depends(get_api_key)
):
    """Rotate an API key."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            rotate_user_api_key(PICKED_CONFIG_PATH, request.api_key)

        result = f.getvalue().strip()
        new_api_key = result.split(": ")[1] if ": " in result else result

        return SuccessResponse(
            message="API key rotated successfully", data={"new_api_key": new_api_key}
        )
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key rotation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/api-keys/{api_key}/disable", response_model=SuccessResponse)
async def disable_api_key_endpoint(
    api_key: str, api_key_dep: str = Depends(get_api_key)
):
    """Disable an API key."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            disable_user_api_key(PICKED_CONFIG_PATH, api_key)

        return SuccessResponse(message="API key disabled successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key disable failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/api-keys/{api_key}/enable", response_model=SuccessResponse)
async def enable_api_key_endpoint(
    api_key: str, api_key_dep: str = Depends(get_api_key)
):
    """Enable an API key."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            enable_user_api_key(PICKED_CONFIG_PATH, api_key)

        return SuccessResponse(message="API key enabled successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key enable failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/v1/api-keys/{api_key}", response_model=SuccessResponse)
async def delete_api_key_endpoint(
    api_key: str, api_key_dep: str = Depends(get_api_key)
):
    """Delete an API key."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            delete_user_api_key(PICKED_CONFIG_PATH, api_key)

        return SuccessResponse(message="API key deleted successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="API key deletion failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/users/search", response_model=SuccessResponse)
async def search_users_endpoint(
    request: UserSearchRequest, api_key: str = Depends(get_api_key)
):
    """Search users."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            search_users(PICKED_CONFIG_PATH, request.search_term)

        results = json.loads(f.getvalue())
        return SuccessResponse(message="Search completed successfully", data=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# SYSTEM ENDPOINTS
# =============================================================================


@router.get("/api/v1/system/health", response_model=SuccessResponse)
async def system_health_check_endpoint(api_key: str = Depends(get_api_key)):
    """Check system health."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            system_health_check(PICKED_CONFIG_PATH)

        health_data = json.loads(f.getvalue())
        return SuccessResponse(
            message="System health check completed", data=health_data
        )
    except SystemExit:
        raise HTTPException(status_code=500, detail="System health check failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/system/backup", response_model=SuccessResponse)
async def system_backup_endpoint(
    request: SystemBackupRequest, api_key: str = Depends(get_api_key)
):
    """Backup system configuration."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            system_backup(PICKED_CONFIG_PATH, request.output_file)

        return SuccessResponse(message="System backup completed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="System backup failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/system/restore", response_model=SuccessResponse)
async def system_restore_endpoint(
    request: SystemRestoreRequest, api_key: str = Depends(get_api_key)
):
    """Restore system configuration."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            system_restore(PICKED_CONFIG_PATH, request.input_file)

        return SuccessResponse(message="System restore completed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="System restore failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/system/reset", response_model=SuccessResponse)
async def system_reset_endpoint(
    request: SystemResetRequest, api_key: str = Depends(get_api_key)
):
    """Reset system configuration."""
    try:
        f = io.StringIO()
        with redirect_stdout(f):
            system_reset(PICKED_CONFIG_PATH, request.confirm)

        return SuccessResponse(message="System reset completed successfully")
    except SystemExit:
        raise HTTPException(status_code=400, detail="System reset failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
