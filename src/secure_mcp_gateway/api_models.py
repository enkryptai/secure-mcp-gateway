"""Shared API models and dependencies."""

import os
from datetime import datetime
from typing import Any, List, Optional

from fastapi import Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from secure_mcp_gateway.cli import load_config
from secure_mcp_gateway.utils import CONFIG_PATH, DOCKER_CONFIG_PATH, is_docker

# Configuration
is_docker_running = is_docker()
PICKED_CONFIG_PATH = DOCKER_CONFIG_PATH if is_docker_running else CONFIG_PATH


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
    server_args: Optional[List[str]] = None
    description: Optional[str] = None


class ServerUpdateRequest(BaseModel):
    server_command: Optional[str] = None
    server_args: Optional[List[str]] = None
    description: Optional[str] = None


class ServerGuardrailsRequest(BaseModel):
    enabled: bool = True
    policy_name: Optional[str] = None


class ConfigValidateRequest(BaseModel):
    config_name: str


class ConfigImportRequest(BaseModel):
    file_path: str
    config_name: str


class ConfigExportRequest(BaseModel):
    config_name: str
    output_file: str


class ConfigSearchRequest(BaseModel):
    search_term: str


# Project Models
class ProjectCreateRequest(BaseModel):
    project_name: str
    mcp_config_name: Optional[str] = None


class ProjectAssignConfigRequest(BaseModel):
    config_name: str


class ProjectAddUserRequest(BaseModel):
    email: EmailStr


class ProjectExportRequest(BaseModel):
    output_file: str


class ProjectSearchRequest(BaseModel):
    search_term: str


# User Models
class UserCreateRequest(BaseModel):
    email: EmailStr


class UserUpdateRequest(BaseModel):
    new_email: EmailStr


class UserGenerateApiKeyRequest(BaseModel):
    project_name: Optional[str] = None


class ApiKeyRotateRequest(BaseModel):
    pass


class UserDeleteRequest(BaseModel):
    user_identifier: str


class UserSearchRequest(BaseModel):
    search_term: str


# System Models
class SystemBackupRequest(BaseModel):
    output_file: str


class SystemRestoreRequest(BaseModel):
    backup_file: str


class SystemResetRequest(BaseModel):
    confirm: bool = False


# =============================================================================
# AUTHENTICATION DEPENDENCY
# =============================================================================


def get_api_key(authorization: Optional[str] = Header(None)) -> str:
    """Extract and validate admin API key from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format. Use 'Bearer <api_key>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    api_key = authorization[7:]  # Remove "Bearer " prefix

    # Validate admin API key exists in config
    try:
        config = load_config(PICKED_CONFIG_PATH)

        # Check if admin_apikey exists and matches
        if "admin_apikey" not in config:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Admin API key not configured. Please regenerate configuration.",
            )

        if api_key != config["admin_apikey"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin API key. Administrative operations require admin_apikey.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return api_key
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration file not found",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {e!s}",
        )
