"""Shared API models and dependencies."""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

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


class SandboxConfig(BaseModel):
    """Per-server sandbox configuration (all fields optional, merged with global defaults)."""

    enabled: Optional[bool] = None
    runtime: Optional[str] = Field(None, description="docker | podman | bwrap | microsandbox | novavm")
    image: Optional[str] = Field(None, description="Container image (Docker/Podman only)")
    memory_limit: Optional[str] = Field(None, description="e.g. '512m', '1g'")
    cpu_limit: Optional[str] = Field(None, description="e.g. '1.0', '2'")
    pids_limit: Optional[int] = None
    network: Optional[str] = Field(None, description="'none' = no network, 'host' = full network access, 'bridge' = Docker bridge (Docker only)")
    read_only: Optional[bool] = None
    allowed_env: Optional[List[str]] = Field(
        None, description="Allowlist of env var names passed into the sandbox"
    )
    nova_api_url: Optional[str] = Field(None, description="NovaVM API endpoint")
    nova_socket: Optional[str] = Field(None, description="NovaVM socket path")


# Deny-list entry. Either a bare tool-name string (supports fnmatch globs)
# or a dict with at least a ``name`` key.  We keep the alias permissive so
# callers can mix-and-match in the same array.
DenyToolEntry = Any


class ServerAddRequest(BaseModel):
    server_name: str
    server_command: str
    server_args: Optional[List[str]] = None
    description: Optional[str] = None
    sandbox: Optional[SandboxConfig] = None
    denied_tools: Optional[List[DenyToolEntry]] = Field(
        None,
        description=(
            "Tools to deny. Each entry is a tool-name string (supports fnmatch "
            "globs like 'tool_a_*' or '*') or an object with 'name', 'reason', "
            "and optional 'description' fields."
        ),
    )


class ServerUpdateRequest(BaseModel):
    server_command: Optional[str] = None
    server_args: Optional[List[str]] = None
    description: Optional[str] = None
    sandbox: Optional[SandboxConfig] = None


class ServerGuardrailsRequest(BaseModel):
    enabled: bool = True
    guardrail_name: Optional[str] = None


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


# MCP Health Check Models
class MCPServerConfigBody(BaseModel):
    command: str
    args: List[str]
    env: Optional[Dict[str, str]] = None


class MCPServerRequest(BaseModel):
    server_name: str
    config: MCPServerConfigBody
    description: Optional[str] = ""
    sandbox: Optional[SandboxConfig] = Field(
        None,
        description=(
            "Per-call sandbox override. Health endpoints sandbox by default "
            "(enabled=True). Set 'enabled': false here to opt out, or override "
            "runtime / resource limits for this single call."
        ),
    )


class MCPToolRequest(MCPServerRequest):
    tool_name: str
    tool_args: Optional[Dict[str, Any]] = None


# =============================================================================
# AUTHENTICATION DEPENDENCY
# =============================================================================


def get_api_key(apikey: Optional[str] = Header(None)) -> str:
    """Extract and validate API key from the 'apikey' header (cloud-compatible).

    Policy is delegated to :func:`secure_mcp_gateway.auth_policy.resolve_admin_keys`
    so this dependency and ``api_server.get_api_key`` stay in lock-step.
    """
    from secure_mcp_gateway.auth_policy import (
        describe_missing_admin_key_hint,
        resolve_admin_keys,
    )

    if not apikey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="apikey header required",
        )

    try:
        config = load_config(PICKED_CONFIG_PATH)
        acceptable = resolve_admin_keys(config)

        if not acceptable:
            provider = (
                (config.get("plugins") or {}).get("auth", {}).get("provider")
                or "local_apikey"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Admin API key not configured. "
                    + describe_missing_admin_key_hint(provider)
                ),
            )

        if apikey not in acceptable:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key.",
            )

        return apikey
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
