"""Shared API models and dependencies."""

import os
from datetime import datetime
from typing import Any

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
    detail: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class SuccessResponse(BaseModel):
    message: str
    data: Any | None = None
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

    enabled: bool | None = None
    runtime: str | None = Field(
        None, description="docker | podman | bwrap | microsandbox | novavm"
    )
    image: str | None = Field(None, description="Container image (Docker/Podman only)")
    memory_limit: str | None = Field(None, description="e.g. '512m', '1g'")
    cpu_limit: str | None = Field(None, description="e.g. '1.0', '2'")
    pids_limit: int | None = None
    network: str | None = Field(
        None,
        description="'none' = no network, 'host' = full network access, 'bridge' = Docker bridge (Docker only)",
    )
    read_only: bool | None = None
    allowed_env: list[str] | None = Field(
        None, description="Allowlist of env var names passed into the sandbox"
    )
    nova_api_url: str | None = Field(None, description="NovaVM API endpoint")
    nova_socket: str | None = Field(None, description="NovaVM socket path")


# Deny-list entry. Either a bare tool-name string (supports fnmatch globs)
# or a dict with at least a ``name`` key.  We keep the alias permissive so
# callers can mix-and-match in the same array.
DenyToolEntry = Any


class ServerAddRequest(BaseModel):
    server_name: str
    server_command: str
    server_args: list[str] | None = None
    description: str | None = None
    sandbox: SandboxConfig | None = None
    denied_tools: list[DenyToolEntry] | None = Field(
        None,
        description=(
            "Tools to deny. Each entry is a tool-name string (supports fnmatch "
            "globs like 'tool_a_*' or '*') or an object with 'name', 'reason', "
            "and optional 'description' fields."
        ),
    )


class ServerUpdateRequest(BaseModel):
    server_command: str | None = None
    server_args: list[str] | None = None
    description: str | None = None
    sandbox: SandboxConfig | None = None


class ServerGuardrailsRequest(BaseModel):
    enabled: bool = True
    guardrail_name: str | None = None


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
    mcp_config_name: str | None = None


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
    project_name: str | None = None


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
    args: list[str]
    env: dict[str, str] | None = None


class MCPServerRequest(BaseModel):
    """Request body for the /mcp-playground/* routes.

    Supports two mutually-exclusive modes; the route handler picks based on
    which fields / headers are present (see ``_resolve_mode`` in
    ``api_health_routes.py``):

    - **Inline**: caller supplies ``server_name`` + ``config`` in the body.
      Auth is the local admin apikey check.
    - **Registry**: caller supplies the ``X-Enkrypt-MCP-Registry-Server``
      header and omits ``server_name``/``config``. The gateway fetches the
      config from ``GET /mcp-registry/get-server`` and uses the cloud's
      200/401 as the apikey gate.

    Both fields are therefore optional at the Pydantic layer; the route
    handler enforces the per-mode invariants and returns 400 on ambiguity.
    Sandbox overrides are only honoured in inline mode (registry mode runs
    with sandbox at its global default).
    """

    server_name: str | None = Field(
        None,
        description=(
            "Display name for the MCP server. Required in inline mode; "
            "ignored / inferred from the registry response in registry-header mode."
        ),
    )
    config: MCPServerConfigBody | None = Field(
        None,
        description=(
            "Inline execution config (command/args/env). Required in inline mode; "
            "must be absent in registry-header mode (the gateway will fetch from "
            "the Enkrypt cloud's /mcp-registry/get-server)."
        ),
    )
    description: str | None = ""
    sandbox: SandboxConfig | None = Field(
        None,
        description=(
            "Per-call sandbox override. Health endpoints sandbox by default "
            "(enabled=True). Set 'enabled': false here to opt out, or override "
            "runtime / resource limits for this single call. Only honoured in "
            "inline mode — registry-header requests always use the global default."
        ),
    )


class MCPToolRequest(MCPServerRequest):
    tool_name: str
    tool_args: dict[str, Any] | None = None


# =============================================================================
# AUTHENTICATION DEPENDENCY
# =============================================================================


def get_api_key(apikey: str | None = Header(None)) -> str:
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
            provider = (config.get("plugins") or {}).get("auth", {}).get(
                "provider"
            ) or "local_apikey"
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


def get_api_key_raw(apikey: str | None = Header(None)) -> str:
    """Return the raw 'apikey' header value without validating it.

    Used only by the /mcp-playground/* routes, where validation depends on
    the request mode:

    - **Inline mode**: the route handler still validates via
      :func:`secure_mcp_gateway.auth_policy.resolve_admin_keys` (same policy
      as :func:`get_api_key`).
    - **Registry mode**: the cloud's ``GET /mcp-registry/get-server`` call
      is the gate — a 200 means the apikey is valid, a 401/403 means it
      isn't. We must not pre-reject the apikey here, otherwise a valid
      cloud-tenant apikey that doesn't appear in the gateway's local admin
      list would be rejected before reaching the cloud.

    All other admin routes continue to use :func:`get_api_key`.
    """
    if not apikey:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="apikey header required",
        )
    return apikey
