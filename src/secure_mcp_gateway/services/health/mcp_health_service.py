"""MCP Server health check and info service.

Provides connectivity checks, tool discovery, and tool execution
for arbitrary MCP servers supplied via raw JSON config (no pre-registration required).

Sandboxing
----------
The health endpoints accept arbitrary user-supplied commands + args, so they
spawn the target MCP server **inside a sandbox by default** (``sandbox.enabled = True``).
Callers can override or opt out via the ``sandbox`` field in the request body.
"""

import time
from typing import Any, Dict, List, Optional

from secure_mcp_gateway.client import forward_tool_call, get_server_metadata_only
from secure_mcp_gateway.plugins.sandbox.config_manager import (
    get_sandbox_config_manager,
)
from secure_mcp_gateway.utils import logger


class MCPHealthService:
    """On-demand health check and info retrieval for MCP servers."""

    @staticmethod
    def _resolve_sandbox(
        sandbox_override: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build the effective sandbox config for a health-endpoint call.

        The health endpoints sandbox by default. The caller may pass
        ``sandbox_override`` to disable or fine-tune. Per-call values win
        over the gateway's global sandbox defaults.
        """
        effective: Dict[str, Any] = {"enabled": True}
        if sandbox_override:
            effective.update(
                {k: v for k, v in sandbox_override.items() if v is not None}
            )
        return effective

    @staticmethod
    def _build_gateway_config(
        server_name: str,
        config: Dict[str, Any],
        description: str = "",
        sandbox_override: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        sandbox_cfg = MCPHealthService._resolve_sandbox(sandbox_override)
        return {
            "mcp_config": [
                {
                    "server_name": server_name,
                    "description": description,
                    "config": config,
                    "sandbox": sandbox_cfg,
                }
            ],
            "project_id": None,
            "mcp_config_id": None,
        }

    @staticmethod
    def _sandbox_status_payload(sandbox_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Describe what sandbox actually applied for the response payload."""
        manager = get_sandbox_config_manager()
        provider = manager.get_provider()
        requested_enabled = bool(sandbox_cfg.get("enabled", False))
        provider_name = provider.get_name() if provider else None

        if not requested_enabled:
            applied = "disabled"
        elif provider is None:
            applied = "fell-through (no provider registered)"
        else:
            applied = f"sandboxed via {provider_name}"

        return {
            "requested_enabled": requested_enabled,
            "provider": provider_name,
            "runtime": sandbox_cfg.get("runtime"),
            "applied": applied,
        }

    async def check_server_health(
        self,
        server_name: str,
        config: Dict[str, Any],
        description: str = "",
        sandbox: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Spawn the MCP server, initialise a session, and return connectivity info."""
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        try:
            result = await get_server_metadata_only(server_name, gateway_config)
            elapsed_ms = (time.monotonic() - start) * 1000
            metadata = result.get("server_metadata", {})

            return {
                "server_name": server_name,
                "connectivity": {
                    "status": "connected",
                    "server_name_from_server": metadata.get("name", "unknown"),
                    "server_version": metadata.get("version", "unknown"),
                    "server_description": metadata.get("description", ""),
                    "response_time_ms": round(elapsed_ms, 1),
                },
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error(
                f"[MCPHealthService] Server health check failed for {server_name}: {exc}"
            )
            return {
                "server_name": server_name,
                "connectivity": {
                    "status": "unreachable",
                    "error": f"{type(exc).__name__}: {exc}",
                    "response_time_ms": round(elapsed_ms, 1),
                },
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }

    async def get_server_info(
        self,
        server_name: str,
        config: Dict[str, Any],
        description: str = "",
        sandbox: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Spawn the MCP server and discover all tools with their schemas."""
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        try:
            result = await forward_tool_call(server_name, None, None, gateway_config)
            elapsed_ms = (time.monotonic() - start) * 1000

            metadata = result.get("server_metadata", {})
            tools_result = result.get("tools")

            tool_list = self._serialize_tools(tools_result)

            return {
                "server_name": server_name,
                "server_info": {
                    "name": metadata.get("name", "unknown"),
                    "version": metadata.get("version", "unknown"),
                    "description": metadata.get("description", ""),
                },
                "tools": tool_list,
                "tool_count": len(tool_list),
                "response_time_ms": round(elapsed_ms, 1),
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error(
                f"[MCPHealthService] Server info failed for {server_name}: {exc}"
            )
            return {
                "server_name": server_name,
                "error": f"{type(exc).__name__}: {exc}",
                "response_time_ms": round(elapsed_ms, 1),
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }

    async def execute_tool_health_check(
        self,
        server_name: str,
        config: Dict[str, Any],
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        description: str = "",
        sandbox: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Spawn the MCP server and execute a specific tool."""
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        try:
            result = await forward_tool_call(
                server_name, tool_name, tool_args, gateway_config
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            content = self._serialize_call_result(result)
            is_error = getattr(result, "isError", False)

            resp: Dict[str, Any] = {
                "server_name": server_name,
                "tool_name": tool_name,
                "execution": {
                    "status": "error" if is_error else "ok",
                    "result": content,
                    "response_time_ms": round(elapsed_ms, 1),
                },
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }
            return resp
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error(
                f"[MCPHealthService] Tool execution failed for {server_name}/{tool_name}: {exc}"
            )
            return {
                "server_name": server_name,
                "tool_name": tool_name,
                "execution": {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "response_time_ms": round(elapsed_ms, 1),
                },
                "sandbox": self._sandbox_status_payload(sandbox_cfg),
            }

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_tools(tools_result: Any) -> List[Dict[str, Any]]:
        """Convert MCP SDK ListToolsResult into plain dicts."""
        if tools_result is None:
            return []

        raw_tools: list = []
        if hasattr(tools_result, "tools"):
            raw_tools = list(tools_result.tools)
        elif isinstance(tools_result, dict):
            raw_tools = tools_result.get("tools", [])
        else:
            raw_tools = list(tools_result) if tools_result else []

        serialized: List[Dict[str, Any]] = []
        for t in raw_tools:
            if isinstance(t, dict):
                serialized.append(
                    {
                        "name": t.get("name", "unknown"),
                        "description": t.get("description", ""),
                        "inputSchema": t.get("inputSchema"),
                    }
                )
            else:
                entry: Dict[str, Any] = {
                    "name": getattr(t, "name", "unknown"),
                    "description": getattr(t, "description", ""),
                }
                input_schema = getattr(t, "inputSchema", None)
                if input_schema is not None:
                    if hasattr(input_schema, "model_dump"):
                        entry["inputSchema"] = input_schema.model_dump()
                    elif hasattr(input_schema, "dict"):
                        entry["inputSchema"] = input_schema.dict()
                    else:
                        entry["inputSchema"] = input_schema
                else:
                    entry["inputSchema"] = None
                serialized.append(entry)
        return serialized

    @staticmethod
    def _serialize_call_result(result: Any) -> Any:
        """Convert MCP SDK CallToolResult into a JSON-safe structure."""
        if result is None:
            return None

        content_items = getattr(result, "content", None)
        if content_items is None:
            if isinstance(result, dict):
                return result
            return str(result)

        content: List[Dict[str, Any]] = []
        for item in content_items:
            entry: Dict[str, Any] = {"type": getattr(item, "type", "unknown")}
            if hasattr(item, "text"):
                entry["text"] = item.text
            if hasattr(item, "data"):
                entry["data"] = item.data
            if hasattr(item, "mimeType"):
                entry["mimeType"] = item.mimeType
            content.append(entry)
        return content
