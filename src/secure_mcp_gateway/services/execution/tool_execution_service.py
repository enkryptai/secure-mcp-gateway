from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class ToolExecutionService:
    """
    Manages a single stdio MCP session and executes one or more tool calls.

    This service intentionally does not perform guardrail checks or discovery.
    Those concerns should be handled by higher-level orchestrators and passed in
    via arguments (e.g., already-resolved server_config and guardrail runners).
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None

    @staticmethod
    def _normalize_tool_name(tool_call: dict[str, Any]) -> str:
        candidates = [
            tool_call.get("name"),
            tool_call.get("tool_name"),
            tool_call.get("tool"),
            tool_call.get("function"),
            tool_call.get("function_name"),
            tool_call.get("function_id"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        return ""

    @staticmethod
    def _normalize_tools_available(server_tools: Any) -> tuple[bool, set]:
        """
        Normalizes the available tools into a set of tool names.

        Supports formats used in the gateway today:
        - ListToolsResult.tools: list with objects having .name
        - {"tools": list|dict}
        - flat dict { name: description }
        - plain list of tool dicts (from cache)
        Returns (valid, names)
        """
        names: set = set()
        try:
            if hasattr(server_tools, "tools"):
                tools_attr = server_tools.tools
                if isinstance(tools_attr, list):
                    for tool in tools_attr:
                        name = getattr(tool, "name", None)
                        if isinstance(name, str) and name:
                            names.add(name)
                    return True, names
                if isinstance(tools_attr, dict):
                    for key in tools_attr:
                        if isinstance(key, str) and key:
                            names.add(key)
                    return True, names

            if isinstance(server_tools, dict):
                if "tools" in server_tools:
                    inner = server_tools.get("tools")
                    if isinstance(inner, list):
                        for item in inner:
                            if isinstance(item, dict):
                                if "name" in item and isinstance(item["name"], str):
                                    names.add(item["name"])
                                else:
                                    for k in item:
                                        if isinstance(k, str):
                                            names.add(k)
                        return True, names
                    if isinstance(inner, dict):
                        for key in inner:
                            if isinstance(key, str):
                                names.add(key)
                        return True, names
                else:
                    for key in server_tools:
                        if isinstance(key, str):
                            names.add(key)
                    return True, names

            # Handle plain list of tool dicts (e.g., from cache)
            if isinstance(server_tools, list):
                for item in server_tools:
                    if isinstance(item, dict) and "name" in item:
                        name = item["name"]
                        if isinstance(name, str) and name:
                            names.add(name)
                    elif hasattr(item, "name"):
                        # Handle tool objects with .name attribute
                        name = getattr(item, "name", None)
                        if isinstance(name, str) and name:
                            names.add(name)
                if names:  # Only return True if we found at least one tool
                    return True, names

        except Exception:
            return False, set()

        return False, set()

    @staticmethod
    def get_available_tool_names(server_tools: Any) -> tuple[bool, set[str]]:
        """
        Public helper to expose normalized tool names to callers.
        """
        return ToolExecutionService._normalize_tools_available(server_tools)

    @asynccontextmanager
    async def open_session(
        self, server_config: dict[str, Any]
    ) -> AsyncIterator[ClientSession]:
        """
        Opens a single stdio MCP session using the provided server_config.

        server_config must provide: command: str, args: list[str], env: Optional[dict]
        """
        command: str = server_config["command"]
        args: list[str] = server_config.get("args", [])
        env: dict[str, str] | None = server_config.get("env")

        async with stdio_client(
            StdioServerParameters(command=command, args=args, env=env)
        ) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize and capture server metadata
                init_result = await session.initialize()

                # Extract server description from initialization response
                # InitializeResult is a Pydantic model, so we access attributes directly
                server_info = getattr(init_result, "serverInfo", {})
                if hasattr(server_info, "description"):
                    server_description = server_info.description
                else:
                    server_description = getattr(server_info, "description", "")

                if hasattr(server_info, "name"):
                    server_name = server_info.name
                else:
                    server_name = getattr(server_info, "name", "unknown")

                if hasattr(server_info, "version"):
                    server_version = server_info.version
                else:
                    server_version = getattr(server_info, "version", "unknown")

                # Store the dynamic server metadata for later use
                session._server_description = server_description
                session._server_name = server_name
                session._server_version = server_version
                session._server_info = server_info

                self._session = session
                try:
                    yield session
                finally:
                    self._session = None

    @staticmethod
    async def call_tool(
        session: ClientSession, tool_name: str, args: dict[str, Any]
    ) -> Any:
        return await session.call_tool(tool_name, arguments=args)

    async def execute_batch(
        self,
        server_name: str,
        tool_calls: list[dict[str, Any]],
        server_config: dict[str, Any],
        server_tools: Any,
        extract_text: bool = True,
    ) -> dict[str, Any]:
        """
        Executes a batch of tools in a single stdio session. No guardrails are applied here.
        Returns a normalized result with per-call statuses and responses.
        """
        tool_calls = tool_calls or []
        valid, available = self._normalize_tools_available(server_tools)
        if not valid:
            return {
                "status": "error",
                "message": "Unknown server tools format",
                "server_name": server_name,
                "results": [],
            }

        for tool_call in tool_calls:
            name = self._normalize_tool_name(tool_call)
            if not name or name not in available:
                return {
                    "status": "error",
                    "message": f"Tool '{name or 'unknown'}' not found for this server",
                    "server_name": server_name,
                    "results": [],
                }

        results: list[dict[str, Any]] = []

        async with self.open_session(server_config) as session:
            # Capture server metadata for potential return
            server_metadata = {
                "description": getattr(session, "_server_description", None),
                "name": getattr(session, "_server_name", None),
                "version": getattr(session, "_server_version", None),
                "server_info": getattr(session, "_server_info", None),
            }

            for index, tool_call in enumerate(tool_calls):
                name = self._normalize_tool_name(tool_call)
                args = (
                    tool_call.get("args")
                    or tool_call.get("arguments")
                    or tool_call.get("tool_arguments")
                    or tool_call.get("tool_input_arguments")
                    or tool_call.get("tool_args")
                    or tool_call.get("tool_input_args")
                    or tool_call.get("parameters")
                    or tool_call.get("input")
                    or tool_call.get("params")
                    or {}
                )
                try:
                    result = await self.call_tool(session, name, args)
                    text_output = ""
                    if extract_text and hasattr(result, "content") and result.content:
                        first = result.content[0]
                        if getattr(first, "type", None) == "text":
                            text_output = getattr(first, "text", "") or ""

                    results.append(
                        {
                            "status": "success",
                            "message": "Request processed successfully",
                            "response": text_output,
                            "enkrypt_mcp_data": {
                                "call_index": index,
                                "server_name": server_name,
                                "tool_name": name,
                                "args": args,
                            },
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "status": "error",
                            "error": str(exc),
                            "message": "Error while processing tool call",
                            "enkrypt_mcp_data": {
                                "call_index": index,
                                "server_name": server_name,
                                "tool_name": name,
                                "args": args,
                            },
                        }
                    )
                    break

        successful_calls = len([r for r in results if r["status"] == "success"])
        failed_calls = len([r for r in results if r["status"] == "error"])

        return {
            "server_name": server_name,
            "status": "success" if failed_calls == 0 else "partial",
            "summary": {
                "total_calls": len(tool_calls),
                "successful_calls": successful_calls,
                "blocked_calls": 0,
                "failed_calls": failed_calls,
            },
            "results": results,
        }
