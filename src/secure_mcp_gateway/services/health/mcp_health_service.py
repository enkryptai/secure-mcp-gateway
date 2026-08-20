"""MCP Server health check and info service.

Provides connectivity checks, tool discovery, and tool execution
for arbitrary MCP servers supplied via raw JSON config (no pre-registration required).

Sandboxing
----------
The health endpoints accept arbitrary user-supplied commands + args, so they
spawn the target MCP server **inside a sandbox by default** (``sandbox.enabled = True``).
Callers can override or opt out via the ``sandbox`` field in the request body.

OpenTelemetry coverage
----------------------
Each public method emits:

* a span with canonical name (``enkrypt.health.server_check``,
  ``enkrypt.health.server_info``, ``enkrypt.health.tool_call``) carrying the
  server name, endpoint label, status, latency, and optional tool metadata;
* structured info/error logs with ``server_name``, ``endpoint``, ``status`` and
  ``response_time_ms``;
* metrics ``enkrypt.health.requests`` / ``.success`` / ``.failures`` (counters)
  and ``enkrypt.health.duration`` (histogram, seconds) labelled by endpoint
  and status, so per-endpoint dashboards can be built without log scraping.

Telemetry calls are guarded so the service still works when the global
telemetry manager has not been initialised (e.g. unit tests / standalone API
server runs).
"""

import time
from typing import Any, Dict, List, Optional

from secure_mcp_gateway.client import forward_tool_call, get_server_metadata_only
from secure_mcp_gateway.plugins.sandbox.config_manager import (
    get_sandbox_config_manager,
)
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
from secure_mcp_gateway.plugins.telemetry.conventions import (
    SpanAttributes,
    SpanNames,
    set_span_attr_with_legacy,
)
from secure_mcp_gateway.utils import logger

# ---------------------------------------------------------------------------
# Telemetry helpers
# ---------------------------------------------------------------------------


def _get_tracer():
    """Return a tracer if telemetry is initialised, otherwise ``None``.

    The manager raises ``RuntimeError`` when no provider is active.  The health
    APIs run inside the FastAPI process which may or may not have telemetry
    bootstrapped (see telemetry-bootstrap follow-up), so we tolerate both.
    """
    try:
        return get_telemetry_config_manager().get_tracer()
    except Exception:  # pragma: no cover - telemetry not initialised
        return None


def _record_metrics(
    *,
    endpoint: str,
    status: str,
    duration_seconds: float,
    server_name: str,
    tool_name: Optional[str] = None,
) -> None:
    """Increment health-API counters and record latency."""
    try:
        manager = get_telemetry_config_manager()
    except Exception:  # pragma: no cover
        return

    base_attrs: Dict[str, Any] = {
        "endpoint": endpoint,
        "status": status,
        "server_name": server_name,
    }
    if tool_name is not None:
        base_attrs["tool_name"] = tool_name

    request_counter = manager.health_request_counter
    if request_counter is not None:
        request_counter.add(1, attributes=base_attrs)

    duration = manager.health_request_duration
    if duration is not None:
        duration.record(duration_seconds, attributes=base_attrs)

    if status == "ok":
        success = manager.health_success_counter
        if success is not None:
            success.add(1, attributes=base_attrs)
    else:
        failure = manager.health_failure_counter
        if failure is not None:
            failure.add(1, attributes=base_attrs)


def _set_span_basics(span, *, endpoint: str, server_name: str) -> None:
    if span is None:
        return
    try:
        span.set_attribute(SpanAttributes.HEALTH_ENDPOINT, endpoint)
        set_span_attr_with_legacy(span, SpanAttributes.SERVER_NAME, server_name)
    except Exception:  # pragma: no cover
        pass


def _set_span_outcome(
    span,
    *,
    status: str,
    elapsed_ms: float,
    extra_attrs: Optional[Dict[str, Any]] = None,
    error: Optional[BaseException] = None,
) -> None:
    if span is None:
        return
    try:
        span.set_attribute(SpanAttributes.HEALTH_STATUS, status)
        span.set_attribute(SpanAttributes.HEALTH_RESPONSE_TIME_MS, round(elapsed_ms, 1))
        span.set_attribute(
            SpanAttributes.SUCCESS, status == "ok" or status == "connected"
        )
        if extra_attrs:
            for k, v in extra_attrs.items():
                if v is not None:
                    span.set_attribute(k, v)
        if error is not None:
            span.set_attribute(SpanAttributes.ERROR_CODE, type(error).__name__)
            span.set_attribute(SpanAttributes.ERROR_MESSAGE, str(error))
            try:
                span.record_exception(error)
            except Exception:  # pragma: no cover
                pass
    except Exception:  # pragma: no cover
        pass


class _NullSpanCtx:
    """Async-safe no-op span context used when no tracer is available."""

    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def _span(name: str):
    tracer = _get_tracer()
    if tracer is None:
        return _NullSpanCtx()
    try:
        return tracer.start_as_current_span(name)
    except Exception:  # pragma: no cover
        return _NullSpanCtx()


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
        endpoint = "server_check"
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        with _span(SpanNames.HEALTH_SERVER_CHECK) as span:
            _set_span_basics(span, endpoint=endpoint, server_name=server_name)
            logger.info(
                "[MCPHealthService] Server health check started",
                extra={"endpoint": endpoint, "server_name": server_name},
            )

            try:
                result = await get_server_metadata_only(server_name, gateway_config)
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000
                metadata = result.get("server_metadata", {}) if result else {}

                _set_span_outcome(
                    span,
                    status="connected",
                    elapsed_ms=elapsed_ms,
                )
                _record_metrics(
                    endpoint=endpoint,
                    status="ok",
                    duration_seconds=elapsed,
                    server_name=server_name,
                )
                logger.info(
                    "[MCPHealthService] Server health check ok",
                    extra={
                        "endpoint": endpoint,
                        "server_name": server_name,
                        "status": "connected",
                        "response_time_ms": round(elapsed_ms, 1),
                    },
                )

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
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000
                _set_span_outcome(
                    span,
                    status="unreachable",
                    elapsed_ms=elapsed_ms,
                    error=exc,
                )
                _record_metrics(
                    endpoint=endpoint,
                    status="unreachable",
                    duration_seconds=elapsed,
                    server_name=server_name,
                )
                logger.error(
                    "[MCPHealthService] Server health check failed",
                    extra={
                        "endpoint": endpoint,
                        "server_name": server_name,
                        "status": "unreachable",
                        "response_time_ms": round(elapsed_ms, 1),
                        "error": f"{type(exc).__name__}: {exc}",
                    },
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
        endpoint = "server_info"
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        with _span(SpanNames.HEALTH_SERVER_INFO) as span:
            _set_span_basics(span, endpoint=endpoint, server_name=server_name)
            logger.info(
                "[MCPHealthService] Server info started",
                extra={"endpoint": endpoint, "server_name": server_name},
            )

            try:
                result = await forward_tool_call(
                    server_name, None, None, gateway_config
                )
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000

                metadata = result.get("server_metadata", {}) if result else {}
                tools_result = result.get("tools") if result else None
                tool_list = self._serialize_tools(tools_result)

                _set_span_outcome(
                    span,
                    status="ok",
                    elapsed_ms=elapsed_ms,
                    extra_attrs={SpanAttributes.HEALTH_TOOL_COUNT: len(tool_list)},
                )
                _record_metrics(
                    endpoint=endpoint,
                    status="ok",
                    duration_seconds=elapsed,
                    server_name=server_name,
                )
                logger.info(
                    "[MCPHealthService] Server info ok",
                    extra={
                        "endpoint": endpoint,
                        "server_name": server_name,
                        "status": "ok",
                        "tool_count": len(tool_list),
                        "response_time_ms": round(elapsed_ms, 1),
                    },
                )

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
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000
                _set_span_outcome(
                    span,
                    status="error",
                    elapsed_ms=elapsed_ms,
                    error=exc,
                )
                _record_metrics(
                    endpoint=endpoint,
                    status="error",
                    duration_seconds=elapsed,
                    server_name=server_name,
                )
                logger.error(
                    "[MCPHealthService] Server info failed",
                    extra={
                        "endpoint": endpoint,
                        "server_name": server_name,
                        "status": "error",
                        "response_time_ms": round(elapsed_ms, 1),
                        "error": f"{type(exc).__name__}: {exc}",
                    },
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
        endpoint = "tool_call"
        gateway_config = self._build_gateway_config(
            server_name, config, description, sandbox
        )
        sandbox_cfg = gateway_config["mcp_config"][0]["sandbox"]
        start = time.monotonic()

        with _span(SpanNames.HEALTH_TOOL_CALL) as span:
            _set_span_basics(span, endpoint=endpoint, server_name=server_name)
            if span is not None:
                try:
                    set_span_attr_with_legacy(span, SpanAttributes.TOOL_NAME, tool_name)
                except Exception:  # pragma: no cover
                    pass
            logger.info(
                "[MCPHealthService] Tool execution started",
                extra={
                    "endpoint": endpoint,
                    "server_name": server_name,
                    "tool_name": tool_name,
                },
            )

            try:
                result = await forward_tool_call(
                    server_name, tool_name, tool_args, gateway_config
                )
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000

                content = self._serialize_call_result(result)
                is_error = bool(getattr(result, "isError", False))
                status = "error" if is_error else "ok"

                _set_span_outcome(
                    span,
                    status=status,
                    elapsed_ms=elapsed_ms,
                )
                _record_metrics(
                    endpoint=endpoint,
                    status=status,
                    duration_seconds=elapsed,
                    server_name=server_name,
                    tool_name=tool_name,
                )
                if is_error:
                    logger.error(
                        "[MCPHealthService] Tool execution returned error",
                        extra={
                            "endpoint": endpoint,
                            "server_name": server_name,
                            "tool_name": tool_name,
                            "status": status,
                            "response_time_ms": round(elapsed_ms, 1),
                        },
                    )
                else:
                    logger.info(
                        "[MCPHealthService] Tool execution ok",
                        extra={
                            "endpoint": endpoint,
                            "server_name": server_name,
                            "tool_name": tool_name,
                            "status": status,
                            "response_time_ms": round(elapsed_ms, 1),
                        },
                    )

                return {
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "execution": {
                        "status": status,
                        "result": content,
                        "response_time_ms": round(elapsed_ms, 1),
                    },
                    "sandbox": self._sandbox_status_payload(sandbox_cfg),
                }
            except Exception as exc:
                elapsed = time.monotonic() - start
                elapsed_ms = elapsed * 1000
                _set_span_outcome(
                    span,
                    status="error",
                    elapsed_ms=elapsed_ms,
                    error=exc,
                )
                _record_metrics(
                    endpoint=endpoint,
                    status="error",
                    duration_seconds=elapsed,
                    server_name=server_name,
                    tool_name=tool_name,
                )
                logger.error(
                    "[MCPHealthService] Tool execution failed",
                    extra={
                        "endpoint": endpoint,
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "status": "error",
                        "response_time_ms": round(elapsed_ms, 1),
                        "error": f"{type(exc).__name__}: {exc}",
                    },
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
