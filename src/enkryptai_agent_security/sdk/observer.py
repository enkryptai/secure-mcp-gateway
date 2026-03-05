"""Central observer — consumes ``AgentEvent`` objects, bridges them to OTel
spans and counters, records guardrail verdicts as span events, and
conditionally skips LLM spans when OpenLLMetry handles them.

Thread-safe: all span dictionaries are guarded by a ``threading.Lock``.

Metric naming follows the shared ``enkryptai_agent_security`` conventions:
  - Dot-separated namespaces
  - Durations in **seconds** (not milliseconds)
  - No ``_total`` suffix (OTel adds it)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable

from enkryptai_agent_security.telemetry.conventions import (
    MetricNames,
    SourceProduct,
    SpanAttributes,
    SpanNames,
)
from enkryptai_agent_security.telemetry.openllmetry import any_llm_instrumentor_active
from enkryptai_agent_security.telemetry.redaction import PayloadPolicy, sanitize_attributes

from enkryptai_agent_security.sdk.events import AgentEvent, EventName

log = logging.getLogger("enkryptai_agent_security.sdk.observer")


@dataclass
class _SpanHandle:
    __slots__ = ("span", "start_ns")
    span: Any  # opentelemetry.trace.Span | _NoOpSpan
    start_ns: int


class AgentObserver:
    """Receives :class:`AgentEvent` objects and translates them into
    OTel spans + metrics.

    Instantiated once per SDK lifecycle; the singleton is held in ``_state``.
    """

    def __init__(
        self,
        tracer: Any,
        meter: Any,
        payload_policy: PayloadPolicy | None = None,
    ) -> None:
        self._tracer = tracer
        self._meter = meter
        self._policy = payload_policy or PayloadPolicy()
        self._lock = threading.Lock()

        # Span registries keyed by correlation ID
        self._run_spans: dict[str, _SpanHandle] = {}
        self._step_spans: dict[str, _SpanHandle] = {}
        self._tool_spans: dict[str, _SpanHandle] = {}
        self._llm_spans: dict[str, _SpanHandle] = {}

        # Whether OpenLLMetry instrumentors handle LLM spans for us.
        # Checked once at init time so we don't pay import cost per event.
        self._openllmetry_active: bool = any_llm_instrumentor_active()
        if self._openllmetry_active:
            log.info(
                "OpenLLMetry LLM instrumentor detected — "
                "SDK will skip its own LLM spans"
            )

        # ----- Shared metrics (using canonical MetricNames) -----
        self._tool_calls = meter.create_counter(MetricNames.TOOL_CALLS)
        self._tool_duration = meter.create_histogram(MetricNames.TOOL_DURATION)
        self._tool_errors = meter.create_counter(MetricNames.TOOL_ERRORS)
        self._guardrail_blocks = meter.create_counter(MetricNames.GUARDRAIL_BLOCKS)
        self._guardrail_duration = meter.create_histogram(MetricNames.GUARDRAIL_DURATION)

        # ----- SDK-specific metrics (agent-level, no shared equivalent) -----
        self._runs_total = meter.create_counter("enkrypt.agent.runs")
        self._steps_total = meter.create_counter("enkrypt.agent.steps")
        self._llm_calls_total = meter.create_counter("enkrypt.agent.llm_calls")
        self._run_duration = meter.create_histogram("enkrypt.agent.run.duration")
        self._step_duration = meter.create_histogram("enkrypt.agent.step.duration")
        self._llm_duration = meter.create_histogram("enkrypt.agent.llm_call.duration")

        self._handlers: dict[EventName, Callable[[AgentEvent], None]] = {
            EventName.LIFECYCLE_START: self._on_lifecycle_start,
            EventName.LIFECYCLE_END: self._on_lifecycle_end,
            EventName.STEP_START: self._on_step_start,
            EventName.STEP_END: self._on_step_end,
            EventName.TOOL_CALL_START: self._on_tool_start,
            EventName.TOOL_CALL_END: self._on_tool_end,
            EventName.LLM_CALL_START: self._on_llm_start,
            EventName.LLM_CALL_END: self._on_llm_end,
            EventName.MEMORY_READ: self._on_memory,
            EventName.MEMORY_WRITE: self._on_memory,
            EventName.GUARDRAIL_CHECK: self._on_guardrail,
            EventName.GUARDRAIL_BLOCK: self._on_guardrail,
            EventName.ERROR: self._on_error,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def emit(self, event: AgentEvent) -> None:
        handler = self._handlers.get(event.name)
        if handler is not None:
            handler(event)

    @property
    def open_span_count(self) -> int:
        with self._lock:
            return (
                len(self._run_spans)
                + len(self._step_spans)
                + len(self._tool_spans)
                + len(self._llm_spans)
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _on_lifecycle_start(self, ev: AgentEvent) -> None:
        self._runs_total.add(1, {"agent_id": ev.agent_id})
        span = self._tracer.start_span(
            "agent.run",
            attributes=self._base_attrs(ev),
        )
        with self._lock:
            self._run_spans[ev.run_id] = _SpanHandle(span=span, start_ns=ev.ts_ns)

    def _on_lifecycle_end(self, ev: AgentEvent) -> None:
        with self._lock:
            handle = self._run_spans.pop(ev.run_id, None)
        if handle is None:
            return
        self._finish(handle, ev)
        duration_s = (ev.ts_ns - handle.start_ns) / 1_000_000_000
        self._run_duration.record(duration_s, {"agent_id": ev.agent_id})

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def _on_step_start(self, ev: AgentEvent) -> None:
        if ev.step_id is None:
            return
        self._steps_total.add(1, {"agent_id": ev.agent_id})
        span = self._tracer.start_span("agent.step", attributes=self._base_attrs(ev))
        with self._lock:
            self._step_spans[ev.step_id] = _SpanHandle(span=span, start_ns=ev.ts_ns)

    def _on_step_end(self, ev: AgentEvent) -> None:
        if ev.step_id is None:
            return
        with self._lock:
            handle = self._step_spans.pop(ev.step_id, None)
        if handle is None:
            return
        self._finish(handle, ev)
        duration_s = (ev.ts_ns - handle.start_ns) / 1_000_000_000
        self._step_duration.record(duration_s, {"agent_id": ev.agent_id})

    # ------------------------------------------------------------------
    # Tool calls
    # ------------------------------------------------------------------

    def _on_tool_start(self, ev: AgentEvent) -> None:
        if ev.tool_call_id is None:
            return
        attrs = {
            "agent_id": ev.agent_id,
            SpanAttributes.TOOL_NAME: ev.tool_name or "",
            SpanAttributes.SOURCE_PRODUCT: SourceProduct.SDK,
        }
        self._tool_calls.add(1, attrs)
        span = self._tracer.start_span(
            SpanNames.TOOL_EXECUTE, attributes=self._base_attrs(ev)
        )
        with self._lock:
            self._tool_spans[ev.tool_call_id] = _SpanHandle(span=span, start_ns=ev.ts_ns)

    def _on_tool_end(self, ev: AgentEvent) -> None:
        if ev.tool_call_id is None:
            return
        with self._lock:
            handle = self._tool_spans.pop(ev.tool_call_id, None)
        if handle is None:
            return
        self._finish(handle, ev)
        duration_s = (ev.ts_ns - handle.start_ns) / 1_000_000_000
        attrs = {
            "agent_id": ev.agent_id,
            SpanAttributes.TOOL_NAME: ev.tool_name or "",
        }
        self._tool_duration.record(duration_s, attrs)

    # ----------------------------------------------------------------
    # LLM calls — skipped when OpenLLMetry handles them
    # ------------------------------------------------------------------

    def _on_llm_start(self, ev: AgentEvent) -> None:
        if ev.llm_call_id is None:
            return
        if self._openllmetry_active:
            return
        self._llm_calls_total.add(1, {"agent_id": ev.agent_id, "model": ev.model_name or ""})
        span = self._tracer.start_span("agent.llm_call", attributes=self._base_attrs(ev))
        with self._lock:
            self._llm_spans[ev.llm_call_id] = _SpanHandle(span=span, start_ns=ev.ts_ns)

    def _on_llm_end(self, ev: AgentEvent) -> None:
        if ev.llm_call_id is None:
            return
        if self._openllmetry_active:
            return
        with self._lock:
            handle = self._llm_spans.pop(ev.llm_call_id, None)
        if handle is None:
            return
        self._finish(handle, ev)
        duration_s = (ev.ts_ns - handle.start_ns) / 1_000_000_000
        attrs = {"agent_id": ev.agent_id, "model": ev.model_name or ""}
        self._llm_duration.record(duration_s, attrs)

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def _on_memory(self, ev: AgentEvent) -> None:
        span = self._find_active_span(ev)
        if span is not None:
            span.add_event(ev.name.value, attributes=self._safe_attrs(ev.attributes))

    # ------------------------------------------------------------------
    # Guardrail events (Enkrypt-specific)
    # ------------------------------------------------------------------

    def _on_guardrail(self, ev: AgentEvent) -> None:
        if ev.blocked:
            self._guardrail_blocks.add(1, {"agent_id": ev.agent_id})
        if ev.guardrail:
            duration_s = ev.guardrail.processing_time_ms / 1000.0
            self._guardrail_duration.record(
                duration_s,
                {"agent_id": ev.agent_id, "provider": ev.guardrail.provider},
            )
        span = self._find_active_span(ev)
        if span is not None:
            attrs: dict[str, Any] = {
                SpanAttributes.SOURCE_PRODUCT: SourceProduct.SDK,
            }
            if ev.blocked:
                attrs[SpanAttributes.GUARDRAIL_ACTION] = "block"
            if ev.guardrail:
                attrs[SpanAttributes.GUARDRAIL_ACTION] = ev.guardrail.action.value
                attrs[SpanAttributes.GUARDRAIL_VIOLATIONS] = ",".join(ev.guardrail.violations)
            span.add_event(SpanNames.GUARDRAIL_CHECK, attributes=attrs)

    # ------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------

    def _on_error(self, ev: AgentEvent) -> None:
        self._tool_errors.add(
            1,
            {"agent_id": ev.agent_id, "error_type": ev.error_type or ""},
        )
        span = self._find_active_span(ev)
        if span is not None:
            span.add_event("agent.error", attributes={
                SpanAttributes.ERROR_CODE: ev.error_type or "",
                SpanAttributes.ERROR_MESSAGE: ev.error_message or "",
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base_attrs(self, ev: AgentEvent) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "agent.id": ev.agent_id,
            "agent.run_id": ev.run_id,
            SpanAttributes.SOURCE_PRODUCT: SourceProduct.SDK,
        }
        if ev.step_id:
            attrs["agent.step_id"] = ev.step_id
        if ev.tool_name:
            attrs[SpanAttributes.TOOL_NAME] = ev.tool_name
        if ev.model_name:
            attrs["gen_ai.request.model"] = ev.model_name
        if ev.blocked:
            attrs[SpanAttributes.GUARDRAIL_ACTION] = "block"
        if ev.pii_redacted:
            attrs["agent.pii_redacted"] = True
        attrs.update(self._safe_attrs(ev.attributes))
        return attrs

    def _safe_attrs(self, raw: dict[str, Any]) -> dict[str, Any]:
        return sanitize_attributes(raw, self._policy)

    def _find_active_span(self, ev: AgentEvent) -> Any | None:
        """Walk up the correlation chain to find the innermost active span."""
        with self._lock:
            if ev.tool_call_id and ev.tool_call_id in self._tool_spans:
                return self._tool_spans[ev.tool_call_id].span
            if ev.llm_call_id and ev.llm_call_id in self._llm_spans:
                return self._llm_spans[ev.llm_call_id].span
            if ev.step_id and ev.step_id in self._step_spans:
                return self._step_spans[ev.step_id].span
            if ev.run_id in self._run_spans:
                return self._run_spans[ev.run_id].span
        return None

    @staticmethod
    def _finish(handle: _SpanHandle, ev: AgentEvent) -> None:
        if ev.ok is False:
            handle.span.set_attribute("agent.ok", False)
            if ev.error_message:
                handle.span.set_attribute(SpanAttributes.ERROR_MESSAGE, ev.error_message)
        else:
            handle.span.set_attribute("agent.ok", True)
        handle.span.end()
