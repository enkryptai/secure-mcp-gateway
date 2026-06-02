"""
Safe, no-throw helpers for incrementing the Prometheus counter / histogram
instruments declared in ``opentelemetry_provider.py``.

Why this module exists
----------------------
The OpenTelemetry provider declares ~17 metric instruments, but most
application code never touches them, so the corresponding Prometheus metrics
were flat zero (the original Grafana alert rules had to be Loki/LogQL backed
as a result).  Sprinkling

    if telemetry_manager and telemetry_manager.foo_counter:
        telemetry_manager.foo_counter.add(1, attributes=...)

across 4-5 files is verbose, easy to break, and makes attribute conventions
drift between call sites.  This module centralises that pattern: each helper
takes only domain arguments, looks up the manager lazily, picks the right
instrument by name, attaches the standard label set, and never raises.

If telemetry has not been initialised (e.g. unit tests, CLI commands) every
helper degrades to a no-op silently.

Helpers
-------
``record_tool_call_outcome(server_name, tool_name, outcome, duration_ms=None)``
    outcome in {"success", "failure", "error", "blocked"}.

``record_guardrail_violations(direction, violation_types, server_name,
                              tool_name, guardrail_name=None)``
    direction in {"input", "output"}.  Increments overall +
    directional + per-check counters.

``record_pii_redaction(direction, count=1, server_name="", tool_name="")``
    direction in {"input", "output"}.

``record_auth_outcome(provider, outcome)``
    outcome in {"success", "failure"}.

``record_guardrail_api(direction, status_code, duration_ms,
                       provider="enkrypt", check_kind="policy")``
    Increments request counter + records latency histogram around external
    guardrail API calls.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

logger = logging.getLogger(__name__)


def _get_manager():
    """Return the live telemetry manager or ``None``.  Never raises."""
    try:
        from secure_mcp_gateway.plugins.telemetry.config_manager import (
            get_telemetry_config_manager,
        )

        return get_telemetry_config_manager()
    except Exception:
        return None


def _safe_attrs(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """Drop None values - OTel SDK rejects them."""
    return {k: v for k, v in attrs.items() if v is not None and v != ""}


def _add(
    counter: Any,
    value: int = 1,
    attributes: Optional[Mapping[str, Any]] = None,
) -> None:
    if counter is None:
        return
    try:
        counter.add(value, attributes=_safe_attrs(attributes or {}))
    except Exception as exc:
        logger.debug("metrics_helpers: failed to record counter: %s", exc)


def _record(
    histogram: Any,
    value: float,
    attributes: Optional[Mapping[str, Any]] = None,
) -> None:
    if histogram is None:
        return
    try:
        histogram.record(value, attributes=_safe_attrs(attributes or {}))
    except Exception as exc:
        logger.debug("metrics_helpers: failed to record histogram: %s", exc)


# ---------------------------------------------------------------------------
# Tool call lifecycle
# ---------------------------------------------------------------------------

_TOOL_CALL_OUTCOME_COUNTERS = {
    "success": "tool_call_success_counter",
    "failure": "tool_call_failure_counter",
    "error": "tool_call_error_counter",
    "blocked": "tool_call_blocked_counter",
}


def record_tool_call_outcome(
    server_name: str,
    tool_name: str,
    outcome: str,
    duration_ms: Optional[float] = None,
    block_reason: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> None:
    """Increment the right tool-call lifecycle counter.

    Parameters
    ----------
    server_name, tool_name : str
        Used as labels.
    outcome : str
        One of ``"success" | "failure" | "error" | "blocked"``.
    duration_ms : float | None
        If supplied, also records ``tool_call_duration``.
    block_reason : str | None
        Only used when ``outcome == "blocked"`` (e.g. ``input_violation``,
        ``output_violation``, ``deny_list``).
    user_id, project_id : str | None
        Authenticated request principal.  Optional — when present, attached as
        metric attributes so per-user / per-project Grafana alerts (e.g. the
        ``User Repeatedly Triggering Guardrails`` rule) can target a single
        offender.  ``_safe_attrs`` strips these when ``None``/empty so we don't
        explode label cardinality with empty strings.
    """
    mgr = _get_manager()
    if mgr is None:
        return

    attrs = {
        "server_name": server_name,
        "tool_name": tool_name,
        "outcome": outcome,
        "user_id": user_id,
        "project_id": project_id,
    }
    if outcome == "blocked" and block_reason:
        attrs["block_reason"] = block_reason

    counter_name = _TOOL_CALL_OUTCOME_COUNTERS.get(outcome)
    if counter_name is not None:
        _add(getattr(mgr, counter_name, None), 1, attrs)

    if duration_ms is not None:
        _record(getattr(mgr, "tool_call_duration", None), duration_ms, attrs)


# ---------------------------------------------------------------------------
# Guardrail violations
# ---------------------------------------------------------------------------

_GUARDRAIL_DIRECTION_COUNTERS = {
    "input": "input_guardrail_violation_counter",
    "output": "output_guardrail_violation_counter",
}

# Per-check counters - only fire when the violation type matches.
_GUARDRAIL_TYPE_COUNTERS = {
    "relevancy": "relevancy_violation_counter",
    "adherence": "adherence_violation_counter",
    "hallucination": "hallucination_violation_counter",
}


def record_guardrail_violations(
    direction: str,
    violation_types: Iterable[Any],
    server_name: str = "",
    tool_name: str = "",
    guardrail_name: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> None:
    """Record one or more guardrail violations.

    Increments:
      - ``guardrail_violation_counter``  (overall, once per violation)
      - ``input_guardrail_violation_counter`` or
        ``output_guardrail_violation_counter`` (directional)
      - one of {relevancy, adherence, hallucination}_violation_counter
        if the violation_type matches.

    Parameters
    ----------
    user_id, project_id : str | None
        Authenticated request principal.  Optional — when present, attached as
        metric attributes so the Grafana ``User Repeatedly Triggering
        Guardrails`` alert can target a single offender via PromQL ``sum by
        (user_id) (...)``.  ``_safe_attrs`` strips these when ``None``/empty.
    """
    mgr = _get_manager()
    if mgr is None:
        return

    directional_name = _GUARDRAIL_DIRECTION_COUNTERS.get(direction)

    for vt in violation_types or ():
        vt_str = str(vt).lower()
        attrs = {
            "direction": direction,
            "violation_type": vt_str,
            "server_name": server_name,
            "tool_name": tool_name,
            "guardrail_name": guardrail_name,
            "user_id": user_id,
            "project_id": project_id,
        }
        _add(getattr(mgr, "guardrail_violation_counter", None), 1, attrs)
        if directional_name:
            _add(getattr(mgr, directional_name, None), 1, attrs)
        type_counter_name = _GUARDRAIL_TYPE_COUNTERS.get(vt_str)
        if type_counter_name:
            _add(getattr(mgr, type_counter_name, None), 1, attrs)


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------


def record_pii_redaction(
    direction: str,
    count: int = 1,
    server_name: str = "",
    tool_name: str = "",
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> None:
    """Increment ``pii_redactions_counter`` when input is redacted or output
    is de-anonymised.  ``direction`` is ``"input"`` or ``"output"``.

    ``user_id`` / ``project_id`` are attached as metric attributes when
    present so the ``PII Detected`` alert can pivot per-principal.
    """
    if count <= 0:
        return
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "direction": direction,
        "server_name": server_name,
        "tool_name": tool_name,
        "user_id": user_id,
        "project_id": project_id,
    }
    _add(getattr(mgr, "pii_redactions_counter", None), count, attrs)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_AUTH_OUTCOME_COUNTERS = {
    "success": "auth_success_counter",
    "failure": "auth_failure_counter",
}


def record_auth_outcome(
    provider: str,
    outcome: str,
    failure_reason: Optional[str] = None,
) -> None:
    """outcome in {"success", "failure"}.  ``provider`` identifies which auth
    plugin produced the result (e.g. ``local_apikey``, ``enkrypt``).
    """
    mgr = _get_manager()
    if mgr is None:
        return
    counter_name = _AUTH_OUTCOME_COUNTERS.get(outcome)
    if counter_name is None:
        return
    attrs = {"provider": provider, "outcome": outcome}
    if outcome == "failure" and failure_reason:
        attrs["failure_reason"] = failure_reason
    _add(getattr(mgr, counter_name, None), 1, attrs)


# ---------------------------------------------------------------------------
# Guardrail API (external HTTP calls to a guardrail provider)
# ---------------------------------------------------------------------------


def record_guardrail_api(
    direction: str,
    status_code: int,
    duration_ms: float,
    provider: str = "enkrypt",
    check_kind: str = "policy",
) -> None:
    """Increment ``guardrail_api_request_counter`` and record
    ``guardrail_api_request_duration`` around an external guardrail provider
    call.

    Parameters
    ----------
    direction : str
        ``"input"`` or ``"output"``.
    status_code : int
        HTTP status code returned by the guardrail provider (use ``0`` for
        client-side / network failures).
    duration_ms : float
        Elapsed time in milliseconds.
    provider : str
        Provider name label, e.g. ``"enkrypt"``.
    check_kind : str
        Sub-kind of guardrail check, e.g. ``"policy" | "relevancy" |
        "adherence" | "hallucination" | "pii"``.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "direction": direction,
        "status_code": str(status_code),
        "provider": provider,
        "check_kind": check_kind,
    }
    _add(getattr(mgr, "guardrail_api_request_counter", None), 1, attrs)
    _record(getattr(mgr, "guardrail_api_request_duration", None), duration_ms, attrs)


# ---------------------------------------------------------------------------
# Compliance framework attribution
# ---------------------------------------------------------------------------


def record_compliance_hits(
    violations: Iterable[Any],
    direction: str,
    server_name: str = "",
    tool_name: str = "",
    guardrail_name: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> None:
    """Walk each violation's ``metadata.details.compliance_mapping`` and
    increment :data:`MetricNames.GUARDRAIL_COMPLIANCE_HIT` once per
    ``(framework, framework_id)`` pair.

    The upstream Enkrypt guardrail provider returns shape::

        violation.metadata = {
            "policy_type": "injection_attack",
            "value": 1,
            "details": {
                "safe": "0.000075",
                "attack": "0.999925",
                "compliance_mapping": {
                    "owasp_llm_2025": ["LLM01:2025 Prompt Injection"],
                    "mitre_atlas":    ["AML.T0051", "AML.T0054"],
                    "nist_ai_rmf":    ["MAP 2.3, MEASURE 2.3 ..."],
                    "eu_ai_act":      ["Article 15(4) ..."],
                    "iso_iec_standards": ["ISO/IEC 27001 A.14.2 ..."]
                }
            }
        }

    Each entry becomes a counter increment so the Security Posture dashboard
    can render per-framework heat-maps without having to re-parse the raw
    response on the query side.

    No-op when ``violations`` is empty, the provider did not return a
    ``compliance_mapping``, or telemetry is disabled.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    counter = getattr(mgr, "guardrail_compliance_hit_counter", None)
    if counter is None:
        return

    for v in violations or ():
        # GuardrailViolation has ``metadata`` (dict) and ``violation_type``
        # (enum or str).  Use getattr so this works for both attrs-style
        # objects and plain dicts.
        metadata = getattr(v, "metadata", None) or (
            v.get("metadata") if isinstance(v, Mapping) else None
        )
        if not metadata:
            continue
        details = (metadata.get("details") or {}) if isinstance(metadata, Mapping) else {}
        mapping = details.get("compliance_mapping") if isinstance(details, Mapping) else None
        if not isinstance(mapping, Mapping):
            continue
        vt = getattr(v, "violation_type", None)
        if vt is None and isinstance(v, Mapping):
            vt = v.get("violation_type")
        vt_str = str(vt).lower() if vt is not None else ""

        for framework, ids in mapping.items():
            if not isinstance(ids, (list, tuple)):
                ids = [ids]
            for fw_id in ids:
                attrs = {
                    "framework": str(framework),
                    "framework_id": str(fw_id),
                    "direction": direction,
                    "violation_type": vt_str,
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "guardrail_name": guardrail_name,
                    "user_id": user_id,
                    "project_id": project_id,
                }
                _add(counter, 1, attrs)


# ---------------------------------------------------------------------------
# Centralised error emission (one increment per MCPGatewayError)
# ---------------------------------------------------------------------------


def record_error_by_code(
    error_code: Any,
    severity: Any = None,
    recovery_strategy: Any = None,
    component: Optional[str] = None,
    server_name: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> None:
    """Increment :data:`MetricNames.ERRORS_BY_CODE` with the error's
    ``ErrorCode``, ``ErrorSeverity`` and ``RecoveryStrategy`` as attributes.

    Powers every widget in the *Error Forensics* dashboard.  Called from
    :func:`error_handling.ErrorMonitor.track_error` so every error
    automatically lands here -- no per-call-site instrumentation required.

    All arguments may be enum instances *or* strings; ``str(...)`` is used
    to coerce.  Empty values are stripped by ``_safe_attrs``.
    """
    mgr = _get_manager()
    if mgr is None:
        return

    def _stringify(value: Any) -> str:
        if value is None:
            return ""
        v = getattr(value, "value", value)
        return str(v)

    attrs = {
        "error_code": _stringify(error_code),
        "severity": _stringify(severity),
        "recovery_strategy": _stringify(recovery_strategy),
        "component": component,
        "server_name": server_name,
        "tool_name": tool_name,
    }
    _add(getattr(mgr, "errors_by_code_counter", None), 1, attrs)


# ---------------------------------------------------------------------------
# Tool permission denied (server-tool allow/deny policy)
# ---------------------------------------------------------------------------


def record_tool_permission_denied(
    server_name: str,
    tool_name: str,
    reason: str = "deny_list",
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> None:
    """Increment :data:`MetricNames.TOOL_PERMISSION_DENIED` when a tool is
    refused by the per-server allow/deny policy (before the tool even runs).

    ``reason`` is the kind of policy refusal:
      ``"deny_list"``   -- tool explicitly on the deny list
      ``"not_in_allow_list"`` -- allow-list is set and tool is not in it
      ``"server_disabled"``   -- the whole server is administratively off
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "server_name": server_name,
        "tool_name": tool_name,
        "reason": reason,
        "user_id": user_id,
        "project_id": project_id,
    }
    _add(getattr(mgr, "tool_permission_denied_counter", None), 1, attrs)


# ---------------------------------------------------------------------------
# Degradation (fail-open / fail-closed verdicts)
# ---------------------------------------------------------------------------


def record_degradation(
    mode: str,
    reason: str,
    component: str,
    server_name: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> None:
    """Increment :data:`MetricNames.DEGRADATION_FAIL_OPEN` or
    :data:`MetricNames.DEGRADATION_FAIL_CLOSED` when a guardrail / downstream
    error forces the gateway to a degraded verdict.

    Parameters
    ----------
    mode : str
        ``"fail_open"`` -- the call was allowed despite the error
        ``"fail_closed"`` -- the call was blocked because of the error
    reason : str
        Short reason tag, e.g. ``"guardrail_timeout"``,
        ``"guardrail_api_error"``, ``"upstream_unreachable"``.
    component : str
        Which subsystem degraded, e.g. ``"input_guardrail"``,
        ``"output_guardrail"``, ``"tool_execution"``.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    counter_attr = (
        "degradation_fail_open_counter"
        if mode == "fail_open"
        else "degradation_fail_closed_counter"
    )
    attrs = {
        "mode": mode,
        "reason": reason,
        "component": component,
        "server_name": server_name,
        "tool_name": tool_name,
    }
    _add(getattr(mgr, counter_attr, None), 1, attrs)


# ---------------------------------------------------------------------------
# MCP client transport errors (HTTP / stdio)
# ---------------------------------------------------------------------------


def record_transport_error(
    transport: str,
    error_kind: str,
    server_name: str = "",
    tool_name: Optional[str] = None,
    status_code: Optional[int] = None,
) -> None:
    """Increment :data:`MetricNames.TRANSPORT_ERRORS` when the MCP client
    fails to talk to a downstream server.

    Parameters
    ----------
    transport : str
        ``"http"``, ``"stdio"``, ``"sse"``, ``"streamable_http"``.
    error_kind : str
        Short tag, e.g. ``"timeout"``, ``"connect_refused"``,
        ``"unexpected_eof"``, ``"http_5xx"``, ``"unauthorized"``.
    status_code : int | None
        HTTP status code when available (HTTP transports only).
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "transport": transport,
        "error_kind": error_kind,
        "server_name": server_name,
        "tool_name": tool_name,
        "status_code": str(status_code) if status_code is not None else None,
    }
    _add(getattr(mgr, "transport_error_counter", None), 1, attrs)


# ---------------------------------------------------------------------------
# Discovery failures per downstream MCP server
# ---------------------------------------------------------------------------


def record_discovery_failure(
    server_name: str,
    reason: str,
    transport: Optional[str] = None,
) -> None:
    """Increment :data:`MetricNames.DISCOVERY_SERVER_FAILURES` when a
    downstream server's tool discovery fails.

    ``reason`` is a short tag, e.g. ``"timeout"``, ``"connect_refused"``,
    ``"initialize_failed"``, ``"empty_result"``, ``"transport_error"``.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "server_name": server_name,
        "reason": reason,
        "transport": transport,
    }
    _add(getattr(mgr, "discovery_server_failure_counter", None), 1, attrs)


__all__ = [
    "record_tool_call_outcome",
    "record_guardrail_violations",
    "record_pii_redaction",
    "record_auth_outcome",
    "record_guardrail_api",
    "record_compliance_hits",
    "record_error_by_code",
    "record_tool_permission_denied",
    "record_degradation",
    "record_transport_error",
    "record_discovery_failure",
]
