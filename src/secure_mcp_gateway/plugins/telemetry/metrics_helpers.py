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
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

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
    attributes: Mapping[str, Any] | None = None,
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
    attributes: Mapping[str, Any] | None = None,
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
    duration_ms: float | None = None,
    block_reason: str | None = None,
    user_id: str | None = None,
    project_id: str | None = None,
    project_name: str | None = None,
    project_registry: str | None = None,
    org_id: str | None = None,
    gateway_name: str | None = None,
    gateway_version: str | None = None,
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
    user_id, project_id, project_name, project_registry, org_id,
    gateway_name, gateway_version : str | None
        Identity attributes echoed from ``request_context`` (cloud auth)
        or the local apikey lookup. Optional -- when present, attached as
        metric attributes so per-tenant / per-gateway-revision PromQL
        alerts (e.g. ``sum by (gateway_version)``, ``sum by (org_id)``)
        work without a Loki pivot. ``_safe_attrs`` strips these when
        ``None``/empty so we don't explode label cardinality with empty
        strings.
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
        "project_name": project_name,
        "project_registry": project_registry,
        "org_id": org_id,
        "gateway_name": gateway_name,
        "gateway_version": gateway_version,
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
    guardrail_name: str | None = None,
    user_id: str | None = None,
    project_id: str | None = None,
    project_name: str | None = None,
    project_registry: str | None = None,
    org_id: str | None = None,
    gateway_name: str | None = None,
    gateway_version: str | None = None,
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
            "project_name": project_name,
            "project_registry": project_registry,
            "org_id": org_id,
            "gateway_name": gateway_name,
            "gateway_version": gateway_version,
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
    user_id: str | None = None,
    project_id: str | None = None,
    project_name: str | None = None,
    project_registry: str | None = None,
    org_id: str | None = None,
    gateway_name: str | None = None,
    gateway_version: str | None = None,
) -> None:
    """Increment ``pii_redactions_counter`` when input is redacted or output
    is de-anonymised.  ``direction`` is ``"input"`` or ``"output"``.

    Identity attributes (``user_id`` / ``project_id`` / ``project_name`` /
    ``project_registry`` / ``org_id`` / ``gateway_name`` / ``gateway_version``)
    are attached when present so the ``PII Detected`` alert can pivot
    per-principal or per-gateway revision.
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
        "project_name": project_name,
        "project_registry": project_registry,
        "org_id": org_id,
        "gateway_name": gateway_name,
        "gateway_version": gateway_version,
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
    failure_reason: str | None = None,
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
# Playground registry lookup (/mcp-playground/* in registry-header mode)
# ---------------------------------------------------------------------------


def record_registry_lookup(
    outcome: str,
    duration_ms: float,
    status_code: int | None = None,
    cache: str = "miss",
    saved_name: str | None = None,
    server_version: str | None = None,
    registry_name: str | None = None,
    project_name: str | None = None,
) -> None:
    """Record latency of a ``GET /mcp-registry/get-server`` call.

    Parameters
    ----------
    outcome : str
        ``"success" | "auth_error" | "not_found" | "upstream_error" | "timeout"``.
    duration_ms : float
        Elapsed time in milliseconds (including cache hits, which are ~0).
    status_code : int | None
        HTTP status returned by the cloud (``0`` / ``None`` for network /
        timeout failures, omitted on cache hits).
    cache : str
        ``"hit"`` if the response was served from the in-process 10s cache,
        ``"miss"`` if the cloud was actually contacted.
    saved_name, server_version, registry_name, project_name : str | None
        Labels echoed from the request headers — attached so per-server /
        per-registry dashboards work without a Loki pivot. ``_safe_attrs``
        strips ``None`` / empty so we don't explode label cardinality.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "outcome": outcome,
        "cache": cache,
        "status_code": str(status_code) if status_code is not None else None,
        "saved_name": saved_name,
        "server_version": server_version,
        "registry_name": registry_name,
        "project_name": project_name,
    }
    _record(
        getattr(mgr, "playground_registry_lookup_duration", None),
        duration_ms,
        attrs,
    )


# ---------------------------------------------------------------------------
# Playground consumer-info lookup (/mcp-playground/* inline mode + provider=enkrypt)
# ---------------------------------------------------------------------------


def record_consumer_info_lookup(
    outcome: str,
    duration_ms: float,
    status_code: int | None = None,
    cache: str = "miss",
    user_id: str | None = None,
    org_id: str | None = None,
    project_name: str | None = None,
    is_internal_req: bool | None = None,
) -> None:
    """Record latency of a ``GET /consumer-info`` call.

    Parameters
    ----------
    outcome : str
        ``"success" | "auth_error" | "upstream_error" | "timeout"``.
    duration_ms : float
        Elapsed time in milliseconds (cache hits are ~0).
    status_code : int | None
        HTTP status returned by the cloud (``None`` on network/timeout
        failures and on cache hits).
    cache : str
        ``"hit"`` if served from the in-process 5min cache, ``"miss"`` if
        the cloud was actually contacted.
    user_id, org_id, project_name, is_internal_req : optional identity
        labels echoed from the response. Same names as ``record_tool_call_outcome``
        so per-tenant dashboards stay consistent. ``_safe_attrs`` strips
        ``None`` / empty so we don't explode label cardinality.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "outcome": outcome,
        "cache": cache,
        "status_code": str(status_code) if status_code is not None else None,
        "user_id": user_id,
        "org_id": org_id,
        "project_name": project_name,
        "is_internal_req": str(is_internal_req).lower()
        if is_internal_req is not None
        else None,
    }
    _record(
        getattr(mgr, "playground_consumer_info_lookup_duration", None),
        duration_ms,
        attrs,
    )


__all__ = [
    "record_auth_outcome",
    "record_consumer_info_lookup",
    "record_guardrail_api",
    "record_guardrail_violations",
    "record_pii_redaction",
    "record_registry_lookup",
    "record_tool_call_outcome",
]
