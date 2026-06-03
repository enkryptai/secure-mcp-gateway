"""
Safe, no-throw helpers for incrementing the Prometheus counter / histogram
instruments declared in ``opentelemetry_provider.py``.

Per-request phase timing (Cache & Performance dashboard)
--------------------------------------------------------
``RequestTimings`` lives on a ``contextvars.ContextVar`` so async tasks
inside the same request share the same accumulator without having to
thread it through method signatures.  Each phase is wrapped with
``phase_timer("preprocess_duration_ms")`` which records elapsed
wall-clock ms under that field name.  At log time, the success /
blocked log lines splat ``**finalize_request_timings()`` to surface
the breakdown alongside the existing structured fields.

The dashboard's "Per-Request Latency Breakdown" panels query the
corresponding ``log.attributes.*_duration_ms`` fields (already
declared in ``gateway-logs-elastic-template.json``).


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

import contextvars
import logging
import time
from typing import Any, Iterable, Mapping, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-request phase timing  (Cache & Performance dashboard)
# ---------------------------------------------------------------------------

# A contextvar so async tasks within the same request share the same
# accumulator without per-method-signature threading.  When two phases
# run concurrently (e.g. async input guardrails) we accumulate -- the
# resulting *_duration_ms field will be the SUM of overlapping phases,
# not wall time, but the total_request_duration_ms (computed from a
# single start mark) is wall time.  Dashboards label each panel "Avg
# (ms)" so summed concurrent phases are still meaningful.
_REQUEST_TIMINGS: contextvars.ContextVar[Optional[dict[str, Any]]] = (
    contextvars.ContextVar("enkrypt_request_timings", default=None)
)


def start_request_timings() -> dict[str, Any]:
    """Initialise a fresh timings dict for the current request /
    contextvar scope.  Returns the dict so the caller can attach it
    to the span if desired.

    Idempotent: if a dict already exists, returns it unchanged.
    """
    existing = _REQUEST_TIMINGS.get()
    if existing is not None:
        return existing
    t: dict[str, Any] = {"_request_start": time.perf_counter()}
    _REQUEST_TIMINGS.set(t)
    return t


def get_request_timings() -> Optional[dict[str, Any]]:
    """Return the active timings dict (or None if not in a request)."""
    return _REQUEST_TIMINGS.get()


def finalize_request_timings() -> dict[str, Any]:
    """Compute ``total_request_duration_ms`` from the request start
    mark and return a clean ``*_duration_ms`` dict suitable for
    splatting into ``logger.info(..., extra=build_log_extra(..., **))``.

    Always returns at least ``{}`` -- never raises.  Internal
    bookkeeping keys (prefixed ``_``) are stripped from the return.
    """
    t = _REQUEST_TIMINGS.get()
    if not t:
        return {}
    start = t.pop("_request_start", None)
    if start is not None:
        t["total_request_duration_ms"] = (time.perf_counter() - start) * 1000.0
    # Drop any other underscore-prefixed bookkeeping; keep only numeric
    # _duration_ms fields rounded to 2 dp for dashboard readability.
    return {
        k: round(float(v), 2)
        for k, v in t.items()
        if not k.startswith("_") and isinstance(v, (int, float))
    }


def reset_request_timings() -> None:
    """Drop the current request's timings dict.  Call at request exit
    if you don't want it leaking to the next operation in the same
    async context (rare; contextvars usually scope per-task)."""
    _REQUEST_TIMINGS.set(None)


class phase_timer:
    """Context manager + async context manager that records elapsed
    ms into the active request timings dict under ``field_name``.

    Repeated entries with the same name ACCUMULATE (so a multi-leg
    phase like "two guardrail checks" naturally sums into one
    ``guardrail_duration_ms`` field).  No-op if no request timings
    dict is active.

    Example::

        async with phase_timer("preprocess_duration_ms"):
            await input_guardrail.validate(...)
        async with phase_timer("guardrail_duration_ms"):
            await input_guardrail.validate(...)   # adds to same accumulator
    """

    __slots__ = ("field_name", "_start", "_also_into")

    def __init__(self, field_name: str, *also_into: str) -> None:
        self.field_name = field_name
        # Extra accumulator names -- e.g. preprocess_duration_ms also
        # contributes to guardrail_duration_ms.  Passed positionally.
        self._also_into = also_into
        self._start: float = 0.0

    def __enter__(self) -> "phase_timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._record()

    async def __aenter__(self) -> "phase_timer":
        self._start = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self._record()

    def _record(self) -> None:
        elapsed_ms = (time.perf_counter() - self._start) * 1000.0
        t = _REQUEST_TIMINGS.get()
        if t is None:
            return
        for name in (self.field_name, *self._also_into):
            t[name] = t.get(name, 0.0) + elapsed_ms


def record_session_active(delta: int, server_name: str = "") -> None:
    """Bump the ``enkrypt.session.active`` UpDownCounter by ``delta``.

    Positive on session acquire (new worker), negative on release /
    evict / reap.  No-op if telemetry is disabled.  Server name is
    attached as an attribute so the dashboard's "Active Sessions"
    panel can pivot per-server.
    """
    mgr = _get_manager()
    if mgr is None or delta == 0:
        return
    _add(getattr(mgr, "active_sessions_gauge", None), delta, {
        "server_name": server_name,
    })


def record_phase_ms(field_name: str, elapsed_ms: float, *also_into: str) -> None:
    """Manually record a phase duration (when a context manager isn't
    convenient -- e.g. timing was captured by a different mechanism
    like an OTel span end-time).  No-op if no request timings dict
    is active.
    """
    t = _REQUEST_TIMINGS.get()
    if t is None:
        return
    try:
        v = float(elapsed_ms)
    except (TypeError, ValueError):
        return
    for name in (field_name, *also_into):
        t[name] = t.get(name, 0.0) + v


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
# Per-detector violation detail (PII entities + Toxicity subtypes)
#
# The upstream Enkrypt guardrail provider returns rich per-detector detail
# inside ``violation.metadata["details"]``, but the schema is opaque (Enkrypt
# changes shapes between detector versions and is not strictly typed on our
# side).  These helpers parse the most common shapes defensively, emit
# metrics for what they find, and ALWAYS return a small dict the caller can
# splat into a structlog ``info()`` call (so log-based dashboards still get
# the breakdown even if the metric shape evolves).
#
# Schema reference (best-effort, from observed responses + fallback default
# at ``enkrypt_provider._DETECTOR_DEFAULTS``):
#
#   PII detector       -> details["pii"]["entities"]: list[{"type": "EMAIL",
#                                                            "value": "...",
#                                                            "start": int,
#                                                            "end":   int}]
#                         OR list of bare type strings ["EMAIL", "PHONE"].
#
#   Toxicity detector  -> details["toxicity"] is a dict of subtype->score
#                         floats, e.g. {"toxicity": 0.91, "severe_toxicity":
#                         0.12, "insult": 0.74, "threat": 0.0, ...}.
#                         Sometimes nested under "categories" or "scores".
#
# When the actual response deviates we still want a record of what arrived;
# the helpers therefore return ``details_keys`` (the top-level keys of the
# details dict) so the operator can spot drift in the Audit / Guardrails
# Deep Dive dashboards and update the parser.
# ---------------------------------------------------------------------------


# Toxicity subtypes Enkrypt is known to surface today.  Anything outside
# this set still gets emitted as long as the value is numeric -- the set is
# only used to tag the metric attribute when we want a stable enum value.
_KNOWN_TOXICITY_SUBTYPES = frozenset({
    "toxicity",
    "severe_toxicity",
    "obscene",
    "threat",
    "insult",
    "identity_hate",
    "identity_attack",
    "hate",
})


def _score_bucket(score: float) -> str:
    """Map a 0..1 detector score to a coarse bucket for dashboarding.

    Detector scores are continuous floats; turning them into a 3-bucket
    keyword (low|medium|high) lets dashboards do a simple pie/stack-bar
    without needing percentile aggregations on every panel.
    """
    try:
        v = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if v >= 0.85:
        return "high"
    if v >= 0.5:
        return "medium"
    return "low"


def _extract_pii_entities(details: Any) -> tuple[list[str], int]:
    """Return ``(entity_types, count)`` from a PII details payload.

    Defensive against the three shapes we have seen Enkrypt return:
      - ``{"entities": [{"type": "EMAIL", ...}, ...]}``  (most common)
      - ``{"entities": ["EMAIL", "PHONE"]}``
      - ``["EMAIL", "PHONE"]``                            (bare list)

    Empty list and ``count == 0`` mean "nothing to emit"; callers should
    skip emission rather than emit a zero-count metric.
    """
    if not details:
        return [], 0

    raw_entities: list[Any] = []
    if isinstance(details, Mapping):
        for key in ("entities", "pii_entities", "found_entities", "types"):
            v = details.get(key)
            if isinstance(v, list) and v:
                raw_entities = v
                break
    elif isinstance(details, list):
        raw_entities = details

    types: list[str] = []
    for item in raw_entities:
        if isinstance(item, Mapping):
            t = (
                item.get("type")
                or item.get("entity_type")
                or item.get("label")
                or item.get("name")
            )
            if t:
                types.append(str(t).upper())
        elif isinstance(item, str):
            types.append(item.upper())
    return types, len(types)


def _extract_toxicity_subtypes(
    details: Any,
    threshold: float = 0.5,
) -> tuple[list[tuple[str, float]], list[str]]:
    """Return ``(triggered, all_keys_seen)`` where ``triggered`` is a list
    of ``(subtype, score)`` tuples for every subtype above ``threshold``.

    Defensive against Enkrypt shapes:
      - flat ``{"insult": 0.85, "threat": 0.02, ...}``   (most common)
      - nested ``{"categories": {<same>}}`` / ``{"scores": {<same>}}``
      - list ``[{"name": "insult", "score": 0.85}, ...]``

    Returns the raw keys-seen list so the caller can attach
    ``toxicity_details_keys`` to a debug log when nothing crossed the
    threshold (helps operators spot schema drift).
    """
    if not details:
        return [], []

    payload: Mapping[str, Any]
    if isinstance(details, Mapping):
        for key in ("categories", "scores", "subtypes"):
            inner = details.get(key)
            if isinstance(inner, Mapping):
                payload = inner
                break
        else:
            payload = details
    else:
        payload = {}

    triggered: list[tuple[str, float]] = []
    keys_seen: list[str] = []

    if isinstance(payload, Mapping):
        for k, v in payload.items():
            keys_seen.append(str(k))
            try:
                score = float(v)
            except (TypeError, ValueError):
                continue
            if score >= threshold:
                triggered.append((str(k).lower(), score))
    elif isinstance(details, list):
        for item in details:
            if isinstance(item, Mapping):
                name = item.get("name") or item.get("subtype") or item.get("type")
                score_raw = (
                    item.get("score")
                    or item.get("value")
                    or item.get("confidence")
                )
                if not name:
                    continue
                keys_seen.append(str(name))
                try:
                    score = float(score_raw)
                except (TypeError, ValueError):
                    continue
                if score >= threshold:
                    triggered.append((str(name).lower(), score))

    triggered.sort(key=lambda t: t[1], reverse=True)
    return triggered, sorted(set(keys_seen))


def record_pii_entities(
    violations: Iterable[Any],
    direction: str,
    server_name: str = "",
    tool_name: str = "",
    guardrail_name: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> dict[str, Any]:
    """Walk violations of type ``pii``, extract per-entity detail and emit
    ``enkrypt.guardrail.pii_entity`` (one increment per entity, attribute
    ``entity_type``).

    Returns a dict suitable for splatting into a structured log so log-based
    dashboards get matching fields:

        {"pii_entities_count":  int,
         "pii_entity_types":    list[str],   # unique, sorted
         "pii_details_keys":    list[str]}   # for debug/drift detection
    """
    mgr = _get_manager()
    counter = getattr(mgr, "guardrail_pii_entity_counter", None) if mgr else None

    total = 0
    types_all: list[str] = []
    details_keys: set[str] = set()

    for v in violations or ():
        vt = getattr(v, "violation_type", None)
        if vt is None and isinstance(v, Mapping):
            vt = v.get("violation_type")
        vt_str = str(vt).lower() if vt is not None else ""
        if "pii" not in vt_str:
            continue

        metadata = getattr(v, "metadata", None) or (
            v.get("metadata") if isinstance(v, Mapping) else None
        )
        if not metadata:
            continue
        details = metadata.get("details") if isinstance(metadata, Mapping) else None
        if isinstance(details, Mapping):
            details_keys.update(str(k) for k in details.keys())

        types, count = _extract_pii_entities(details)
        if not types:
            continue
        total += count
        types_all.extend(types)

        if counter is not None:
            for t in types:
                _add(counter, 1, {
                    "entity_type":    t,
                    "direction":      direction,
                    "server_name":    server_name,
                    "tool_name":      tool_name,
                    "guardrail_name": guardrail_name,
                    "user_id":        user_id,
                    "project_id":     project_id,
                })

    return {
        "pii_entities_count": total,
        "pii_entity_types":   sorted(set(types_all)) if types_all else [],
        "pii_details_keys":   sorted(details_keys) if details_keys else [],
    }


def record_toxicity_subtypes(
    violations: Iterable[Any],
    direction: str,
    server_name: str = "",
    tool_name: str = "",
    guardrail_name: Optional[str] = None,
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Walk violations of type ``toxicity`` (or ``toxic_content``), extract
    per-subtype scores above ``threshold`` and emit
    ``enkrypt.guardrail.toxicity_subtype`` (one increment per subtype,
    attributes ``subtype`` + ``score_bucket``).

    Returns a dict suitable for splatting into a structured log:

        {"toxicity_subtypes":      list[str],   # unique sorted
         "toxicity_top_subtype":   str | "",
         "toxicity_top_score":     float,
         "toxicity_details_keys":  list[str]}
    """
    mgr = _get_manager()
    counter = getattr(mgr, "guardrail_toxicity_subtype_counter", None) if mgr else None

    triggered_all: list[tuple[str, float]] = []
    details_keys: set[str] = set()

    for v in violations or ():
        vt = getattr(v, "violation_type", None)
        if vt is None and isinstance(v, Mapping):
            vt = v.get("violation_type")
        vt_str = str(vt).lower() if vt is not None else ""
        # Match both "toxicity" and the ViolationType.TOXIC_CONTENT enum
        # name ("toxic_content"); strict equality would miss either form.
        if "toxic" not in vt_str:
            continue

        metadata = getattr(v, "metadata", None) or (
            v.get("metadata") if isinstance(v, Mapping) else None
        )
        if not metadata:
            continue
        details = metadata.get("details") if isinstance(metadata, Mapping) else None
        if isinstance(details, Mapping):
            details_keys.update(str(k) for k in details.keys())

        triggered, _ = _extract_toxicity_subtypes(details, threshold=threshold)
        triggered_all.extend(triggered)

        if counter is not None:
            for subtype, score in triggered:
                _add(counter, 1, {
                    "subtype":        subtype,
                    "score_bucket":   _score_bucket(score),
                    "direction":      direction,
                    "server_name":    server_name,
                    "tool_name":      tool_name,
                    "guardrail_name": guardrail_name,
                    "user_id":        user_id,
                    "project_id":     project_id,
                })

    subtypes_unique = sorted({s for s, _ in triggered_all})
    top_subtype, top_score = ("", 0.0)
    if triggered_all:
        top_subtype, top_score = max(triggered_all, key=lambda t: t[1])

    return {
        "toxicity_subtypes":     subtypes_unique,
        "toxicity_top_subtype":  top_subtype,
        "toxicity_top_score":    round(top_score, 4) if top_score else 0.0,
        "toxicity_details_keys": sorted(details_keys) if details_keys else [],
    }


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


# ---------------------------------------------------------------------------
# Audit / compliance (Audit Trail dashboard)
# ---------------------------------------------------------------------------
#
# Two-layer emission contract, applied by every helper below:
#   1. The "umbrella" counters (admin_actions_counter and -- when the
#      operation is privileged -- privileged_operations_counter) always fire,
#      with a standardised attribute set: action / resource_type / surface /
#      actor / actor_id / success.  These power top-N actor, by-action, by-
#      surface aggregations in the Audit Trail dashboard.
#   2. The "specific" counter for the event category fires alongside (e.g.
#      audit_apikey_rotated_counter for rotate-apikey, projects_created_counter
#      for create-project).  These power per-KPI tiles like "API Keys Rotated".
#
# Why both?  The umbrella alone can't power per-event-type KPI cards without
# expensive client-side aggregation; the specific alone can't power "Top
# Actors" because OSD can't union-aggregate across 17 separate metric names
# in one panel.  Emitting both is cheap (~17 instruments, one .add() each)
# and keeps every Audit Trail panel queryable without bespoke pivots.
#
# Each helper also accepts ``surface`` (cli / rest_api / mcp_gateway), which
# is the dashboard's "Operations by Surface (gateway:8000 vs api:8001)"
# panel pivot.

_PRIVILEGED_ACTIONS = {
    # System destructive / installer-level
    "system_reset",
    "system_restore",
    "system_backup",
    # Settings that change auth posture
    "settings_enkrypt_api_key_set",
    "settings_telemetry_changed",
    # Cache mutations
    "cache_flush",
    # Anything that creates / rotates / deletes credentials
    "apikey_created",
    "apikey_deleted",
    "apikey_disabled",
    "apikey_rotated",
}


def _record_admin_envelope(
    mgr: Any,
    *,
    action: str,
    resource_type: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Increment the umbrella counters + return the attribute dict the
    caller should reuse for the specific counter.

    Internal -- public callers go through the typed helpers below.
    """
    attrs: dict[str, Any] = {
        "action": action,
        "resource_type": resource_type,
        "surface": surface,
        "actor": actor,
        "actor_id": actor_id,
        "target_id": target_id,
        "success": "true" if success else "false",
    }
    if extra:
        # Don't let extras silently overwrite the canonical attributes --
        # the dashboard pivots on those exact field names.
        for k, v in extra.items():
            attrs.setdefault(k, v)
    if not success and failure_reason:
        attrs["failure_reason"] = failure_reason

    _add(getattr(mgr, "admin_actions_counter", None), 1, attrs)
    if action in _PRIVILEGED_ACTIONS:
        _add(getattr(mgr, "privileged_operations_counter", None), 1, attrs)
    return attrs


def record_admin_action(
    action: str,
    resource_type: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
    **extra: Any,
) -> None:
    """Generic admin-action emission for mutations that don't have a
    specific counter (e.g. listing/searching/exporting/importing).

    For mutations that DO have a dedicated counter (apikey/user/project
    lifecycle, system ops, cache flush, settings), prefer the typed
    helpers below -- they call this internally AND fire the specific
    counter alongside.

    Parameters
    ----------
    action : str
        Short tag for the action, snake_case (e.g. ``"config_list"``,
        ``"apikey_export"``).
    resource_type : str
        What the action operates on: ``"config"``, ``"apikey"``,
        ``"user"``, ``"project"``, ``"settings"``, ``"system"``,
        ``"cache"``.
    surface : str
        ``"cli"`` (admin CLI), ``"rest_api"`` (admin API on port 8001),
        or ``"mcp_gateway"`` (cache-flush endpoint on port 8000).
    actor : str | None
        Human-readable actor (email, CLI username).  Optional.
    actor_id : str | None
        Stable actor ID (apikey suffix, user_id).  Optional.
    target_id : str | None
        ID of the resource being acted on.  Optional.
    success : bool
        Whether the action succeeded.  Always emit on both paths so the
        dashboard can show success rate.
    failure_reason : str | None
        Short tag when success is False (e.g. ``"unauthorized"``,
        ``"not_found"``, ``"validation_error"``).
    """
    mgr = _get_manager()
    if mgr is None:
        return
    _record_admin_envelope(
        mgr,
        action=action,
        resource_type=resource_type,
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
        extra=extra,
    )


def record_cache_flush(
    scope: str,
    surface: str,
    authorization_path: Optional[str] = None,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit for every cache-flush request.

    Parameters
    ----------
    scope : str
        ``"all"`` | ``"gateway_config"`` | ``"server_config"`` |
        ``"tool_cache"`` -- matches the cache-management service's
        cache_type argument.
    surface : str
        ``"rest_api"`` (port 8001) or ``"mcp_gateway"`` (port 8000) --
        the two surfaces that expose the flush endpoint.
    authorization_path : str | None
        ``"admin_apikey"`` (super-admin) or ``"org_id_allowlist"``
        (per-org allow-list) -- which auth route accepted the request.
        Powers the "Cache Flush Authorization Paths" panel.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = _record_admin_envelope(
        mgr,
        action="cache_flush",
        resource_type="cache",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
        extra={"scope": scope, "authorization_path": authorization_path},
    )
    _add(getattr(mgr, "admin_cache_flush_counter", None), 1, attrs)


_APIKEY_LIFECYCLE_COUNTERS = {
    "created": "audit_apikey_created_counter",
    "deleted": "audit_apikey_deleted_counter",
    "disabled": "audit_apikey_disabled_counter",
    "rotated": "audit_apikey_rotated_counter",
}


def record_apikey_lifecycle(
    event: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit on apikey CRUD.

    ``event`` is one of ``created`` | ``deleted`` | ``disabled`` |
    ``rotated``.  Rotation additionally bumps the umbrella
    ``apikey_rotations_counter``.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    specific = _APIKEY_LIFECYCLE_COUNTERS.get(event)
    if specific is None:
        # Unknown event -- only emit the envelope so the request still
        # shows up in totals; don't silently drop.
        record_admin_action(
            action=f"apikey_{event}",
            resource_type="apikey",
            surface=surface,
            actor=actor,
            actor_id=actor_id,
            target_id=target_id,
            success=success,
            failure_reason=failure_reason,
        )
        return
    attrs = _record_admin_envelope(
        mgr,
        action=f"apikey_{event}",
        resource_type="apikey",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
    )
    _add(getattr(mgr, specific, None), 1, attrs)
    if event == "rotated":
        _add(getattr(mgr, "apikey_rotations_counter", None), 1, attrs)


_USER_LIFECYCLE_COUNTERS = {
    "created": "audit_user_created_counter",
    "deleted": "audit_user_deleted_counter",
}


def record_user_lifecycle(
    event: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit on user CRUD.  ``event`` is ``created`` | ``deleted``."""
    mgr = _get_manager()
    if mgr is None:
        return
    specific = _USER_LIFECYCLE_COUNTERS.get(event)
    attrs = _record_admin_envelope(
        mgr,
        action=f"user_{event}",
        resource_type="user",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
    )
    if specific:
        _add(getattr(mgr, specific, None), 1, attrs)


def record_project_created(
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit on project create.  Currently the only project lifecycle
    event the dashboard surfaces as a KPI."""
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = _record_admin_envelope(
        mgr,
        action="project_created",
        resource_type="project",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
    )
    _add(getattr(mgr, "projects_created_counter", None), 1, attrs)


_SYSTEM_OP_COUNTERS = {
    "backup": "system_backup_completed_counter",
    "reset": "system_reset_counter",
    "restore": "system_restore_counter",
}


def record_system_op(
    op: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit on system ops.  ``op`` is ``backup`` | ``reset`` | ``restore``.

    These are intentionally tagged as privileged ops (see
    ``_PRIVILEGED_ACTIONS``) -- the dashboard's "Privileged Operations"
    panel will pick them up automatically via the umbrella counter.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    specific = _SYSTEM_OP_COUNTERS.get(op)
    attrs = _record_admin_envelope(
        mgr,
        action=f"system_{op}",
        resource_type="system",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        success=success,
        failure_reason=failure_reason,
    )
    if specific:
        _add(getattr(mgr, specific, None), 1, attrs)


_SETTINGS_COUNTERS = {
    "enkrypt_api_key_set": "audit_settings_enkrypt_api_key_set_counter",
    "telemetry_changed": "audit_settings_telemetry_changed_counter",
}


def record_settings_change(
    setting: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
    **extra: Any,
) -> None:
    """Emit on changes to security-sensitive settings.

    ``setting`` is ``enkrypt_api_key_set`` | ``telemetry_changed``.
    Other settings without a dedicated counter fall back to the umbrella
    via ``record_admin_action`` so they're still visible in totals.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    specific = _SETTINGS_COUNTERS.get(setting)
    attrs = _record_admin_envelope(
        mgr,
        action=f"settings_{setting}",
        resource_type="settings",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        success=success,
        failure_reason=failure_reason,
        extra=extra,
    )
    if specific:
        _add(getattr(mgr, specific, None), 1, attrs)


def record_config_modified(
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    change_kind: Optional[str] = None,
    changed_fields: Optional[Iterable[str]] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit on every successful change to mcp_configs / servers /
    guardrails / projects/users/apikeys at the *file* level (i.e. things
    that go through ``cli config update-*`` or the equivalent REST
    endpoints).

    Parameters
    ----------
    change_kind : str | None
        Short tag (``add_server``, ``update_server``, ``remove_server``,
        ``update_guardrails``, ...).  Powers the dashboard's
        "Actions by Type" panel.
    changed_fields : iterable of str | None
        Names of fields that were modified.  Joined comma-separated into
        a single ``changed_fields`` attribute so the panel "Recent Audit
        Events (changed_fields)" can show them; *not* exploded into
        per-field labels to avoid cardinality blow-up.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    extra: dict[str, Any] = {}
    if change_kind:
        extra["change_kind"] = change_kind
    if changed_fields:
        extra["changed_fields"] = ",".join(sorted(set(changed_fields)))
    attrs = _record_admin_envelope(
        mgr,
        action="config_modified",
        resource_type="config",
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
        extra=extra,
    )
    _add(getattr(mgr, "audit_config_modified_counter", None), 1, attrs)


def record_unauthorized_http(
    endpoint: str,
    surface: str,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    reason: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> None:
    """Emit on every 401/403 from the admin REST surface or the
    gateway-MCP surface.

    Distinct from :func:`record_auth_outcome` (which counts per-apikey,
    per-provider auth decisions): this counter is per-HTTP-request and
    pivots on endpoint / status_code / reason for the "Unauthorized HTTP"
    KPI tile.
    """
    mgr = _get_manager()
    if mgr is None:
        return
    attrs = {
        "endpoint": endpoint,
        "surface": surface,
        "method": method,
        "status_code": str(status_code) if status_code is not None else None,
        "reason": reason,
        "actor_id": actor_id,
    }
    _add(getattr(mgr, "auth_unauthorized_http_counter", None), 1, attrs)


__all__ = [
    "record_tool_call_outcome",
    "record_guardrail_violations",
    "record_pii_redaction",
    "record_auth_outcome",
    "record_guardrail_api",
    "record_compliance_hits",
    "record_pii_entities",
    "record_toxicity_subtypes",
    # Per-request phase timing (Cache & Performance dashboard)
    "start_request_timings",
    "get_request_timings",
    "finalize_request_timings",
    "reset_request_timings",
    "phase_timer",
    "record_phase_ms",
    "record_session_active",
    "record_error_by_code",
    "record_tool_permission_denied",
    "record_degradation",
    "record_transport_error",
    "record_discovery_failure",
    # Audit / compliance (Audit Trail dashboard)
    "record_admin_action",
    "record_cache_flush",
    "record_apikey_lifecycle",
    "record_user_lifecycle",
    "record_project_created",
    "record_system_op",
    "record_settings_change",
    "record_config_modified",
    "record_unauthorized_http",
]
