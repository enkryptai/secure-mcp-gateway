"""Structured audit logging for the Audit Trail dashboard.

Why a separate module
---------------------
Audit events are a distinct telemetry class from operational logs:

* They MUST persist regardless of log-level (so we always log at INFO,
  not DEBUG).
* They MUST emit a stable structured shape -- ``log.attributes.audit_action``,
  ``log.attributes.actor``, ``log.attributes.surface``,
  ``log.attributes.target_id``, ``log.attributes.changed_fields`` --
  because the "Recent Admin Log Entries" panels in the Audit Trail
  dashboard pivot on those field names.
* They MUST also fire the matching metric counter (via
  :mod:`secure_mcp_gateway.plugins.telemetry.metrics_helpers`) so the
  numeric KPIs and the per-entry log table stay in sync from a single
  call site.  This module is the single source of truth for the two
  emissions; callers always go through :func:`log_audit`, never raw
  ``logger.info`` for admin events.

Usage
-----
Inside any admin mutation handler (CLI command, REST endpoint, cache
flush, system op)::

    from secure_mcp_gateway.audit import log_audit

    log_audit(
        action="apikey_rotated",
        resource_type="apikey",
        surface="cli",  # cli | rest_api | mcp_gateway
        actor="alice@example.com",
        actor_id="****abcd",        # last 4 chars of the *actor's* apikey
        target_id="****1234",        # the rotated apikey's last 4 chars
        success=True,
        changed_fields=("apikey_value",),
    )

If the underlying mutation fails, set ``success=False`` and pass
``failure_reason="unauthorized"`` (or similar tag).  Always emit -- the
dashboard's success-rate panels need both outcomes.

The metric emission is automatic: ``log_audit`` introspects the
``action`` argument and dispatches to the right metrics_helpers function
(see :data:`_METRIC_DISPATCH`).
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

from .plugins.telemetry import metrics_helpers as mh

# Try to import structlog up-front so the import error (if any) only
# happens once.  But we resolve the BoundLogger lazily inside each
# log_audit() call (see ``_get_audit_logger``) -- structlog's processor
# chain can be reconfigured at runtime (e.g. by telemetry reload), and a
# BoundLogger captured at module import time keeps its old processors,
# so log lines emitted after the reload silently route to a dead chain.
# Resolving each call ensures we always pick up the current config.
try:
    import structlog as _structlog
except Exception:  # pragma: no cover - structlog may not be installed
    _structlog = None  # type: ignore[assignment]


def _get_audit_logger() -> Any:
    """Return a fresh logger for the audit channel.

    structlog (when available) gives us JSON output with the canonical
    ``log.attributes.*`` shape the dashboard pivots on.  If structlog
    isn't installed or fails to construct, fall back to stdlib logging
    so the call never crashes.
    """
    if _structlog is not None:
        try:
            return _structlog.get_logger("enkrypt.audit")
        except Exception:
            pass
    return logging.getLogger("enkrypt.audit")


# Backwards-compat alias.  Existing tests monkeypatch this; we keep it
# pointing at a freshly-resolved logger so the test fixture still works.
_audit_logger: Any = _get_audit_logger()


# ---------------------------------------------------------------------------
# Action -> metrics-helper dispatch
# ---------------------------------------------------------------------------
#
# The audit dashboard pairs every log entry with a metric counter.  Rather
# than make every caller remember to call both, we route by ``action``
# below.  Adding a new audit category? Add the action keys here and they
# get instrumented automatically.

_APIKEY_EVENTS = {"apikey_created", "apikey_deleted", "apikey_disabled", "apikey_rotated"}
_USER_EVENTS = {"user_created", "user_deleted"}
_SYSTEM_EVENTS = {"system_backup", "system_reset", "system_restore"}
_SETTINGS_EVENTS = {
    "settings_enkrypt_api_key_set",
    "settings_telemetry_changed",
}


def _emit_metric(
    *,
    action: str,
    resource_type: str,
    surface: str,
    actor: Optional[str],
    actor_id: Optional[str],
    target_id: Optional[str],
    success: bool,
    failure_reason: Optional[str],
    changed_fields: Optional[Iterable[str]],
    extra: Mapping[str, Any],
) -> None:
    """Fire the matching metric counter for the audit event.

    Never raises -- metric emission must not break the admin mutation
    itself.  This duplicates ``record_admin_action``'s safety net for
    paranoia: the helper is already no-op-safe but if a future helper
    refactor accidentally lets through an exception, we catch it here.
    """
    common = dict(
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
    )
    try:
        if action in _APIKEY_EVENTS:
            mh.record_apikey_lifecycle(
                event=action.removeprefix("apikey_"),
                surface=surface,
                **common,
            )
        elif action in _USER_EVENTS:
            mh.record_user_lifecycle(
                event=action.removeprefix("user_"),
                surface=surface,
                **common,
            )
        elif action == "project_created":
            mh.record_project_created(surface=surface, **common)
        elif action in _SYSTEM_EVENTS:
            mh.record_system_op(
                op=action.removeprefix("system_"),
                surface=surface,
                actor=actor,
                actor_id=actor_id,
                success=success,
                failure_reason=failure_reason,
            )
        elif action in _SETTINGS_EVENTS:
            mh.record_settings_change(
                setting=action.removeprefix("settings_"),
                surface=surface,
                actor=actor,
                actor_id=actor_id,
                success=success,
                failure_reason=failure_reason,
                **{k: v for k, v in extra.items() if k not in {
                    "actor", "actor_id", "target_id", "success", "failure_reason",
                }},
            )
        elif action == "cache_flush":
            mh.record_cache_flush(
                scope=str(extra.get("scope", "all")),
                surface=surface,
                authorization_path=extra.get("authorization_path"),
                **common,
            )
        elif action == "config_modified":
            mh.record_config_modified(
                surface=surface,
                actor=actor,
                actor_id=actor_id,
                target_id=target_id,
                change_kind=extra.get("change_kind"),
                changed_fields=changed_fields,
                success=success,
                failure_reason=failure_reason,
            )
        else:
            # Unknown action -- still emit the envelope so the dashboard's
            # "Admin Actions (total)" tile counts it.
            mh.record_admin_action(
                action=action,
                resource_type=resource_type,
                surface=surface,
                **common,
            )
    except Exception:  # pragma: no cover - never let metric break audit log
        pass


def log_audit(
    *,
    action: str,
    resource_type: str,
    surface: str,
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    success: bool = True,
    failure_reason: Optional[str] = None,
    changed_fields: Optional[Iterable[str]] = None,
    **extra: Any,
) -> None:
    """Emit one audit event (structured log + matching metric counter).

    All parameters are keyword-only because callers nearly always pass
    several and positional ordering would be a footgun.

    Parameters
    ----------
    action : str
        Snake_case tag.  Either one of the known events (see
        ``_APIKEY_EVENTS`` etc.) or a free-form tag for things like
        ``"config_search"``.  Known events route to the typed metric
        helper; unknown ones fall through to the umbrella.
    resource_type : str
        ``apikey`` | ``user`` | ``project`` | ``config`` | ``settings``
        | ``system`` | ``cache``.
    surface : str
        ``cli`` (admin CLI), ``rest_api`` (admin API on :8001), or
        ``mcp_gateway`` (cache-flush endpoint on :8000).
    actor : str | None
        Human-readable actor (e.g. ``alice@enkryptai.com``).  Optional;
        when missing, panel shows ``unknown``.
    actor_id : str | None
        Stable actor ID (apikey suffix, OS username for CLI).
    target_id : str | None
        Resource ID being acted on.
    success : bool
        Whether the underlying mutation succeeded.  Always emit on both
        paths so the dashboard's success-rate panels work.
    failure_reason : str | None
        Short tag when ``success`` is False.
    changed_fields : iterable of str | None
        For ``config_modified`` events: which fields were touched.  Joined
        comma-separated in the metric label and the log record (avoids
        cardinality blow-up of one label per field name).
    **extra
        Any additional context that goes into the structured log record
        as ``log.attributes.<key>``.  Reserved keys (``action``, ``actor``,
        ``actor_id``, ``target_id``, ``surface``, ``success``,
        ``failure_reason``, ``changed_fields``, ``resource_type``) are
        ignored to avoid duplication.
    """
    # Drop both signature-reserved keys AND the synthetic log-record keys
    # (``audit_action`` / ``admin_action``) that this function constructs
    # below.  If a caller's ``**extra`` smuggles in any of these, we
    # ignore the override -- the canonical positional / constructed value
    # wins.  See test_log_audit_constructed_log_keys_cannot_be_overwritten_by_extras.
    _RESERVED_LOG_KEYS = {
        # signature args (Python rejects collisions for these at parse
        # time, but a **dict-splat from user-controlled input could carry
        # them through unnoticed; belt-and-suspenders)
        "action", "actor", "actor_id", "target_id", "surface",
        "success", "failure_reason", "changed_fields", "resource_type",
        # synthesised log-record keys (NOT signature args, so this is
        # the layer where a caller could actually overwrite them)
        "audit_action", "admin_action",
    }
    extra_payload: dict[str, Any] = {
        k: v for k, v in extra.items() if k not in _RESERVED_LOG_KEYS
    }

    # Build the structured log record.  Keys MUST match what the Audit
    # Trail dashboard's "Recent Admin Log Entries" panels query:
    #   log.attributes.audit_action / .admin_action / .actor / .surface /
    #   .target_id / .changed_fields
    # We populate both ``audit_action`` and ``admin_action`` because the
    # dashboard uses different field names across panels (legacy /
    # current convention split).  Cheap on storage, no ambiguity.
    log_attrs: dict[str, Any] = {
        "audit_action": action,
        "admin_action": action,
        "resource_type": resource_type,
        "surface": surface,
        "actor": actor or "",
        "actor_id": actor_id or "",
        "target_id": target_id or "",
        "success": "true" if success else "false",
    }
    if not success and failure_reason:
        log_attrs["failure_reason"] = failure_reason
    if changed_fields:
        log_attrs["changed_fields"] = ",".join(sorted(set(changed_fields)))
    log_attrs.update(extra_payload)

    try:
        # Resolve the logger AT CALL TIME, not at module import.  The
        # gateway's telemetry reload re-initialises structlog's processor
        # chain; a BoundLogger captured at import time keeps the old
        # chain and silently routes to no handlers after reload.  Tests
        # monkeypatch ``_get_audit_logger`` to inject a recording fake.
        #
        # structlog binds **kwargs as bound context that the JSON/console
        # renderer surfaces alongside the event.  ``extra=log_attrs``
        # would bury the whole audit envelope under a single ``extra``
        # key in the rendered log record, which the dashboard's KQL
        # queries (log.attributes.admin_action, log.attributes.actor,
        # ...) cannot pivot on.  Splat the dict instead.
        _get_audit_logger().info(
            f"audit.{action}",  # always INFO so audit events survive log-level filters
            **log_attrs,
        )
    except Exception:  # pragma: no cover - never let logging crash a mutation
        pass

    _emit_metric(
        action=action,
        resource_type=resource_type,
        surface=surface,
        actor=actor,
        actor_id=actor_id,
        target_id=target_id,
        success=success,
        failure_reason=failure_reason,
        changed_fields=changed_fields,
        extra=extra_payload,
    )


__all__ = ["log_audit"]
