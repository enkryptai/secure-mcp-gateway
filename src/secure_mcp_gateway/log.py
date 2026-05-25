"""Structured logging configuration.

Standalone module with **no imports from secure_mcp_gateway** so it can be
imported at the very top of any entry-point (gateway, api_server, CLI) before
the rest of the package is loaded — avoiding circular-import issues.

Usage::

    # At the top of your entry-point (gateway.py, api_server.py, …)
    from secure_mcp_gateway.log import configure_logging
    configure_logging(level="INFO", json_output=False)

    # Everywhere else
    from secure_mcp_gateway.log import get_logger
    logger = get_logger(__name__)
    logger.info("request handled", server_name="echo", duration_ms=42)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog

_configured = False


# ---------------------------------------------------------------------------
# Identity-attribute canonicalisation (shared by logs / metrics / traces)
# ---------------------------------------------------------------------------
#
# Lives here -- in the foundation logging module -- so the structlog
# processor below can apply it without importing the rest of the package
# (which would re-introduce the circular-import problem this module was
# carved out to avoid). ``utils.py`` re-exports both names for the metric
# helpers and ``build_log_extra`` so there's still a single source of truth.
#
# The map mirrors ``plugins.telemetry.conventions.SpanAttributes`` so the
# same identity attribute lands at ``log.attributes.enkrypt@*`` /
# ``metric.attributes.enkrypt@*`` / ``span.attributes.enkrypt@*`` in
# OpenSearch (Data Prepper rewrites dots to ``@`` in the field path).
# Categorical / domain-specific keys (``outcome``, ``direction``,
# ``provider``, ``check_kind``, ``status_code``, ``violation_type``,
# ``failure_reason``, ``block_reason``, ``cache``, ad-hoc diagnostic kwargs)
# don't have a canonical dotted name and pass through unchanged.
CANONICAL_ATTR_KEYS: dict[str, str] = {
    "custom_id":        "enkrypt.custom.id",
    "server_name":      "enkrypt.server.name",
    "org_id":           "enkrypt.org.id",
    "project_id":       "enkrypt.project.id",
    "project_name":     "enkrypt.project.name",
    "registry_name":    "enkrypt.project.registry",
    "project_registry": "enkrypt.project.registry",
    "user_id":          "enkrypt.user.id",
    "email":            "enkrypt.user.email",
    "user_email":       "enkrypt.user.email",
    "mcp_config_id":    "enkrypt.config.id",
    "gateway_name":     "enkrypt.gateway.name",
    "gateway_version":  "enkrypt.gateway.version",
    "error":            "enkrypt.error.message",
    "tool_name":        "enkrypt.tool.name",
    "request_id":       "enkrypt.request.id",
    "num_tool_calls":   "enkrypt.tool.num_calls",
    "tool_arguments":   "enkrypt.tool.arguments",
    "guardrail_name":   "enkrypt.guardrail.name",
}

# Backward-compatibility aliases for commonly-filtered identity keys.
# We emit these alongside the canonical dotted names so existing dashboards
# filtering on legacy snake_case fields keep working while the canonical
# ``enkrypt.*`` fields remain the source of truth.
LEGACY_FILTER_COMPAT_ATTR_KEYS: dict[str, str] = {
    "enkrypt.gateway.name": "gateway_name",
    "enkrypt.org.id": "org_id",
    "enkrypt.project.id": "project_id",
    "enkrypt.project.name": "project_name",
    "enkrypt.server.name": "server_name",
    "enkrypt.tool.name": "tool_name",
    "enkrypt.user.id": "user_id",
}


def add_legacy_filter_aliases(attrs: dict[str, Any] | None) -> dict[str, Any]:
    """Duplicate selected canonical keys under legacy snake_case aliases."""
    if not attrs:
        return {}
    out = dict(attrs)
    for canonical_key, legacy_key in LEGACY_FILTER_COMPAT_ATTR_KEYS.items():
        if canonical_key in attrs and legacy_key not in out:
            out[legacy_key] = attrs[canonical_key]
    return out


def canonicalize_attr_keys(attrs: dict[str, Any] | None) -> dict[str, Any]:
    """Rewrite known snake_case identity keys to the dotted ``enkrypt.*``
    convention. Unknown keys (categorical / diagnostic / ad-hoc) pass
    through unchanged.
    """
    if not attrs:
        return {}
    canonical = {CANONICAL_ATTR_KEYS.get(k, k): v for k, v in attrs.items()}
    return add_legacy_filter_aliases(canonical)


# Reserved structlog / stdlib LogRecord keys we must NOT rename even if they
# happen to match an entry in ``CANONICAL_ATTR_KEYS`` (none currently do, but
# this is the safe-by-construction list to consult before adding aliases).
_PROTECTED_LOG_RECORD_KEYS = frozenset(
    {
        "event", "level", "logger", "timestamp", "exception", "exc_info",
        "stack_info", "msg", "message", "name", "pathname", "filename",
        "module", "lineno", "funcName", "created", "msecs",
        "relativeCreated", "thread", "threadName", "processName", "process",
        "args",
    }
)


def _install_event_dict_promoting_record_factory() -> None:
    """Promote structlog event-dict keys onto ``LogRecord.__dict__``.

    Why: the OpenTelemetry SDK's ``LoggingHandler`` extracts log-attributes
    by iterating ``record.__dict__`` (anything not in a small reserved set
    becomes an OTel attribute, then ``log.attributes.*`` in OpenSearch).
    structlog's ``stdlib.ProcessorFormatter.wrap_for_formatter`` packages
    the entire event-dict into ``record.msg`` (a Python dict, not a
    string) -- without intervention the dict's keys never land on
    ``record.__dict__`` and OpenSearch's ``gateway-logs`` only ever sees
    ``log.attributes.code.*`` / ``log.attributes.service.*`` (the OTel
    auto-attributes), never ``log.attributes.enkrypt@*``.

    A *logger filter* doesn't work for this because stdlib's
    ``Logger.callHandlers`` walks the parent chain dispatching to
    ancestor *handlers* but never runs ancestor *filters* -- so a filter
    on the root logger is a no-op for any child logger that propagates
    (which is every gateway log site, since they all bind a child
    logger). Instead we install a record factory that runs at record
    *creation* time -- before any filter, formatter, or handler --
    guaranteeing the keys are available on ``__dict__`` for every
    handler that subsequently sees the record (stream, OTel, anything
    third-party libs add).

    ``setdefault`` semantics avoid clobbering attributes already set by
    stdlib ``Logger.makeRecord``'s own ``extra=`` promotion path.
    Idempotent -- safe to call more than once; only installs the wrapper
    on the first call.
    """
    base = logging.getLogRecordFactory()
    if getattr(base, "_enkrypt_event_dict_promoter", False):
        return  # already wrapped, don't double-stack

    def _factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = base(*args, **kwargs)
        msg = record.msg
        if isinstance(msg, dict):
            for k, v in msg.items():
                if k in _PROTECTED_LOG_RECORD_KEYS:
                    continue
                record.__dict__.setdefault(k, v)
        return record

    _factory._enkrypt_event_dict_promoter = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(_factory)


def _canonicalize_event_dict(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor: flatten ``extra={...}`` and rewrite identity
    keys to the dotted ``enkrypt.*`` convention.

    Handles two log-site shapes uniformly:

    1. ``logger.info("...", server_name=..., custom_id=...)`` -- structlog
       kwargs land directly in ``event_dict``; rename in place.
    2. ``logger.info("...", extra={"server_name": ..., "custom_id": ...})``
       -- the entire ``extra=`` kwarg lands as a single nested dict-valued
       entry under the key ``"extra"``. Splat its contents into the
       top-level dict (so OTel exports each key as an individual log
       attribute and OpenSearch indexes them as flat
       ``log.attributes.<name>`` fields rather than burying them under a
       nested ``extra`` JSON blob), then rename.

    Either way every identity key ends up at
    ``log.attributes.enkrypt@*`` in OpenSearch without a per-site sweep.
    """
    extra = event_dict.pop("extra", None)
    if isinstance(extra, dict):
        # Flatten: caller-supplied ``extra`` keys become top-level event
        # dict keys. Existing top-level keys (e.g. ``event``, ``level``)
        # win on collision so the renderer's reserved fields stay intact.
        for k, v in extra.items():
            event_dict.setdefault(k, v)

    protected: dict[str, Any] = {}
    dynamic: dict[str, Any] = {}
    for k, v in event_dict.items():
        if k in _PROTECTED_LOG_RECORD_KEYS:
            protected[k] = v
            continue
        dynamic[k] = v
    return {**protected, **canonicalize_attr_keys(dynamic)}


def configure_logging(
    level: str = "INFO",
    json_output: bool | None = None,
    service_name: str = "secure-mcp-gateway",
) -> None:
    """One-time logging bootstrap.  Safe to call more than once (no-ops after first)."""
    global _configured
    if _configured:
        return
    _configured = True

    if json_output is None:
        json_output = os.environ.get("ENKRYPT_LOG_FORMAT", "").lower() == "json"

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        # Rewrite identity keys to the dotted ``enkrypt.*`` convention so
        # ``log.attributes.enkrypt@*`` lines up with the metric/trace side.
        # Catches kwargs-style structlog calls (``logger.info("...",
        # server_name=...)``) here in the structlog pipeline.
        _canonicalize_event_dict,
    ]

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # foreign_pre_chain runs on records emitted via the stdlib API
        # (``logging.getLogger().info("...", extra={...})``) -- including
        # the inline ``extra={...}`` dicts in ``services/...py`` that
        # bypass ``build_log_extra`` -- so those records get the same
        # identity-key rewrite as native structlog calls.
        foreign_pre_chain=[_canonicalize_event_dict],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Promote structlog event-dict keys onto ``LogRecord.__dict__`` so the
    # OpenTelemetry ``LoggingHandler`` (added later by
    # ``OpenTelemetryProvider``) sees them as log attributes. Without this
    # they remain buried inside ``record.msg`` (a dict) and OpenSearch's
    # ``gateway-logs`` never grows ``log.attributes.enkrypt@*`` fields.
    # Done via record factory rather than a logger filter because
    # filters on parent loggers are skipped during ``callHandlers``
    # propagation in stdlib.
    _install_event_dict_promoting_record_factory()


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structured logger bound to *name*."""
    return structlog.get_logger(name)
