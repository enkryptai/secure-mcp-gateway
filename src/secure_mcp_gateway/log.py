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

import structlog

_configured = False


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


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structured logger bound to *name*."""
    return structlog.get_logger(name)
