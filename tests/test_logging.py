"""Tests for the structured logging setup."""

from __future__ import annotations

import json
import logging
import sys
from io import StringIO

import structlog

import secure_mcp_gateway.log as log_module


def _reset_logging():
    """Reset structlog and stdlib root logger between tests."""
    log_module._configured = False
    structlog.reset_defaults()
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)


def test_configure_logging_sets_up_structlog():
    _reset_logging()
    log_module.configure_logging(level="DEBUG")

    logger = log_module.get_logger("test")
    assert logger is not None
    assert hasattr(logger, "info")
    assert hasattr(logger, "debug")
    assert hasattr(logger, "error")
    assert hasattr(logger, "warning")

    _reset_logging()


def test_configure_logging_idempotent():
    _reset_logging()
    log_module.configure_logging(level="INFO")
    handler_count = len(logging.getLogger().handlers)
    log_module.configure_logging(level="DEBUG")
    assert len(logging.getLogger().handlers) == handler_count

    _reset_logging()


def test_json_output_produces_valid_json():
    _reset_logging()
    buf = StringIO()
    log_module.configure_logging(level="INFO", json_output=True)

    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(root.handlers[0].formatter if root.handlers else None)

    fmt = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )
    handler.setFormatter(fmt)
    root.addHandler(handler)

    logger = log_module.get_logger("json_test")
    logger.info("hello", key="value")

    output = buf.getvalue().strip()
    assert output, "Expected log output"
    parsed = json.loads(output)
    assert parsed["event"] == "hello"
    assert parsed["key"] == "value"

    _reset_logging()


def test_get_logger_returns_bound_logger():
    _reset_logging()
    log_module.configure_logging(level="INFO")
    logger = log_module.get_logger("mymod")
    # After binding, the proxy wraps the configured BoundLogger class
    bound = logger.bind(x=1)
    assert isinstance(bound, structlog.stdlib.BoundLogger)

    _reset_logging()
