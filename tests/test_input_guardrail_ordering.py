"""The sync input guardrail must decide before the tool runs; deny entries accept ``name`` or ``pattern``."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from secure_mcp_gateway.plugins.guardrails.base import (
    GuardrailAction,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
)
from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager


def _ensure_telemetry() -> None:
    manager = get_telemetry_config_manager()
    if manager.get_active_provider() is None:
        from secure_mcp_gateway.plugins.telemetry.example_providers import (
            ConsoleTelemetryProvider,
        )

        manager.register_provider(ConsoleTelemetryProvider())
        manager.initialize_provider("console", {})


_ensure_telemetry()
from secure_mcp_gateway.services.execution.deny_matcher import (
    filter_denied_tools,
    is_tool_denied,
)
from secure_mcp_gateway.services.execution import (
    secure_tool_execution_service as stes,
)
from secure_mcp_gateway.services.execution.secure_tool_execution_service import (
    SecureToolExecutionService,
)


class _Span:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def set_attribute(self, *a, **k):
        pass

    def record_exception(self, *a, **k):
        pass


class _Tracer:
    def start_as_current_span(self, *a, **k):
        return _Span()


@pytest.fixture(autouse=True)
def _noop_tracer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stes, "tracer", _Tracer())


GUARDRAILS_CONFIG = {
    "input_policy_name": "p",
    "pii_redaction": False,
}


def _safe() -> GuardrailResponse:
    return GuardrailResponse(is_safe=True, action=GuardrailAction.ALLOW, violations=[])


def _unsafe() -> GuardrailResponse:
    violation = GuardrailViolation(
        violation_type=ViolationType.INJECTION_ATTACK,
        severity=0.9,
        message="injection",
        action=GuardrailAction.BLOCK,
        metadata={},
    )
    return GuardrailResponse(
        is_safe=False, action=GuardrailAction.BLOCK, violations=[violation]
    )


def _service(verdict, *, async_mode: bool = False):
    guardrail = SimpleNamespace(validate=AsyncMock(return_value=verdict))
    call_tool = AsyncMock(
        return_value=SimpleNamespace(content=[SimpleNamespace(type="text", text="ok")])
    )
    service = SimpleNamespace(
        ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED=async_mode,
        guardrail_manager=SimpleNamespace(get_input_guardrail=lambda server_config: guardrail),
        tool_execution_service=SimpleNamespace(call_tool=call_tool),
        _unwrap_timeout_result=SecureToolExecutionService._unwrap_timeout_result,
        _extract_text_result=lambda result: SecureToolExecutionService._extract_text_result(
            None, result
        ),
    )
    return service, guardrail, call_tool


async def _run(service):
    return await SecureToolExecutionService._execute_with_input_guardrails(
        service,
        SimpleNamespace(request_id="r1"),
        "cid",
        "srv",
        0,
        "delete_repo",
        {"repo": "x"},
        '{"repo": "x"}',
        '{"repo": "x"}',
        GUARDRAILS_CONFIG | {"input_guardrails_config": {}},
        object(),
        SimpleNamespace(set_attribute=lambda *a, **k: None),
        SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None),
    )


async def test_sync_mode_does_not_call_tool_when_input_is_unsafe() -> None:
    service, guardrail, call_tool = _service(_unsafe())
    result = await _run(service)
    assert result["status"] == "blocked_input"
    guardrail.validate.assert_awaited_once()
    call_tool.assert_not_awaited()


async def test_sync_mode_calls_tool_when_input_is_safe() -> None:
    service, guardrail, call_tool = _service(_safe())
    result = await _run(service)
    assert result["text_result"] == "ok"
    call_tool.assert_awaited_once()


async def test_sync_mode_does_not_call_tool_when_guardrail_returns_nothing() -> None:
    service, guardrail, call_tool = _service(None)
    with pytest.raises(Exception):
        await _run(service)
    call_tool.assert_not_awaited()


async def test_sync_mode_does_not_call_tool_when_guardrail_errors() -> None:
    service, guardrail, call_tool = _service(_safe())
    guardrail.validate = AsyncMock(side_effect=RuntimeError("guardrail down"))
    with pytest.raises(Exception, match="guardrail down"):
        await _run(service)
    call_tool.assert_not_awaited()


async def test_async_mode_still_runs_both_and_blocks_unsafe_input() -> None:
    service, guardrail, call_tool = _service(_unsafe(), async_mode=True)
    result = await _run(service)
    assert result["status"] == "blocked_input"
    call_tool.assert_awaited_once()


def test_deny_entry_accepts_name_key() -> None:
    match = is_tool_denied("delete_repo", [{"name": "delete_*", "reason": "no deletes"}])
    assert match == {"name": "delete_repo", "pattern": "delete_*", "reason": "no deletes"}


def test_deny_entry_accepts_pattern_key() -> None:
    match = is_tool_denied(
        "delete_repo", [{"pattern": "delete_*", "reason": "no destructive ops"}]
    )
    assert match is not None
    assert match["pattern"] == "delete_*"
    assert match["reason"] == "no destructive ops"


def test_deny_entry_name_wins_over_pattern() -> None:
    assert is_tool_denied("a", [{"name": "a", "pattern": "b"}]) is not None
    assert is_tool_denied("b", [{"name": "a", "pattern": "b"}]) is None


def test_deny_entry_without_a_pattern_denies_nothing() -> None:
    assert is_tool_denied("delete_repo", [{"reason": "oops"}, ""]) is None


def test_deny_all_wildcard_exempts_configured_tools_with_pattern_key() -> None:
    entries = [{"pattern": "*"}]
    allowed = {"echo": "Echo"}
    assert is_tool_denied("echo", entries, allowed) is None
    assert is_tool_denied("other", entries, allowed) is not None
    assert filter_denied_tools(["echo", "other"], entries, allowed) == ["echo"]
