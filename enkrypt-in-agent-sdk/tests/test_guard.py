"""Tests for the GuardEngine with the keyword provider (no network needed)."""

import asyncio

from enkrypt_agent_sdk.events import GuardrailAction
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider


def _make_engine(keywords: list[str], *, fail_open: bool = True) -> GuardEngine:
    registry = GuardrailRegistry()
    registry.register(KeywordGuardrailProvider())
    return GuardEngine(
        registry,
        input_policy={
            "enabled": True,
            "policy_name": "test",
            "block": ["keyword_detector"],
            "blocked_keywords": keywords,
        },
        output_policy={
            "enabled": True,
            "policy_name": "test",
            "block": ["keyword_detector"],
            "blocked_keywords": keywords,
        },
        fail_open=fail_open,
    )


class TestGuardEngineInput:
    def test_safe_input(self):
        engine = _make_engine(["hack", "exploit"])
        verdict = asyncio.run(engine.check_input("Hello, how are you?"))
        assert verdict.is_safe

    def test_blocked_input(self):
        engine = _make_engine(["hack", "exploit"])
        verdict = asyncio.run(engine.check_input("Let me hack into the system"))
        assert not verdict.is_safe
        assert verdict.action == GuardrailAction.BLOCK
        assert "keyword_detector" in verdict.violations

    def test_case_insensitive(self):
        engine = _make_engine(["exploit"])
        verdict = asyncio.run(engine.check_input("EXPLOIT this vulnerability"))
        assert not verdict.is_safe


class TestGuardEngineOutput:
    def test_safe_output(self):
        engine = _make_engine(["hack"])
        verdict = asyncio.run(engine.check_output("Here is the summary.", "Summarize this"))
        assert verdict.is_safe

    def test_blocked_output(self):
        engine = _make_engine(["hack"])
        verdict = asyncio.run(engine.check_output("You can hack the server by...", "How to access?"))
        assert not verdict.is_safe


class TestGuardEngineNoProvider:
    def test_no_guard_returns_allow(self):
        registry = GuardrailRegistry()
        engine = GuardEngine(registry)
        verdict = asyncio.run(engine.check_input("anything"))
        assert verdict.is_safe
        assert verdict.action == GuardrailAction.ALLOW
