"""Tests for the GuardEngine with the keyword provider (no network needed)."""

import asyncio

from enkryptai_agent_security.sdk.events import GuardrailAction
from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.guardrails.base import GuardrailRegistry
from enkryptai_agent_security.sdk.guardrails.keyword_provider import KeywordGuardrailProvider


def _make_engine(keywords: list[str], *, fail_open: bool = True) -> GuardEngine:
    registry = GuardrailRegistry()
    registry.register(KeywordGuardrailProvider())
    policy = {
        "enabled": True,
        "policy_name": "test",
        "block": ["keyword_detector"],
        "blocked_keywords": keywords,
    }
    return GuardEngine(
        registry,
        pre_llm_policy=policy,
        pre_tool_policy=policy,
        post_tool_policy=policy,
        post_llm_policy=policy,
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


class TestGuardEnginePerCheckpoint:
    """Test that per-checkpoint policies create distinct guards."""

    def test_different_policies_per_checkpoint(self):
        registry = GuardrailRegistry()
        registry.register(KeywordGuardrailProvider())
        engine = GuardEngine(
            registry,
            pre_llm_policy={
                "enabled": True,
                "policy_name": "llm",
                "block": ["keyword_detector"],
                "blocked_keywords": ["llm_blocked"],
            },
            pre_tool_policy={
                "enabled": True,
                "policy_name": "tool",
                "block": ["keyword_detector"],
                "blocked_keywords": ["tool_blocked"],
            },
        )
        # pre_llm should block "llm_blocked" but not "tool_blocked"
        v1 = asyncio.run(engine.check_input("llm_blocked text", checkpoint="pre_llm"))
        assert not v1.is_safe
        v2 = asyncio.run(engine.check_input("tool_blocked text", checkpoint="pre_llm"))
        assert v2.is_safe

        # pre_tool should block "tool_blocked" but not "llm_blocked"
        v3 = asyncio.run(engine.check_input("tool_blocked text", checkpoint="pre_tool"))
        assert not v3.is_safe
        v4 = asyncio.run(engine.check_input("llm_blocked text", checkpoint="pre_tool"))
        assert v4.is_safe

    def test_guard_for_checkpoint(self):
        registry = GuardrailRegistry()
        registry.register(KeywordGuardrailProvider())
        policy = {
            "enabled": True,
            "policy_name": "test",
            "block": ["keyword_detector"],
            "blocked_keywords": ["bad"],
        }
        engine = GuardEngine(
            registry,
            pre_llm_policy=policy,
            pre_tool_policy=policy,
            post_tool_policy=policy,
            post_llm_policy=policy,
        )
        assert engine.guard_for_checkpoint("pre_llm") is not None
        assert engine.guard_for_checkpoint("pre_tool") is not None
        assert engine.guard_for_checkpoint("post_tool") is not None
        assert engine.guard_for_checkpoint("post_llm") is not None
        assert engine.guard_for_checkpoint("nonexistent") is None

    def test_guard_for_checkpoint_none_when_no_output_policy(self):
        registry = GuardrailRegistry()
        registry.register(KeywordGuardrailProvider())
        policy = {
            "enabled": True,
            "policy_name": "test",
            "block": ["keyword_detector"],
            "blocked_keywords": ["bad"],
        }
        engine = GuardEngine(
            registry,
            pre_llm_policy=policy,
            pre_tool_policy=policy,
        )
        # Input checkpoints have guards, output checkpoints don't
        assert engine.guard_for_checkpoint("pre_llm") is not None
        assert engine.guard_for_checkpoint("pre_tool") is not None
        assert engine.guard_for_checkpoint("post_tool") is None
        assert engine.guard_for_checkpoint("post_llm") is None

    def test_same_policy_all_checkpoints(self):
        """When the same policy is set for all checkpoints, all should block."""
        registry = GuardrailRegistry()
        registry.register(KeywordGuardrailProvider())
        policy = {
            "enabled": True,
            "policy_name": "shared",
            "block": ["keyword_detector"],
            "blocked_keywords": ["shared_bad"],
        }
        engine = GuardEngine(
            registry,
            pre_llm_policy=policy,
            pre_tool_policy=policy,
        )
        # Both input checkpoints should block "shared_bad"
        v1 = asyncio.run(engine.check_input("shared_bad text", checkpoint="pre_llm"))
        assert not v1.is_safe
        v2 = asyncio.run(engine.check_input("shared_bad text", checkpoint="pre_tool"))
        assert not v2.is_safe
