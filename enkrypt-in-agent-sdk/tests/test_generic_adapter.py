"""Tests for the GenericAgentAdapter context manager API — sync and async."""

import asyncio

import pytest

from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter
from enkrypt_agent_sdk.events import GuardrailAction
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpMeter, _NoOpTracer


def _make_adapter(
    keywords: list[str] | None = None,
) -> GenericAgentAdapter:
    observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
    guard: GuardEngine | None = None
    if keywords is not None:
        registry = GuardrailRegistry()
        registry.register(KeywordGuardrailProvider())
        guard = GuardEngine(
            registry,
            input_policy={
                "enabled": True,
                "policy_name": "test",
                "block": ["keyword_detector"],
                "blocked_keywords": keywords,
            },
        )
    return GenericAgentAdapter(observer, guard, agent_id="test-agent")


# ---------------------------------------------------------------------------
# Async flows (arun / astep / atool_call / allm_call)
# ---------------------------------------------------------------------------

async def _async_full_flow():
    adapter = _make_adapter()
    async with adapter.arun(task="Test task") as run_ctx:
        assert run_ctx.run_id
        async with run_ctx.astep(reason="Plan") as step_ctx:
            async with step_ctx.atool_call("search", input="query") as tc:
                tc.set_output("result")
            async with step_ctx.allm_call(model="gpt-4") as lc:
                lc.set_output("Generated text", tokens={"input": 10, "output": 20})


async def _async_input_blocked():
    adapter = _make_adapter(keywords=["hack"])
    async with adapter.arun(task="Test") as run_ctx:
        async with run_ctx.astep(reason="Attack") as step_ctx:
            async with step_ctx.atool_call("cmd", input="hack the system") as tc:
                tc.set_output("should not reach")


async def _async_safe_input():
    adapter = _make_adapter(keywords=["hack"])
    async with adapter.arun(task="Test") as run_ctx:
        async with run_ctx.astep(reason="Safe step") as step_ctx:
            async with step_ctx.atool_call("search", input="hello world") as tc:
                tc.set_output("results")


async def _async_exception_in_tool():
    adapter = _make_adapter()
    async with adapter.arun(task="Test") as run_ctx:
        async with run_ctx.astep(reason="Step") as step_ctx:
            async with step_ctx.atool_call("broken") as tc:
                raise RuntimeError("boom")


async def _async_exception_in_step():
    adapter = _make_adapter()
    async with adapter.arun(task="Test") as run_ctx:
        async with run_ctx.astep(reason="Bad step"):
            raise ValueError("step error")


class TestAsyncAdapter:
    def test_full_flow(self):
        asyncio.run(_async_full_flow())

    def test_input_blocked(self):
        with pytest.raises(GuardrailBlockedError):
            asyncio.run(_async_input_blocked())

    def test_safe_input_passes(self):
        asyncio.run(_async_safe_input())

    def test_exception_in_tool(self):
        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(_async_exception_in_tool())

    def test_exception_in_step(self):
        with pytest.raises(ValueError):
            asyncio.run(_async_exception_in_step())


# ---------------------------------------------------------------------------
# Sync flows (run / step / tool_call / llm_call)
# ---------------------------------------------------------------------------

class TestSyncAdapter:
    def test_full_sync_flow(self):
        adapter = _make_adapter()
        with adapter.run(task="Sync task") as run_ctx:
            assert run_ctx.run_id
            with run_ctx.step(reason="Plan") as step_ctx:
                with step_ctx.tool_call("search", input="query") as tc:
                    tc.set_output("sync result")
                with step_ctx.llm_call(model="gpt-4") as lc:
                    lc.set_output("sync text", tokens={"input": 5, "output": 10})

    def test_sync_input_blocked(self):
        adapter = _make_adapter(keywords=["hack"])
        with pytest.raises(GuardrailBlockedError):
            with adapter.run(task="Test") as run_ctx:
                with run_ctx.step(reason="Attack") as step_ctx:
                    with step_ctx.tool_call("cmd", input="hack the system") as tc:
                        tc.set_output("should not reach")

    def test_sync_safe_input(self):
        adapter = _make_adapter(keywords=["hack"])
        with adapter.run(task="Test") as run_ctx:
            with run_ctx.step(reason="Safe") as step_ctx:
                with step_ctx.tool_call("search", input="hello") as tc:
                    tc.set_output("ok")

    def test_sync_exception_in_tool(self):
        adapter = _make_adapter()
        with pytest.raises(RuntimeError, match="boom"):
            with adapter.run(task="Test") as run_ctx:
                with run_ctx.step(reason="Step") as step_ctx:
                    with step_ctx.tool_call("broken") as tc:
                        raise RuntimeError("boom")

    def test_sync_exception_in_step(self):
        adapter = _make_adapter()
        with pytest.raises(ValueError):
            with adapter.run(task="Test") as run_ctx:
                with run_ctx.step(reason="Bad"):
                    raise ValueError("step error")


# ---------------------------------------------------------------------------
# Wildcard keyword tests (Sentry pattern)
# ---------------------------------------------------------------------------

class TestWildcardKeywords:
    def test_wildcard_matches(self):
        adapter = _make_adapter(keywords=["hack*"])
        with pytest.raises(GuardrailBlockedError):
            with adapter.run(task="Test") as run:
                with run.step(reason="s") as step:
                    with step.tool_call("cmd", input="hacking attempt") as tc:
                        tc.set_output("nope")

    def test_wildcard_no_match(self):
        adapter = _make_adapter(keywords=["hack*"])
        with adapter.run(task="Test") as run:
            with run.step(reason="s") as step:
                with step.tool_call("cmd", input="hello world") as tc:
                    tc.set_output("ok")
