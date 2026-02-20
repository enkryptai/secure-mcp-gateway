"""
Enkrypt In-Agent SDK — Demo
============================

This demo shows four usage patterns:

1. **auto_secure()** — one-liner with keyword arguments
2. **GenericAgentAdapter** — sync context managers (``with``)
3. **GenericAgentAdapter** — async context managers (``async with``)
4. **Keyword guardrail** — offline guardrail with wildcard support

Run::

    cd enkrypt-in-agent-sdk
    pip install -e ".[dev]"
    python examples/demo.py
"""

from __future__ import annotations

import asyncio

from enkrypt_agent_sdk import (
    AgentGuard,
    GenericAgentAdapter,
    GuardEngine,
    auto_secure,
    get_compliance_mapping,
    init_telemetry,
    initialize,
    is_encoded,
    shutdown,
)
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError


# ── Pattern 1: auto_secure() with keyword args ────────────────────────

def demo_auto_secure():
    print("\n=== Pattern 1: auto_secure() (keyword shorthand) ===\n")
    results = auto_secure(
        service_name="demo-agent",
        # To use Enkrypt guardrails, set:
        #   enkrypt_api_key="ek-...",
        #   guardrail_policy="Sample Airline Guardrail",
        #   block=["injection_attack", "toxicity"],
        #   pii_redaction=True,
    )
    print(f"  Framework instrumentation results: {results}")
    shutdown()


# ── Pattern 2: Sync context managers (with) ───────────────────────────

def demo_sync_adapter():
    print("\n=== Pattern 2: Sync GenericAgentAdapter (with) ===\n")

    observer, guard = initialize()
    adapter = GenericAgentAdapter(observer, guard, agent_id="sync-agent")

    with adapter.run(task="Summarize a document") as run_ctx:
        print(f"  Run started: {run_ctx.run_id}")

        with run_ctx.step(reason="Retrieve document") as step:
            with step.tool_call("file_read", input="/tmp/doc.txt") as tc:
                tc.set_output("The document contains important information...")
                print("  Tool call completed (sync).")

        with run_ctx.step(reason="Generate summary") as step:
            with step.llm_call(model="gpt-4") as lc:
                lc.set_output("This document discusses...", tokens={"input": 50, "output": 30})
                print("  LLM call completed (sync).")

    print("  Run finished successfully.")
    shutdown()


# ── Pattern 3: Async context managers (async with) ────────────────────

async def demo_async_adapter():
    print("\n=== Pattern 3: Async GenericAgentAdapter (async with) ===\n")

    observer, guard = initialize()
    adapter = GenericAgentAdapter(observer, guard, agent_id="async-agent")

    async with adapter.arun(task="Summarize a document") as run_ctx:
        print(f"  Run started: {run_ctx.run_id}")

        async with run_ctx.astep(reason="Retrieve document") as step:
            async with step.atool_call("file_read", input="/tmp/doc.txt") as tc:
                tc.set_output("The document contains important information...")
                print("  Tool call completed (async).")

        async with run_ctx.astep(reason="Generate summary") as step:
            async with step.allm_call(model="gpt-4") as lc:
                lc.set_output("This document discusses...", tokens={"input": 50, "output": 30})
                print("  LLM call completed (async).")

    print("  Run finished successfully.")
    shutdown()


# ── Pattern 4: Keyword guardrail with wildcards ───────────────────────

def demo_keyword_guardrail():
    print("\n=== Pattern 4: Keyword guardrail (wildcards, sync) ===\n")

    from enkrypt_agent_sdk.observer import AgentObserver
    from enkrypt_agent_sdk.otel_setup import _NoOpMeter, _NoOpTracer

    registry = GuardrailRegistry()
    registry.register(KeywordGuardrailProvider())

    guard = GuardEngine(
        registry,
        input_policy={
            "enabled": True,
            "policy_name": "safety",
            "block": ["keyword_detector"],
            "blocked_keywords": ["hack*", "exploit*", "rm -rf", "drop table"],
        },
    )

    observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
    adapter = GenericAgentAdapter(observer, guard, agent_id="safe-agent")

    # Safe request (sync)
    with adapter.run(task="Safe task") as run_ctx:
        with run_ctx.step(reason="Normal") as step:
            with step.tool_call("search", input="weather in NYC") as tc:
                tc.set_output("72F and sunny")
                print("  Safe request passed.")

    # Dangerous request — wildcard matches "hacking"
    try:
        with adapter.run(task="Dangerous task") as run_ctx:
            with run_ctx.step(reason="Attack") as step:
                with step.tool_call("cmd", input="hacking attempt") as tc:
                    tc.set_output("should not reach here")
    except GuardrailBlockedError as e:
        print(f"  Blocked (wildcard): {e}")


# ── Bonus: Encoding detection + compliance mapping ────────────────────

def demo_sentry_features():
    print("\n=== Bonus: Sentry features (encoding + compliance) ===\n")

    fmt = is_encoded("SGVsbG8gV29ybGQh")
    print(f"  Encoding detected: {fmt}")

    mapping = get_compliance_mapping("injection_attack")
    if mapping:
        print(f"  OWASP mapping: {mapping.get('owasp_llm_2025', [])}")
        print(f"  MITRE mapping: {mapping.get('mitre_atlas', [])}")


# ── Main ──────────────────────────────────────────────────────────────

def main():
    print("Enkrypt In-Agent SDK — Demo")
    print("=" * 50)

    demo_auto_secure()
    demo_sync_adapter()
    asyncio.run(demo_async_adapter())
    demo_keyword_guardrail()
    demo_sentry_features()

    print("\n" + "=" * 50)
    print("Demo complete!")


if __name__ == "__main__":
    main()
