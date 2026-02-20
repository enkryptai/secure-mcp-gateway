"""
=============================================================================
  Generic Adapter + Enkrypt AI Guardrails Example
=============================================================================

Demonstrates the Generic adapter for manual instrumentation with real tools:
- PART 1:  Without security (tools execute without guardrails)
- PART 2A: With Enkrypt AI guardrails — auto_secure() method (recommended)
- PART 2B: With Enkrypt AI guardrails — manual setup method (advanced)

You can run both parts, or comment out either 2A or 2B to test one method.

The Generic adapter provides context managers for manual instrumentation.
No auto-patch is needed -- you wrap your code with the adapter's
run/step/tool_call/llm_call context managers.

Run:
    cd enkrypt-in-agent-sdk
    python examples/generic/real_test.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _env_setup import (
    env,
    print_header,
    print_result,
    ATTACK_INPUTS,
    GuardrailBlockedError,
    real_search_web,
    real_get_weather,
    real_calculator,
    simulated_run_command,
)

env.print_config(llm_provider="none")
env.require("enkrypt", "policy")

# ------------------------------------------------------------------
# Define tools (real implementations)
# ------------------------------------------------------------------

execution_log = []


def search_web(query: str) -> str:
    """Search the web for information."""
    execution_log.append(f"search_web({query})")
    return real_search_web(query)


def run_command(command: str) -> str:
    """Execute a system command (simulated)."""
    execution_log.append(f"run_command({command})")
    return simulated_run_command(command)


def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    execution_log.append(f"get_weather({city})")
    return real_get_weather(city)


def calculator(expression: str) -> str:
    """Calculate a math expression."""
    execution_log.append(f"calculator({expression})")
    return real_calculator(expression)


# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------

def run_security_tests(guard, adapter, method_name):
    """Run the standard security test suite against the current setup."""

    from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter

    print(f"  Testing safe operations ({method_name}):")
    execution_log.clear()

    with adapter.run(task="Answer user questions") as run_ctx:
        with run_ctx.step(reason="Search query") as step_ctx:
            with step_ctx.tool_call("search_web", input="Python programming") as tc:
                result = search_web("Python programming")
                tc.set_output(result)
                print(f"  search_web result: {result[:200]}...")

        with run_ctx.step(reason="Weather check") as step_ctx:
            with step_ctx.tool_call("get_weather", input="Tokyo") as tc:
                result = get_weather("Tokyo")
                tc.set_output(result)
                print(f"  get_weather result: {result}")

    print(f"  Execution log: {execution_log}")
    print("  Status: PASSED (safe operations worked)")
    print()

    print(f"  Testing dangerous inputs ({method_name}):")
    blocked_count = 0
    total_tests = 0

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  [{total_tests}] Input ({reason}): {attack_input[:60]}...")
        try:
            verdict = asyncio.run(guard.check_input(attack_input, tool_name="run_command"))
            if not verdict.is_safe:
                blocked_count += 1
                print(f"    Result: BLOCKED ({verdict.violations})")
            else:
                result = run_command(attack_input)
                print(f"    Result: ALLOWED - {result[:100]}...")
        except GuardrailBlockedError as e:
            blocked_count += 1
            print(f"    Result: BLOCKED: {e}")

    print(f"\n  Blocking: {blocked_count}/{total_tests}")

    print(f"\n  Testing direct attacks via adapter context ({method_name}):")
    execution_log.clear()

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  Attacking: run_command('{attack_input[:50]}...')")
        try:
            verdict = asyncio.run(guard.check_input(attack_input, tool_name="run_command"))
            if not verdict.is_safe:
                blocked_count += 1
                print(f"    Result: BLOCKED ({verdict.violations})")
            else:
                execution_log.append(f"run_command({attack_input})")
                print(f"    Result: ALLOWED")
        except GuardrailBlockedError as e:
            blocked_count += 1
            print(f"    Result: BLOCKED: {e}")

    print()
    print_result(blocked_count, total_tests, execution_log)


# ===================================================================
# PART 1: WITHOUT SECURITY
# ===================================================================
print_header("PART 1: Generic Adapter (No Security)")

from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = GenericAgentAdapter(observer, guard_engine=None)

print("  Running agentic loop without guardrails:")
execution_log.clear()

with adapter.run(task="Answer user questions") as run_ctx:
    with run_ctx.step(reason="Search query") as step_ctx:
        with step_ctx.tool_call("search_web", input="Python programming") as tc:
            result = search_web("Python programming")
            tc.set_output(result)
            print(f"  search_web result: {result[:200]}...")

    with run_ctx.step(reason="Weather check") as step_ctx:
        with step_ctx.tool_call("get_weather", input="Tokyo") as tc:
            result = get_weather("Tokyo")
            tc.set_output(result)
            print(f"  get_weather result: {result}")

    with run_ctx.step(reason="Calculate") as step_ctx:
        with step_ctx.tool_call("calculator", input="42 * 17") as tc:
            result = calculator("42 * 17")
            tc.set_output(result)
            print(f"  calculator result: {result}")

    with run_ctx.step(reason="Dangerous command") as step_ctx:
        with step_ctx.tool_call("run_command", input="rm -rf /") as tc:
            result = run_command("rm -rf /")
            tc.set_output(result)
            print(f"  run_command result: {result}")

print(f"\n  Execution log: {execution_log}")
dangerous_count = sum(1 for x in execution_log if "run_command" in x)
print(f"  Dangerous commands that ran: {dangerous_count}")
if dangerous_count > 0:
    print("  Status: VULNERABLE (commands executed without checks)")
print()


# ===================================================================
# PART 2A: auto_secure() — Automatic method (recommended)
# ===================================================================

print_header("PART 2A: auto_secure() — Automatic Method (recommended)")

from enkrypt_agent_sdk import auto_secure, get_guard_engine, unsecure

auto_secure(fail_open=False)
guard = get_guard_engine()

adapter_a = GenericAgentAdapter(observer=None, guard_engine=guard)

print(f"  Setup: auto_secure(fail_open=False)")
print(f"  Policy: {env.enkrypt_policy}")
print(f"  Block:  {', '.join(env.enkrypt_block_list)}")
print()

run_security_tests(guard, adapter_a, "auto_secure()")

unsecure()

# ===================================================================
# PART 2B: Manual setup — Advanced method
# ===================================================================

print_header("PART 2B: Manual Setup — Advanced Method")

from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkrypt_agent_sdk.guard import GuardEngine

registry = GuardrailRegistry()
registry.register(EnkryptGuardrailProvider(
    api_key=os.environ["ENKRYPT_API_KEY"],
    base_url=os.environ.get("ENKRYPT_BASE_URL", "https://api.enkryptai.com"),
))
guard = GuardEngine(registry, input_policy={
    "enabled": True,
    "policy_name": os.environ["ENKRYPT_GUARDRAIL_POLICY"],
    "block": [b.strip() for b in os.environ.get("ENKRYPT_BLOCK_LIST", "injection_attack,toxicity,policy_violation,nsfw").split(",")],
}, fail_open=False)
observer_b = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter_b = GenericAgentAdapter(observer=observer_b, guard_engine=guard, agent_id="my-agent")

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + GenericAgentAdapter")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, adapter_b, "manual setup")

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and adapter")
print("=" * 70)
