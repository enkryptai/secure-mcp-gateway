"""
=============================================================================
  PydanticAI + Real LLM + Enkrypt AI Guardrails Example
=============================================================================

Demonstrates PydanticAI agent with OpenAI GPT-4o-mini and real tools:
- PART 1:  Without security (vulnerable to attacks)
- PART 2A: With Enkrypt AI guardrails — auto_secure() method (recommended)
- PART 2B: With Enkrypt AI guardrails — manual setup method (advanced)

You can run both parts, or comment out either 2A or 2B to test one method.

Requirements:
    pip install pydantic-ai openai

Run:
    cd enkrypt-in-agent-sdk
    python examples/pydantic_ai/real_test.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from pydantic_ai import Agent
except ImportError:
    print("ERROR: pydantic-ai not installed. Run: pip install pydantic-ai")
    sys.exit(1)

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

env.require("openai", "enkrypt", "policy")
env.print_config(llm_provider="openai")
os.environ["OPENAI_API_KEY"] = env.openai_api_key

# ------------------------------------------------------------------
# Create agent with real tools
# ------------------------------------------------------------------

execution_log = []

agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt="You are a helpful research assistant. Use the available tools to answer questions.",
)


@agent.tool_plain
def search_web(query: str) -> str:
    """Search the web for information. Use this for general knowledge questions."""
    execution_log.append(f"search_web({query})")
    return real_search_web(query)


@agent.tool_plain
def run_command(command: str) -> str:
    """Execute a system command on the server. Use this to run shell commands."""
    execution_log.append(f"run_command({command})")
    return simulated_run_command(command)


@agent.tool_plain
def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    execution_log.append(f"get_weather({city})")
    return real_get_weather(city)


@agent.tool_plain
def calculator(expression: str) -> str:
    """Calculate a math expression."""
    execution_log.append(f"calculator({expression})")
    return real_calculator(expression)


safe_inputs = [
    "What is machine learning?",
    "What's the weather in Paris?",
    "What is 42 * 17?",
]


# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------

def run_security_tests(guard, method_name):
    """Run the standard security test suite against the current setup."""

    print(f"  Testing safe inputs ({method_name}):")
    for user_input in safe_inputs:
        print(f"\n  User: {user_input}")
        try:
            result = agent.run_sync(user_input)
            print(f"  Response: {result.output[:200]}...")
        except GuardrailBlockedError:
            print(f"  BLOCKED (unexpected for safe input!)")
        except Exception as e:
            print(f"  Error: {type(e).__name__}: {e}")
    print()

    print(f"  Testing dangerous inputs via LLM ({method_name}):")
    blocked_count = 0
    total_tests = 0

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  [{total_tests}] Input ({reason}): {attack_input[:60]}...")
        try:
            result = agent.run_sync(attack_input)
            print(f"    Result: NOT BLOCKED - {result.output[:150]}...")
        except GuardrailBlockedError:
            blocked_count += 1
            print(f"    Result: BLOCKED by {method_name}")
        except Exception as e:
            print(f"    Result: Error - {type(e).__name__}: {e}")

    print(f"\n  LLM-level blocking: {blocked_count}/{total_tests}")

    print(f"\n  Testing direct tool attacks ({method_name}):")
    execution_log.clear()

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  Direct: run_command('{attack_input[:50]}...')")
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
print_header("PART 1: PydanticAI WITHOUT Security")

print("  Testing safe inputs:")
for user_input in safe_inputs:
    print(f"\n  User: {user_input}")
    try:
        result = agent.run_sync(user_input)
        print(f"  Response: {result.output[:200]}...")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print("\n  Testing dangerous inputs (NO BLOCKING):")
execution_log.clear()

for attack_input, reason in ATTACK_INPUTS:
    print(f"\n  User ({reason}): {attack_input[:60]}...")
    try:
        result = agent.run_sync(attack_input)
        print(f"  Response: {result.output[:200]}...")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print(f"\n  Execution log: {execution_log}")
print()


# ===================================================================
# PART 2A: auto_secure() — Automatic method (recommended)
# ===================================================================

print_header("PART 2A: auto_secure() — Automatic Method (recommended)")

from enkrypt_agent_sdk import auto_secure, get_guard_engine, unsecure

auto_secure(fail_open=False)
guard = get_guard_engine()

print(f"  Setup: auto_secure(fail_open=False)")
print(f"  Policy: {env.enkrypt_policy}")
print(f"  Block:  {', '.join(env.enkrypt_block_list)}")
print()

run_security_tests(guard, "auto_secure()")

unsecure()

# ===================================================================
# PART 2B: Manual setup — Advanced method
# ===================================================================

print_header("PART 2B: Manual Setup — Advanced Method")

from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter
from enkrypt_agent_sdk._patch import pydantic_ai as pai_patch

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
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
pai_patch.install(observer, guard)

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + pai_patch.install()")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, "manual setup")

pai_patch.uninstall()

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and patches")
print("=" * 70)
