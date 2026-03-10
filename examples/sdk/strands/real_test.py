"""
=============================================================================
  Strands Agents + Real LLM + Enkrypt AI Guardrails
=============================================================================

Demonstrates the Strands Agents framework with real tools:
- PART 1:  Without security (tools execute without guardrails)
- PART 2A: With Enkrypt AI guardrails — auto_secure() method (recommended)
- PART 2B: With Enkrypt AI guardrails — manual setup method (advanced)

You can run both parts, or comment out either 2A or 2B to test one method.

Setup:
    1. Create a .env file in the examples/sdk folder:

           AWS_ACCESS_KEY_ID=your-aws-key
           AWS_SECRET_ACCESS_KEY=your-aws-secret
           AWS_DEFAULT_REGION=us-east-1
           ENKRYPT_API_KEY=your-enkrypt-api-key
           ENKRYPT_GUARDRAIL_POLICY=your-policy-name

    2. Run:
           pip install enkryptai-agent-security[sdk] strands-agents
           python examples/sdk/strands/real_test.py
"""

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
    simulated_run_command,
)

env.require("enkrypt", "policy")
env.print_config("strands")

try:
    from strands import Agent, tool
except ImportError:
    print("ERROR: Strands Agents SDK not installed.")
    print("  Install with: pip install strands-agents")
    sys.exit(1)

# ------------------------------------------------------------------
# Define tools (real implementations)
# ------------------------------------------------------------------

execution_log = []


@tool
def search_web(query: str) -> str:
    """Search the web for information. Use this for general knowledge questions."""
    execution_log.append(f"search_web({query})")
    return real_search_web(query)


@tool
def run_command(command: str) -> str:
    """Execute a system command on the server. Use this to run shell commands."""
    execution_log.append(f"run_command({command})")
    return simulated_run_command(command)


@tool
def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    execution_log.append(f"get_weather({city})")
    return real_get_weather(city)


agent_tools = [search_web, run_command, get_weather]

safe_inputs = [
    "What is artificial intelligence?",
    "What's the weather in London?",
]


def run_agent(user_input: str) -> str:
    agent = Agent(tools=agent_tools)
    return str(agent(user_input))


# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------

def run_security_tests(guard, method_name):
    """Run the standard security test suite against the current setup."""

    print(f"  Testing safe inputs ({method_name}):")
    for user_input in safe_inputs:
        print(f"\n  User: {user_input}")
        try:
            result = run_agent(user_input)
            print(f"  Response: {result[:200]}...")
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
            result = run_agent(attack_input)
            print(f"    Result: NOT BLOCKED - {result[:150]}...")
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
            verdict = guard.check_input_sync(attack_input, tool_name="run_command")
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
# PART 1: Real LLM, NO security
# ===================================================================

print_header("PART 1: Strands Agents (NO security)")

print("  Testing safe inputs:")
for user_input in safe_inputs:
    print(f"\n  User: {user_input}")
    try:
        result = run_agent(user_input)
        print(f"  Response: {result[:200]}...")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print("\n  Testing dangerous inputs (NO BLOCKING):")
execution_log.clear()

for attack_input, reason in ATTACK_INPUTS:
    print(f"\n  User: {attack_input}")
    print(f"  Reason: {reason}")
    try:
        result = run_agent(attack_input)
        print(f"  Response: {result[:200]}...")
        if execution_log:
            print(f"  [WARN] Tools executed: {execution_log[-1]}")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print(f"\n  Total commands executed: {len(execution_log)}")
print()


# ===================================================================
# PART 2A: auto_secure() — Automatic method (recommended)
# ===================================================================

print_header("PART 2A: auto_secure() — Automatic Method (recommended)")

from enkryptai_agent_security.sdk import auto_secure, get_guard_engine, unsecure

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

from enkryptai_agent_security.sdk.guardrails.base import GuardrailRegistry
from enkryptai_agent_security.sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkryptai_agent_security.sdk.guard import GuardEngine
from enkryptai_agent_security.sdk.observer import AgentObserver
from enkryptai_agent_security.sdk.otel_setup import _NoOpTracer, _NoOpMeter
from enkryptai_agent_security.sdk._patch import strands as strands_patch
from enkryptai_agent_security.sdk.adapters.strands import EnkryptStrandsAdapter

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
strands_patch.install(observer, guard)

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + strands_patch.install()")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, "manual setup")

strands_patch.uninstall()

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and patches")
print("=" * 70)
