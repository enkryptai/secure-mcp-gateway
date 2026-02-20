"""
=============================================================================
  CrewAI + Real LLM + Enkrypt AI Guardrails Example
=============================================================================

Demonstrates CrewAI agent with OpenAI GPT-4o-mini and real tools:
- PART 1:  Without security (vulnerable to attacks)
- PART 2A: With Enkrypt AI guardrails — auto_secure() method (recommended)
- PART 2B: With Enkrypt AI guardrails — manual setup method (advanced)

You can run both parts, or comment out either 2A or 2B to test one method.

Requirements:
    pip install crewai openai

Run:
    cd enkrypt-in-agent-sdk
    python examples/crewai/real_test.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from crewai import Agent, Task, Crew
    from crewai.tools import tool
except ImportError:
    print("ERROR: crewai not installed. Run: pip install crewai")
    sys.exit(1)

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

env.require("openai", "enkrypt", "policy")
env.print_config(llm_provider="openai")
os.environ["OPENAI_API_KEY"] = env.openai_api_key

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


agent = Agent(
    role="researcher",
    goal="Research topics and execute commands as needed",
    backstory="You are a helpful research assistant with access to web search, weather, and command execution tools.",
    tools=[search_web, run_command, get_weather],
    verbose=True,
    llm="openai/gpt-4o-mini",
)


# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------

def run_security_tests(guard, method_name):
    """Run the standard security test suite against the current setup."""

    print(f"  Testing safe input ({method_name}):")
    execution_log.clear()
    try:
        task = Task(
            description="Search for information about machine learning trends",
            agent=agent,
            expected_output="A summary of machine learning trends",
        )
        crew = Crew(agents=[agent], tasks=[task], verbose=True)
        result = crew.kickoff()
        print(f"  Output: {str(result)[:300]}")
        print("  Status: PASSED (safe input allowed)")
    except GuardrailBlockedError:
        print(f"  BLOCKED (unexpected for safe input!)")
    except Exception as e:
        print(f"  Error: {e}")
    print()

    print(f"  Testing dangerous inputs via LLM ({method_name}):")
    blocked_count = 0
    total_tests = 0

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  [{total_tests}] Input ({reason}): {attack_input[:60]}...")
        try:
            task = Task(
                description=attack_input,
                agent=agent,
                expected_output="Result of the task",
            )
            crew = Crew(agents=[agent], tasks=[task], verbose=True)
            result = crew.kickoff()
            print(f"    Result: NOT BLOCKED - {str(result)[:150]}")
        except GuardrailBlockedError:
            blocked_count += 1
            print(f"    Result: BLOCKED by {method_name}")
        except Exception as e:
            print(f"    Result: Error - {e}")

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
print_header("PART 1: CrewAI WITHOUT Security")

print("  Testing safe input:")
execution_log.clear()
try:
    task = Task(
        description="Search for information about machine learning trends",
        agent=agent,
        expected_output="A summary of machine learning trends",
    )
    crew = Crew(agents=[agent], tasks=[task], verbose=True)
    result = crew.kickoff()
    print(f"  Output: {str(result)[:300]}")
    print("  Status: PASSED (executed normally)\n")
except Exception as e:
    print(f"  Error: {e}\n")

print("  Testing dangerous inputs (NO BLOCKING):")
for attack_input, reason in ATTACK_INPUTS:
    print(f"\n  Input ({reason}): {attack_input[:60]}...")
    try:
        task = Task(
            description=attack_input,
            agent=agent,
            expected_output="Result of the task",
        )
        crew = Crew(agents=[agent], tasks=[task], verbose=True)
        result = crew.kickoff()
        print(f"  Output: {str(result)[:200]}")
        print(f"  Status: VULNERABLE (executed without protection!)")
    except Exception as e:
        print(f"  Error: {e}")

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
from enkrypt_agent_sdk._patch import crewai as crew_patch

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
crew_patch.install(observer, guard)

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + crew_patch.install()")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, "manual setup")

crew_patch.uninstall()

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and patches")
print("=" * 70)
