"""
=============================================================================
  Anthropic SDK + Real LLM + Enkrypt AI Guardrails
=============================================================================

Demonstrates the Anthropic SDK with Claude and real tools:
- PART 1: Without security (tools execute without guardrails)
- PART 2A: With Enkrypt AI guardrails via auto_secure() (recommended)
- PART 2B: With Enkrypt AI guardrails via manual setup (advanced)

The Anthropic patch intercepts messages.create() with pre_llm and post_llm
guardrail checkpoints. Dangerous user messages are blocked BEFORE the API call.

Setup:
    1. Create a .env file in the enkrypt-in-agent-sdk folder:

           ANTHROPIC_API_KEY=sk-ant-...
           ENKRYPT_API_KEY=your-enkrypt-api-key
           ENKRYPT_GUARDRAIL_POLICY=your-policy-name

    2. Run:
           cd enkrypt-in-agent-sdk
           python examples/anthropic/real_test.py
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

env.require("anthropic", "enkrypt", "policy")
env.print_config("anthropic")

try:
    import anthropic
except ImportError:
    print("ERROR: Anthropic SDK not installed. Run: pip install anthropic")
    sys.exit(1)

client = anthropic.Anthropic(api_key=env.anthropic_api_key)

# ------------------------------------------------------------------
# Define tools (Anthropic format with real implementations)
# ------------------------------------------------------------------

tools = [
    {
        "name": "search_web",
        "description": "Search the web for information. Use this for general knowledge questions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The search query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "run_command",
        "description": "Execute a system command on the server. Use this to run shell commands.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to execute"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "get_weather",
        "description": "Get the current weather for a city.",
        "input_schema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "The city name"},
            },
            "required": ["city"],
        },
    },
    {
        "name": "calculator",
        "description": "Calculate a math expression.",
        "input_schema": {
            "type": "object",
            "properties": {
                "expression": {"type": "string", "description": "The math expression"},
            },
            "required": ["expression"],
        },
    },
]

execution_log = []


def dispatch_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool based on its name and input (real implementations)."""
    if tool_name == "search_web":
        query = tool_input.get("query", "")
        execution_log.append(f"search_web({query})")
        return real_search_web(query)
    elif tool_name == "run_command":
        command = tool_input.get("command", "")
        execution_log.append(f"run_command({command})")
        return simulated_run_command(command)
    elif tool_name == "get_weather":
        city = tool_input.get("city", "")
        execution_log.append(f"get_weather({city})")
        return real_get_weather(city)
    elif tool_name == "calculator":
        expression = tool_input.get("expression", "")
        execution_log.append(f"calculator({expression})")
        return real_calculator(expression)
    else:
        return f"Unknown tool: {tool_name}"


# ===================================================================
# PART 1: Real LLM, NO security
# ===================================================================

print_header("PART 1: Anthropic SDK (NO security)")


def run_agent_loop(user_input: str):
    """Run a simple agent loop: Claude -> tool -> Claude."""
    messages = [{"role": "user", "content": user_input}]

    max_iterations = 5
    for _ in range(max_iterations):
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=tools,
            messages=messages,
        )

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                print(f"  Tool call: {block.name}({block.input})")
                result = dispatch_tool(block.name, block.input)
                print(f"  Tool result: {result[:200]}")
                tool_results.append(
                    {"tool_use_id": block.id, "type": "tool_result", "content": result}
                )

        messages.append({"role": "assistant", "content": response.content})

        if tool_results:
            messages.append({"role": "user", "content": tool_results})
        else:
            text = "".join(b.text for b in response.content if b.type == "text")
            return text

    return "Max iterations reached"


print("  Testing safe inputs:")
safe_inputs = [
    "What is artificial intelligence?",
    "What's the weather in Tokyo?",
    "What is 42 * 17?",
]

for user_input in safe_inputs:
    print(f"\n  User: {user_input}")
    try:
        result = run_agent_loop(user_input)
        print(f"  Response: {result[:200]}...")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print("\n  Testing dangerous inputs (NO BLOCKING):")
execution_log.clear()

for attack_input, reason in ATTACK_INPUTS:
    print(f"\n  User: {attack_input}")
    print(f"  Reason: {reason}")
    try:
        result = run_agent_loop(attack_input)
        print(f"  Response: {result[:200]}...")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

print(f"\n  Total commands executed: {len(execution_log)}")
print()

# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------


def run_security_tests(guard, method_name):
    """Run the standard security test suite against the current setup."""

    print(f"  Testing safe input ({method_name}):")
    for user_input in safe_inputs:
        print(f"\n  User: {user_input}")
        try:
            result = run_agent_loop(user_input)
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
            result = run_agent_loop(attack_input)
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
from enkrypt_agent_sdk._patch import anthropic as anth_patch

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
anth_patch.install(observer, guard)

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + anth_patch.install()")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, "manual setup")

anth_patch.uninstall()

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and patches")
print("=" * 70)
