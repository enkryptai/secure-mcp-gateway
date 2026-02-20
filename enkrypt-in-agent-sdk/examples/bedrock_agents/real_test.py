"""
=============================================================================
  Amazon Bedrock Agents + Enkrypt AI Guardrails Example
=============================================================================

Demonstrates Bedrock Agents trace processing with Enkrypt guardrails:
- PART 1:  Trace processing without guardrails
- PART 2A: With Enkrypt AI guardrails — auto_secure() method (recommended)
- PART 2B: With Enkrypt AI guardrails — manual setup method (advanced)

You can run both parts, or comment out either 2A or 2B to test one method.

Note: Bedrock Agents requires AWS credentials and a deployed agent.
This example uses the adapter directly for trace processing.

Requirements:
    pip install boto3

Run:
    cd enkrypt-in-agent-sdk
    python examples/bedrock_agents/real_test.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import boto3
except ImportError:
    print("ERROR: boto3 not installed. Run: pip install boto3")
    sys.exit(1)

from _env_setup import (
    env,
    print_header,
    print_result,
    ATTACK_INPUTS,
    GuardrailBlockedError,
    real_search_web,
    simulated_run_command,
)

env.print_config(llm_provider="none")
env.require("enkrypt", "policy")

# ------------------------------------------------------------------
# Define tools (real implementations)
# ------------------------------------------------------------------

execution_log = []


def dispatch_tool(tool_name: str, args: dict) -> str:
    if tool_name == "search_web":
        query = args.get("query", "")
        execution_log.append(f"search_web({query})")
        return real_search_web(query)
    elif tool_name == "run_command":
        cmd = args.get("cmd", args.get("command", ""))
        execution_log.append(f"run_command({cmd})")
        return simulated_run_command(cmd)
    return f"Unknown tool: {tool_name}"


# ------------------------------------------------------------------
# Shared security test suite (used by both PART 2A and 2B)
# ------------------------------------------------------------------

def run_security_tests(guard, adapter, method_name):
    """Run the standard security test suite against the current setup."""

    print(f"  Testing safe trace ({method_name}):")
    execution_log.clear()
    safe_trace = {
        "orchestrationTrace": {
            "invocationInput": {
                "actionGroupInvocationInput": {
                    "apiPath": "search_web",
                    "parameters": {"query": "machine learning trends"},
                },
            },
        },
    }
    run_id = adapter.process_trace(safe_trace)
    tool_result = dispatch_tool("search_web", {"query": "machine learning trends"})
    print(f"  Tool result: {tool_result[:200]}...")
    print(f"  Tools called: {execution_log}")
    print("  Status: PASSED (safe trace processed)")
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
                result = dispatch_tool("run_command", {"cmd": attack_input})
                print(f"    Result: ALLOWED - {result[:100]}...")
        except GuardrailBlockedError as e:
            blocked_count += 1
            print(f"    Result: BLOCKED: {e}")

    print(f"\n  Blocking: {blocked_count}/{total_tests}")

    print(f"\n  Testing direct attack via trace ({method_name}):")
    execution_log.clear()

    for attack_input, reason in ATTACK_INPUTS:
        total_tests += 1
        print(f"\n  Attack trace: run_command('{attack_input[:50]}...')")
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
# PART 1: Trace processing without guardrails
# ===================================================================
print_header("PART 1: Bedrock Agents Trace Processing (No Security)")

from enkrypt_agent_sdk.adapters.bedrock_agents import BedrockAgentsAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = BedrockAgentsAdapter(observer, guard_engine=None)

sample_trace = {
    "orchestrationTrace": {
        "modelInvocationInput": {"foundationModel": "anthropic.claude-v2"},
        "invocationInput": {
            "actionGroupInvocationInput": {
                "apiPath": "search_web",
                "parameters": {"query": "What is Python programming?"},
            },
        },
    },
}

run_id = adapter.process_trace(sample_trace)
print(f"  Processed sample Bedrock trace (run_id: {run_id})")

print("  Simulating tool dispatch from trace:")
tool_result = dispatch_tool("search_web", {"query": "What is Python programming?"})
print(f"  Tool result: {tool_result[:200]}...")
print("  Status: Trace processed (no guardrails)\n")


# ===================================================================
# PART 2A: auto_secure() — Automatic method (recommended)
# ===================================================================

print_header("PART 2A: auto_secure() — Automatic Method (recommended)")

from enkrypt_agent_sdk import auto_secure, get_guard_engine, get_observer, unsecure

auto_secure(fail_open=False)
guard = get_guard_engine()

observer_a = get_observer()
adapter_a = BedrockAgentsAdapter(observer_a, guard_engine=guard)

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
adapter_b = BedrockAgentsAdapter(observer_b, guard_engine=guard)

print(f"  Setup: Manual GuardrailRegistry + GuardEngine + BedrockAgentsAdapter")
print(f"  Policy: {os.environ['ENKRYPT_GUARDRAIL_POLICY']}")
print()

run_security_tests(guard, adapter_b, "manual setup")

# ===================================================================

print("=" * 70)
print("  DONE! Both methods provide the same protection:")
print("  - auto_secure():  1 line, reads env vars, patches all frameworks")
print("  - Manual setup:   Full control over registry, guard, and adapter")
print("=" * 70)
