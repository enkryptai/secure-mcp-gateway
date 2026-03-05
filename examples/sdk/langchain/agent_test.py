"""
LangChain Agent + Enkrypt AI Guardrails Test
=============================================

A simple LangChain agent with a multiply tool, secured by Enkrypt AI.

- PART 1: Agent runs WITHOUT security (vulnerable)
- PART 2: Agent runs WITH Enkrypt auto_secure() (protected)

Setup:
    1. Fill in .env in the examples/sdk folder with your keys
    2. Run:
           pip install enkryptai-agent-security[sdk]
           python examples/sdk/langchain/agent_test.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _env_setup import env, print_header, ATTACK_INPUTS, GuardrailBlockedError

env.require("openai", "enkrypt", "policy")
env.print_config(llm_provider="openai")

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage

# -- Define tool ---------------------------------------------------------------

@tool
def multiply_numbers(a: float, b: float) -> str:
    """Multiply two numbers together. Use this for any multiplication."""
    return str(a * b)


llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
llm_with_tools = llm.bind_tools([multiply_numbers])


def run_agent(user_input: str):
    """Simple tool-calling loop: user -> LLM -> tool -> answer."""
    print(f"  User: {user_input}")
    messages = [
        SystemMessage(content="You are a helpful math assistant. Use tools when appropriate."),
        HumanMessage(content=user_input),
    ]
    response = llm_with_tools.invoke(messages)

    if response.tool_calls:
        for tc in response.tool_calls:
            print(f"  LLM calls: {tc['name']}({tc['args']})")
            tool_fn = {"multiply_numbers": multiply_numbers}[tc["name"]]
            result = tool_fn.invoke(tc["args"])
            print(f"  Tool result: {result}")
    else:
        print(f"  LLM response: {response.content[:200]}")
    print()


# ==============================================================================
# PART 1: No security -- agent runs unprotected
# ==============================================================================

print_header("PART 1: LangChain Agent -- NO Security")

print("--- Safe input ---\n")
try:
    run_agent("What is 25 multiplied by 4?")
except Exception as e:
    print(f"  Error: {e}\n")

print("--- Dangerous input (NO protection) ---\n")
for attack_input, reason in ATTACK_INPUTS:
    print(f"  [{reason}] {attack_input[:70]}...")
    try:
        run_agent(attack_input)
        print(f"    NOT BLOCKED\n")
    except Exception as e:
        print(f"    Error: {e}\n")


# ==============================================================================
# PART 2: With Enkrypt auto_secure() -- all inputs are guarded
# ==============================================================================

print_header("PART 2: LangChain Agent -- WITH Enkrypt auto_secure()")

from enkryptai_agent_security.sdk import auto_secure, unsecure

auto_secure(fail_open=False)

print(f"  Policy:  {env.enkrypt_policy}")
print(f"  Block:   {', '.join(env.enkrypt_block_list)}")
print()

print("--- Safe input (should work normally) ---\n")
try:
    run_agent("What is 25 multiplied by 4?")
except GuardrailBlockedError as e:
    print(f"  Unexpectedly BLOCKED: {e}\n")
except Exception as e:
    print(f"  Error: {e}\n")

print("--- Dangerous inputs (should be BLOCKED by Enkrypt) ---\n")
blocked_count = 0
total_tests = len(ATTACK_INPUTS)

for attack_input, reason in ATTACK_INPUTS:
    print(f"  [{reason}] {attack_input[:70]}...")
    try:
        run_agent(attack_input)
        print(f"    NOT BLOCKED\n")
    except GuardrailBlockedError as e:
        blocked_count += 1
        print(f"    BLOCKED by Enkrypt! Violations: {e.violations}\n")
    except Exception as e:
        print(f"    Error: {e}\n")

unsecure()

# -- Summary -------------------------------------------------------------------

print("=" * 70)
print(f"  RESULTS: {blocked_count}/{total_tests} dangerous inputs blocked")
print("=" * 70)
if blocked_count == total_tests:
    print("  ALL attacks were blocked by Enkrypt AI guardrails!")
elif blocked_count > 0:
    print(f"  {blocked_count}/{total_tests} attacks blocked. Review your block list.")
else:
    print("  No attacks were blocked. Check your configuration.")
print()
