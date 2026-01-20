#!/usr/bin/env python
"""
Multi-Agent with Handoffs Demo - OpenAI Agents SDK

This example demonstrates how Enkrypt AI Guardrails works with
multi-agent systems and agent handoffs in the OpenAI Agents SDK.

Usage:
    python demo_multi_agent.py
"""
import asyncio
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from agents import Agent, Runner, function_tool
    from pydantic import BaseModel
    AGENTS_AVAILABLE = True
except ImportError:
    AGENTS_AVAILABLE = False

from enkrypt_guardrails_hook import EnkryptRunHooks


# Define output types
if AGENTS_AVAILABLE:
    class MathResult(BaseModel):
        number: int
        explanation: str

    class TextResult(BaseModel):
        text: str

    # Define tools
    @function_tool
    def multiply(a: int, b: int) -> int:
        """Multiply two numbers."""
        return a * b

    @function_tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b


async def main():
    print("=" * 70)
    print("Enkrypt AI Guardrails - Multi-Agent Handoffs Demo")
    print("OpenAI Agents SDK Edition")
    print("=" * 70)

    if not AGENTS_AVAILABLE:
        print("\nError: OpenAI Agents SDK is not installed.")
        print("Install it with: pip install openai-agents")
        return

    # Create hooks that track handoffs
    hooks = EnkryptRunHooks(
        block_on_violation=True,
        log_only_mode=False,
    )

    # Create specialized agents
    math_agent = Agent(
        name="Math Agent",
        instructions=(
            "You are a math specialist. Solve math problems. "
            "Use the multiply and add tools for calculations."
        ),
        tools=[multiply, add],
        output_type=MathResult,
    )

    writer_agent = Agent(
        name="Writer Agent",
        instructions=(
            "You are a creative writer. Help with writing tasks. "
            "Write clear and engaging content."
        ),
        output_type=TextResult,
    )

    # Create router agent that can handoff to specialists
    router_agent = Agent(
        name="Router Agent",
        instructions=(
            "You are a routing agent. Analyze the user's request and "
            "hand off to the appropriate specialist:\n"
            "- For math problems, hand off to Math Agent\n"
            "- For writing tasks, hand off to Writer Agent\n"
            "- For general questions, answer yourself"
        ),
        handoffs=[math_agent, writer_agent],
    )

    print("\nMulti-Agent System Created:")
    print("  - Router Agent (coordinator)")
    print("    -> Math Agent (specialist)")
    print("    -> Writer Agent (specialist)")
    print("\nGuardrails monitor all agents and handoffs.")
    print("\n" + "-" * 70)

    # Test cases that demonstrate handoffs
    test_prompts = [
        {
            "name": "Math problem (handoff to Math Agent)",
            "prompt": "What is 7 times 8?",
        },
        {
            "name": "Writing task (handoff to Writer Agent)",
            "prompt": "Write a haiku about programming",
        },
        {
            "name": "General question (no handoff)",
            "prompt": "What day comes after Tuesday?",
        },
        {
            "name": "Complex math (handoff)",
            "prompt": "Calculate 15 plus 25, then multiply by 2",
        },
    ]

    for i, test in enumerate(test_prompts, 1):
        hooks.reset()
        print(f"\n[Test {i}] {test['name']}")
        print(f"   Prompt: {test['prompt']}")

        try:
            result = await Runner.run(
                router_agent,
                hooks=hooks,
                input=test["prompt"]
            )

            print(f"   Status: COMPLETED")
            print(f"   Output: {result.final_output}")

            # Show event count and any violations
            usage = hooks.get_token_usage()
            print(f"   Events tracked: {usage['event_count']}")

            violations = hooks.get_current_violations()
            if violations:
                print(f"   Violations: {len(violations)}")

        except Exception as e:
            print(f"   Status: ERROR")
            print(f"   Error: {str(e)[:60]}...")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Guardrails hook events in multi-agent runs:")
    print("  - on_agent_start: Called for each agent in the chain")
    print("  - on_agent_end: Called when each agent completes")
    print("  - on_handoff: Called when control passes between agents")
    print("  - on_tool_start/end: Called for all tool uses")
    print("  - on_llm_start/end: Called for all LLM calls")
    print("\nCheck ~/openai_agents/guardrails_logs/ for detailed audit logs.")


if __name__ == "__main__":
    asyncio.run(main())
