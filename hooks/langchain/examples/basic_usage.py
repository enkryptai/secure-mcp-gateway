#!/usr/bin/env python
"""
Basic usage example for Enkrypt AI Guardrails with LangChain.

This example shows how to use the EnkryptGuardrailsHandler with LangChain's
ChatOpenAI model.

Requirements:
    pip install langchain langchain-openai

Environment:
    OPENAI_API_KEY: Your OpenAI API key
    ENKRYPT_API_KEY: Your Enkrypt API key (or configure in guardrails_config.json)
"""
import os
import sys

# Add parent directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enkrypt_guardrails_handler import (
    EnkryptGuardrailsHandler,
    GuardrailsViolationError,
    get_guardrails_metrics,
)

# Check for required API keys
if not os.environ.get("OPENAI_API_KEY"):
    print("Warning: OPENAI_API_KEY not set. Set it to run this demo.")
    print("  PowerShell: $env:OPENAI_API_KEY = 'your-key'")
    print("  Bash: export OPENAI_API_KEY='your-key'")


def main():
    """Run basic usage demo."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("Please install langchain-openai: pip install langchain-openai")
        return

    print("=" * 60)
    print("Enkrypt AI Guardrails - Basic LangChain Usage Demo")
    print("=" * 60)

    # Create the guardrails handler
    handler = EnkryptGuardrailsHandler(
        raise_on_violation=True,
        block_sensitive_tools=True,
    )

    # Create LLM with guardrails handler
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        callbacks=[handler],
    )

    # Test 1: Safe prompt
    print("\n--- Test 1: Safe Prompt ---")
    try:
        response = llm.invoke("What is Python programming language?")
        print(f"Response: {response.content[:200]}...")
        print("Result: PASSED (safe prompt allowed)")
    except GuardrailsViolationError as e:
        print(f"Unexpected block: {e}")
    except Exception as e:
        print(f"Error: {e}")

    # Test 2: Another safe prompt
    print("\n--- Test 2: Another Safe Prompt ---")
    try:
        response = llm.invoke("Explain machine learning in simple terms.")
        print(f"Response: {response.content[:200]}...")
        print("Result: PASSED (safe prompt allowed)")
    except GuardrailsViolationError as e:
        print(f"Unexpected block: {e}")
    except Exception as e:
        print(f"Error: {e}")

    # Print metrics
    print("\n--- Metrics ---")
    metrics = get_guardrails_metrics()
    for hook_name, hook_metrics in metrics.items():
        if hook_metrics["total_calls"] > 0:
            print(f"  {hook_name}:")
            print(f"    Total calls: {hook_metrics['total_calls']}")
            print(f"    Blocked: {hook_metrics['blocked_calls']}")
            print(f"    Allowed: {hook_metrics['allowed_calls']}")
            print(f"    Avg latency: {hook_metrics['avg_latency_ms']:.2f}ms")


if __name__ == "__main__":
    main()
