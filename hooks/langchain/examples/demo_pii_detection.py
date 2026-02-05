#!/usr/bin/env python
"""
PII detection demo for Enkrypt AI Guardrails with LangChain.

This example demonstrates how the guardrails detect and block PII
(Personal Identifiable Information) in prompts.

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


PII_PROMPTS = [
    "My social security number is 123-45-6789. Can you verify it?",
    "Send an email to john.doe@example.com about the meeting",
    "My credit card number is 4532-1234-5678-9012, expiry 12/25",
    "Call me at 555-123-4567 to discuss the contract",
    "My bank account number is 1234567890 and routing is 987654321",
    "Process refund for customer Jane Smith at 123 Main St, New York, NY 10001",
]

SAFE_PROMPTS = [
    "What are common types of personally identifiable information?",
    "Explain GDPR compliance requirements",
    "How should companies protect customer data?",
]


def main():
    """Run PII detection demo."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("Please install langchain-openai: pip install langchain-openai")
        return

    print("=" * 60)
    print("Enkrypt AI Guardrails - PII Detection Demo")
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

    # Test PII prompts
    print("\n--- Testing PII Prompts (should be BLOCKED) ---")
    blocked_count = 0
    for i, prompt in enumerate(PII_PROMPTS, 1):
        print(f"\nTest {i}: {prompt[:60]}...")
        try:
            response = llm.invoke(prompt)
            print(f"  Result: NOT BLOCKED")
            print(f"  Note: May be audit-only mode or PII not in block list")
        except GuardrailsViolationError as e:
            blocked_count += 1
            print(f"  Result: BLOCKED")
            print(f"  Violations: {[v['detector'] for v in e.violations]}")
            if any(v['detector'] == 'pii' for v in e.violations):
                for v in e.violations:
                    if v['detector'] == 'pii' and 'entities' in v:
                        print(f"  PII types found: {v['entities']}")
        except Exception as e:
            print(f"  Error: {type(e).__name__}: {e}")

    # Test safe prompts
    print("\n--- Testing Safe Prompts (should be ALLOWED) ---")
    allowed_count = 0
    for i, prompt in enumerate(SAFE_PROMPTS, 1):
        print(f"\nTest {i}: {prompt[:60]}...")
        try:
            response = llm.invoke(prompt)
            allowed_count += 1
            print(f"  Result: ALLOWED")
            print(f"  Response preview: {response.content[:100]}...")
        except GuardrailsViolationError as e:
            print(f"  Result: BLOCKED (unexpected)")
            print(f"  Violations: {[v['detector'] for v in e.violations]}")
        except Exception as e:
            print(f"  Error: {type(e).__name__}: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"PII prompts blocked: {blocked_count}/{len(PII_PROMPTS)}")
    print(f"Safe prompts allowed: {allowed_count}/{len(SAFE_PROMPTS)}")
    print("\nNote: PII detection depends on your Enkrypt policy configuration.")
    print("Some PII may be audit-only if not in the 'block' list.")

    # Print metrics
    print("\n--- Metrics ---")
    metrics = get_guardrails_metrics()
    for hook_name, hook_metrics in metrics.items():
        if hook_metrics["total_calls"] > 0:
            print(f"  {hook_name}:")
            print(f"    Total: {hook_metrics['total_calls']}, Blocked: {hook_metrics['blocked_calls']}")


if __name__ == "__main__":
    main()
