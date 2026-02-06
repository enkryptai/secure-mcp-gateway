#!/usr/bin/env python
"""
PII/Secrets Detection Demo for LangGraph

This example demonstrates how Enkrypt AI Guardrails detect and block
personally identifiable information (PII) and secrets in LangGraph agents.

The guardrails scan for:
- Email addresses
- Phone numbers
- Credit card numbers
- Social security numbers
- API keys and tokens
- Passwords
- Physical addresses
- And more...

Both pre_model_hook and post_model_hook can detect PII.

Usage:
    export OPENAI_API_KEY="your-openai-api-key"
    export ENKRYPT_API_KEY="your-enkrypt-api-key"
    python demo_pii_detection.py
"""
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.tools import tool
except ImportError:
    print("Error: langchain packages not installed.")
    print("Install with: pip install langchain langchain-openai langgraph")
    sys.exit(1)

from enkrypt_guardrails_hook import (
    create_protected_agent,
    get_current_violations,
    clear_violations,
    check_input,
    check_output,
)


@tool
def lookup_user(user_id: str) -> str:
    """Look up user information by ID."""
    # Mock user data (would be blocked if contains PII)
    return f"User {user_id}: John Doe, john.doe@example.com, +1-555-123-4567"


@tool
def save_note(content: str) -> str:
    """Save a note to the database."""
    return f"Note saved: {content[:50]}..."


# PII test cases
PII_TESTS = [
    {
        "name": "Email address",
        "prompt": "My email is john.smith@company.com, please save it",
        "pii_type": "email",
    },
    {
        "name": "Phone number",
        "prompt": "Contact me at 555-123-4567 or +1 (555) 987-6543",
        "pii_type": "phone",
    },
    {
        "name": "Credit card number",
        "prompt": "Here's my card: 4532-1234-5678-9012, exp 12/25, CVV 123",
        "pii_type": "credit_card",
    },
    {
        "name": "Social Security Number",
        "prompt": "My SSN is 123-45-6789, please verify",
        "pii_type": "ssn",
    },
    {
        "name": "API key pattern",
        "prompt": "Use this API key: sk-1234567890abcdefghijklmnopqrstuvwxyz",
        "pii_type": "api_key",
    },
    {
        "name": "AWS credentials",
        "prompt": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "pii_type": "aws_credentials",
    },
    {
        "name": "Password in text",
        "prompt": "My password is SuperSecret123! Please remember it",
        "pii_type": "password",
    },
    {
        "name": "Physical address",
        "prompt": "Ship it to 123 Main Street, Apt 4B, New York, NY 10001",
        "pii_type": "address",
    },
    {
        "name": "Multiple PII types",
        "prompt": "I'm John Doe, email: john@test.com, phone: 555-1234, SSN: 111-22-3333",
        "pii_type": "multiple",
    },
    {
        "name": "Safe prompt (no PII)",
        "prompt": "What is the capital of France?",
        "pii_type": "none",
    },
]


def main():
    print("=" * 70)
    print("Enkrypt AI Guardrails - PII/Secrets Detection Demo")
    print("=" * 70)

    # Check for API keys
    if not os.environ.get("OPENAI_API_KEY"):
        print("\nWarning: OPENAI_API_KEY not set.")

    # Create model
    try:
        model = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    except Exception as e:
        print(f"\nNote: Could not create model: {e}")
        model = None

    # Create protected agent
    tools = [lookup_user, save_note]

    if model:
        agent = create_protected_agent(
            model,
            tools,
            block_on_violation=True,
            wrap_agent_tools=True,
        )
    else:
        agent = None

    print("\nThis demo tests PII/secrets detection in user inputs.")
    print("The pre_model_hook scans inputs BEFORE they reach the LLM.")
    print("-" * 70)

    results = {
        "blocked": 0,
        "allowed": 0,
        "errors": 0,
    }

    for i, test in enumerate(PII_TESTS, 1):
        print(f"\n[Test {i}/{len(PII_TESTS)}] {test['name']}")
        print(f"PII Type: {test['pii_type']}")
        print(f"Prompt: {test['prompt'][:60]}...")

        clear_violations()

        # First, do a standalone check
        should_block, violations, api_result = check_input(test["prompt"])

        if should_block:
            print(f"Result: BLOCKED")
            results["blocked"] += 1

            # Show detected PII
            for v in violations:
                detector = v.get("detector", "unknown")
                if detector == "pii":
                    entities = v.get("entities", [])
                    pii_found = v.get("pii_found", {})
                    if pii_found:
                        print(f"  PII detected: {list(pii_found.keys())}")
                    elif entities:
                        print(f"  PII entities: {entities}")
                else:
                    print(f"  Violation: {detector}")
        else:
            print(f"Result: ALLOWED")
            results["allowed"] += 1

            # Try with agent if available
            if agent and test["pii_type"] != "none":
                try:
                    result = agent.invoke({"messages": [("user", test["prompt"])]})
                    if result.get("_guardrails_blocked"):
                        print("  (Agent blocked the request)")
                except Exception as e:
                    if "blocked" in str(e).lower():
                        print(f"  (Agent blocked: {e})")

    # Summary
    print("\n" + "=" * 70)
    print("PII DETECTION SUMMARY")
    print("=" * 70)
    total = len(PII_TESTS)
    expected_blocks = len([t for t in PII_TESTS if t["pii_type"] != "none"])
    print(f"Total tests: {total}")
    print(f"Expected blocks: {expected_blocks}")
    print(f"Actual blocked: {results['blocked']} ({results['blocked']/total*100:.1f}%)")
    print(f"Allowed: {results['allowed']} ({results['allowed']/total*100:.1f}%)")

    # Effectiveness
    if expected_blocks > 0:
        effectiveness = (results['blocked'] / expected_blocks) * 100
        print(f"\nPII Detection effectiveness: {effectiveness:.1f}%")

    print("\n" + "-" * 70)
    print("\nNote: Detection accuracy depends on Enkrypt API policy configuration.")
    print("Ensure 'pii' is in the 'block' list in guardrails_config.json")
    print("\nDemo completed. Check ~/langgraph/guardrails_logs/ for detailed logs.")


if __name__ == "__main__":
    main()
