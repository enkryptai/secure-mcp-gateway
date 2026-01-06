#!/usr/bin/env python
"""
afterAgentResponse Hook - Audits the agent's final response text using Enkrypt AI Guardrails.

Per Cursor hooks spec, this hook is observability-only (no blocking output fields supported).
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (  # noqa: E402
    check_with_enkrypt_api,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
)

HOOK_NAME = "afterAgentResponse"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({}))
        return

    text = data.get("text", "")

    violations = []
    api_result = None
    if is_hook_enabled(HOOK_NAME) and text and text.strip():
        should_alert, violations, api_result = check_with_enkrypt_api(text, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (visible in Cursor hooks output)
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_alert:
            log_security_alert(
                "agent_response_violation",
                {
                    "hook": HOOK_NAME,
                    "policy_name": get_hook_policy_name(HOOK_NAME),
                    "violations": violations,
                    "response_preview": text[:500] + "..." if len(text) > 500 else text,
                },
                data,
            )

    log_data = {
        **data,
        "text_size": len(text),
        "violations": violations,
        "api_result": api_result,
    }
    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # afterAgentResponse has no supported output fields; return empty object.
    print(json.dumps({}))


if __name__ == "__main__":
    main()


