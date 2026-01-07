#!/usr/bin/env python
"""
PostToolUse Hook - Audits tool results using Enkrypt AI Guardrails.

Claude Code Hook: Runs after Claude executes a tool.
Input: { "tool_name": "...", "tool_input": {...}, "tool_response": {...} }
Output: {} (audit-only, no blocking)
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    analyze_tool_result,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
)

HOOK_NAME = "PostToolUse"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_response = data.get("tool_response", {})

    # Convert tool_response to string for analysis
    if isinstance(tool_response, dict):
        response_str = json.dumps(tool_response)
    else:
        response_str = str(tool_response) if tool_response else ""

    # Analyze the result for sensitive data patterns
    analysis = analyze_tool_result(tool_name, response_str)

    # Check with this hook's guardrails if enabled
    output_violations = []
    if is_hook_enabled(HOOK_NAME) and response_str:
        should_alert, output_violations, api_result = check_with_enkrypt_api(response_str, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (visible in Claude Code hooks output)
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_alert:
            log_security_alert("tool_output_violation", {
                "hook": HOOK_NAME,
                "policy_name": get_hook_policy_name(HOOK_NAME),
                "tool_name": tool_name,
                "violations": output_violations,
            }, data)

    log_data = {
        **data,
        "result_size": len(response_str),
        "analysis": analysis,
        "output_violations": output_violations,
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Alert if sensitive data detected via pattern matching
    if analysis["sensitive_data_hints"]:
        log_security_alert("sensitive_data_in_tool_result", {
            "hook": HOOK_NAME,
            "tool_name": tool_name,
            "detected": analysis["sensitive_data_hints"],
        }, data)

    print(json.dumps({}))


if __name__ == "__main__":
    main()
