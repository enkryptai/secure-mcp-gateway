#!/usr/bin/env python
"""
PreToolUse Hook - Gates tool execution using Enkrypt AI Guardrails.

Claude Code Hook: Runs before Claude executes a tool.
Input: { "tool_name": "...", "tool_input": {...} }
Deny: { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..." } }
Allow: { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow" } }
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    check_tool,
    format_violation_message,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_guardrail_name,
)

HOOK_NAME = "PreToolUse"


def create_response(decision: str, reason: str = None) -> dict:
    """Create Claude Code PreToolUse response format."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        output["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return output


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps(create_response("allow")))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Convert tool_input to string for guardrails check
    if isinstance(tool_input, dict):
        tool_input_str = json.dumps(tool_input)
    else:
        tool_input_str = str(tool_input) if tool_input else ""

    # First check tool patterns (sensitive tools)
    decision, reason = check_tool(tool_name, tool_input_str)

    # If allowed and this hook's guardrails are enabled, scan input with Enkrypt API
    if decision == "allow" and tool_input_str and is_hook_enabled(HOOK_NAME):
        should_block, violations, api_result = check_with_enkrypt_api(tool_input_str, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (visible in Claude Code hooks output)
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_block:
            violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
            decision = "deny"
            reason = f"Tool input blocked by Enkrypt AI Guardrails:\n\n{violation_message}"
            log_security_alert("tool_input_blocked", {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "tool_name": tool_name,
                "violations": violations,
            }, data)

    result = create_response(decision, reason)

    log_event(HOOK_NAME, data, result)
    log_to_combined(HOOK_NAME, data, result)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
