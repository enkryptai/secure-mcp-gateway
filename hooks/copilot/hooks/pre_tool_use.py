#!/usr/bin/env python
"""
preToolUse Hook - Gates tool execution using Enkrypt AI Guardrails.

This is the ONLY Copilot hook that can block actions.
Returns {"permissionDecision": "deny", "permissionDecisionReason": "..."} to block,
or {"permissionDecision": "allow"} to allow.

Input from Copilot:
{
    "timestamp": 1704614600000,
    "cwd": "/path/to/project",
    "toolName": "bash",
    "toolArgs": "{\"command\": \"ls\"}"
}
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

HOOK_NAME = "preToolUse"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({"permissionDecision": "allow"}))
        sys.exit(0)

    tool_name = data.get("toolName", "")
    tool_args = data.get("toolArgs", "")

    # First check tool patterns (sensitive tools list)
    permission_decision, reason = check_tool(tool_name, tool_args)

    # If allowed and this hook's guardrails are enabled, scan input with Enkrypt API
    if permission_decision == "allow" and tool_args and is_hook_enabled(HOOK_NAME):
        should_block, violations, api_result = check_with_enkrypt_api(tool_args, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (single line for cleaner output)
        print(f"[Enkrypt Guardrails] {json.dumps(api_result)}", file=sys.stderr)
        if should_block:
            violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
            permission_decision = "deny"
            reason = f"Blocked by Enkrypt AI Guardrails:\n{violation_message}"
            log_security_alert("tool_input_blocked", {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "tool_name": tool_name,
                "violations": violations,
            }, data)

    result = {"permissionDecision": permission_decision}
    if reason:
        result["permissionDecisionReason"] = reason

    log_event(HOOK_NAME, data, result)
    log_to_combined(HOOK_NAME, data, result)

    # Output must be single-line JSON to stdout
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
