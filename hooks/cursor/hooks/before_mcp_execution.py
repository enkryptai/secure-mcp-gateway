#!/usr/bin/env python
"""
beforeMCPExecution Hook - Gates MCP tools using Enkrypt AI Guardrails.
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    check_mcp_tool,
    format_violation_message,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
)

HOOK_NAME = "beforeMCPExecution"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"permission": "allow"}))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", "")

    # First check MCP tool patterns
    permission, user_message, agent_message = check_mcp_tool(tool_name, tool_input)

    # If allowed and this hook's guardrails are enabled, scan input with Enkrypt API
    if permission == "allow" and tool_input and is_hook_enabled(HOOK_NAME):
        should_block, violations, api_result = check_with_enkrypt_api(tool_input, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (visible in Cursor hooks output)
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_block:
            violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
            permission = "deny"
            user_message = f"⛔ MCP tool input blocked by Enkrypt AI:\n\n{violation_message}"
            agent_message = "The MCP tool input contains policy violations and has been blocked."
            log_security_alert("mcp_input_blocked", {
                "hook": HOOK_NAME,
                "policy_name": get_hook_policy_name(HOOK_NAME),
                "tool_name": tool_name,
                "violations": violations,
            }, data)

    result = {"permission": permission}
    if user_message:
        result["user_message"] = user_message
    if agent_message:
        result["agent_message"] = agent_message

    log_event(HOOK_NAME, data, result)
    log_to_combined(HOOK_NAME, data, result)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
