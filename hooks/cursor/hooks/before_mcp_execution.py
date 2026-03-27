#!/usr/bin/env python
"""
beforeMCPExecution Hook - Gates MCP tools using Enkrypt AI Guardrails.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_mcp_tool,
    check_with_enkrypt_api,
    format_violation_message,
    get_hook_guardrail_name,
    is_hook_enabled,
    log_event,
    log_security_alert,
    log_to_combined,
)

HOOK_NAME = "beforeMCPExecution"


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({"permission": "allow"}))
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", "")

    permission, user_message, agent_message = check_mcp_tool(tool_name, tool_input)

    if permission == "allow" and tool_input and is_hook_enabled(HOOK_NAME):
        should_block, violations, api_result = check_with_enkrypt_api(
            tool_input, hook_name=HOOK_NAME
        )
        print(
            f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
            file=sys.stderr,
        )
        if should_block:
            violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
            permission = "deny"
            user_message = f"⛔ MCP tool input blocked by Enkrypt AI:\n\n{violation_message}"
            agent_message = (
                "The MCP tool input contains policy violations and has been blocked."
            )
            log_security_alert(
                "mcp_input_blocked",
                {
                    "hook": HOOK_NAME,
                    "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                    "tool_name": tool_name,
                    "violations": violations,
                },
                data,
            )

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
