#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - PreToolUse Hook for Claude Code

This hook runs before a tool is executed. It can:
- Allow the tool call (permissionDecision: "allow")
- Deny the tool call (permissionDecision: "deny")
- Ask the user (permissionDecision: "ask")
- Modify tool input (updatedInput)
- Add context (additionalContext)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {
        "command": "ls -la",
        "description": "List files"
    },
    "tool_use_id": "toolu_01ABC123"
}

Hook Output (JSON):
{
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow|deny|ask",
        "permissionDecisionReason": "Reason for decision",
        "updatedInput": { "modified": "params" },
        "additionalContext": "Extra info for Claude"
    }
}
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    check_with_enkrypt_api,
    is_hook_enabled,
    is_sensitive_tool,
    extract_text_from_tool_input,
    format_blocking_error,
    create_json_output,
    output_json,
    output_error,
    log_event,
    log_security_alert,
)


def main():
    """Main entry point for PreToolUse hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "PreToolUse"
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_use_id = input_data.get("tool_use_id", "")
    session_id = input_data.get("session_id", "")
    cwd = input_data.get("cwd", "")

    # Log the hook invocation
    log_event("hook_invoked", {
        "hook": hook_name,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "session_id": session_id,
    })

    # Check if guardrails are enabled
    if not is_hook_enabled(hook_name):
        sys.exit(0)

    # Check if this is a sensitive tool that needs extra scrutiny
    is_sensitive = is_sensitive_tool(tool_name)

    # Extract text content from tool input
    text_to_check = extract_text_from_tool_input(tool_name, tool_input)

    if not text_to_check:
        # No text to check, allow through
        sys.exit(0)

    # Check with Enkrypt API
    should_block, violations, raw_result = check_with_enkrypt_api(text_to_check, hook_name)

    if should_block:
        # Log security alert
        log_security_alert(
            "tool_input_blocked",
            {
                "tool_name": tool_name,
                "violations": violations,
                "is_sensitive_tool": is_sensitive,
                "input_preview": text_to_check[:200] if len(text_to_check) > 200 else text_to_check,
            },
            {"session_id": session_id, "tool_use_id": tool_use_id, "cwd": cwd}
        )

        # Deny the tool call using JSON output
        detector_names = [v["detector"] for v in violations]
        output = create_json_output(
            hook_event_name=hook_name,
            permission_decision="deny",
            permission_decision_reason=f"Tool input blocked by Enkrypt Guardrails: {', '.join(detector_names)}",
        )
        output_json(output)
        sys.exit(0)

    # For sensitive tools, add a warning context
    if is_sensitive:
        log_event("sensitive_tool_allowed", {
            "tool_name": tool_name,
            "session_id": session_id,
        })

        # Optionally add context for sensitive tools
        output = create_json_output(
            hook_event_name=hook_name,
            permission_decision="ask",  # Ask user for sensitive tools
            permission_decision_reason=f"Sensitive tool '{tool_name}' - please confirm execution",
            additional_context=f"Note: '{tool_name}' is a sensitive tool. Proceed with caution.",
        )
        output_json(output)
        sys.exit(0)

    # Log successful check
    log_event("hook_completed", {
        "hook": hook_name,
        "tool_name": tool_name,
        "blocked": False,
    })

    # Allow the tool call (no output needed for simple allow)
    sys.exit(0)


if __name__ == "__main__":
    main()
