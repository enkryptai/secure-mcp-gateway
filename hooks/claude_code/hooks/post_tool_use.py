#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - PostToolUse Hook for Claude Code

This hook runs after a tool completes successfully. It can:
- Provide feedback to Claude (decision: "block" with reason)
- Add context (additionalContext)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {
        "command": "ls -la"
    },
    "tool_response": {
        "output": "file1.txt\nfile2.txt",
        "exitCode": 0
    },
    "tool_use_id": "toolu_01ABC123"
}

Hook Output (JSON):
{
    "decision": "block",
    "reason": "Tool output contains sensitive data",
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "Warning: Output may contain PII"
    }
}
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    check_with_enkrypt_api,
    is_hook_enabled,
    extract_text_from_tool_response,
    format_blocking_error,
    create_json_output,
    output_json,
    output_error,
    log_event,
    log_security_alert,
)


def main():
    """Main entry point for PostToolUse hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "PostToolUse"
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_response = input_data.get("tool_response", {})
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

    # Extract text content from tool response
    text_to_check = extract_text_from_tool_response(tool_name, tool_response)

    if not text_to_check:
        # No text to check, allow through
        sys.exit(0)

    # Limit text size to avoid API timeouts
    max_text_length = 10000
    if len(text_to_check) > max_text_length:
        text_to_check = text_to_check[:max_text_length]

    # Check with Enkrypt API
    should_block, violations, raw_result = check_with_enkrypt_api(text_to_check, hook_name)

    if should_block:
        # Log security alert
        log_security_alert(
            "tool_output_violation",
            {
                "tool_name": tool_name,
                "violations": violations,
                "output_preview": text_to_check[:200] if len(text_to_check) > 200 else text_to_check,
            },
            {"session_id": session_id, "tool_use_id": tool_use_id, "cwd": cwd}
        )

        # Provide feedback to Claude
        detector_names = [v["detector"] for v in violations]
        output = create_json_output(
            hook_event_name=hook_name,
            decision="block",
            reason=f"Tool output flagged by Enkrypt Guardrails: {', '.join(detector_names)}. Please review and handle appropriately.",
            additional_context=f"Warning: The output from '{tool_name}' contains potentially sensitive content ({', '.join(detector_names)}). Consider sanitizing or redacting before sharing.",
        )
        output_json(output)
        sys.exit(0)

    # Log successful check
    log_event("hook_completed", {
        "hook": hook_name,
        "tool_name": tool_name,
        "blocked": False,
    })

    # Success - no output needed
    sys.exit(0)


if __name__ == "__main__":
    main()
