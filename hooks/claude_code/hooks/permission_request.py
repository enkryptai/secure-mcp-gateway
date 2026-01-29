#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - PermissionRequest Hook for Claude Code

This hook runs when a permission dialog is shown to the user.
It can:
- Allow the permission automatically (behavior: "allow")
- Deny the permission automatically (behavior: "deny")
- Let the user decide (default - no output)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "PermissionRequest",
    "tool_name": "Bash",
    "tool_input": {
        "command": "rm -rf /tmp/test"
    },
    "tool_use_id": "toolu_01ABC123"
}

Hook Output (JSON):
{
    "hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": {
            "behavior": "allow|deny",
            "updatedInput": { "command": "modified_command" },  // optional, for allow
            "message": "Reason for denial",  // optional, for deny
            "interrupt": true  // optional, for deny - stops Claude
        }
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
    log_event,
    log_security_alert,
)


def main():
    """Main entry point for PermissionRequest hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "PermissionRequest"
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

    # Check if guardrails are enabled for this hook
    if not is_hook_enabled(hook_name):
        # Let user decide (no output)
        sys.exit(0)

    # Extract text content from tool input
    text_to_check = extract_text_from_tool_input(tool_name, tool_input)

    if not text_to_check:
        sys.exit(0)

    # Check with Enkrypt API
    should_block, violations, raw_result = check_with_enkrypt_api(text_to_check, hook_name)

    if should_block:
        # Log security alert
        log_security_alert(
            "permission_denied",
            {
                "tool_name": tool_name,
                "violations": violations,
                "input_preview": text_to_check[:200] if len(text_to_check) > 200 else text_to_check,
            },
            {"session_id": session_id, "tool_use_id": tool_use_id, "cwd": cwd}
        )

        # Deny the permission
        detector_names = [v["detector"] for v in violations]
        output = {
            "hookSpecificOutput": {
                "hookEventName": hook_name,
                "decision": {
                    "behavior": "deny",
                    "message": f"Permission denied by Enkrypt Guardrails: {', '.join(detector_names)}",
                }
            }
        }
        print(json.dumps(output))
        sys.exit(0)

    # Check if this is a sensitive tool - let user decide
    if is_sensitive_tool(tool_name):
        log_event("sensitive_tool_permission", {
            "tool_name": tool_name,
            "session_id": session_id,
            "action": "user_decides",
        })
        # No output - let user decide
        sys.exit(0)

    # Log successful check
    log_event("hook_completed", {
        "hook": hook_name,
        "tool_name": tool_name,
        "blocked": False,
    })

    # No output - let user decide (or auto-allow based on policy)
    sys.exit(0)


if __name__ == "__main__":
    main()
