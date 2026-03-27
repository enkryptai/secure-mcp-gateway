#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - PreToolUse Hook for Claude Code

This hook runs before a tool is executed. It can:
- Allow the tool call (permissionDecision: "allow")
- Deny the tool call (permissionDecision: "deny")
- Ask the user (permissionDecision: "ask")
- Modify tool input (updatedInput)
- Add context (additionalContext)

For Read tool calls, the hook reads the target file from disk and scans
the contents through Enkrypt AI Guardrails before the agent sees the data.
This prevents sensitive file contents (PII, secrets, etc.) from reaching
the model.

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

import json
import os
import sys

os.environ.setdefault(
    "ENKRYPT_GUARDRAILS_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardrails_config.json"),
)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    create_json_output,
    extract_file_content_for_read,
    extract_text_from_tool_input,
    is_hook_enabled,
    is_sensitive_tool,
    log_event,
    log_security_alert,
    output_json,
    read_hook_input,
)


def _handle_file_read(tool_input, hook_name, session_id, tool_use_id, cwd):
    """Scan file contents before allowing a Read tool call.

    Returns (should_exit, exit_code) — if should_exit is True the caller
    should ``sys.exit(exit_code)`` immediately.
    """
    file_path = tool_input.get("file_path", "")
    content = extract_file_content_for_read(tool_input)

    if not content or not content.strip():
        log_event(
            "file_read_scan_skipped",
            {
                "hook": hook_name,
                "file_path": file_path,
                "reason": "file unreadable or empty",
            },
        )
        return False, 0

    should_block, violations, raw_result = check_with_enkrypt_api(content, hook_name)

    print(
        f"\n[Enkrypt Guardrails - File: {os.path.basename(file_path)}]\n"
        f"{json.dumps(raw_result, indent=2)}",
        file=sys.stderr,
    )

    if should_block:
        log_security_alert(
            "file_read_blocked",
            {
                "tool_name": "Read",
                "file_path": file_path,
                "violations": violations,
                "content_size": len(content),
            },
            {"session_id": session_id, "tool_use_id": tool_use_id, "cwd": cwd},
        )

        detector_names = [v["detector"] for v in violations]
        output = create_json_output(
            hook_event_name=hook_name,
            permission_decision="deny",
            permission_decision_reason=(
                f"File read blocked by Enkrypt Guardrails — "
                f"{os.path.basename(file_path)} contains: "
                f"{', '.join(detector_names)}"
            ),
        )
        output_json(output)
        return True, 0

    log_event(
        "file_read_scan_passed",
        {
            "hook": hook_name,
            "file_path": file_path,
            "content_size": len(content),
        },
    )
    return False, 0


def main():
    """Main entry point for PreToolUse hook."""
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "PreToolUse"
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    tool_use_id = input_data.get("tool_use_id", "")
    session_id = input_data.get("session_id", "")
    cwd = input_data.get("cwd", "")

    log_event(
        "hook_invoked",
        {
            "hook": hook_name,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "session_id": session_id,
        },
    )

    if not is_hook_enabled(hook_name):
        sys.exit(0)

    is_sensitive = is_sensitive_tool(tool_name)

    if tool_name == "Read":
        should_exit, code = _handle_file_read(
            tool_input, hook_name, session_id, tool_use_id, cwd
        )
        if should_exit:
            sys.exit(code)

    text_to_check = extract_text_from_tool_input(tool_name, tool_input)

    if not text_to_check:
        sys.exit(0)

    should_block, violations, raw_result = check_with_enkrypt_api(text_to_check, hook_name)

    if should_block:
        log_security_alert(
            "tool_input_blocked",
            {
                "tool_name": tool_name,
                "violations": violations,
                "is_sensitive_tool": is_sensitive,
                "input_preview": text_to_check[:200]
                if len(text_to_check) > 200
                else text_to_check,
            },
            {"session_id": session_id, "tool_use_id": tool_use_id, "cwd": cwd},
        )

        detector_names = [v["detector"] for v in violations]
        output = create_json_output(
            hook_event_name=hook_name,
            permission_decision="deny",
            permission_decision_reason=(
                f"Tool input blocked by Enkrypt Guardrails: {', '.join(detector_names)}"
            ),
        )
        output_json(output)
        sys.exit(0)

    if is_sensitive:
        log_event(
            "sensitive_tool_allowed",
            {
                "tool_name": tool_name,
                "session_id": session_id,
            },
        )

        output = create_json_output(
            hook_event_name=hook_name,
            permission_decision="ask",
            permission_decision_reason=(
                f"Sensitive tool '{tool_name}' - please confirm execution"
            ),
            additional_context=(
                f"Note: '{tool_name}' is a sensitive tool. Proceed with caution."
            ),
        )
        output_json(output)
        sys.exit(0)

    log_event(
        "hook_completed",
        {
            "hook": hook_name,
            "tool_name": tool_name,
            "blocked": False,
        },
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
