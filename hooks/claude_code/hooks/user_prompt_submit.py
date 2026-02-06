#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - UserPromptSubmit Hook for Claude Code

This hook runs when the user submits a prompt, before Claude processes it.
It can:
- Add context to the conversation (stdout with exit code 0)
- Block prompts (exit code 2 or JSON with decision: "block")
- Validate prompt content

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "The user's prompt text"
}

Hook Output:
- Exit code 0: Success, stdout added as context
- Exit code 2: Block prompt, stderr shown to user
- JSON output with decision control for advanced use
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    check_with_enkrypt_api,
    is_hook_enabled,
    format_blocking_error,
    create_json_output,
    output_json,
    output_error,
    log_event,
    log_security_alert,
)


def main():
    """Main entry point for UserPromptSubmit hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        # No input, allow through
        sys.exit(0)

    hook_name = "UserPromptSubmit"
    prompt = input_data.get("prompt", "")
    session_id = input_data.get("session_id", "")
    cwd = input_data.get("cwd", "")

    # Log the hook invocation
    log_event("hook_invoked", {
        "hook": hook_name,
        "session_id": session_id,
        "prompt_length": len(prompt),
        "cwd": cwd,
    })

    # Check if guardrails are enabled
    if not is_hook_enabled(hook_name):
        sys.exit(0)

    # Skip empty prompts
    if not prompt or not prompt.strip():
        sys.exit(0)

    # Check with Enkrypt API
    should_block, violations, raw_result = check_with_enkrypt_api(prompt, hook_name)

    if should_block:
        # Log security alert
        log_security_alert(
            "prompt_blocked",
            {
                "violations": violations,
                "prompt_preview": prompt[:200] if len(prompt) > 200 else prompt,
            },
            {"session_id": session_id, "cwd": cwd}
        )

        # Option 1: Use exit code 2 with stderr (simpler)
        # error_message = format_blocking_error(violations, hook_name)
        # output_error(error_message)
        # sys.exit(2)

        # Option 2: Use JSON output with decision control (more flexible)
        detector_names = [v["detector"] for v in violations]
        output = create_json_output(
            hook_event_name=hook_name,
            decision="block",
            reason=f"Prompt blocked by Enkrypt Guardrails: {', '.join(detector_names)}. Please rephrase your request.",
        )
        output_json(output)
        sys.exit(0)

    # Log successful check
    log_event("hook_completed", {
        "hook": hook_name,
        "session_id": session_id,
        "blocked": False,
    })

    # Success - allow the prompt
    # Optionally add context (printed to stdout will be added to conversation)
    # print("Additional context: Current time is ...")

    sys.exit(0)


if __name__ == "__main__":
    main()
