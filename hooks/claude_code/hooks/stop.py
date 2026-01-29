#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - Stop Hook for Claude Code

This hook runs when Claude finishes responding (not on user interrupt).
It can:
- Allow Claude to stop (default)
- Force Claude to continue (decision: "block" with reason)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "Stop",
    "stop_hook_active": false  // true if already continuing from a stop hook
}

Hook Output (JSON):
{
    "decision": "block",  // Prevent stopping
    "reason": "You haven't completed the security review yet."
}
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    log_event,
    metrics,
)


def main():
    """Main entry point for Stop hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "Stop"
    session_id = input_data.get("session_id", "")
    stop_hook_active = input_data.get("stop_hook_active", False)
    transcript_path = input_data.get("transcript_path", "")

    # Log the hook invocation
    log_event("hook_invoked", {
        "hook": hook_name,
        "session_id": session_id,
        "stop_hook_active": stop_hook_active,
    })

    # IMPORTANT: Check if we're already in a stop hook loop
    # This prevents infinite loops where the hook keeps blocking stop
    if stop_hook_active:
        log_event("stop_hook_skipped", {
            "reason": "stop_hook_already_active",
            "session_id": session_id,
        })
        sys.exit(0)

    # Example: Custom logic to determine if Claude should continue
    # You can read the transcript_path to analyze the conversation
    # and decide if more work needs to be done

    # For now, we just log the stop event and allow it
    log_event("session_stop", {
        "session_id": session_id,
        "metrics": metrics.get_metrics(),
    })

    # To block stopping and force Claude to continue:
    # output = {
    #     "decision": "block",
    #     "reason": "Please complete the security review before stopping."
    # }
    # print(json.dumps(output))

    # Allow Claude to stop
    sys.exit(0)


if __name__ == "__main__":
    main()
