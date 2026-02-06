#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - SubagentStop Hook for Claude Code

This hook runs when a Claude Code subagent (Task tool call) finishes.
It can:
- Allow the subagent to stop (default)
- Force the subagent to continue (decision: "block" with reason)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/main/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "SubagentStop",
    "stop_hook_active": false,
    "agent_id": "def456",
    "agent_transcript_path": "/path/to/.../subagents/agent-def456.jsonl"
}

Hook Output (JSON):
{
    "decision": "block",  // Prevent stopping
    "reason": "Subagent hasn't completed the task yet."
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
    """Main entry point for SubagentStop hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "SubagentStop"
    session_id = input_data.get("session_id", "")
    stop_hook_active = input_data.get("stop_hook_active", False)
    agent_id = input_data.get("agent_id", "")
    agent_transcript_path = input_data.get("agent_transcript_path", "")

    # Log the hook invocation
    log_event("hook_invoked", {
        "hook": hook_name,
        "session_id": session_id,
        "agent_id": agent_id,
        "stop_hook_active": stop_hook_active,
    })

    # IMPORTANT: Check if we're already in a stop hook loop
    if stop_hook_active:
        log_event("subagent_stop_hook_skipped", {
            "reason": "stop_hook_already_active",
            "session_id": session_id,
            "agent_id": agent_id,
        })
        sys.exit(0)

    # Log subagent completion
    log_event("subagent_stop", {
        "session_id": session_id,
        "agent_id": agent_id,
        "agent_transcript_path": agent_transcript_path,
    })

    # To block stopping and force subagent to continue:
    # output = {
    #     "decision": "block",
    #     "reason": "Please complete the assigned task before stopping."
    # }
    # print(json.dumps(output))

    # Allow subagent to stop
    sys.exit(0)


if __name__ == "__main__":
    main()
