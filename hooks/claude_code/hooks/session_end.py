#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - SessionEnd Hook for Claude Code

This hook runs when a Claude Code session ends.
It can:
- Perform cleanup tasks
- Log session statistics
- Save session state

Note: This hook cannot block session termination.

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "SessionEnd",
    "reason": "clear|logout|prompt_input_exit|other"
}
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    log_event,
    metrics,
    close_http_session,
)


def main():
    """Main entry point for SessionEnd hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "SessionEnd"
    session_id = input_data.get("session_id", "")
    reason = input_data.get("reason", "")
    transcript_path = input_data.get("transcript_path", "")

    # Log session end with metrics
    session_metrics = metrics.get_metrics()
    log_event("session_end", {
        "session_id": session_id,
        "reason": reason,
        "transcript_path": transcript_path,
        "metrics": session_metrics,
    })

    # Calculate session statistics
    total_calls = sum(m.get("total_calls", 0) for m in session_metrics.values())
    total_blocked = sum(m.get("blocked", 0) for m in session_metrics.values())
    total_errors = sum(m.get("errors", 0) for m in session_metrics.values())

    log_event("session_summary", {
        "session_id": session_id,
        "total_guardrail_checks": total_calls,
        "total_blocked": total_blocked,
        "total_errors": total_errors,
        "block_rate": (total_blocked / total_calls * 100) if total_calls > 0 else 0,
    })

    # Cleanup
    close_http_session()

    # SessionEnd hooks cannot block termination
    sys.exit(0)


if __name__ == "__main__":
    main()
