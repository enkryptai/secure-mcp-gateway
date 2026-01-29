#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - PreCompact Hook for Claude Code

This hook runs before Claude Code performs a context compaction operation.
It can:
- Log compaction events
- Add custom instructions for compaction
- Prepare for context reduction

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "PreCompact",
    "trigger": "manual|auto",
    "custom_instructions": ""  // From /compact command, empty for auto
}

Matchers:
- manual: Invoked from /compact command
- auto: Invoked from auto-compact (full context window)
"""

import sys
import json

from enkrypt_guardrails import (
    read_hook_input,
    log_event,
    metrics,
)


def main():
    """Main entry point for PreCompact hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "PreCompact"
    session_id = input_data.get("session_id", "")
    trigger = input_data.get("trigger", "")
    custom_instructions = input_data.get("custom_instructions", "")
    transcript_path = input_data.get("transcript_path", "")

    # Log the compaction event
    log_event("pre_compact", {
        "hook": hook_name,
        "session_id": session_id,
        "trigger": trigger,
        "has_custom_instructions": bool(custom_instructions),
        "transcript_path": transcript_path,
    })

    # Log metrics before compaction
    current_metrics = metrics.get_metrics()
    if current_metrics:
        log_event("pre_compact_metrics", {
            "session_id": session_id,
            "metrics": current_metrics,
        })

    # PreCompact hooks don't typically produce output
    # but could add custom instructions if needed
    sys.exit(0)


if __name__ == "__main__":
    main()
