#!/usr/bin/env python
"""
Stop Hook - Handles agent loop completion.

Claude Code Hook: Runs when the agent loop ends.
Input: { "session_id": "...", "stop_hook_active": false }
Output: {} (logging only)
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    get_timestamp,
    log_event,
    log_to_combined,
    LOG_DIR
)

HOOK_NAME = "Stop"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    session_id = data.get("session_id", "")
    stop_hook_active = data.get("stop_hook_active", False)
    cwd = data.get("cwd", "")
    transcript_path = data.get("transcript_path", "")

    # Generate session summary
    summary = {
        "session_id": session_id,
        "stop_hook_active": stop_hook_active,
        "cwd": cwd,
        "transcript_path": transcript_path,
        "timestamp": get_timestamp(),
    }

    log_event(HOOK_NAME, {**data, "summary": summary})
    log_to_combined(HOOK_NAME, data)

    # Write session summary
    summary_file = LOG_DIR / "session_summaries.jsonl"
    with open(summary_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary) + "\n")

    print(json.dumps({}))


if __name__ == "__main__":
    main()
