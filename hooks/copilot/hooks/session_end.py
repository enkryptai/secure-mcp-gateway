#!/usr/bin/env python
"""
sessionEnd Hook - Logs session completion and writes summary.

This hook is observational — its output is ignored by Copilot.

Input from Copilot:
{
    "timestamp": 1704618000000,
    "cwd": "/path/to/project",
    "reason": "complete" | "error" | "abort" | "timeout" | "user_exit"
}
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    get_timestamp,
    log_event,
    log_to_combined,
    LOG_DIR,
)

HOOK_NAME = "sessionEnd"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    reason = data.get("reason", "unknown")
    cwd = data.get("cwd", "")
    timestamp = data.get("timestamp")

    # Generate session summary
    summary = {
        "reason": reason,
        "cwd": cwd,
        "copilot_timestamp": timestamp,
        "local_timestamp": get_timestamp(),
    }

    log_event(HOOK_NAME, {**data, "summary": summary})
    log_to_combined(HOOK_NAME, data)

    # Write session summary
    summary_file = LOG_DIR / "session_summaries.jsonl"
    with open(summary_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary) + "\n")

    # Output is ignored by Copilot
    print(json.dumps({}))


if __name__ == "__main__":
    main()
