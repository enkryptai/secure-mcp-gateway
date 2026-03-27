#!/usr/bin/env python
"""
stop Hook - Handles agent loop completion.
"""
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    LOG_DIR,
    get_timestamp,
    log_event,
    log_to_combined,
)


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event("stop", {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    status = data.get("status", "completed")
    loop_count = data.get("loop_count", 0)

    summary = {
        "conversation_id": data.get("conversation_id"),
        "generation_id": data.get("generation_id"),
        "status": status,
        "loop_count": loop_count,
        "model": data.get("model"),
        "user_email": data.get("user_email"),
        "timestamp": get_timestamp(),
    }

    log_event("stop", {**data, "summary": summary})
    log_to_combined("stop", data)

    summary_file = LOG_DIR / "session_summaries.jsonl"
    with open(summary_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary) + "\n")

    print(json.dumps({}))


if __name__ == "__main__":
    main()
