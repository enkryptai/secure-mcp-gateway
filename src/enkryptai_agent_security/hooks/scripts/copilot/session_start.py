#!/usr/bin/env python
"""
sessionStart Hook - Logs session initialization.

This hook is observational — its output is ignored by Copilot.

Input from Copilot:
{
    "timestamp": 1704614400000,
    "cwd": "/path/to/project",
    "source": "new" | "resume" | "startup",
    "initialPrompt": "user's initial message"
}
"""
import sys
import json
import os

os.environ.setdefault(
    "ENKRYPT_GUARDRAILS_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardrails_config.json"),
)
from enkryptai_agent_security.hooks.providers.copilot import (
    get_timestamp,
    log_event,
    log_to_combined,
)

HOOK_NAME = "sessionStart"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    source = data.get("source", "unknown")
    initial_prompt = data.get("initialPrompt", "")
    cwd = data.get("cwd", "")

    log_data = {
        **data,
        "source": source,
        "cwd": cwd,
        "has_initial_prompt": bool(initial_prompt),
        "local_timestamp": get_timestamp(),
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Output is ignored by Copilot
    print(json.dumps({}))


if __name__ == "__main__":
    main()
