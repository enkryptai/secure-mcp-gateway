#!/usr/bin/env python
"""
errorOccurred Hook - Logs errors from Copilot agent sessions.

This hook is observational — its output is ignored by Copilot.

Input from Copilot:
{
    "timestamp": 1704614800000,
    "cwd": "/path/to/project",
    "error": {
        "message": "Something went wrong",
        "name": "Error",
        "stack": "Error: Something went wrong\n    at ..."
    }
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
    log_security_alert,
)

HOOK_NAME = "errorOccurred"

# Error patterns that may indicate security issues
SECURITY_ERROR_PATTERNS = [
    "permission denied",
    "access denied",
    "unauthorized",
    "forbidden",
    "authentication",
    "certificate",
    "ssl",
    "tls",
    "injection",
    "malicious",
]


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    error = data.get("error", {})
    error_message = error.get("message", "")
    error_name = error.get("name", "")
    error_stack = error.get("stack", "")
    cwd = data.get("cwd", "")

    log_data = {
        **data,
        "error_name": error_name,
        "error_message": error_message,
        "has_stack": bool(error_stack),
        "local_timestamp": get_timestamp(),
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Check if error message suggests a security issue
    error_text_lower = f"{error_message} {error_name}".lower()
    security_hints = [
        pattern for pattern in SECURITY_ERROR_PATTERNS
        if pattern in error_text_lower
    ]

    if security_hints:
        log_security_alert("security_related_error", {
            "hook": HOOK_NAME,
            "error_name": error_name,
            "error_message": error_message[:500],
            "security_hints": security_hints,
        }, data)

    # Output is ignored by Copilot
    print(json.dumps({}))


if __name__ == "__main__":
    main()
