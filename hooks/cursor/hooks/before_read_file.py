#!/usr/bin/env python3
"""
beforeReadFile Hook - Scans file contents via Enkrypt AI Guardrails before the agent reads the file.

Fires before the agent reads a file. Can block the read if the file contents contain
policy violations (PII, secrets, injection payloads, etc.), preventing sensitive data
from being sent to the model.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    get_hook_guardrail_name,
    is_hook_enabled,
    log_event,
    log_security_alert,
    log_to_combined,
)

HOOK_NAME = "beforeReadFile"
MAX_CONTENT_CHARS = 8000


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({"permission": "allow"}))
        return

    file_path = data.get("file_path", "")
    content = data.get("content", "")

    if not content.strip():
        print(json.dumps({"permission": "allow"}))
        return

    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {"file_path": file_path, "skipped": "guardrails disabled"})
        print(json.dumps({"permission": "allow"}))
        return

    scan_content = content[:MAX_CONTENT_CHARS]
    truncated = len(content) > MAX_CONTENT_CHARS

    should_block, violations, api_result = check_with_enkrypt_api(
        scan_content, hook_name=HOOK_NAME
    )

    print(
        f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
        file=sys.stderr,
    )

    if should_block:
        violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
        log_security_alert(
            "file_read_blocked",
            {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "file_path": file_path,
                "violations": violations,
                "truncated": truncated,
            },
            data,
        )
        result = {
            "permission": "deny",
            "user_message": (
                f"⛔ File read blocked by Enkrypt AI Guardrails:\n\n{violation_message}"
            ),
        }
    else:
        result = {"permission": "allow"}

    log_event(
        HOOK_NAME,
        {
            "file_path": file_path,
            "content_size": len(content),
            "truncated": truncated,
            "violations": violations,
        },
        result,
    )
    log_to_combined(HOOK_NAME, data, result)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
