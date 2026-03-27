#!/usr/bin/env python3
"""
afterFileEdit Hook - Audits file edits via Enkrypt AI Guardrails after the agent writes to a file.

Fires after the agent edits a file. This is an audit-only hook (Cursor does not support
blocking on afterFileEdit), but logs security alerts if written content contains policy
violations so they can be reviewed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    get_hook_guardrail_name,
    is_hook_enabled,
    log_event,
    log_security_alert,
    log_to_combined,
)

HOOK_NAME = "afterFileEdit"
MAX_CONTENT_CHARS = 8000


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    file_path = data.get("file_path", "")
    edits = data.get("edits", [])

    if not edits:
        print(json.dumps({}))
        return

    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {"file_path": file_path, "skipped": "guardrails disabled"})
        print(json.dumps({}))
        return

    new_content = "\n".join(
        edit.get("new_string", "") for edit in edits if edit.get("new_string", "").strip()
    )

    if not new_content.strip():
        print(json.dumps({}))
        return

    scan_content = new_content[:MAX_CONTENT_CHARS]
    truncated = len(new_content) > MAX_CONTENT_CHARS

    should_alert, violations, api_result = check_with_enkrypt_api(
        scan_content, hook_name=HOOK_NAME
    )

    print(
        f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
        file=sys.stderr,
    )

    if should_alert:
        log_security_alert(
            "file_edit_violation",
            {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "file_path": file_path,
                "violations": violations,
                "truncated": truncated,
            },
            data,
        )

    log_event(
        HOOK_NAME,
        {
            "file_path": file_path,
            "edit_count": len(edits),
            "scan_size": len(new_content),
            "truncated": truncated,
            "violations": violations,
        },
    )
    log_to_combined(HOOK_NAME, data)

    print(json.dumps({}))


if __name__ == "__main__":
    main()
