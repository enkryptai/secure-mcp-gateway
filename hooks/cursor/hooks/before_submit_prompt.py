#!/usr/bin/env python
"""
beforeSubmitPrompt Hook - Validates prompts AND attached file contents
using Enkrypt AI Guardrails.

Scans both the user's prompt text and the contents of any files referenced
via @filepath patterns or the attachments array before they reach the LLM.
This is critical because Cursor resolves user @-attached files internally
and sends their contents directly to the model without triggering the
beforeReadFile hook.
"""
import json
import os
import re
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

HOOK_NAME = "beforeSubmitPrompt"
MAX_FILE_CHARS = 8000


def _extract_file_refs(prompt, workspace_roots):
    """Extract file paths from @-references in prompt text.

    Handles both absolute paths (possibly containing spaces) and
    relative paths resolved against workspace_roots.
    """
    files = []
    parts = re.split(r"(?:^|(?<=\s))@", prompt)

    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue

        if part.startswith("/"):
            words = part.split()
            for end in range(len(words), 0, -1):
                candidate = " ".join(words[:end])
                if os.path.isfile(candidate):
                    files.append(candidate)
                    break
        else:
            token = part.split()[0] if part.split() else ""
            if not token:
                continue
            for root in workspace_roots or []:
                full = os.path.join(root, token)
                if os.path.isfile(full):
                    files.append(full)
                    break

    return files


def _read_file_safe(path, max_chars=MAX_FILE_CHARS):
    """Read file contents as text, returning None for binary/unreadable files."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            return f.read(max_chars)
    except (UnicodeDecodeError, ValueError):
        try:
            with open(path, "r", encoding="latin-1") as f:
                return f.read(max_chars)
        except Exception:
            return None
    except (OSError, IOError):
        return None


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({"continue": True}))
        return

    prompt = data.get("prompt", "")
    attachments = data.get("attachments", [])
    workspace_roots = data.get("workspace_roots", [])

    if not prompt.strip():
        print(json.dumps({"continue": True}))
        return

    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        print(json.dumps({"continue": True}))
        return

    should_block, violations, api_result = check_with_enkrypt_api(
        prompt, hook_name=HOOK_NAME
    )
    print(
        f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
        file=sys.stderr,
    )

    all_violations = list(violations)
    blocked_files = []

    file_paths = set()
    for att in attachments:
        fp = att.get("file_path", "")
        if fp and att.get("type") == "file":
            file_paths.add(fp)

    for fp in _extract_file_refs(prompt, workspace_roots):
        file_paths.add(fp)

    for fp in sorted(file_paths):
        content = _read_file_safe(fp)
        if not content or not content.strip():
            continue

        file_should_block, file_violations, file_api_result = check_with_enkrypt_api(
            content, hook_name=HOOK_NAME
        )
        print(
            f"\n[Enkrypt Guardrails - File: {os.path.basename(fp)}]\n"
            f"{json.dumps(file_api_result, indent=2)}",
            file=sys.stderr,
        )

        if file_violations:
            all_violations.extend(file_violations)
        if file_should_block:
            should_block = True
            blocked_files.append(fp)

    if should_block:
        violation_message = format_violation_message(
            all_violations, hook_name=HOOK_NAME
        )
        if blocked_files:
            file_names = ", ".join(os.path.basename(f) for f in blocked_files)
            violation_message += f"\n\nBlocked file(s): {file_names}"

        result = {
            "continue": False,
            "user_message": (
                f"⛔ Prompt blocked by Enkrypt AI Guardrails:\n\n{violation_message}"
            ),
        }
        log_security_alert(
            "prompt_blocked",
            {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "violations": all_violations,
                "prompt_preview": (
                    prompt[:200] + "..." if len(prompt) > 200 else prompt
                ),
                "scanned_files": sorted(file_paths),
                "blocked_files": blocked_files,
            },
            data,
        )
    else:
        result = {"continue": True}

    log_event(
        HOOK_NAME,
        {
            **data,
            "api_result": api_result,
            "violations": all_violations,
            "scanned_files": sorted(file_paths),
            "blocked_files": blocked_files,
        },
        result,
    )
    log_to_combined(HOOK_NAME, data, result)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
