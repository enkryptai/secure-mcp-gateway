#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - UserPromptSubmit Hook for Claude Code

This hook runs when the user submits a prompt, before Claude processes it.
It can:
- Add context to the conversation (stdout with exit code 0)
- Block prompts (exit code 2 or JSON with decision: "block")
- Validate prompt content

In addition to scanning the prompt text, this hook extracts @filepath
references from the prompt, reads the files from disk, and scans their
contents through Enkrypt AI Guardrails. This ensures sensitive file data
is caught at submission time, before the agent ever reads the file.

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "The user's prompt text"
}

Hook Output:
- Exit code 0: Success, stdout added as context
- Exit code 2: Block prompt, stderr shown to user
- JSON output with decision control for advanced use
"""

import json
import os
import re
import sys
from pathlib import Path

os.environ.setdefault(
    "ENKRYPT_GUARDRAILS_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardrails_config.json"),
)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    MAX_FILE_CHARS,
    _read_file_safe,
    check_with_enkrypt_api,
    create_json_output,
    is_hook_enabled,
    log_event,
    log_security_alert,
    output_json,
    read_hook_input,
)

MAX_FILE_SCAN_CHARS = MAX_FILE_CHARS


def _extract_file_refs(prompt, cwd=None):
    """Extract file paths from @-references in prompt text.

    Handles absolute paths (possibly with spaces) and relative paths
    resolved against the working directory.
    """
    files = set()
    parts = re.split(r"(?:^|(?<=\s))@", prompt)

    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue

        if part.startswith("/"):
            words = part.split()
            for i in range(len(words), 0, -1):
                candidate = Path(" ".join(words[:i]))
                if candidate.is_file():
                    files.add(str(candidate.resolve()))
                    break
        else:
            token = part.split()[0] if part.split() else ""
            if not token:
                continue
            if cwd:
                full = Path(cwd) / token
                if full.is_file():
                    files.add(str(full.resolve()))
    return list(files)


def main():
    """Main entry point for UserPromptSubmit hook."""
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "UserPromptSubmit"
    prompt = input_data.get("prompt", "")
    session_id = input_data.get("session_id", "")
    cwd = input_data.get("cwd", "")

    log_event(
        "hook_invoked",
        {
            "hook": hook_name,
            "session_id": session_id,
            "prompt_length": len(prompt),
            "cwd": cwd,
        },
    )

    if not is_hook_enabled(hook_name):
        sys.exit(0)

    if not prompt or not prompt.strip():
        sys.exit(0)

    should_block, violations, raw_result = check_with_enkrypt_api(prompt, hook_name)

    print(
        f"\n[Enkrypt Guardrails Response]\n{json.dumps(raw_result, indent=2)}",
        file=sys.stderr,
    )

    all_violations = list(violations)
    blocked_files = []

    file_paths = _extract_file_refs(prompt, cwd)

    for fp in sorted(file_paths):
        content = _read_file_safe(fp, MAX_FILE_SCAN_CHARS)
        if not content or not content.strip():
            log_event(
                "file_scan_skipped",
                {
                    "hook": hook_name,
                    "file_path": fp,
                    "reason": "unreadable or empty",
                },
            )
            continue

        file_block, file_violations, file_result = check_with_enkrypt_api(content, hook_name)

        print(
            f"\n[Enkrypt Guardrails - File: {os.path.basename(fp)}]\n"
            f"{json.dumps(file_result, indent=2)}",
            file=sys.stderr,
        )

        if file_violations:
            all_violations.extend(file_violations)
        if file_block:
            should_block = True
            blocked_files.append(fp)

    if should_block:
        log_security_alert(
            "prompt_blocked",
            {
                "violations": all_violations,
                "prompt_preview": prompt[:200] if len(prompt) > 200 else prompt,
                "scanned_files": sorted(file_paths),
                "blocked_files": blocked_files,
            },
            {"session_id": session_id, "cwd": cwd},
        )

        detector_names = [v["detector"] for v in all_violations]
        reason = f"Prompt blocked by Enkrypt Guardrails: {', '.join(detector_names)}."
        if blocked_files:
            file_names = ", ".join(os.path.basename(f) for f in blocked_files)
            reason += f" Blocked file(s): {file_names}."
        reason += " Please rephrase your request."

        output = create_json_output(
            hook_event_name=hook_name,
            decision="block",
            reason=reason,
        )
        output_json(output)
        sys.exit(0)

    log_event(
        "hook_completed",
        {
            "hook": hook_name,
            "session_id": session_id,
            "blocked": False,
            "scanned_files": sorted(file_paths),
        },
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
