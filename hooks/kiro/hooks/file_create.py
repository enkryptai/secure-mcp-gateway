#!/usr/bin/env python
"""
FileCreate Hook - Validates new files when they are created.

Kiro Hook: Runs when new files matching specific patterns are created.
Input: File path and content (via stdin or environment)
Block: Exit code 1, stderr contains block reason
Allow: Exit code 0

Use Cases:
- Generate boilerplate code for new components
- Add license headers to new files
- Validate new file content for secrets
- Set up test files when creating implementation files
"""
import sys
import json
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_file_content,
    format_violation_message,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
    is_sensitive_file,
    analyze_file_content,
    flush_logs,
)

HOOK_NAME = "FileCreate"


def read_file_safely(file_path: str, max_size: int = 1024 * 1024) -> tuple[str, bool]:
    """
    Read file content safely with size limit.

    Returns:
        Tuple of (content, is_truncated)
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return "", False

        file_size = path.stat().st_size
        if file_size > max_size:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(max_size)
            return content, True

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return content, False

    except (IOError, OSError) as e:
        return f"Error reading file: {e}", False


def main():
    # Get file path from environment or stdin
    file_path = os.environ.get("FILE_PATH", "")
    file_content = os.environ.get("FILE_CONTENT", "")

    # Try to read from stdin as fallback
    if not file_path:
        try:
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
                if stdin_content:
                    try:
                        data = json.loads(stdin_content)
                        file_path = data.get("file_path", data.get("path", ""))
                        file_content = data.get("content", data.get("file_content", ""))
                    except json.JSONDecodeError:
                        file_path = stdin_content
        except IOError:
            pass

    # If we have a file path but no content, try to read the file
    if file_path and not file_content:
        file_content, is_truncated = read_file_safely(file_path)
    else:
        is_truncated = False

    data = {
        "file_path": file_path,
        "content_length": len(file_content),
        "is_truncated": is_truncated,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "pwd": os.environ.get("PWD", os.getcwd()),
    }

    if not file_path:
        print("No file path provided", file=sys.stderr)
        sys.exit(1)

    # Quick local analysis
    analysis = analyze_file_content(file_path, file_content)
    data["local_analysis"] = analysis

    # Warn about creating sensitive files
    if analysis["is_sensitive_file"]:
        print(f"Warning: Creating sensitive file: {file_path}", file=sys.stderr)

    # Check if this hook's guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        if analysis["sensitive_data_hints"]:
            hints = ", ".join(analysis["sensitive_data_hints"])
            print(f"Warning: New file may contain sensitive data: {hints}", file=sys.stderr)

        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        flush_logs()
        sys.exit(0)

    # Only check content if file has content
    if not file_content.strip():
        log_event(HOOK_NAME, {**data, "skipped": "empty file"})
        flush_logs()
        # For new empty files, might want to provide boilerplate
        print(f"New file created: {file_path}")
        sys.exit(0)

    # Check with Enkrypt AI API
    should_block, violations, api_result = check_file_content(file_path, file_content, hook_name=HOOK_NAME)

    print(f"\n[Enkrypt Guardrails Response for {file_path}]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)

    if should_block:
        violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
        result = {
            "blocked": True,
            "file_path": file_path,
            "reason": violation_message
        }
        log_security_alert("file_create_blocked", {
            "hook": HOOK_NAME,
            "policy_name": get_hook_policy_name(HOOK_NAME),
            "file_path": file_path,
            "violations": violations,
            "content_preview": file_content[:200] + "..." if len(file_content) > 200 else file_content,
        }, data)
        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        print(f"File creation blocked by Enkrypt AI Guardrails:\n\nFile: {file_path}\n\n{violation_message}", file=sys.stderr)
        sys.exit(1)
    else:
        result = {"blocked": False, "file_path": file_path}

        if analysis["sensitive_data_hints"]:
            hints = ", ".join(analysis["sensitive_data_hints"])
            print(f"Notice: New file contains potentially sensitive data: {hints}")

        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        print(f"File created: {file_path}")
        sys.exit(0)


if __name__ == "__main__":
    main()
