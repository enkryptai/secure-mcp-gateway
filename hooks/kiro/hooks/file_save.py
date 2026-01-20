#!/usr/bin/env python
"""
FileSave Hook - Validates file content when files are saved.

Kiro Hook: Runs when files matching specific patterns are saved.
Input: File path and content (via stdin or environment)
Block: Exit code 1, stderr contains block reason
Allow: Exit code 0

Use Cases:
- Scan for secrets/credentials before committing
- Validate code quality
- Check for PII in saved files
- Enforce coding standards
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
    get_hook_guardrail_name,
    is_sensitive_file,
    analyze_file_content,
    flush_logs,
)

HOOK_NAME = "FileSave"


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
            # Read only first part of large files
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
                        # Assume stdin is the file path
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
        # No file path provided
        print("No file path provided", file=sys.stderr)
        sys.exit(1)

    if not file_content.strip():
        # Empty file, allow
        log_event(HOOK_NAME, {**data, "skipped": "empty file"})
        flush_logs()
        sys.exit(0)

    # Quick local analysis first
    analysis = analyze_file_content(file_path, file_content)
    data["local_analysis"] = analysis

    # Check if this hook's guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        # Even if guardrails disabled, warn about sensitive files
        if analysis["is_sensitive_file"]:
            print(f"Warning: Saving sensitive file: {file_path}", file=sys.stderr)
        if analysis["sensitive_data_hints"]:
            hints = ", ".join(analysis["sensitive_data_hints"])
            print(f"Warning: File may contain sensitive data: {hints}", file=sys.stderr)

        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        flush_logs()
        sys.exit(0)

    # Check with Enkrypt AI API
    should_block, violations, api_result = check_file_content(file_path, file_content, hook_name=HOOK_NAME)

    # Log guardrails response
    print(f"\n[Enkrypt Guardrails Response for {file_path}]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)

    if should_block:
        violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
        result = {
            "blocked": True,
            "file_path": file_path,
            "reason": violation_message
        }
        log_security_alert("file_save_blocked", {
            "hook": HOOK_NAME,
            "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
            "file_path": file_path,
            "violations": violations,
            "content_preview": file_content[:200] + "..." if len(file_content) > 200 else file_content,
        }, data)
        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        # Exit code 1 signals block
        print(f"File save blocked by Enkrypt AI Guardrails:\n\nFile: {file_path}\n\n{violation_message}", file=sys.stderr)
        sys.exit(1)
    else:
        result = {"blocked": False, "file_path": file_path}

        # Provide warnings even if not blocking
        if analysis["is_sensitive_file"]:
            print(f"Notice: Saving sensitive file: {file_path}")
        if analysis["sensitive_data_hints"]:
            hints = ", ".join(analysis["sensitive_data_hints"])
            print(f"Notice: File contains potentially sensitive data: {hints}")

        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        sys.exit(0)


if __name__ == "__main__":
    main()
