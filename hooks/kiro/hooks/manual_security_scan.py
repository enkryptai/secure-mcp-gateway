#!/usr/bin/env python
"""
Manual Security Scan Hook - On-demand security scanning.

Kiro Hook: Manually triggered hook for security scanning.
This can be triggered on-demand to scan files, code, or content.

Use Cases:
- On-demand code reviews
- Security scanning before commits
- Documentation review
- Pre-deployment security checks
"""
import sys
import json
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    check_file_content,
    format_violation_message,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
    analyze_file_content,
    flush_logs,
    SENSITIVE_FILE_PATTERNS,
)

HOOK_NAME = "Manual"


def scan_directory(directory: str, file_patterns: list = None) -> list:
    """Scan a directory for files to check."""
    files_to_scan = []
    dir_path = Path(directory)

    if not dir_path.exists():
        return files_to_scan

    # Default patterns if none specified
    if not file_patterns:
        file_patterns = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.json", "*.yaml", "*.yml", "*.env*"]

    for pattern in file_patterns:
        for file_path in dir_path.rglob(pattern):
            if file_path.is_file():
                # Skip common non-source directories
                if any(part in str(file_path) for part in ["node_modules", ".git", "__pycache__", "venv", ".venv"]):
                    continue
                files_to_scan.append(str(file_path))

    return files_to_scan


def read_file_safely(file_path: str, max_size: int = 512 * 1024) -> tuple[str, bool]:
    """Read file content safely with size limit."""
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
    # Read scan target from stdin or environment
    scan_target = os.environ.get("SCAN_TARGET", "")
    scan_type = os.environ.get("SCAN_TYPE", "text")  # text, file, directory

    # Try to read from stdin
    if not scan_target:
        try:
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
                if stdin_content:
                    try:
                        data = json.loads(stdin_content)
                        scan_target = data.get("target", data.get("content", data.get("text", "")))
                        scan_type = data.get("type", "text")
                    except json.JSONDecodeError:
                        scan_target = stdin_content
                        scan_type = "text"
        except IOError:
            pass

    data = {
        "scan_target": scan_target[:200] + "..." if len(scan_target) > 200 else scan_target,
        "scan_type": scan_type,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "pwd": os.environ.get("PWD", os.getcwd()),
    }

    if not scan_target:
        print("No scan target provided. Use SCAN_TARGET env var or stdin.", file=sys.stderr)
        print("\nUsage:")
        print("  echo 'text to scan' | python manual_security_scan.py")
        print("  SCAN_TARGET=/path/to/file SCAN_TYPE=file python manual_security_scan.py")
        print("  SCAN_TARGET=/path/to/dir SCAN_TYPE=directory python manual_security_scan.py")
        sys.exit(1)

    # Check if guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        print("Warning: Manual hook guardrails are disabled", file=sys.stderr)
        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        flush_logs()
        sys.exit(0)

    all_violations = []
    scan_results = []

    if scan_type == "file":
        # Scan a single file
        file_content, is_truncated = read_file_safely(scan_target)
        if file_content:
            should_block, violations, api_result = check_file_content(scan_target, file_content, hook_name=HOOK_NAME)
            scan_results.append({
                "file": scan_target,
                "blocked": should_block,
                "violations": violations,
                "truncated": is_truncated,
            })
            all_violations.extend(violations)

    elif scan_type == "directory":
        # Scan all files in directory
        files = scan_directory(scan_target)
        print(f"Scanning {len(files)} files in {scan_target}...", file=sys.stderr)

        for file_path in files:
            file_content, is_truncated = read_file_safely(file_path)
            if file_content:
                should_block, violations, api_result = check_file_content(file_path, file_content, hook_name=HOOK_NAME)
                if violations:
                    scan_results.append({
                        "file": file_path,
                        "blocked": should_block,
                        "violations": violations,
                        "truncated": is_truncated,
                    })
                    all_violations.extend(violations)

    else:
        # Scan text content directly
        should_block, violations, api_result = check_with_enkrypt_api(scan_target, hook_name=HOOK_NAME)
        scan_results.append({
            "type": "text",
            "blocked": should_block,
            "violations": violations,
        })
        all_violations.extend(violations)

    # Generate report
    report = {
        "scan_type": scan_type,
        "total_violations": len(all_violations),
        "files_with_issues": len([r for r in scan_results if r.get("violations")]),
        "results": scan_results,
    }

    log_event(HOOK_NAME, data, report)
    log_to_combined(HOOK_NAME, data, report)

    if all_violations:
        log_security_alert("manual_scan_issues", {
            "hook": HOOK_NAME,
            "policy_name": get_hook_policy_name(HOOK_NAME),
            "total_violations": len(all_violations),
            "files_with_issues": len([r for r in scan_results if r.get("violations")]),
        }, data)

    flush_logs()

    # Output report
    print("\n" + "=" * 60)
    print("SECURITY SCAN REPORT")
    print("=" * 60)

    if all_violations:
        print(f"\nFound {len(all_violations)} potential security issues:\n")

        for result in scan_results:
            if result.get("violations"):
                if result.get("file"):
                    print(f"\nFile: {result['file']}")
                violation_msg = format_violation_message(result["violations"], hook_name=HOOK_NAME)
                print(violation_msg)
                print("-" * 40)

        print(f"\nTotal: {len(all_violations)} issues in {len([r for r in scan_results if r.get('violations')])} items")
        sys.exit(1)
    else:
        print("\nNo security issues detected.")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
