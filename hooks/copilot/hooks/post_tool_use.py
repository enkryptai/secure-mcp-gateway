#!/usr/bin/env python
"""
postToolUse Hook - Audits tool results using Enkrypt AI Guardrails.

This hook is AUDIT-ONLY — its output is ignored by Copilot.
Violations are logged to security_alerts.jsonl for forensics.

Input from Copilot:
{
    "timestamp": 1704614700000,
    "cwd": "/path/to/project",
    "toolName": "bash",
    "toolArgs": "{\"command\": \"ls\"}",
    "toolResult": {
        "resultType": "success",
        "textResultForLlm": "file1.txt\nfile2.txt"
    }
}
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    analyze_tool_result,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_guardrail_name,
)

HOOK_NAME = "postToolUse"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    tool_name = data.get("toolName", "")
    tool_result = data.get("toolResult", {})
    result_type = tool_result.get("resultType", "")
    result_text = tool_result.get("textResultForLlm", "")

    # Analyze the result for sensitive data patterns
    analysis = analyze_tool_result(tool_name, result_text)

    # Check with this hook's guardrails if enabled
    output_violations = []
    if is_hook_enabled(HOOK_NAME) and result_text:
        should_alert, output_violations, api_result = check_with_enkrypt_api(result_text, hook_name=HOOK_NAME)
        # Log guardrails response to stderr
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_alert:
            log_security_alert("tool_output_violation", {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "tool_name": tool_name,
                "result_type": result_type,
                "violations": output_violations,
            }, data)

    log_data = {
        **data,
        "result_size": len(result_text),
        "result_type": result_type,
        "analysis": analysis,
        "output_violations": output_violations,
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Alert if sensitive data detected via pattern matching
    if analysis["sensitive_data_hints"]:
        log_security_alert("sensitive_data_in_tool_result", {
            "hook": HOOK_NAME,
            "tool_name": tool_name,
            "detected": analysis["sensitive_data_hints"],
        }, data)

    # Output is ignored by Copilot — return empty object
    print(json.dumps({}))


if __name__ == "__main__":
    main()
