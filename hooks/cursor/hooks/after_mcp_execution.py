#!/usr/bin/env python
"""
afterMCPExecution Hook - Audits MCP results using Enkrypt AI Guardrails.
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    analyze_mcp_result,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_guardrail_name,
)

HOOK_NAME = "afterMCPExecution"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    tool_name = data.get("tool_name", "")
    result_json = data.get("result_json", "")
    duration = data.get("duration", 0)

    # Analyze the result for sensitive data patterns
    analysis = analyze_mcp_result(tool_name, result_json)

    # Check with this hook's guardrails if enabled
    output_violations = []
    if is_hook_enabled(HOOK_NAME) and result_json:
        should_alert, output_violations, api_result = check_with_enkrypt_api(result_json, hook_name=HOOK_NAME)
        # Log guardrails response to stderr (visible in Cursor hooks output)
        print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)
        if should_alert:
            log_security_alert("mcp_output_violation", {
                "hook": HOOK_NAME,
                "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                "tool_name": tool_name,
                "violations": output_violations,
            }, data)

    log_data = {
        **data,
        "duration_ms": duration,
        "result_size": len(result_json),
        "analysis": analysis,
        "output_violations": output_violations,
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Alert if sensitive data detected via pattern matching
    if analysis["sensitive_data_hints"]:
        log_security_alert("sensitive_data_in_mcp_result", {
            "hook": HOOK_NAME,
            "tool_name": tool_name,
            "detected": analysis["sensitive_data_hints"],
        }, data)

    print(json.dumps({}))


if __name__ == "__main__":
    main()
