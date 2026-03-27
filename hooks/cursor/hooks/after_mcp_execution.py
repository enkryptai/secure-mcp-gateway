#!/usr/bin/env python
"""
afterMCPExecution Hook - Audits MCP results using Enkrypt AI Guardrails.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    analyze_mcp_result,
    check_with_enkrypt_api,
    get_hook_guardrail_name,
    is_hook_enabled,
    log_event,
    log_security_alert,
    log_to_combined,
)

HOOK_NAME = "afterMCPExecution"


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    tool_name = data.get("tool_name", "")
    result_json = data.get("result_json", "")
    duration = data.get("duration", 0)

    analysis = analyze_mcp_result(tool_name, result_json)

    output_violations = []
    if is_hook_enabled(HOOK_NAME) and result_json:
        should_alert, output_violations, api_result = check_with_enkrypt_api(
            result_json, hook_name=HOOK_NAME
        )
        print(
            f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}",
            file=sys.stderr,
        )
        if should_alert:
            log_security_alert(
                "mcp_output_violation",
                {
                    "hook": HOOK_NAME,
                    "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                    "tool_name": tool_name,
                    "violations": output_violations,
                },
                data,
            )

    log_data = {
        **data,
        "duration_ms": duration,
        "result_size": len(result_json),
        "analysis": analysis,
        "output_violations": output_violations,
    }

    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    if analysis["sensitive_data_hints"]:
        log_security_alert(
            "sensitive_data_in_mcp_result",
            {
                "hook": HOOK_NAME,
                "tool_name": tool_name,
                "detected": analysis["sensitive_data_hints"],
            },
            data,
        )

    print(json.dumps({}))


if __name__ == "__main__":
    main()
