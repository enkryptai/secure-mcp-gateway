#!/usr/bin/env python
"""
userPromptSubmitted Hook - Audits prompts using Enkrypt AI Guardrails.

NOTE: This hook is AUDIT-ONLY in GitHub Copilot. Its output is ignored by
Copilot (prompt modification/blocking is not supported). Violations are
logged to security_alerts.jsonl for forensics.

Input from Copilot:
{
    "timestamp": 1704614500000,
    "cwd": "/path/to/project",
    "prompt": "user's message"
}
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_guardrail_name,
)

HOOK_NAME = "userPromptSubmitted"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
        print(json.dumps({}))
        return

    prompt = data.get("prompt", "")

    if not prompt.strip():
        print(json.dumps({}))
        return

    # Check if this hook's guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        print(json.dumps({}))
        return

    # Check with Enkrypt AI API (audit-only — output is ignored by Copilot)
    should_alert, violations, api_result = check_with_enkrypt_api(prompt, hook_name=HOOK_NAME)

    # Log guardrails response to stderr
    print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)

    if should_alert:
        log_security_alert("prompt_violation", {
            "hook": HOOK_NAME,
            "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
            "violations": violations,
            "prompt_preview": prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "note": "audit-only — Copilot does not support prompt blocking",
        }, data)

    log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations})
    log_to_combined(HOOK_NAME, data)

    # Output is ignored by Copilot — return empty object
    print(json.dumps({}))


if __name__ == "__main__":
    main()
