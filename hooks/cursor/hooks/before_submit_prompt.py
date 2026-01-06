#!/usr/bin/env python
"""
beforeSubmitPrompt Hook - Validates prompts using Enkrypt AI Guardrails.
"""
import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    log_event,
    log_to_combined,
    log_security_alert,
    is_hook_enabled,
    get_hook_policy_name,
)

HOOK_NAME = "beforeSubmitPrompt"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"continue": True}))
        return

    prompt = data.get("prompt", "")

    if not prompt.strip():
        print(json.dumps({"continue": True}))
        return

    # Check if this hook's guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        print(json.dumps({"continue": True}))
        return

    # Check with Enkrypt AI API
    should_block, violations, api_result = check_with_enkrypt_api(prompt, hook_name=HOOK_NAME)

    # Log guardrails response to stderr (visible in Cursor hooks output)
    print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)

    if should_block:
        violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
        result = {
            "continue": False,
            "user_message": f"⛔ Prompt blocked by Enkrypt AI Guardrails:\n\n{violation_message}"
        }
        log_security_alert("prompt_blocked", {
            "hook": HOOK_NAME,
            "policy_name": get_hook_policy_name(HOOK_NAME),
            "violations": violations,
            "prompt_preview": prompt[:200] + "..." if len(prompt) > 200 else prompt,
        }, data)
    else:
        result = {"continue": True}

    log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
    log_to_combined(HOOK_NAME, data, result)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
