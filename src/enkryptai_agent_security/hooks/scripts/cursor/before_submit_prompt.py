#!/usr/bin/env python
"""
beforeSubmitPrompt Hook - Validates prompts using Enkrypt AI Guardrails.
"""
import json
import sys

from enkryptai_agent_security.hooks.providers.cursor import (
    check_with_enkrypt_api,
    format_violation_message,
    get_hook_guardrail_name,
    is_hook_enabled,
    log_event,
    log_security_alert,
    log_to_combined,
)

HOOK_NAME = "beforeSubmitPrompt"


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except json.JSONDecodeError as e:
        log_event(HOOK_NAME, {"parse_error": str(e), "error_type": "JSONDecodeError"})
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
            "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
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
