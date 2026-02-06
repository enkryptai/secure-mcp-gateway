#!/usr/bin/env python
"""
PromptSubmit Hook - Validates user prompts using Enkrypt AI Guardrails.

Kiro Hook: Runs when user submits a prompt.
Input: USER_PROMPT environment variable contains the user's prompt
Block: Exit code 1, stderr contains block reason
Allow: Exit code 0

This hook can be used as a "shell command" action in Kiro hooks.
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
    get_hook_guardrail_name,
    flush_logs,
)

HOOK_NAME = "PromptSubmit"


def main():
    # Get user prompt from environment variable (Kiro passes it this way)
    prompt = os.environ.get("USER_PROMPT", "")

    # Also try reading from stdin as fallback
    if not prompt:
        try:
            if not sys.stdin.isatty():
                stdin_content = sys.stdin.read().strip()
                if stdin_content:
                    try:
                        data = json.loads(stdin_content)
                        prompt = data.get("prompt", data.get("USER_PROMPT", ""))
                    except json.JSONDecodeError:
                        prompt = stdin_content
        except IOError:
            pass

    data = {
        "prompt": prompt,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "pwd": os.environ.get("PWD", os.getcwd()),
    }

    if not prompt.strip():
        # Empty prompt, allow
        sys.exit(0)

    # Check if this hook's guardrails are enabled
    if not is_hook_enabled(HOOK_NAME):
        log_event(HOOK_NAME, {**data, "skipped": "guardrails disabled"})
        flush_logs()
        sys.exit(0)

    # Check with Enkrypt AI API
    should_block, violations, api_result = check_with_enkrypt_api(prompt, hook_name=HOOK_NAME)

    # Log guardrails response to stderr (visible in Kiro hooks output)
    print(f"\n[Enkrypt Guardrails Response]\n{json.dumps(api_result, indent=2)}", file=sys.stderr)

    if should_block:
        violation_message = format_violation_message(violations, hook_name=HOOK_NAME)
        result = {
            "blocked": True,
            "reason": violation_message
        }
        log_security_alert("prompt_blocked", {
            "hook": HOOK_NAME,
            "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
            "violations": violations,
            "prompt_preview": prompt[:200] + "..." if len(prompt) > 200 else prompt,
        }, data)
        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        # Exit code 1 signals block to Kiro - stderr is sent to agent
        print(f"Prompt blocked by Enkrypt AI Guardrails:\n\n{violation_message}", file=sys.stderr)
        sys.exit(1)
    else:
        result = {"blocked": False}
        log_event(HOOK_NAME, {**data, "api_result": api_result, "violations": violations}, result)
        log_to_combined(HOOK_NAME, data, result)
        flush_logs()

        # Exit code 0 signals allow - stdout can provide context to agent
        # For PromptSubmit with "Add to prompt" action, we might append context
        sys.exit(0)


if __name__ == "__main__":
    main()
