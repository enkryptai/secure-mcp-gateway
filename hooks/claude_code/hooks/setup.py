#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - Setup Hook for Claude Code

This hook runs when Claude Code is invoked with setup flags:
- --init or --init-only: Repository initialization
- --maintenance: Periodic maintenance tasks

Use this for operations you don't want on every session:
- Installing dependencies
- Running migrations
- Periodic maintenance/cleanup tasks

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "Setup",
    "trigger": "init|maintenance"
}

Hook Output (JSON):
{
    "hookSpecificOutput": {
        "hookEventName": "Setup",
        "additionalContext": "Setup completed: dependencies installed"
    }
}

Environment Variables:
- CLAUDE_ENV_FILE: Path to file for persisting env vars (like SessionStart)
"""

import sys
import os
import json
import datetime

from enkrypt_guardrails import (
    read_hook_input,
    log_event,
    is_hook_enabled,
    create_json_output,
    output_json,
    ENKRYPT_API_KEY,
)


def main():
    """Main entry point for Setup hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "Setup"
    session_id = input_data.get("session_id", "")
    trigger = input_data.get("trigger", "")
    cwd = input_data.get("cwd", "")

    # Log setup invocation
    log_event("setup", {
        "hook": hook_name,
        "session_id": session_id,
        "trigger": trigger,
        "cwd": cwd,
    })

    # Check if guardrails are enabled
    if not is_hook_enabled(hook_name):
        sys.exit(0)

    context_parts = []

    if trigger == "init":
        # Repository initialization
        context_parts.append("[Enkrypt AI Guardrails] Repository initialized with security guardrails.")

        if ENKRYPT_API_KEY:
            context_parts.append("Guardrails API configured and ready.")
        else:
            context_parts.append("Warning: ENKRYPT_API_KEY not set. Configure in guardrails_config.json.")

    elif trigger == "maintenance":
        # Maintenance tasks
        context_parts.append("[Enkrypt AI Guardrails] Maintenance check completed.")
        context_parts.append(f"Timestamp: {datetime.datetime.now().isoformat()}")

    # Persist environment variables if CLAUDE_ENV_FILE is available
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if env_file:
        try:
            with open(env_file, "a") as f:
                f.write('export ENKRYPT_GUARDRAILS_INITIALIZED="true"\n')
                f.write(f'export ENKRYPT_SETUP_TRIGGER="{trigger}"\n')
            log_event("setup_env_persisted", {"env_file": env_file, "trigger": trigger})
        except Exception as e:
            log_event("setup_env_error", {"error": str(e)})

    # Output context if we have any
    if context_parts:
        output = create_json_output(
            hook_event_name=hook_name,
            additional_context="\n".join(context_parts),
        )
        output_json(output)

    sys.exit(0)


if __name__ == "__main__":
    main()
