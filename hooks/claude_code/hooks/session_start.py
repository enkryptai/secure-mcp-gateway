#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - SessionStart Hook for Claude Code

This hook runs when a Claude Code session starts or resumes.
It can:
- Load development context
- Set up environment variables (via CLAUDE_ENV_FILE)
- Add context to the conversation (stdout or additionalContext)

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "SessionStart",
    "source": "startup|resume|clear|compact",
    "model": "claude-sonnet-4-20250514"
}

Hook Output:
- stdout text is added as context
- JSON with hookSpecificOutput.additionalContext for structured context
- CLAUDE_ENV_FILE can be used to persist environment variables

Environment Variables:
- CLAUDE_ENV_FILE: Path to file for persisting env vars (only available in SessionStart)
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
    _config,
    ENKRYPT_API_KEY,
)


def main():
    """Main entry point for SessionStart hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "SessionStart"
    session_id = input_data.get("session_id", "")
    source = input_data.get("source", "")
    model = input_data.get("model", "")
    cwd = input_data.get("cwd", "")
    agent_type = input_data.get("agent_type", "")

    # Log session start
    log_event("session_start", {
        "session_id": session_id,
        "source": source,
        "model": model,
        "cwd": cwd,
        "agent_type": agent_type,
    })

    # Check if guardrails are enabled
    if not is_hook_enabled(hook_name):
        sys.exit(0)

    # Build context message
    context_parts = []

    # Add guardrails status
    if ENKRYPT_API_KEY:
        context_parts.append("[Enkrypt AI Guardrails] Security guardrails are active for this session.")

        # List enabled hooks
        enabled_hooks = []
        for hook in ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"]:
            if is_hook_enabled(hook):
                enabled_hooks.append(hook)

        if enabled_hooks:
            context_parts.append(f"Active checks: {', '.join(enabled_hooks)}")
    else:
        context_parts.append("[Enkrypt AI Guardrails] Warning: API key not configured. Guardrails are disabled.")

    # Add timestamp
    context_parts.append(f"Session started: {datetime.datetime.now().isoformat()}")

    # Persist environment variables if CLAUDE_ENV_FILE is available
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if env_file:
        try:
            with open(env_file, "a") as f:
                # Example: Set environment variables for the session
                f.write('export ENKRYPT_GUARDRAILS_ACTIVE="true"\n')
                f.write(f'export SESSION_START_TIME="{datetime.datetime.now().isoformat()}"\n')
            log_event("env_vars_persisted", {"env_file": env_file})
        except Exception as e:
            log_event("env_vars_error", {"error": str(e)})

    # Output context
    # Option 1: Simple text output (added to conversation)
    # print("\n".join(context_parts))

    # Option 2: JSON output with additionalContext (more structured)
    output = create_json_output(
        hook_event_name=hook_name,
        additional_context="\n".join(context_parts),
    )
    output_json(output)

    sys.exit(0)


if __name__ == "__main__":
    main()
