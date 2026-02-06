#!/usr/bin/env python3
"""
Enkrypt AI Guardrails - Notification Hook for Claude Code

This hook runs when Claude Code sends notifications.
It can:
- Log notifications
- Trigger custom alerts (Slack, email, etc.)
- Filter notification types

Hook Input (via stdin):
{
    "session_id": "abc123",
    "transcript_path": "/path/to/transcript.jsonl",
    "cwd": "/current/directory",
    "permission_mode": "default",
    "hook_event_name": "Notification",
    "message": "Claude needs your permission to use Bash",
    "notification_type": "permission_prompt|idle_prompt|auth_success|elicitation_dialog"
}

Notification Types:
- permission_prompt: Permission requests from Claude Code
- idle_prompt: When Claude is waiting for user input (60+ seconds idle)
- auth_success: Authentication success notifications
- elicitation_dialog: When Claude Code needs input for MCP tool elicitation
"""

import sys
import json
import os

from enkrypt_guardrails import (
    read_hook_input,
    log_event,
)


def main():
    """Main entry point for Notification hook."""
    # Read input from stdin
    input_data = read_hook_input()

    if not input_data:
        sys.exit(0)

    hook_name = "Notification"
    session_id = input_data.get("session_id", "")
    message = input_data.get("message", "")
    notification_type = input_data.get("notification_type", "")
    cwd = input_data.get("cwd", "")

    # Log the notification
    log_event("notification", {
        "hook": hook_name,
        "session_id": session_id,
        "notification_type": notification_type,
        "message": message[:500] if len(message) > 500 else message,
        "cwd": cwd,
    })

    # Custom handling based on notification type
    if notification_type == "permission_prompt":
        log_event("permission_notification", {
            "session_id": session_id,
            "message": message,
        })
        # Could trigger Slack/email notification here

    elif notification_type == "idle_prompt":
        log_event("idle_notification", {
            "session_id": session_id,
            "message": "Claude is waiting for input",
        })
        # Could trigger reminder notification

    elif notification_type == "auth_success":
        log_event("auth_notification", {
            "session_id": session_id,
            "message": "Authentication successful",
        })

    # Notification hooks don't produce output that affects Claude
    sys.exit(0)


if __name__ == "__main__":
    main()
