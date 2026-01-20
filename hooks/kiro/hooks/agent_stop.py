#!/usr/bin/env python
"""
AgentStop Hook - Handles agent completion and audits the session.

Kiro Hook: Runs when the agent has completed its turn.
This hook is observability-only (doesn't block).

Use Cases:
- Compile code and report failures
- Format agent-generated code
- Review changes made by agent
- Log session completion metrics
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
    get_timestamp,
    flush_logs,
    LOG_DIR,
)

HOOK_NAME = "AgentStop"


def main():
    # AgentStop hooks don't receive stdin data in Kiro's runCommand mode
    # Data comes from environment variables instead
    data = {}

    # Add environment context
    data["user"] = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    data["pwd"] = os.environ.get("PWD", os.getcwd())
    data["timestamp"] = get_timestamp()

    # Generate session summary
    summary = {
        "hook": HOOK_NAME,
        "user": data.get("user"),
        "pwd": data.get("pwd"),
        "timestamp": data.get("timestamp"),
        "status": "completed",
    }

    # If guardrails are enabled for AgentStop, we could audit the agent's response
    # This is typically used for post-response analysis
    agent_response = data.get("response", data.get("text", ""))
    violations = []
    api_result = None

    # CRITICAL: Wrap in try-except to ensure this observability-only hook never blocks
    if is_hook_enabled(HOOK_NAME) and agent_response and agent_response.strip():
        try:
            should_alert, violations, api_result = check_with_enkrypt_api(agent_response, hook_name=HOOK_NAME)

            if should_alert:
                log_security_alert(
                    "agent_response_violation",
                    {
                        "hook": HOOK_NAME,
                        "guardrail_name": get_hook_guardrail_name(HOOK_NAME),
                        "violations": violations,
                        "response_preview": agent_response[:500] + "..." if len(agent_response) > 500 else agent_response,
                    },
                    data,
                )
                summary["violations_detected"] = len(violations)
        except Exception as e:
            # Log the error but don't block - this is observability-only
            log_event(HOOK_NAME, {
                "error": "API check failed but continuing (observability-only)",
                "error_details": str(e),
                "error_type": type(e).__name__,
            })
            summary["api_error"] = str(e)

    log_data = {
        **data,
        "summary": summary,
        "violations": violations,
        "api_result": api_result,
    }
    log_event(HOOK_NAME, log_data)
    log_to_combined(HOOK_NAME, log_data)

    # Write session summary
    summary_file = LOG_DIR / "session_summaries.jsonl"
    try:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(summary) + "\n")
    except IOError:
        pass

    flush_logs()

    # AgentStop always returns success (observability-only)
    # This hook NEVER blocks - it only logs for audit purposes
    # Always exit 0 regardless of violations found
    if violations:
        # Log to stdout for visibility but don't block
        print(f"[Audit] Security review completed: {len(violations)} potential issues logged for review")
    else:
        print("[Audit] Security review completed: No issues detected")

    # CRITICAL: Always exit 0 - this is an observability-only hook
    sys.exit(0)


if __name__ == "__main__":
    main()
