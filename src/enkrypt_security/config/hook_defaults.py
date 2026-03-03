"""Built-in hook defaults for each supported platform.

Used by ``generate-config --hook <platform>`` to populate the unified config.
"""

from __future__ import annotations

from enkrypt_security.config.models import HookPlatformConfig, HookPolicy

# Re-usable block lists
_INPUT_BLOCKS = [
    "injection_attack", "topic_detector", "nsfw", "toxicity",
    "pii", "keyword_detector", "bias", "sponge_attack",
]
_TOOL_INPUT_BLOCKS = ["injection_attack", "nsfw", "toxicity", "pii", "keyword_detector"]
_OUTPUT_BLOCKS = ["pii", "toxicity", "nsfw"]

_SENSITIVE_IDE_TOOLS = [
    "execute_sql", "delete_", "remove_", "drop_",
    "write_file", "run_command", "shell_", "exec_",
]
_SENSITIVE_FRAMEWORK_TOOLS = [
    "execute_sql", "run_command", "shell_*", "bash",
    "delete_*", "remove_*", "drop_*", "write_file",
    "create_file", "modify_file", "send_email", "http_request",
]
_SENSITIVE_FILE_PATTERNS_KIRO = [
    r"\.env$", r"\.env\.", r"secrets?\.", r"credentials?\.",
    r"\.pem$", r"\.key$", "id_rsa", r"config\.json$", r"settings\.json$",
]

_GUARDRAIL = "Sample Airline Guardrail"


def _p(enabled: bool, block: list[str] | None = None) -> HookPolicy:
    return HookPolicy(enabled=enabled, guardrail_name=_GUARDRAIL, block=list(block or []))


PLATFORM_DEFAULTS: dict[str, HookPlatformConfig] = {
    "cursor": HookPlatformConfig(
        sensitive_tools=list(_SENSITIVE_IDE_TOOLS),
        policies={
            "beforeSubmitPrompt": _p(False, _INPUT_BLOCKS),
            "beforeMCPExecution": _p(True, _TOOL_INPUT_BLOCKS),
            "afterMCPExecution": _p(True, _OUTPUT_BLOCKS),
            "afterAgentResponse": _p(False, _OUTPUT_BLOCKS),
            "stop": _p(False),
        },
    ),
    "claude": HookPlatformConfig(
        sensitive_tools=["Bash", "Write", "Edit", "MultiEdit"] + list(_SENSITIVE_IDE_TOOLS),
        policies={
            "UserPromptSubmit": _p(False, _INPUT_BLOCKS),
            "PreToolUse": _p(True, _TOOL_INPUT_BLOCKS),
            "PostToolUse": _p(True, _OUTPUT_BLOCKS),
            "Stop": _p(False),
        },
    ),
    "claude_code": HookPlatformConfig(
        sensitive_tools=[
            "Bash", "Write", "Edit",
            "execute_sql", "delete_*", "remove_*", "drop_*",
            "run_command", "shell_*", "exec_*",
            "mcp__*__write*", "mcp__*__delete*", "mcp__*__execute*",
        ],
        policies={
            "Setup": _p(True),
            "SessionStart": _p(True),
            "UserPromptSubmit": _p(True, ["injection_attack", "nsfw", "toxicity"]),
            "PreToolUse": _p(True, _TOOL_INPUT_BLOCKS),
            "PermissionRequest": _p(True, ["injection_attack", "pii"]),
            "PostToolUse": _p(True, _OUTPUT_BLOCKS),
            "SubagentStop": _p(False),
            "Stop": _p(False),
            "PreCompact": _p(True),
            "Notification": _p(True),
            "SessionEnd": _p(True),
        },
    ),
    "copilot": HookPlatformConfig(
        sensitive_tools=list(_SENSITIVE_IDE_TOOLS),
        policies={
            "userPromptSubmitted": _p(False, _INPUT_BLOCKS),
            "preToolUse": _p(True, _TOOL_INPUT_BLOCKS),
            "postToolUse": _p(True, _OUTPUT_BLOCKS),
            "errorOccurred": _p(False),
        },
    ),
    "kiro": HookPlatformConfig(
        sensitive_tools=list(_SENSITIVE_IDE_TOOLS),
        sensitive_file_patterns=list(_SENSITIVE_FILE_PATTERNS_KIRO),
        policies={
            "PromptSubmit": _p(True, _INPUT_BLOCKS),
            "AgentStop": _p(False, _OUTPUT_BLOCKS),
            "FileSave": _p(True, ["pii", "injection_attack"]),
            "FileCreate": _p(True, ["pii", "injection_attack"]),
            "FileDelete": _p(False),
            "Manual": _p(True, _INPUT_BLOCKS),
        },
    ),
    "langchain": HookPlatformConfig(
        sensitive_tools=_SENSITIVE_FRAMEWORK_TOOLS + ["python_repl", "terminal"],
        policies={
            "on_llm_start": _p(True, _TOOL_INPUT_BLOCKS),
            "on_llm_end": _p(True, _OUTPUT_BLOCKS),
            "on_chat_model_start": _p(True, ["injection_attack", "pii", "toxicity"]),
            "on_chain_start": _p(True, ["injection_attack", "pii"]),
            "on_chain_end": _p(True, ["pii", "toxicity"]),
            "on_tool_start": _p(True, ["injection_attack", "pii"]),
            "on_tool_end": _p(True, ["pii"]),
            "on_agent_action": _p(True, ["injection_attack"]),
            "on_agent_finish": _p(True, _OUTPUT_BLOCKS),
            "on_retriever_start": _p(True, ["injection_attack"]),
            "on_retriever_end": _p(True, ["pii"]),
            "on_text": _p(False),
        },
    ),
    "langgraph": HookPlatformConfig(
        sensitive_tools=_SENSITIVE_FRAMEWORK_TOOLS + ["python_repl", "terminal"],
        policies={
            "pre_model_hook": _p(True, _TOOL_INPUT_BLOCKS),
            "post_model_hook": _p(True, _OUTPUT_BLOCKS),
            "before_tool_call": _p(True, ["injection_attack", "pii"]),
            "after_tool_call": _p(True, ["pii"]),
            "on_agent_action": _p(False),
            "on_agent_finish": _p(True, _OUTPUT_BLOCKS),
        },
    ),
    "openai": HookPlatformConfig(
        sensitive_tools=_SENSITIVE_FRAMEWORK_TOOLS + ["computer_*"],
        policies={
            "on_agent_start": _p(True, _TOOL_INPUT_BLOCKS),
            "on_agent_end": _p(True, _OUTPUT_BLOCKS),
            "on_llm_start": _p(False),
            "on_llm_end": _p(True, _OUTPUT_BLOCKS),
            "on_tool_start": _p(True, ["injection_attack", "pii"]),
            "on_tool_end": _p(True, ["pii"]),
            "on_handoff": _p(False),
        },
    ),
    "strands": HookPlatformConfig(
        sensitive_tools=_SENSITIVE_FRAMEWORK_TOOLS + ["mcp__*"],
        policies={
            "MessageAdded": _p(True, _TOOL_INPUT_BLOCKS),
            "BeforeInvocation": _p(False),
            "AfterInvocation": _p(False),
            "BeforeModelCall": _p(False),
            "AfterModelCall": _p(True, _OUTPUT_BLOCKS),
            "BeforeToolCall": _p(True, ["injection_attack", "pii"]),
            "AfterToolCall": _p(True, ["pii"]),
        },
    ),
    "crewai": HookPlatformConfig(
        sensitive_tools=[],
        policies={
            "before_llm_call": _p(True, ["policy_violation"]),
            "after_llm_call": _p(True, ["policy_violation"]),
            "before_tool_call": _p(True, ["policy_violation"]),
            "after_tool_call": _p(False, ["policy_violation"]),
        },
    ),
}

SUPPORTED_PLATFORMS = sorted(PLATFORM_DEFAULTS.keys())
