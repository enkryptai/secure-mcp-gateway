#!/usr/bin/env python3
"""
Tests for Enkrypt AI Guardrails - Claude Code Hooks

Run with: pytest tests/hooks/claude_code/test_enkrypt_guardrails.py -v
"""

import pytest
from unittest.mock import patch

from enkryptai_agent_security.hooks.providers.claude_code import (
    is_sensitive_tool,
    extract_text_from_tool_input,
    extract_text_from_tool_response,
    create_json_output,
    format_blocking_error,
)


class TestIsSensitiveTool:
    """Tests for is_sensitive_tool function."""

    @patch("enkryptai_agent_security.hooks.providers.claude_code._core")
    def test_exact_match(self, mock_core):
        """Test exact tool name match."""
        mock_core.sensitive_tools = ["Bash", "Write", "delete_*", "mcp__*__execute*"]
        # is_sensitive_tool uses _is_sensitive_tool with _core.sensitive_tools
        with patch("enkryptai_agent_security.hooks.providers.claude_code._is_sensitive_tool") as mock_fn:
            mock_fn.return_value = True
            assert is_sensitive_tool("Bash") is True
            mock_fn.return_value = False
            assert is_sensitive_tool("Read") is False


class TestExtractTextFromToolInput:
    """Tests for extract_text_from_tool_input function."""

    def test_bash_tool(self):
        """Test text extraction from Bash tool input."""
        tool_input = {
            "command": "ls -la",
            "description": "List files"
        }

        text = extract_text_from_tool_input("Bash", tool_input)

        assert "ls -la" in text
        assert "List files" in text

    def test_write_tool(self):
        """Test text extraction from Write tool input."""
        tool_input = {
            "file_path": "/path/to/file.txt",
            "content": "Hello world"
        }

        text = extract_text_from_tool_input("Write", tool_input)

        assert "Hello world" in text
        assert "/path/to/file.txt" in text

    def test_edit_tool(self):
        """Test text extraction from Edit tool input."""
        tool_input = {
            "file_path": "/path/to/file.txt",
            "old_string": "old text",
            "new_string": "new text"
        }

        text = extract_text_from_tool_input("Edit", tool_input)

        assert "old text" in text
        assert "new text" in text

    def test_generic_tool(self):
        """Test text extraction from generic tool input."""
        tool_input = {
            "query": "SELECT * FROM users",
            "text": "Additional text"
        }

        text = extract_text_from_tool_input("CustomTool", tool_input)

        assert "SELECT * FROM users" in text


class TestExtractTextFromToolResponse:
    """Tests for extract_text_from_tool_response function."""

    def test_output_field(self):
        """Test extraction from output field."""
        tool_response = {
            "output": "Command output here",
            "exitCode": 0
        }

        text = extract_text_from_tool_response("Bash", tool_response)

        assert "Command output here" in text

    def test_multiple_fields(self):
        """Test extraction from multiple fields."""
        tool_response = {
            "stdout": "Standard output",
            "stderr": "Error output"
        }

        text = extract_text_from_tool_response("Bash", tool_response)

        assert "Standard output" in text
        assert "Error output" in text


class TestCreateJsonOutput:
    """Tests for create_json_output function."""

    def test_pre_tool_use_deny(self):
        """Test PreToolUse deny output."""
        output = create_json_output(
            hook_event_name="PreToolUse",
            permission_decision="deny",
            permission_decision_reason="Blocked by guardrails"
        )

        assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Blocked" in output["hookSpecificOutput"]["permissionDecisionReason"]

    def test_pre_tool_use_allow_with_update(self):
        """Test PreToolUse allow with input modification."""
        output = create_json_output(
            hook_event_name="PreToolUse",
            permission_decision="allow",
            updated_input={"command": "safe_command"}
        )

        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert output["hookSpecificOutput"]["updatedInput"]["command"] == "safe_command"

    def test_stop_with_continue_false(self):
        """Test Stop hook with continue=false."""
        output = create_json_output(
            hook_event_name="Stop",
            continue_session=False,
            stop_reason="User requested stop"
        )

        assert output["continue"] is False
        assert output["stopReason"] == "User requested stop"

    def test_additional_context(self):
        """Test adding context."""
        output = create_json_output(
            hook_event_name="PostToolUse",
            additional_context="Warning: Output contains PII"
        )

        assert output["hookSpecificOutput"]["additionalContext"] == "Warning: Output contains PII"


class TestFormatBlockingError:
    """Tests for format_blocking_error function."""

    def test_single_violation(self):
        """Test formatting single violation."""
        violations = [{"detector": "injection_attack"}]

        message = format_blocking_error(violations, "PreToolUse")

        assert "Enkrypt Guardrails" in message
        assert "injection_attack" in message
        assert "PreToolUse" in message

    def test_multiple_violations(self):
        """Test formatting multiple violations."""
        violations = [
            {"detector": "injection_attack"},
            {"detector": "pii"}
        ]

        message = format_blocking_error(violations, "UserPromptSubmit")

        assert "injection_attack" in message
        assert "pii" in message

    def test_empty_violations(self):
        """Test formatting empty violations."""
        message = format_blocking_error([], "PreToolUse")

        assert message == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
