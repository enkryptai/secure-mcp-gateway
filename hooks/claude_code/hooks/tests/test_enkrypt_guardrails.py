#!/usr/bin/env python3
"""
Tests for Enkrypt AI Guardrails - Claude Code Hooks

Run with: pytest tests/test_enkrypt_guardrails.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from enkrypt_guardrails import (
    parse_enkrypt_response,
    is_sensitive_tool,
    extract_text_from_tool_input,
    extract_text_from_tool_response,
    create_json_output,
    format_blocking_error,
    HookMetrics,
    MetricsCollector,
)


class TestParseEnkryptResponse:
    """Tests for parse_enkrypt_response function."""

    def test_no_violations(self):
        """Test response with no violations."""
        result = {
            "summary": {
                "injection_attack": 0,
                "pii": 0,
                "toxicity": 0,
            },
            "details": {}
        }
        block_list = ["injection_attack", "pii", "toxicity"]

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 0

    def test_injection_attack_detected(self):
        """Test injection attack detection."""
        result = {
            "summary": {
                "injection_attack": 1,
                "pii": 0,
            },
            "details": {
                "injection_attack": {
                    "safe": "0.01",
                    "attack": "0.99"
                }
            }
        }
        block_list = ["injection_attack"]

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 1
        assert violations[0]["detector"] == "injection_attack"
        assert violations[0]["blocked"] is True

    def test_toxicity_as_list(self):
        """Test toxicity detection with list format."""
        result = {
            "summary": {
                "toxicity": ["toxicity", "insult"],
            },
            "details": {
                "toxicity": {"categories": ["insult"]}
            }
        }
        block_list = ["toxicity"]

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 1
        assert violations[0]["detector"] == "toxicity"

    def test_detector_not_in_block_list(self):
        """Test that detections not in block list are ignored."""
        result = {
            "summary": {
                "injection_attack": 1,
                "pii": 1,
            },
            "details": {}
        }
        block_list = ["toxicity"]  # Neither injection nor pii

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 0

    def test_multiple_violations(self):
        """Test multiple violations detection."""
        result = {
            "summary": {
                "injection_attack": 1,
                "pii": 1,
                "toxicity": 1,
            },
            "details": {}
        }
        block_list = ["injection_attack", "pii", "toxicity"]

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 3

    def test_empty_response(self):
        """Test handling of empty response."""
        violations = parse_enkrypt_response({}, ["injection_attack"])

        assert len(violations) == 0

    def test_on_topic_special_case(self):
        """Test on_topic=0 means OFF topic (violation)."""
        result = {
            "summary": {
                "on_topic": 0,  # OFF topic
            },
            "details": {}
        }
        block_list = ["topic_detector"]

        violations = parse_enkrypt_response(result, block_list)

        assert len(violations) == 1
        assert violations[0]["detector"] == "topic_detector"


class TestIsSensitiveTool:
    """Tests for is_sensitive_tool function."""

    @patch("enkrypt_guardrails._config", {
        "sensitive_tools": ["Bash", "Write", "delete_*", "mcp__*__execute*"]
    })
    def test_exact_match(self):
        """Test exact tool name match."""
        assert is_sensitive_tool("Bash") is True
        assert is_sensitive_tool("Write") is True
        assert is_sensitive_tool("Read") is False

    @patch("enkrypt_guardrails._config", {
        "sensitive_tools": ["delete_*", "execute_*", "mcp__memory__"]
    })
    def test_wildcard_match(self):
        """Test wildcard pattern matching."""
        assert is_sensitive_tool("delete_file") is True
        assert is_sensitive_tool("delete_user") is True
        assert is_sensitive_tool("execute_query") is True
        assert is_sensitive_tool("mcp__memory__write") is True
        assert is_sensitive_tool("mcp__db__read") is False


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


class TestMetricsCollector:
    """Tests for MetricsCollector class."""

    def test_record_call(self):
        """Test recording a call."""
        collector = MetricsCollector()
        collector.record_call("PreToolUse", blocked=False, latency_ms=100)

        metrics = collector.get_metrics()

        assert "PreToolUse" in metrics
        assert metrics["PreToolUse"]["total_calls"] == 1
        assert metrics["PreToolUse"]["allowed"] == 1
        assert metrics["PreToolUse"]["avg_latency_ms"] == 100

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        collector = MetricsCollector()
        collector.record_call("PreToolUse", blocked=True, latency_ms=150)

        metrics = collector.get_metrics()

        assert metrics["PreToolUse"]["blocked"] == 1

    def test_record_error(self):
        """Test recording an error."""
        collector = MetricsCollector()
        collector.record_call("PreToolUse", blocked=False, latency_ms=50, error=True)

        metrics = collector.get_metrics()

        assert metrics["PreToolUse"]["errors"] == 1

    def test_reset(self):
        """Test resetting metrics."""
        collector = MetricsCollector()
        collector.record_call("PreToolUse", blocked=False, latency_ms=100)
        collector.reset()

        metrics = collector.get_metrics()

        assert len(metrics) == 0


class TestHookMetrics:
    """Tests for HookMetrics dataclass."""

    def test_avg_latency_no_calls(self):
        """Test average latency with no calls."""
        metrics = HookMetrics()

        assert metrics.avg_latency_ms == 0

    def test_avg_latency_with_calls(self):
        """Test average latency calculation."""
        metrics = HookMetrics(
            total_calls=4,
            total_latency_ms=400
        )

        assert metrics.avg_latency_ms == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
