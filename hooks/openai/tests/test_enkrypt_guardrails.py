#!/usr/bin/env python
"""
Tests for Enkrypt AI Guardrails - OpenAI Agents SDK

Run with: pytest tests/test_enkrypt_guardrails.py -v
"""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    parse_enkrypt_response,
    is_hook_enabled,
    get_hook_policy_name,
    is_sensitive_tool,
    analyze_content,
    get_metrics,
    reset_metrics,
    LOG_DIR,
)


class TestEnkryptGuardrails(unittest.TestCase):
    """Test cases for the core guardrails module."""

    def setUp(self):
        """Set up test fixtures."""
        reset_metrics()

    def test_parse_enkrypt_response_injection(self):
        """Test parsing injection attack detection."""
        response = {
            "summary": {"injection_attack": 1},
            "details": {"injection_attack": {"attack": 0.95}},
        }
        block_list = ["injection_attack"]

        violations = parse_enkrypt_response(response, block_list)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["detector"], "injection_attack")
        self.assertTrue(violations[0]["blocked"])

    def test_parse_enkrypt_response_pii(self):
        """Test parsing PII detection."""
        response = {
            "summary": {"pii": 1},
            "details": {"pii": {"pii": {"email": ["test@example.com"]}}},
        }
        block_list = ["pii"]

        violations = parse_enkrypt_response(response, block_list)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["detector"], "pii")
        self.assertIn("email", violations[0].get("entities", []))

    def test_parse_enkrypt_response_toxicity(self):
        """Test parsing toxicity detection."""
        response = {
            "summary": {"toxicity": ["hate", "threat"]},
            "details": {"toxicity": {"toxicity": 0.85}},
        }
        block_list = ["toxicity"]

        violations = parse_enkrypt_response(response, block_list)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["detector"], "toxicity")
        self.assertEqual(violations[0]["toxicity_types"], ["hate", "threat"])

    def test_parse_enkrypt_response_no_violations(self):
        """Test parsing when no violations detected."""
        response = {
            "summary": {"injection_attack": 0, "pii": 0, "toxicity": []},
            "details": {},
        }
        block_list = ["injection_attack", "pii", "toxicity"]

        violations = parse_enkrypt_response(response, block_list)

        self.assertEqual(len(violations), 0)

    def test_parse_enkrypt_response_not_in_block_list(self):
        """Test that detected items not in block list are ignored."""
        response = {
            "summary": {"injection_attack": 1, "pii": 1},
            "details": {},
        }
        block_list = ["injection_attack"]  # pii not in block list

        violations = parse_enkrypt_response(response, block_list)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["detector"], "injection_attack")

    def test_format_violation_message_injection(self):
        """Test formatting injection attack violation message."""
        violations = [
            {"detector": "injection_attack", "attack_score": 0.95, "blocked": True}
        ]

        message = format_violation_message(violations, hook_name="on_agent_start")

        self.assertIn("Injection attack", message)
        self.assertIn("95.0%", message)

    def test_format_violation_message_pii(self):
        """Test formatting PII violation message."""
        violations = [
            {
                "detector": "pii",
                "pii_found": {"email": ["test@example.com"], "phone": ["555-1234"]},
                "blocked": True,
            }
        ]

        message = format_violation_message(violations)

        self.assertIn("PII", message)

    def test_format_violation_message_multiple(self):
        """Test formatting multiple violations."""
        violations = [
            {"detector": "injection_attack", "blocked": True},
            {"detector": "toxicity", "toxicity_types": ["hate"], "blocked": True},
        ]

        message = format_violation_message(violations)

        self.assertIn("Injection", message)
        self.assertIn("Toxic", message)

    def test_is_sensitive_tool_exact_match(self):
        """Test exact match for sensitive tools."""
        # Temporarily set sensitive tools
        import enkrypt_guardrails
        original = enkrypt_guardrails.SENSITIVE_TOOLS
        enkrypt_guardrails.SENSITIVE_TOOLS = ["execute_sql", "bash"]

        self.assertTrue(is_sensitive_tool("execute_sql"))
        self.assertTrue(is_sensitive_tool("bash"))
        self.assertFalse(is_sensitive_tool("get_weather"))

        enkrypt_guardrails.SENSITIVE_TOOLS = original

    def test_is_sensitive_tool_wildcard(self):
        """Test wildcard matching for sensitive tools."""
        import enkrypt_guardrails
        original = enkrypt_guardrails.SENSITIVE_TOOLS
        enkrypt_guardrails.SENSITIVE_TOOLS = ["shell_*", "delete_*"]

        self.assertTrue(is_sensitive_tool("shell_execute"))
        self.assertTrue(is_sensitive_tool("shell_run"))
        self.assertTrue(is_sensitive_tool("delete_file"))
        self.assertFalse(is_sensitive_tool("get_shell_info"))

        enkrypt_guardrails.SENSITIVE_TOOLS = original

    def test_analyze_content_detects_patterns(self):
        """Test content analysis for sensitive patterns."""
        content = "My password is secret123 and api_key is xyz"

        analysis = analyze_content(content)

        self.assertIn("password reference", analysis["sensitive_data_hints"])
        self.assertIn("API key reference", analysis["sensitive_data_hints"])

    def test_analyze_content_no_patterns(self):
        """Test content analysis with no sensitive patterns."""
        content = "What is the weather like today?"

        analysis = analyze_content(content)

        self.assertEqual(len(analysis["sensitive_data_hints"]), 0)

    @patch("enkrypt_guardrails.get_http_session")
    def test_check_with_enkrypt_api_disabled(self, mock_session):
        """Test that disabled hooks are skipped."""
        # This should return immediately without calling the API
        should_block, violations, result = check_with_enkrypt_api(
            "test text",
            hook_name="disabled_hook"
        )

        self.assertFalse(should_block)
        self.assertEqual(len(violations), 0)
        self.assertIn("skipped", result)

    @patch("enkrypt_guardrails.get_http_session")
    @patch("enkrypt_guardrails.is_hook_enabled")
    def test_check_with_enkrypt_api_timeout(self, mock_enabled, mock_session):
        """Test timeout handling."""
        import requests

        mock_enabled.return_value = True
        mock_response = MagicMock()
        mock_session.return_value.post.side_effect = requests.exceptions.Timeout()

        should_block, violations, result = check_with_enkrypt_api(
            "test text",
            hook_name="on_agent_start"
        )

        self.assertIn("error", result)
        self.assertEqual(result["error"], "timeout")


class TestRunHooks(unittest.TestCase):
    """Test cases for the OpenAI Agents SDK hooks."""

    def test_import_hook_classes(self):
        """Test that hook classes can be imported."""
        from enkrypt_guardrails_hook import (
            EnkryptRunHooks,
            EnkryptAgentHooks,
            EnkryptBlockingRunHooks,
            EnkryptAuditRunHooks,
            GuardrailsViolationError,
        )

        # Create instances
        run_hooks = EnkryptRunHooks()
        agent_hooks = EnkryptAgentHooks()
        blocking_hooks = EnkryptBlockingRunHooks()
        audit_hooks = EnkryptAuditRunHooks()

        # Verify settings
        self.assertTrue(run_hooks.block_on_violation)
        self.assertFalse(run_hooks.log_only_mode)

        self.assertTrue(blocking_hooks.block_on_violation)
        self.assertFalse(blocking_hooks.log_only_mode)

        self.assertFalse(audit_hooks.block_on_violation)
        self.assertTrue(audit_hooks.log_only_mode)

    def test_guardrails_violation_error(self):
        """Test GuardrailsViolationError exception."""
        from enkrypt_guardrails_hook import GuardrailsViolationError

        violations = [{"detector": "pii", "blocked": True}]
        error = GuardrailsViolationError("Test error", violations=violations)

        self.assertEqual(str(error), "Test error")
        self.assertEqual(len(error.violations), 1)

    def test_run_hooks_reset(self):
        """Test resetting run hooks state."""
        from enkrypt_guardrails_hook import EnkryptRunHooks

        hooks = EnkryptRunHooks()
        hooks._current_violations = [{"test": "violation"}]
        hooks._total_input_tokens = 100
        hooks._event_counter = 5

        hooks.reset()

        self.assertEqual(len(hooks._current_violations), 0)
        self.assertEqual(hooks._total_input_tokens, 0)
        self.assertEqual(hooks._event_counter, 0)

    def test_run_hooks_get_metrics(self):
        """Test getting metrics from run hooks."""
        from enkrypt_guardrails_hook import EnkryptRunHooks

        hooks = EnkryptRunHooks()
        metrics = hooks.get_metrics()

        self.assertIsInstance(metrics, dict)


class TestLogDirectory(unittest.TestCase):
    """Test log directory setup."""

    def test_log_directory_exists(self):
        """Test that log directory is created."""
        self.assertTrue(LOG_DIR.exists())

    def test_log_directory_is_directory(self):
        """Test that LOG_DIR is actually a directory."""
        self.assertTrue(LOG_DIR.is_dir())


if __name__ == "__main__":
    unittest.main()
