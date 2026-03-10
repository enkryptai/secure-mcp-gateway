#!/usr/bin/env python
"""
Tests for Enkrypt AI Guardrails - OpenAI Agents SDK

Run with: pytest tests/sdk/framework_hooks/openai/test_enkrypt_guardrails.py -v
"""
import unittest


from enkryptai_agent_security.sdk.framework_hooks.openai_agents import (
    check_with_enkrypt_api,
    format_violation_message,
    is_hook_enabled,
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

    def test_format_violation_message_injection(self):
        """Test formatting injection attack violation message."""
        violations = [
            {"detector": "injection_attack", "attack_score": 0.95, "blocked": True}
        ]

        message = format_violation_message(violations)

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
        import enkryptai_agent_security.sdk.framework_hooks.openai_agents as mod
        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["execute_sql", "bash"]

        self.assertTrue(is_sensitive_tool("execute_sql"))
        self.assertTrue(is_sensitive_tool("bash"))
        self.assertFalse(is_sensitive_tool("get_weather"))

        mod._core.sensitive_tools = original

    def test_is_sensitive_tool_wildcard(self):
        """Test wildcard matching for sensitive tools."""
        import enkryptai_agent_security.sdk.framework_hooks.openai_agents as mod
        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["shell_*", "delete_*"]

        self.assertTrue(is_sensitive_tool("shell_execute"))
        self.assertTrue(is_sensitive_tool("shell_run"))
        self.assertTrue(is_sensitive_tool("delete_file"))
        self.assertFalse(is_sensitive_tool("get_shell_info"))

        mod._core.sensitive_tools = original

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

    def test_check_with_enkrypt_api_disabled(self):
        """Test that disabled hooks are skipped."""
        should_block, violations, result = check_with_enkrypt_api(
            "test text",
            hook_name="disabled_hook"
        )

        self.assertFalse(should_block)
        self.assertEqual(len(violations), 0)

    def test_is_hook_enabled_default(self):
        """Test hook enabled check with default."""
        self.assertFalse(is_hook_enabled("nonexistent_hook"))

    def test_get_metrics_returns_dict(self):
        """Test get_metrics returns dict."""
        m = get_metrics()
        self.assertIsInstance(m, dict)

    def test_reset_metrics_works(self):
        """Test reset_metrics works without error."""
        reset_metrics()
        m = get_metrics()
        self.assertIsInstance(m, dict)


class TestRunHooks(unittest.TestCase):
    """Test cases for the OpenAI Agents SDK hooks."""

    def test_import_hook_classes(self):
        """Test that hook classes can be imported."""
        from enkryptai_agent_security.sdk.framework_hooks.openai_hook import (
            EnkryptRunHooks,
            EnkryptAgentHooks,
            EnkryptBlockingRunHooks,
            EnkryptAuditRunHooks,
        )

        # Create instances
        run_hooks = EnkryptRunHooks()
        _ = EnkryptAgentHooks()
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
        from enkryptai_agent_security.sdk.framework_hooks.openai_hook import GuardrailsViolationError

        violations = [{"detector": "pii", "blocked": True}]
        error = GuardrailsViolationError("Test error", violations=violations)

        self.assertEqual(str(error), "Test error")
        self.assertEqual(len(error.violations), 1)

    def test_run_hooks_reset(self):
        """Test resetting run hooks state."""
        from enkryptai_agent_security.sdk.framework_hooks.openai_hook import EnkryptRunHooks

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
        from enkryptai_agent_security.sdk.framework_hooks.openai_hook import EnkryptRunHooks

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
