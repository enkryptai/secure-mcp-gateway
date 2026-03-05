#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Copilot hooks).
"""
import re
import unittest


from enkryptai_agent_security.hooks.providers.copilot import (
    format_violation_message,
    check_tool,
    analyze_tool_result,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    get_source_event,
    get_metrics,
    get_hook_metrics,
    reset_metrics,
    is_sensitive_tool,
    reload_config,
    flush_logs,
    get_timestamp,
    SENSITIVE_PATTERNS,
    BaseHook,
    LOG_DIR,
)


class TestFormatViolationMessage(unittest.TestCase):
    """Test formatting of violation messages."""

    def test_empty_violations(self):
        """Test formatting empty violations list."""
        result = format_violation_message([])
        self.assertEqual(result, "")

    def test_pii_message(self):
        """Test PII violation message formatting."""
        violations = [{"detector": "pii", "pii_found": {"email": ["test@example.com"]}}]
        result = format_violation_message(violations)
        self.assertIn("PII/Secrets detected", result)
        self.assertIn("email", result)

    def test_injection_message(self):
        """Test injection attack message formatting."""
        violations = [{"detector": "injection_attack", "attack_score": 0.95}]
        result = format_violation_message(violations)
        self.assertIn("Injection attack", result)
        self.assertIn("95.0%", result)

    def test_toxicity_message(self):
        """Test toxicity message formatting."""
        violations = [{"detector": "toxicity", "toxicity_types": ["insult"], "score": 0.8}]
        result = format_violation_message(violations)
        self.assertIn("Toxic content", result)
        self.assertIn("insult", result)

    def test_policy_violation_message(self):
        """Test policy violation message formatting."""
        violations = [{
            "detector": "policy_violation",
            "violating_policy": "No competitor mentions",
            "explanation": "Content mentions competitor products"
        }]
        result = format_violation_message(violations)
        self.assertIn("Policy violation", result)
        self.assertIn("No competitor mentions", result)


class TestCheckTool(unittest.TestCase):
    """Test tool checking logic."""

    def test_safe_tool_allowed(self):
        """Test that safe tools are allowed."""
        permission, reason = check_tool("read_file", '{"path": "/tmp/test.txt"}')
        self.assertEqual(permission, "allow")
        self.assertEqual(reason, "")

    def test_dangerous_sql_requires_confirmation(self):
        """Test that dangerous SQL operations require confirmation."""
        permission, reason = check_tool("run_query", '{"query": "DROP TABLE users"}')
        self.assertEqual(permission, "ask")
        self.assertIn("SQL", reason)

    def test_delete_sql_requires_confirmation(self):
        """Test DELETE SQL requires confirmation."""
        permission, _ = check_tool("execute_query", '{"sql": "DELETE FROM users WHERE id = 1"}')
        self.assertEqual(permission, "ask")

    def test_update_sql_requires_confirmation(self):
        """Test UPDATE SQL requires confirmation."""
        permission, _ = check_tool("db_query", '{"query": "UPDATE users SET name = \'test\'"}')
        self.assertEqual(permission, "ask")

    def test_select_sql_allowed(self):
        """Test SELECT SQL is allowed."""
        permission, _ = check_tool("run_query", '{"query": "SELECT * FROM users"}')
        self.assertEqual(permission, "allow")

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        permission, _ = check_tool("some_tool", "not valid json")
        self.assertEqual(permission, "allow")

    def test_command_field_sql_check(self):
        """Test SQL check in command field."""
        permission, _ = check_tool("execute", '{"command": "DROP DATABASE test"}')
        self.assertEqual(permission, "ask")


class TestAnalyzeToolResult(unittest.TestCase):
    """Test tool result analysis."""

    def test_clean_result(self):
        """Test analysis of clean result."""
        result = analyze_tool_result("read_file", '{"content": "Hello World"}')
        self.assertEqual(result["sensitive_data_hints"], [])
        self.assertFalse(result["is_error"])

    def test_password_detection(self):
        """Test detection of password in result."""
        result = analyze_tool_result("get_config", '{"password": "secret123"}')
        self.assertIn("password reference", result["sensitive_data_hints"])

    def test_api_key_detection(self):
        """Test detection of API key in result."""
        result = analyze_tool_result("get_env", '{"api_key": "sk-12345"}')
        self.assertIn("API key reference", result["sensitive_data_hints"])

    def test_error_detection(self):
        """Test detection of error in result."""
        result = analyze_tool_result("run_command", '{"error": "Command failed"}')
        self.assertTrue(result["is_error"])

    def test_status_error_detection(self):
        """Test detection of error status."""
        result = analyze_tool_result("api_call", '{"status": "failed", "message": "timeout"}')
        self.assertTrue(result["is_error"])

    def test_result_size(self):
        """Test result size calculation."""
        json_str = '{"data": "test"}'
        result = analyze_tool_result("some_tool", json_str)
        self.assertEqual(result["result_size"], len(json_str))


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        from enkryptai_agent_security.hooks.providers.copilot import _core
        _core.metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        from enkryptai_agent_security.hooks.providers.copilot import _core
        _core.metrics.record_call("test_hook", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        from enkryptai_agent_security.hooks.providers.copilot import _core
        _core.metrics.record_call("test_hook", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        from enkryptai_agent_security.hooks.providers.copilot import _core
        _core.metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        _core.metrics.record_call("test_hook", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        from enkryptai_agent_security.hooks.providers.copilot import _core
        _core.metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        reset_metrics("test_hook")
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 0)


class TestPrecompiledPatterns(unittest.TestCase):
    """Test pre-compiled regex patterns."""

    def test_patterns_are_compiled(self):
        """Test patterns are pre-compiled."""
        for pattern, name in SENSITIVE_PATTERNS:
            self.assertIsInstance(pattern, re.Pattern)

    def test_patterns_match_correctly(self):
        """Test patterns match expected text."""
        test_cases = [
            ("password=secret", "password reference"),
            ("api_key=xyz", "API key reference"),
            ("secret=hidden", "secret reference"),
            ("token=abc123", "token reference"),
            ("credential=admin", "credential reference"),
        ]
        for text, expected_name in test_cases:
            found = False
            for pattern, name in SENSITIVE_PATTERNS:
                if pattern.search(text) and name == expected_name:
                    found = True
                    break
            self.assertTrue(found, f"Pattern for '{expected_name}' should match '{text}'")


class TestBaseHookClass(unittest.TestCase):
    """Test base hook class functionality."""

    def test_base_hook_is_enabled_property(self):
        """Test is_enabled property."""

        class TestHook(BaseHook):
            def __init__(self):
                super().__init__("nonExistentHook", {})

            def process(self, data):
                return {}

        hook = TestHook()
        # Hook should not be enabled since it doesn't exist in config
        self.assertFalse(hook.is_enabled)


class TestCopilotSpecificFunctions(unittest.TestCase):
    """Test Copilot-specific functions and configurations."""

    def test_get_source_event_mapping(self):
        """Test Copilot hook name to source event mapping."""
        self.assertEqual(get_source_event("userPromptSubmitted"), "pre-prompt")
        self.assertEqual(get_source_event("preToolUse"), "pre-tool")
        self.assertEqual(get_source_event("postToolUse"), "post-tool")
        self.assertEqual(get_source_event("errorOccurred"), "error")
        # Unknown hook should return itself
        self.assertEqual(get_source_event("unknown"), "unknown")

    def test_log_dir_uses_copilot_path(self):
        """Test that LOG_DIR uses copilot path."""
        self.assertIn("copilot", str(LOG_DIR))

    def test_check_tool_returns_two_values(self):
        """Test check_tool returns (permission, reason) tuple."""
        permission, reason = check_tool("bash", '{"command": "ls"}')
        self.assertEqual(permission, "allow")
        self.assertIsInstance(reason, str)

    def test_get_timestamp(self):
        """Test get_timestamp returns ISO format."""
        timestamp = get_timestamp()
        self.assertIsInstance(timestamp, str)
        # Should be ISO format (contains T)
        self.assertIn("T", timestamp)


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        """Test reload_config function exists."""
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        """Test flush_logs function exists."""
        self.assertTrue(callable(flush_logs))


if __name__ == "__main__":
    unittest.main()
