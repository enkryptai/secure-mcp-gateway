#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Cursor hooks).
"""
import unittest


from enkryptai_agent_security.hooks.providers.cursor import (
    format_violation_message,
    check_mcp_tool,
    analyze_mcp_result,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    get_source_event,
    get_hook_metrics,
    get_metrics,
    reset_metrics,
    is_sensitive_tool,
    reload_config,
    flush_logs,
    metrics,
    BaseHook,
    InputGuardrailHook,
    OutputAuditHook,
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


class TestCheckMcpTool(unittest.TestCase):
    """Test MCP tool checking logic."""

    def test_safe_tool_allowed(self):
        """Test that safe tools are allowed."""
        permission, user_msg, agent_msg = check_mcp_tool("read_file", '{"path": "/tmp/test.txt"}')
        self.assertEqual(permission, "allow")
        self.assertEqual(user_msg, "")
        self.assertEqual(agent_msg, "")

    def test_dangerous_sql_requires_confirmation(self):
        """Test that dangerous SQL operations require confirmation."""
        permission, user_msg, agent_msg = check_mcp_tool("run_query", '{"query": "DROP TABLE users"}')
        self.assertEqual(permission, "ask")
        self.assertIn("SQL", user_msg)

    def test_delete_sql_requires_confirmation(self):
        """Test DELETE SQL requires confirmation."""
        permission, _, _ = check_mcp_tool("execute_query", '{"sql": "DELETE FROM users WHERE id = 1"}')
        self.assertEqual(permission, "ask")

    def test_update_sql_requires_confirmation(self):
        """Test UPDATE SQL requires confirmation."""
        permission, _, _ = check_mcp_tool("db_query", '{"query": "UPDATE users SET name = \'test\'"}')
        self.assertEqual(permission, "ask")

    def test_select_sql_allowed(self):
        """Test SELECT SQL is allowed."""
        permission, _, _ = check_mcp_tool("run_query", '{"query": "SELECT * FROM users"}')
        self.assertEqual(permission, "allow")

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        permission, _, _ = check_mcp_tool("some_tool", "not valid json")
        self.assertEqual(permission, "allow")


class TestAnalyzeMcpResult(unittest.TestCase):
    """Test MCP result analysis."""

    def test_clean_result(self):
        """Test analysis of clean result."""
        result = analyze_mcp_result("read_file", '{"content": "Hello World"}')
        self.assertEqual(result["sensitive_data_hints"], [])
        self.assertFalse(result["is_error"])

    def test_password_detection(self):
        """Test detection of password in result."""
        result = analyze_mcp_result("get_config", '{"password": "secret123"}')
        self.assertIn("password reference", result["sensitive_data_hints"])

    def test_api_key_detection(self):
        """Test detection of API key in result."""
        result = analyze_mcp_result("get_env", '{"api_key": "sk-12345"}')
        self.assertIn("API key reference", result["sensitive_data_hints"])

    def test_error_detection(self):
        """Test detection of error in result."""
        result = analyze_mcp_result("run_command", '{"error": "Command failed"}')
        self.assertTrue(result["is_error"])

    def test_status_error_detection(self):
        """Test detection of error status."""
        result = analyze_mcp_result("api_call", '{"status": "failed", "message": "timeout"}')
        self.assertTrue(result["is_error"])

    def test_result_size(self):
        """Test result size calculation."""
        json_str = '{"data": "test"}'
        result = analyze_mcp_result("some_tool", json_str)
        self.assertEqual(result["result_size"], len(json_str))


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        metrics.record_call("test_hook", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        metrics.record_call("test_hook", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        reset_metrics("test_hook")
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 0)


class TestBaseHookClass(unittest.TestCase):
    """Test base hook class functionality."""

    def test_input_guardrail_hook_defaults(self):
        """Test InputGuardrailHook default output."""

        class TestHook(InputGuardrailHook):
            def __init__(self):
                super().__init__("testHook", "prompt")

        hook = TestHook()
        self.assertEqual(hook.default_output, {"continue": True})
        self.assertEqual(hook.text_field, "prompt")

    def test_output_audit_hook_defaults(self):
        """Test OutputAuditHook default output."""

        class TestHook(OutputAuditHook):
            def __init__(self):
                super().__init__("testHook", "text")

        hook = TestHook()
        self.assertEqual(hook.default_output, {})
        self.assertEqual(hook.text_field, "text")

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


class TestSourceEvent(unittest.TestCase):
    """Test source event mapping."""

    def test_get_source_event(self):
        """Test get_source_event maps hook names correctly."""
        self.assertEqual(get_source_event("beforeSubmitPrompt"), "pre-prompt")
        self.assertEqual(get_source_event("beforeMCPExecution"), "pre-tool")
        self.assertEqual(get_source_event("afterMCPExecution"), "post-tool")
        self.assertEqual(get_source_event("afterAgentResponse"), "post-response")
        # Unknown hook should return itself
        self.assertEqual(get_source_event("unknown"), "unknown")


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
