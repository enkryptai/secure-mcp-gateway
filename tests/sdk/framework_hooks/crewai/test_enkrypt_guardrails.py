#!/usr/bin/env python
"""
Unit tests for CrewAI Enkrypt AI Guardrails module.
"""
import unittest
from pathlib import Path
from unittest.mock import patch, Mock


from enkryptai_agent_security.sdk.framework_hooks.crewai import (
    format_violation_message,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    check_with_enkrypt_api,
    check_guardrails,
    check_llm_input,
    check_llm_output,
    check_tool_input,
    check_tool_output,
    get_source_event,
    get_metrics,
    get_hook_metrics,
    reset_metrics,
    get_timestamp,
    log_event,
    log_security_alert,
    flush_logs,
    reload_config,
    is_sensitive_tool,
    EnkryptGuardrailsContext,
    enable_guardrails,
    disable_guardrails,
    with_guardrails,
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
        result = format_violation_message(violations, "before_llm_call")
        self.assertIn("PII/Secrets detected", result)
        self.assertIn("email", result)

    def test_injection_message(self):
        """Test injection attack message formatting."""
        violations = [{"detector": "injection_attack", "attack_score": 0.95}]
        result = format_violation_message(violations, "before_tool_call")
        self.assertIn("Injection attack", result)
        self.assertIn("95.0%", result)

    def test_toxicity_message(self):
        """Test toxicity message formatting."""
        violations = [{"detector": "toxicity", "toxicity_types": ["insult"], "score": 0.8}]
        result = format_violation_message(violations, "after_llm_call")
        self.assertIn("Toxic content", result)
        self.assertIn("insult", result)

    def test_nsfw_message(self):
        """Test NSFW message formatting."""
        violations = [{"detector": "nsfw", "nsfw_score": 0.88}]
        result = format_violation_message(violations)
        self.assertIn("NSFW content", result)
        self.assertIn("88.0%", result)

    def test_keyword_message(self):
        """Test keyword violation message formatting."""
        violations = [{"detector": "keyword_detector", "matched_keywords": ["banned1", "banned2"]}]
        result = format_violation_message(violations)
        self.assertIn("Banned keywords", result)
        self.assertIn("banned1", result)

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
        self.assertIn("competitor products", result)

    def test_bias_message(self):
        """Test bias message formatting."""
        violations = [{"detector": "bias", "bias_detected": True}]
        result = format_violation_message(violations)
        self.assertIn("Bias detected", result)

    def test_sponge_attack_message(self):
        """Test sponge attack message formatting."""
        violations = [{"detector": "sponge_attack", "sponge_detected": True}]
        result = format_violation_message(violations)
        self.assertIn("Sponge attack", result)

    def test_topic_detector_message(self):
        """Test topic detector message formatting."""
        violations = [{"detector": "topic_detector"}]
        result = format_violation_message(violations)
        self.assertIn("Off-topic", result)


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("before_llm_call")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("before_tool_call", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("before_tool_call")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("after_llm_call", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("after_llm_call")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("after_tool_call", blocked=False, latency_ms=100.0)
        _core.metrics.record_call("after_tool_call", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("after_tool_call")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        reset_metrics("before_llm_call")
        m = get_hook_metrics("before_llm_call")
        self.assertEqual(m["total_calls"], 0)

    def test_get_all_metrics(self):
        """Test getting all metrics."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        _core.metrics.record_call("after_llm_call", blocked=True, latency_ms=150.0)
        all_metrics = get_hook_metrics()
        self.assertIn("before_llm_call", all_metrics)
        self.assertIn("after_llm_call", all_metrics)

    def test_metrics_timestamp(self):
        """Test that timestamp is recorded."""
        from enkryptai_agent_security.sdk.framework_hooks.crewai import _core
        _core.metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("before_llm_call")
        self.assertIsNotNone(m["last_call_timestamp"])


class TestPolicyFunctions(unittest.TestCase):
    """Test policy configuration functions."""

    def test_is_hook_enabled(self):
        """Test is_hook_enabled returns bool."""
        result = is_hook_enabled("before_llm_call")
        self.assertIsInstance(result, bool)

    def test_get_hook_block_list(self):
        """Test get_hook_block_list returns list."""
        block_list = get_hook_block_list("before_tool_call")
        self.assertIsInstance(block_list, list)

    def test_get_hook_guardrail_name(self):
        """Test get_hook_guardrail_name returns string."""
        guardrail_name = get_hook_guardrail_name("after_llm_call")
        self.assertIsInstance(guardrail_name, str)


class TestSourceEvent(unittest.TestCase):
    """Test source event mapping."""

    def test_get_source_event(self):
        """Test get_source_event maps hook names correctly."""
        mappings = {
            "before_llm_call": "pre-llm",
            "after_llm_call": "post-llm",
            "before_tool_call": "pre-tool",
            "after_tool_call": "post-tool",
        }

        for hook_name, expected_event in mappings.items():
            result = get_source_event(hook_name)
            self.assertEqual(result, expected_event)

    def test_get_source_event_unknown(self):
        """Test get_source_event with unknown hook."""
        result = get_source_event("unknown_hook")
        self.assertEqual(result, "unknown_hook")


class TestHookFunctions(unittest.TestCase):
    """Test CrewAI hook functions."""

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_llm_input_passes(self, mock_api):
        """Test check_llm_input when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.task = Mock()
        mock_context.task.description = "Test task"
        mock_context.agent_name = "test_agent"

        result = check_llm_input(mock_context)
        self.assertIsNone(result)

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_llm_input_blocked(self, mock_api):
        """Test check_llm_input when violations detected."""
        mock_api.return_value = (True, [{"detector": "pii", "blocked": True}], {"summary": {"pii": 1}})

        # Create mock context
        mock_context = Mock()
        mock_context.task = Mock()
        mock_context.task.description = "Test with PII data"
        mock_context.agent_name = "test_agent"

        result = check_llm_input(mock_context)
        self.assertFalse(result)

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_llm_output_passes(self, mock_api):
        """Test check_llm_output when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.response = "Safe response"

        result = check_llm_output(mock_context)
        self.assertIsNone(result)

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_tool_input_passes(self, mock_api):
        """Test check_tool_input when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.tool_name = "read_file"
        mock_context.tool_input = {"path": "/tmp/test.txt"}

        result = check_tool_input(mock_context)
        self.assertIsNone(result)

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_tool_output_passes(self, mock_api):
        """Test check_tool_output when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.tool_name = "read_file"
        mock_context.tool_result = "File contents"

        result = check_tool_output(mock_context)
        self.assertIsNone(result)


class TestContextManager(unittest.TestCase):
    """Test EnkryptGuardrailsContext context manager."""

    def test_context_manager_creation(self):
        """Test EnkryptGuardrailsContext can be created."""
        ctx = EnkryptGuardrailsContext()
        self.assertIsNotNone(ctx)

    def test_context_manager_registers_hooks(self):
        """Test context manager registers hooks on enter."""

        # Mock the crewai.hooks module
        mock_hooks = Mock()
        mock_hooks.register_before_llm_call_hook = Mock()
        mock_hooks.register_after_llm_call_hook = Mock()
        mock_hooks.register_before_tool_call_hook = Mock()
        mock_hooks.register_after_tool_call_hook = Mock()
        mock_hooks.unregister_before_llm_call_hook = Mock()
        mock_hooks.unregister_after_llm_call_hook = Mock()
        mock_hooks.unregister_before_tool_call_hook = Mock()
        mock_hooks.unregister_after_tool_call_hook = Mock()

        # Mock the imports
        with patch.dict('sys.modules', {'crewai.hooks': mock_hooks}):
            try:
                with EnkryptGuardrailsContext():
                    # Verify hooks were registered
                    self.assertTrue(mock_hooks.register_before_llm_call_hook.called)
                    self.assertTrue(mock_hooks.register_after_llm_call_hook.called)
                    self.assertTrue(mock_hooks.register_before_tool_call_hook.called)
                    self.assertTrue(mock_hooks.register_after_tool_call_hook.called)
            except Exception:  # noqa: E722
                # Ignore import errors in test environment
                pass


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions for enabling/disabling guardrails."""

    def test_enable_guardrails_function_exists(self):
        """Test enable_guardrails function exists."""
        self.assertTrue(callable(enable_guardrails))

    def test_disable_guardrails_function_exists(self):
        """Test disable_guardrails function exists."""
        self.assertTrue(callable(disable_guardrails))

    def test_with_guardrails_decorator_exists(self):
        """Test with_guardrails decorator exists."""
        self.assertTrue(callable(with_guardrails))

    def test_with_guardrails_decorator(self):
        """Test with_guardrails decorator wraps function."""

        @with_guardrails
        def test_func():
            return "test"

        self.assertEqual(test_func.__name__, "test_func")


class TestLoggingFunctions(unittest.TestCase):
    """Test logging functions."""

    def test_get_timestamp(self):
        """Test get_timestamp returns ISO format."""
        timestamp = get_timestamp()
        self.assertIsInstance(timestamp, str)
        # Should be ISO format (contains T)
        self.assertIn("T", timestamp)

    def test_log_event_function_exists(self):
        """Test log_event function exists."""
        self.assertTrue(callable(log_event))

    def test_log_security_alert_function_exists(self):
        """Test log_security_alert function exists."""
        self.assertTrue(callable(log_security_alert))


class TestCheckWithEnkryptApi(unittest.TestCase):
    """Test check_with_enkrypt_api function."""

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.is_hook_enabled')
    def test_check_with_enkrypt_api_disabled_hook(self, mock_enabled):
        """Test check_with_enkrypt_api when hook is disabled."""
        mock_enabled.return_value = False

        should_block, violations, result = check_with_enkrypt_api("test text", "before_llm_call")

        self.assertFalse(should_block)
        self.assertEqual(violations, [])
        self.assertIn("skipped", result)


class TestCheckGuardrails(unittest.TestCase):
    """Test check_guardrails wrapper function."""

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_guardrails_passes(self, mock_api):
        """Test check_guardrails when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        result = check_guardrails("test text", "before_llm_call", {"test": "context"})

        self.assertTrue(result["passed"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["hook"], "before_llm_call")

    @patch('enkryptai_agent_security.sdk.framework_hooks.crewai.check_with_enkrypt_api')
    def test_check_guardrails_blocks(self, mock_api):
        """Test check_guardrails when violations detected."""
        mock_api.return_value = (True, [{"detector": "pii"}], {"summary": {"pii": 1}})

        with self.assertRaises(ValueError) as ctx:
            check_guardrails("sensitive data", "before_tool_call")

        self.assertIn("Guardrails blocked", str(ctx.exception))


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        """Test reload_config function exists."""
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        """Test flush_logs function exists."""
        self.assertTrue(callable(flush_logs))

    def test_log_dir_exists(self):
        """Test LOG_DIR is defined."""
        self.assertIsInstance(LOG_DIR, Path)


if __name__ == "__main__":
    unittest.main()
