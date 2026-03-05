#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Claude version).

Tests the consolidated provider API after hooks/gateway/sdk unification.
Old dataclass tests (EnkryptApiConfig, HookPolicy, Violation, GuardrailsConfig)
and parse_enkrypt_response tests have been moved to tests/guardrails/ and
tests/config/ respectively, since those are now shared modules.
"""
import json
import unittest
from pathlib import Path

from enkryptai_agent_security.hooks.providers.claude import (
    format_violation_message,
    check_tool,
    analyze_tool_result,
    metrics,
    get_hook_metrics,
    reset_metrics,
    reload_config,
    flush_logs,
    BaseHook,
    InputGuardrailHook,
    OutputAuditHook,
    LOG_DIR,
)
from enkryptai_agent_security.hooks.core import (
    BufferedLogger,
    SENSITIVE_PATTERNS,
)
from enkryptai_agent_security.telemetry.redaction import mask_sensitive_headers


class TestFormatViolationMessage(unittest.TestCase):
    """Test formatting of violation messages."""

    def test_empty_violations(self):
        result = format_violation_message([])
        self.assertEqual(result, "")

    def test_pii_message(self):
        violations = [{"detector": "pii", "pii_found": {"email": ["test@example.com"]}}]
        result = format_violation_message(violations)
        self.assertIn("PII/Secrets detected", result)
        self.assertIn("email", result)

    def test_injection_message(self):
        violations = [{"detector": "injection_attack", "attack_score": 0.95}]
        result = format_violation_message(violations)
        self.assertIn("Injection attack", result)
        self.assertIn("95.0%", result)

    def test_toxicity_message(self):
        violations = [{"detector": "toxicity", "toxicity_types": ["insult"], "score": 0.8}]
        result = format_violation_message(violations)
        self.assertIn("Toxic content", result)
        self.assertIn("insult", result)

    def test_policy_violation_message(self):
        violations = [{
            "detector": "policy_violation",
            "violating_policy": "No competitor mentions",
            "explanation": "Content mentions competitor products"
        }]
        result = format_violation_message(violations)
        self.assertIn("Policy violation", result)
        self.assertIn("No competitor mentions", result)


class TestCheckTool(unittest.TestCase):
    """Test tool checking logic (Claude version)."""

    def test_safe_tool_allowed(self):
        decision, reason = check_tool("Read", {"file_path": "/tmp/test.txt"})
        self.assertEqual(decision, "allow")
        self.assertEqual(reason, "")

    def test_bash_dangerous_command_flagged(self):
        decision, reason = check_tool("Bash", {"command": "sudo rm -rf /"})
        self.assertEqual(decision, "ask")
        self.assertIn("dangerous", reason.lower())

    def test_write_to_env_file_flagged(self):
        decision, reason = check_tool("Write", {"file_path": "/app/.env"})
        self.assertEqual(decision, "ask")
        self.assertIn(".env", reason)

    def test_normal_tool_allowed(self):
        decision, _ = check_tool("Read", {"file_path": "/tmp/test.txt"})
        self.assertEqual(decision, "allow")

    def test_invalid_input_type(self):
        decision, _ = check_tool("some_tool", "not a dict")
        self.assertEqual(decision, "allow")


class TestAnalyzeToolResult(unittest.TestCase):
    """Test tool result analysis (Claude version)."""

    def test_clean_result(self):
        result = analyze_tool_result("Read", {"content": "Hello World"})
        self.assertEqual(result["sensitive_data_hints"], [])
        self.assertFalse(result["is_error"])

    def test_password_detection(self):
        result = analyze_tool_result("Bash", {"password": "secret123"})
        self.assertIn("password reference", result["sensitive_data_hints"])

    def test_api_key_detection(self):
        result = analyze_tool_result("Read", {"api_key": "sk-12345"})
        self.assertIn("API key reference", result["sensitive_data_hints"])

    def test_error_detection(self):
        result = analyze_tool_result("Bash", {"error": "Command failed"})
        self.assertTrue(result["is_error"])

    def test_status_error_detection(self):
        result = analyze_tool_result("WebFetch", {"status": "failed", "message": "timeout"})
        self.assertTrue(result["is_error"])

    def test_result_size(self):
        tool_response = {"data": "test"}
        result = analyze_tool_result("Read", tool_response)
        self.assertEqual(result["result_size"], len(json.dumps(tool_response)))


class TestMaskSensitiveHeaders(unittest.TestCase):
    """Test header masking functionality (now in shared telemetry.redaction)."""

    def test_mask_authorization(self):
        headers = {"Authorization": "Bearer token123456"}
        masked = mask_sensitive_headers(headers)
        self.assertNotEqual(masked["Authorization"], "Bearer token123456")
        self.assertIn("****", masked["Authorization"])

    def test_preserve_non_sensitive(self):
        headers = {"Content-Type": "application/json", "Accept": "*/*"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["Content-Type"], "application/json")
        self.assertEqual(masked["Accept"], "*/*")

    def test_empty_headers(self):
        self.assertEqual(mask_sensitive_headers({}), {})


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        reset_metrics()

    def test_record_call(self):
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        metrics.record_call("test_hook", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        metrics.record_call("test_hook", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        reset_metrics("test_hook")
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 0)


class TestBaseHookClass(unittest.TestCase):
    """Test base hook class functionality."""

    def test_input_guardrail_hook_defaults(self):
        class TestHook(InputGuardrailHook):
            def __init__(self):
                super().__init__("testHook", "prompt")

        hook = TestHook()
        self.assertEqual(hook.default_output, {})
        self.assertEqual(hook.text_field, "prompt")

    def test_output_audit_hook_defaults(self):
        class TestHook(OutputAuditHook):
            def __init__(self):
                super().__init__("testHook", "text")

        hook = TestHook()
        self.assertEqual(hook.default_output, {})
        self.assertEqual(hook.text_field, "text")

    def test_base_hook_is_enabled_property(self):
        class TestHook(BaseHook):
            def __init__(self):
                super().__init__("nonExistentHook", {})

            def process(self, data):
                return {}

        hook = TestHook()
        self.assertFalse(hook.is_enabled)


class TestBufferedLogger(unittest.TestCase):
    """Test buffered logging functionality."""

    def test_buffered_logger_creation(self):
        logger = BufferedLogger(buffer_size=5, flush_interval=1.0)
        self.assertIsNotNone(logger)

    def test_buffered_logger_write_and_flush(self):
        import tempfile

        logger = BufferedLogger(buffer_size=2, flush_interval=10.0)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)

        try:
            logger.write(temp_path, '{"test": 1}\n')
            logger.flush_all()

            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"test": 1}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestPrecompiledPatterns(unittest.TestCase):
    """Test pre-compiled regex patterns (now in shared hooks.core)."""

    def test_patterns_are_compiled(self):
        import re
        for pattern, name in SENSITIVE_PATTERNS:
            self.assertIsInstance(pattern, re.Pattern)

    def test_patterns_match_correctly(self):
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


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        self.assertTrue(callable(flush_logs))


class TestClaudeSpecificFeatures(unittest.TestCase):
    """Test Claude specific features."""

    def test_log_dir_uses_claude_path(self):
        log_path_str = str(LOG_DIR)
        self.assertIn("claude", log_path_str.lower())

    def test_check_tool_function_exists(self):
        self.assertTrue(callable(check_tool))

    def test_analyze_tool_result_function_exists(self):
        self.assertTrue(callable(analyze_tool_result))


if __name__ == "__main__":
    unittest.main()
