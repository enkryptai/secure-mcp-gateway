#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Kiro Hooks).
"""
import re
import unittest


from enkryptai_agent_security.hooks.providers.kiro import (
    format_violation_message,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    is_sensitive_file,
    analyze_file_content,
    flush_logs,
    get_metrics,
    reset_metrics,
    reload_config,
    get_source_event,
    get_timestamp,
    SENSITIVE_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
    KIRO_HOOK_NAMES,
    BaseHook,
    InputGuardrailHook,
    OutputAuditHook,
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


class TestSensitiveFileDetection(unittest.TestCase):
    """Test sensitive file detection."""

    def test_env_file(self):
        """Test .env file is detected as sensitive."""
        self.assertTrue(is_sensitive_file(".env"))
        self.assertTrue(is_sensitive_file("path/to/.env"))
        self.assertTrue(is_sensitive_file(".env.local"))
        self.assertTrue(is_sensitive_file(".env.production"))

    def test_key_files(self):
        """Test key files are detected as sensitive."""
        self.assertTrue(is_sensitive_file("private.key"))
        self.assertTrue(is_sensitive_file("server.pem"))
        self.assertTrue(is_sensitive_file("id_rsa"))
        self.assertTrue(is_sensitive_file("~/.ssh/id_rsa"))

    def test_secrets_files(self):
        """Test secrets files are detected as sensitive."""
        self.assertTrue(is_sensitive_file("secrets.json"))
        self.assertTrue(is_sensitive_file("credentials.yaml"))

    def test_regular_files(self):
        """Test regular files are not detected as sensitive."""
        self.assertFalse(is_sensitive_file("main.py"))
        self.assertFalse(is_sensitive_file("index.js"))
        self.assertFalse(is_sensitive_file("README.md"))


class TestAnalyzeFileContent(unittest.TestCase):
    """Test file content analysis."""

    def test_clean_content(self):
        """Test analysis of clean content."""
        result = analyze_file_content("main.py", "def hello():\n    print('hello')")
        self.assertEqual(result["sensitive_data_hints"], [])
        self.assertFalse(result["is_sensitive_file"])

    def test_password_detection(self):
        """Test detection of password in content."""
        result = analyze_file_content("config.py", "PASSWORD = 'secret123'")
        self.assertIn("password reference", result["sensitive_data_hints"])

    def test_api_key_detection(self):
        """Test detection of API key in content."""
        result = analyze_file_content("config.py", "API_KEY = 'sk-12345'")
        self.assertIn("API key reference", result["sensitive_data_hints"])

    def test_token_detection(self):
        """Test detection of token in content."""
        result = analyze_file_content("auth.py", "access_token = 'abc123'")
        self.assertIn("token reference", result["sensitive_data_hints"])

    def test_sensitive_file_flag(self):
        """Test is_sensitive_file flag in analysis."""
        result = analyze_file_content(".env", "DEBUG=true")
        self.assertTrue(result["is_sensitive_file"])


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        reset_metrics()

    def test_get_metrics_returns_dict(self):
        """Test get_metrics returns a dict."""
        m = get_metrics()
        self.assertIsInstance(m, dict)

    def test_get_metrics_for_hook(self):
        """Test get_metrics for a specific hook."""
        m = get_metrics("test_hook")
        self.assertIsInstance(m, dict)
        self.assertEqual(m["total_calls"], 0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        reset_metrics("test_hook")
        m = get_metrics("test_hook")
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

    def test_input_guardrail_hook_defaults(self):
        """Test InputGuardrailHook default settings."""
        class TestHook(InputGuardrailHook):
            def __init__(self):
                super().__init__("TestHook", "USER_PROMPT")

        hook = TestHook()
        self.assertEqual(hook.text_field, "USER_PROMPT")
        self.assertEqual(hook.hook_name, "TestHook")

    def test_output_audit_hook_defaults(self):
        """Test OutputAuditHook default settings."""
        class TestHook(OutputAuditHook):
            def __init__(self):
                super().__init__("TestHook")

        hook = TestHook()
        self.assertEqual(hook.hook_name, "TestHook")

    def test_base_hook_is_enabled_property(self):
        """Test is_enabled property."""
        class TestHook(BaseHook):
            def __init__(self):
                super().__init__("nonExistentHook")

            def process(self, data):
                return 0, "", ""

        hook = TestHook()
        # Hook should not be enabled since it doesn't exist in config
        self.assertFalse(hook.is_enabled)


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        """Test reload_config function exists."""
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        """Test flush_logs function exists."""
        self.assertTrue(callable(flush_logs))


class TestKiroSpecificFeatures(unittest.TestCase):
    """Test Kiro-specific features."""

    def test_sensitive_file_patterns_loaded(self):
        """Test sensitive file patterns are loaded from config."""
        self.assertIsInstance(SENSITIVE_FILE_PATTERNS, list)

    def test_kiro_hook_names_defined(self):
        """Test Kiro hook names are defined."""
        kiro_hooks = ["PromptSubmit", "AgentStop", "FileSave", "FileCreate", "FileDelete", "Manual"]
        for hook in kiro_hooks:
            self.assertIn(hook, KIRO_HOOK_NAMES)

    def test_get_source_event(self):
        """Test source event mapping."""
        self.assertEqual(get_source_event("PromptSubmit"), "pre-prompt")
        self.assertEqual(get_source_event("AgentStop"), "post-response")
        self.assertEqual(get_source_event("FileSave"), "file-save")

    def test_get_timestamp(self):
        """Test get_timestamp returns ISO format."""
        ts = get_timestamp()
        self.assertIsInstance(ts, str)
        self.assertIn("T", ts)


class TestHookEnabledFunctions(unittest.TestCase):
    """Test hook enabled/block list/guardrail name functions."""

    def test_is_hook_enabled_default(self):
        """Test hook enabled check with default."""
        self.assertFalse(is_hook_enabled("nonexistent_hook"))

    def test_get_hook_block_list_default(self):
        """Test getting default block list."""
        block_list = get_hook_block_list("nonexistent_hook")
        self.assertEqual(block_list, [])

    def test_get_hook_guardrail_name_default(self):
        """Test getting default guardrail name."""
        name = get_hook_guardrail_name("nonexistent_hook")
        self.assertIsInstance(name, str)


if __name__ == "__main__":
    unittest.main()
