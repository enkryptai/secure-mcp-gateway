#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Kiro Hooks).
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from enkrypt_guardrails import (
    parse_enkrypt_response,
    format_violation_message,
    mask_sensitive_headers,
    get_hook_policy,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_policy_name,
    is_sensitive_file,
    analyze_file_content,
    EnkryptApiConfig,
    HookPolicy,
    Violation,
    GuardrailsConfig,
)


class TestDataclasses(unittest.TestCase):
    """Test dataclass definitions."""

    def test_enkrypt_api_config_defaults(self):
        """Test EnkryptApiConfig has correct defaults."""
        config = EnkryptApiConfig()
        self.assertEqual(config.url, "https://api.enkryptai.com/guardrails/policy/detect")
        self.assertEqual(config.api_key, "")
        self.assertTrue(config.ssl_verify)
        self.assertEqual(config.timeout, 15)
        self.assertTrue(config.fail_silently)

    def test_hook_policy_defaults(self):
        """Test HookPolicy has correct defaults."""
        policy = HookPolicy()
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.policy_name, "")
        self.assertEqual(policy.block, [])

    def test_violation_creation(self):
        """Test Violation dataclass creation."""
        violation = Violation(detector="pii", details={"entities": ["email"]})
        self.assertEqual(violation.detector, "pii")
        self.assertTrue(violation.detected)
        self.assertTrue(violation.blocked)
        self.assertEqual(violation.details, {"entities": ["email"]})

    def test_guardrails_config_defaults(self):
        """Test GuardrailsConfig has correct defaults."""
        config = GuardrailsConfig()
        self.assertIsInstance(config.enkrypt_api, EnkryptApiConfig)
        self.assertIsInstance(config.prompt_submit, HookPolicy)
        self.assertEqual(config.sensitive_file_patterns, [])


class TestParseEnkryptResponse(unittest.TestCase):
    """Test parsing of Enkrypt API responses."""

    def test_empty_response(self):
        """Test parsing empty response."""
        result = parse_enkrypt_response({}, ["pii"])
        self.assertEqual(result, [])

    def test_no_violations(self):
        """Test parsing response with no violations."""
        response = {
            "summary": {
                "pii": 0,
                "toxicity": [],
                "nsfw": 0,
            },
            "details": {}
        }
        result = parse_enkrypt_response(response, ["pii", "toxicity", "nsfw"])
        self.assertEqual(result, [])

    def test_pii_violation(self):
        """Test parsing PII violation."""
        response = {
            "summary": {"pii": 1},
            "details": {
                "pii": {
                    "pii": {"email": ["test@example.com"]}
                }
            }
        }
        result = parse_enkrypt_response(response, ["pii"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "pii")
        self.assertTrue(result[0]["blocked"])

    def test_toxicity_violation(self):
        """Test parsing toxicity violation."""
        response = {
            "summary": {"toxicity": ["insult", "threat"]},
            "details": {
                "toxicity": {"toxicity": 0.85}
            }
        }
        result = parse_enkrypt_response(response, ["toxicity"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "toxicity")
        self.assertEqual(result[0]["toxicity_types"], ["insult", "threat"])

    def test_injection_attack_violation(self):
        """Test parsing injection attack violation."""
        response = {
            "summary": {"injection_attack": 1},
            "details": {
                "injection_attack": {"attack": 0.95}
            }
        }
        result = parse_enkrypt_response(response, ["injection_attack"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "injection_attack")
        self.assertEqual(result[0]["attack_score"], 0.95)

    def test_on_topic_violation(self):
        """Test parsing off-topic detection (on_topic=0 means violation)."""
        response = {
            "summary": {"on_topic": 0},
            "details": {}
        }
        result = parse_enkrypt_response(response, ["topic_detector"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "topic_detector")

    def test_on_topic_no_violation(self):
        """Test on_topic=1 means no violation."""
        response = {
            "summary": {"on_topic": 1},
            "details": {}
        }
        result = parse_enkrypt_response(response, ["topic_detector"])
        self.assertEqual(result, [])

    def test_detector_not_in_block_list(self):
        """Test that detections not in block list are ignored."""
        response = {
            "summary": {"pii": 1, "toxicity": ["insult"]},
            "details": {}
        }
        # Only block pii, not toxicity
        result = parse_enkrypt_response(response, ["pii"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "pii")


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


class TestMaskSensitiveHeaders(unittest.TestCase):
    """Test header masking functionality."""

    def test_mask_apikey(self):
        """Test masking of apikey header."""
        headers = {"apikey": "sk-1234567890abcdef"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["apikey"], "****cdef")

    def test_mask_authorization(self):
        """Test masking of Authorization header."""
        headers = {"Authorization": "Bearer token123456"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["Authorization"], "****3456")

    def test_preserve_non_sensitive(self):
        """Test that non-sensitive headers are preserved."""
        headers = {"Content-Type": "application/json", "Accept": "*/*"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["Content-Type"], "application/json")
        self.assertEqual(masked["Accept"], "*/*")

    def test_short_value_masked(self):
        """Test masking of short values."""
        headers = {"apikey": "abc"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["apikey"], "****")

    def test_empty_headers(self):
        """Test handling of empty headers."""
        self.assertEqual(mask_sensitive_headers({}), {})
        self.assertIsNone(mask_sensitive_headers(None))

    def test_mixed_headers(self):
        """Test masking of mixed headers."""
        headers = {
            "Content-Type": "application/json",
            "apikey": "secret-api-key-value",
            "X-Request-ID": "12345",
            "Authorization": "Bearer mytoken123"
        }
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["Content-Type"], "application/json")
        self.assertEqual(masked["X-Request-ID"], "12345")
        self.assertEqual(masked["apikey"], "****alue")
        self.assertEqual(masked["Authorization"], "****n123")


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        from enkrypt_guardrails import reset_metrics
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("test_hook", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        metrics.record_call("test_hook", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        from enkrypt_guardrails import metrics, get_hook_metrics, reset_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        reset_metrics("test_hook")
        m = get_hook_metrics("test_hook")
        self.assertEqual(m["total_calls"], 0)


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation."""

    def test_valid_config(self):
        """Test validation of valid config."""
        from enkrypt_guardrails import validate_config
        config = {
            "enkrypt_api": {
                "url": "https://api.example.com",
                "timeout": 15,
                "ssl_verify": True
            },
            "PromptSubmit": {
                "enabled": True,
                "block": ["pii"]
            }
        }
        errors = validate_config(config)
        self.assertEqual(errors, [])

    def test_invalid_url(self):
        """Test validation of invalid URL."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"url": "not-a-url"}}
        errors = validate_config(config)
        self.assertTrue(any("url" in e for e in errors))

    def test_invalid_timeout(self):
        """Test validation of invalid timeout."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"timeout": -5}}
        errors = validate_config(config)
        self.assertTrue(any("timeout" in e for e in errors))

    def test_invalid_ssl_verify(self):
        """Test validation of invalid ssl_verify."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"ssl_verify": "true"}}
        errors = validate_config(config)
        self.assertTrue(any("ssl_verify" in e for e in errors))

    def test_invalid_hook_enabled(self):
        """Test validation of invalid enabled field."""
        from enkrypt_guardrails import validate_config
        config = {"PromptSubmit": {"enabled": "yes"}}
        errors = validate_config(config)
        self.assertTrue(any("enabled" in e for e in errors))

    def test_invalid_block_list(self):
        """Test validation of invalid block list."""
        from enkrypt_guardrails import validate_config
        config = {"PromptSubmit": {"block": "pii"}}
        errors = validate_config(config)
        self.assertTrue(any("block" in e for e in errors))


class TestConnectionPooling(unittest.TestCase):
    """Test connection pooling functionality."""

    def test_session_creation(self):
        """Test HTTP session is created."""
        from enkrypt_guardrails import get_http_session
        session = get_http_session()
        self.assertIsNotNone(session)

    def test_session_has_adapters(self):
        """Test session has HTTP adapters."""
        from enkrypt_guardrails import get_http_session
        session = get_http_session()
        self.assertIn("https://", session.adapters)
        self.assertIn("http://", session.adapters)

    def test_session_is_singleton(self):
        """Test session is reused (singleton)."""
        from enkrypt_guardrails import get_http_session
        session1 = get_http_session()
        session2 = get_http_session()
        self.assertIs(session1, session2)


class TestPrecompiledPatterns(unittest.TestCase):
    """Test pre-compiled regex patterns."""

    def test_patterns_are_compiled(self):
        """Test patterns are pre-compiled."""
        import re
        from enkrypt_guardrails import SENSITIVE_PATTERNS
        for pattern, name in SENSITIVE_PATTERNS:
            self.assertIsInstance(pattern, re.Pattern)

    def test_patterns_match_correctly(self):
        """Test patterns match expected text."""
        from enkrypt_guardrails import SENSITIVE_PATTERNS
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
        from enkrypt_guardrails import InputGuardrailHook

        class TestHook(InputGuardrailHook):
            def __init__(self):
                super().__init__("TestHook", "USER_PROMPT")

        hook = TestHook()
        self.assertEqual(hook.text_field, "USER_PROMPT")
        self.assertEqual(hook.hook_name, "TestHook")

    def test_output_audit_hook_defaults(self):
        """Test OutputAuditHook default settings."""
        from enkrypt_guardrails import OutputAuditHook

        class TestHook(OutputAuditHook):
            def __init__(self):
                super().__init__("TestHook")

        hook = TestHook()
        self.assertEqual(hook.hook_name, "TestHook")

    def test_base_hook_is_enabled_property(self):
        """Test is_enabled property."""
        from enkrypt_guardrails import BaseHook

        class TestHook(BaseHook):
            def __init__(self):
                super().__init__("nonExistentHook")

            def process(self, data):
                return 0, "", ""

        hook = TestHook()
        # Hook should not be enabled since it doesn't exist in config
        self.assertFalse(hook.is_enabled)


class TestBufferedLogger(unittest.TestCase):
    """Test buffered logging functionality."""

    def test_buffered_logger_creation(self):
        """Test BufferedLogger can be created."""
        from enkrypt_guardrails import BufferedLogger
        logger = BufferedLogger(buffer_size=5, flush_interval=1.0)
        self.assertIsNotNone(logger)

    def test_buffered_logger_write_and_flush(self):
        """Test BufferedLogger write and flush."""
        from enkrypt_guardrails import BufferedLogger

        logger = BufferedLogger(buffer_size=2, flush_interval=10.0)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)

        try:
            # Write entries (should buffer, not flush yet)
            logger.write(temp_path, '{"test": 1}\n')

            # Force flush
            logger.flush_all()

            # Check file was written
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"test": 1}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_buffered_logger_auto_flush_on_buffer_full(self):
        """Test BufferedLogger auto-flushes when buffer is full."""
        from enkrypt_guardrails import BufferedLogger

        logger = BufferedLogger(buffer_size=2, flush_interval=100.0)  # Large interval
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)

        try:
            # Write 2 entries (buffer size is 2, so should auto-flush)
            logger.write(temp_path, '{"entry": 1}\n')
            logger.write(temp_path, '{"entry": 2}\n')

            # Check file was written (auto-flushed)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"entry": 1}', content)
            self.assertIn('{"entry": 2}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestLogRetention(unittest.TestCase):
    """Test log retention settings."""

    def test_log_retention_days_default(self):
        """Test LOG_RETENTION_DAYS has default value."""
        from enkrypt_guardrails import LOG_RETENTION_DAYS
        self.assertIsInstance(LOG_RETENTION_DAYS, int)
        self.assertGreater(LOG_RETENTION_DAYS, 0)

    def test_cleanup_old_logs_exists(self):
        """Test cleanup_old_logs function exists."""
        from enkrypt_guardrails import cleanup_old_logs
        self.assertTrue(callable(cleanup_old_logs))


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        """Test reload_config function exists."""
        from enkrypt_guardrails import reload_config
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        """Test flush_logs function exists."""
        from enkrypt_guardrails import flush_logs
        self.assertTrue(callable(flush_logs))


class TestKiroSpecificFeatures(unittest.TestCase):
    """Test Kiro-specific features."""

    def test_sensitive_file_patterns_loaded(self):
        """Test sensitive file patterns are loaded from config."""
        from enkrypt_guardrails import SENSITIVE_FILE_PATTERNS
        self.assertIsInstance(SENSITIVE_FILE_PATTERNS, list)

    def test_hook_policies_for_kiro(self):
        """Test Kiro hook policies are defined."""
        from enkrypt_guardrails import HOOK_POLICIES
        kiro_hooks = ["PromptSubmit", "AgentStop", "FileSave", "FileCreate", "FileDelete", "Manual"]
        for hook in kiro_hooks:
            self.assertIn(hook, HOOK_POLICIES)


if __name__ == "__main__":
    unittest.main()
