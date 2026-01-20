#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Strands Agents).
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
    is_sensitive_tool,
    analyze_content,
    EnkryptApiConfig,
    HookPolicy,
    HookMetrics,
    validate_config,
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

    def test_hook_metrics_defaults(self):
        """Test HookMetrics has correct defaults."""
        metrics = HookMetrics()
        self.assertEqual(metrics.total_calls, 0)
        self.assertEqual(metrics.blocked_calls, 0)
        self.assertEqual(metrics.allowed_calls, 0)
        self.assertEqual(metrics.errors, 0)
        self.assertEqual(metrics.avg_latency_ms, 0.0)


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

    def test_detector_not_in_block_list(self):
        """Test that detections not in block list are ignored."""
        response = {
            "summary": {"pii": 1, "toxicity": ["insult"]},
            "details": {}
        }
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


class TestSensitiveToolDetection(unittest.TestCase):
    """Test sensitive tool detection."""

    def test_exact_match(self):
        """Test exact tool name match."""
        # This depends on config, but we can test the function
        from enkrypt_guardrails import SENSITIVE_TOOLS
        if "execute_sql" in SENSITIVE_TOOLS:
            self.assertTrue(is_sensitive_tool("execute_sql"))

    def test_wildcard_match(self):
        """Test wildcard pattern matching."""
        from enkrypt_guardrails import SENSITIVE_TOOLS
        # Check if any wildcard patterns exist
        wildcards = [t for t in SENSITIVE_TOOLS if t.endswith("*")]
        if wildcards:
            prefix = wildcards[0][:-1]
            self.assertTrue(is_sensitive_tool(f"{prefix}something"))

    def test_safe_tool(self):
        """Test that safe tools are not flagged."""
        self.assertFalse(is_sensitive_tool("calculator"))
        self.assertFalse(is_sensitive_tool("get_weather"))


class TestAnalyzeContent(unittest.TestCase):
    """Test content analysis."""

    def test_clean_content(self):
        """Test analysis of clean content."""
        result = analyze_content("Hello, how are you today?")
        self.assertEqual(result["sensitive_data_hints"], [])

    def test_password_detection(self):
        """Test detection of password in content."""
        result = analyze_content("The password is secret123")
        self.assertIn("password reference", result["sensitive_data_hints"])

    def test_api_key_detection(self):
        """Test detection of API key in content."""
        result = analyze_content("Use API_KEY=abc123 for auth")
        self.assertIn("API key reference", result["sensitive_data_hints"])

    def test_token_detection(self):
        """Test detection of token in content."""
        result = analyze_content("Bearer token: abc123xyz")
        hints = result["sensitive_data_hints"]
        self.assertTrue(any("token" in h for h in hints))


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
        headers = {"Content-Type": "application/json"}
        masked = mask_sensitive_headers(headers)
        self.assertEqual(masked["Content-Type"], "application/json")

    def test_empty_headers(self):
        """Test handling of empty headers."""
        self.assertEqual(mask_sensitive_headers({}), {})
        self.assertIsNone(mask_sensitive_headers(None))


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation."""

    def test_valid_config(self):
        """Test validation of valid config."""
        config = {
            "enkrypt_api": {
                "url": "https://api.example.com",
                "timeout": 15,
                "ssl_verify": True
            },
            "MessageAdded": {
                "enabled": True,
                "block": ["pii"]
            }
        }
        errors = validate_config(config)
        self.assertEqual(errors, [])

    def test_invalid_url(self):
        """Test validation of invalid URL."""
        config = {"enkrypt_api": {"url": "not-a-url"}}
        errors = validate_config(config)
        self.assertTrue(any("url" in e for e in errors))

    def test_invalid_timeout(self):
        """Test validation of invalid timeout."""
        config = {"enkrypt_api": {"timeout": -5}}
        errors = validate_config(config)
        self.assertTrue(any("timeout" in e for e in errors))

    def test_invalid_hook_enabled(self):
        """Test validation of invalid enabled field."""
        config = {"MessageAdded": {"enabled": "yes"}}
        errors = validate_config(config)
        self.assertTrue(any("enabled" in e for e in errors))


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        from enkrypt_guardrails import reset_metrics
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        from enkrypt_guardrails import metrics, get_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        m = get_metrics("test_hook")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        from enkrypt_guardrails import metrics, get_metrics
        metrics.record_call("test_hook", blocked=True, latency_ms=100.0)
        m = get_metrics("test_hook")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        from enkrypt_guardrails import metrics, get_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0, error=True)
        m = get_metrics("test_hook")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        from enkrypt_guardrails import metrics, get_metrics
        metrics.record_call("test_hook", blocked=False, latency_ms=100.0)
        metrics.record_call("test_hook", blocked=False, latency_ms=200.0)
        m = get_metrics("test_hook")
        self.assertEqual(m["avg_latency_ms"], 150.0)


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
        ]
        for text, expected_name in test_cases:
            found = False
            for pattern, name in SENSITIVE_PATTERNS:
                if pattern.search(text) and name == expected_name:
                    found = True
                    break
            self.assertTrue(found, f"Pattern for '{expected_name}' should match '{text}'")


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
            logger.write(temp_path, '{"test": 1}\n')
            logger.flush_all()

            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"test": 1}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestStrandsHookProvider(unittest.TestCase):
    """Test the Strands HookProvider implementation."""

    def test_hook_import(self):
        """Test that hook classes can be imported."""
        from enkrypt_guardrails_hook import (
            EnkryptGuardrailsHook,
            EnkryptGuardrailsBlockingHook,
            EnkryptGuardrailsAuditHook,
        )
        self.assertIsNotNone(EnkryptGuardrailsHook)
        self.assertIsNotNone(EnkryptGuardrailsBlockingHook)
        self.assertIsNotNone(EnkryptGuardrailsAuditHook)

    def test_hook_initialization(self):
        """Test hook initialization with default parameters."""
        from enkrypt_guardrails_hook import EnkryptGuardrailsHook
        hook = EnkryptGuardrailsHook()
        self.assertTrue(hook.block_on_violation)
        self.assertFalse(hook.log_only_mode)
        self.assertTrue(hook.check_user_messages)
        self.assertTrue(hook.check_assistant_messages)

    def test_blocking_hook_settings(self):
        """Test blocking hook has correct settings."""
        from enkrypt_guardrails_hook import EnkryptGuardrailsBlockingHook
        hook = EnkryptGuardrailsBlockingHook()
        self.assertTrue(hook.block_on_violation)
        self.assertFalse(hook.log_only_mode)

    def test_audit_hook_settings(self):
        """Test audit hook has correct settings."""
        from enkrypt_guardrails_hook import EnkryptGuardrailsAuditHook
        hook = EnkryptGuardrailsAuditHook()
        self.assertFalse(hook.block_on_violation)
        self.assertTrue(hook.log_only_mode)

    def test_custom_sensitive_tools(self):
        """Test custom sensitive tools list."""
        from enkrypt_guardrails_hook import EnkryptGuardrailsHook
        custom_tools = ["my_dangerous_tool", "another_tool"]
        hook = EnkryptGuardrailsHook(sensitive_tools=custom_tools)
        self.assertIn("my_dangerous_tool", hook._sensitive_tools)
        self.assertIn("another_tool", hook._sensitive_tools)


class TestStrandsHookEvents(unittest.TestCase):
    """Test Strands hook event handling (without Strands installed)."""

    def test_hook_policies_for_strands(self):
        """Test Strands hook policies are defined."""
        from enkrypt_guardrails import HOOK_POLICIES
        strands_hooks = [
            "MessageAdded", "BeforeInvocation", "AfterInvocation",
            "BeforeModelCall", "AfterModelCall",
            "BeforeToolCall", "AfterToolCall"
        ]
        for hook in strands_hooks:
            self.assertIn(hook, HOOK_POLICIES)

    def test_get_source_event_mapping(self):
        """Test source event mapping for API headers."""
        from enkrypt_guardrails import get_source_event
        self.assertEqual(get_source_event("MessageAdded"), "message-added")
        self.assertEqual(get_source_event("BeforeToolCall"), "pre-tool")
        self.assertEqual(get_source_event("AfterToolCall"), "post-tool")
        self.assertEqual(get_source_event("AfterModelCall"), "post-model")


if __name__ == "__main__":
    unittest.main()
