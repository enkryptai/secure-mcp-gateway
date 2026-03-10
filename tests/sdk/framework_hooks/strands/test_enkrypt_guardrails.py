#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails module (Strands Agents).
"""
import unittest


from enkryptai_agent_security.sdk.framework_hooks.strands import (
    format_violation_message,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    is_sensitive_tool,
    analyze_content,
    get_metrics,
    reset_metrics,
    get_source_event,
    SENSITIVE_TOOLS,
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


class TestSensitiveToolDetection(unittest.TestCase):
    """Test sensitive tool detection."""

    def test_exact_match(self):
        """Test exact tool name match."""
        if "execute_sql" in SENSITIVE_TOOLS:
            self.assertTrue(is_sensitive_tool("execute_sql"))

    def test_wildcard_match(self):
        """Test wildcard pattern matching."""
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


class TestHookFunctions(unittest.TestCase):
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


class TestStrandsHookProvider(unittest.TestCase):
    """Test the Strands HookProvider implementation."""

    def test_hook_import(self):
        """Test that hook classes can be imported."""
        from enkryptai_agent_security.sdk.framework_hooks.strands_hook import (
            EnkryptGuardrailsHook,
            EnkryptGuardrailsBlockingHook,
            EnkryptGuardrailsAuditHook,
        )
        self.assertIsNotNone(EnkryptGuardrailsHook)
        self.assertIsNotNone(EnkryptGuardrailsBlockingHook)
        self.assertIsNotNone(EnkryptGuardrailsAuditHook)

    def test_hook_initialization(self):
        """Test hook initialization with default parameters."""
        from enkryptai_agent_security.sdk.framework_hooks.strands_hook import EnkryptGuardrailsHook
        hook = EnkryptGuardrailsHook()
        self.assertTrue(hook.block_on_violation)
        self.assertFalse(hook.log_only_mode)
        self.assertTrue(hook.check_user_messages)
        self.assertTrue(hook.check_assistant_messages)

    def test_blocking_hook_settings(self):
        """Test blocking hook has correct settings."""
        from enkryptai_agent_security.sdk.framework_hooks.strands_hook import EnkryptGuardrailsBlockingHook
        hook = EnkryptGuardrailsBlockingHook()
        self.assertTrue(hook.block_on_violation)
        self.assertFalse(hook.log_only_mode)

    def test_audit_hook_settings(self):
        """Test audit hook has correct settings."""
        from enkryptai_agent_security.sdk.framework_hooks.strands_hook import EnkryptGuardrailsAuditHook
        hook = EnkryptGuardrailsAuditHook()
        self.assertFalse(hook.block_on_violation)
        self.assertTrue(hook.log_only_mode)

    def test_custom_sensitive_tools(self):
        """Test custom sensitive tools list."""
        from enkryptai_agent_security.sdk.framework_hooks.strands_hook import EnkryptGuardrailsHook
        custom_tools = ["my_dangerous_tool", "another_tool"]
        hook = EnkryptGuardrailsHook(sensitive_tools=custom_tools)
        self.assertIn("my_dangerous_tool", hook._sensitive_tools)
        self.assertIn("another_tool", hook._sensitive_tools)


class TestStrandsHookEvents(unittest.TestCase):
    """Test Strands hook event handling."""

    def test_get_source_event_mapping(self):
        """Test source event mapping for API headers."""
        self.assertEqual(get_source_event("MessageAdded"), "message-added")
        self.assertEqual(get_source_event("BeforeToolCall"), "pre-tool")
        self.assertEqual(get_source_event("AfterToolCall"), "post-tool")
        self.assertEqual(get_source_event("AfterModelCall"), "post-model")


if __name__ == "__main__":
    unittest.main()
