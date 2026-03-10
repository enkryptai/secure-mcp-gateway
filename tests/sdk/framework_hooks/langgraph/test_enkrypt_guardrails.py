#!/usr/bin/env python
"""
Unit Tests for Enkrypt AI Guardrails LangGraph Integration

Run with: pytest tests/sdk/framework_hooks/langgraph/test_enkrypt_guardrails.py -v
"""
import pytest


class TestFormatViolationMessage:
    """Tests for format_violation_message function."""

    def test_injection_attack_message(self):
        """Test formatting injection attack message."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import format_violation_message

        violations = [
            {"detector": "injection_attack", "attack_score": 0.95}
        ]

        message = format_violation_message(violations)

        assert "Injection attack" in message
        assert "95" in message or "0.95" in message

    def test_pii_message(self):
        """Test formatting PII message."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import format_violation_message

        violations = [
            {"detector": "pii", "entities": ["email", "phone"], "pii_found": {"email": ["test@test.com"]}}
        ]

        message = format_violation_message(violations)

        assert "PII" in message or "pii" in message.lower()

    def test_empty_violations(self):
        """Test empty violations list."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import format_violation_message

        violations = []

        message = format_violation_message(violations)

        assert message == ""


class TestIsSensitiveTool:
    """Tests for is_sensitive_tool function."""

    def test_exact_match(self):
        """Test exact tool name match."""
        import enkryptai_agent_security.sdk.framework_hooks.langgraph as mod
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import is_sensitive_tool

        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["execute_sql", "bash"]

        assert is_sensitive_tool("execute_sql") is True
        assert is_sensitive_tool("bash") is True
        assert is_sensitive_tool("get_weather") is False

        mod._core.sensitive_tools = original

    def test_wildcard_match(self):
        """Test wildcard pattern matching."""
        import enkryptai_agent_security.sdk.framework_hooks.langgraph as mod
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import is_sensitive_tool

        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["shell_*", "execute_*"]

        assert is_sensitive_tool("shell_execute") is True
        assert is_sensitive_tool("execute_sql") is True

        mod._core.sensitive_tools = original

    def test_safe_tool(self):
        """Test non-sensitive tool."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import is_sensitive_tool

        # A clearly safe tool name
        assert is_sensitive_tool("get_weather_forecast_safe") is False


class TestCheckWithEnkryptApi:
    """Tests for check_with_enkrypt_api function."""

    def test_disabled_hook_skipped(self):
        """Test that disabled hooks are skipped."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import check_with_enkrypt_api

        should_block, violations, result = check_with_enkrypt_api(
            "test text",
            hook_name="nonexistent_disabled_hook"
        )

        assert isinstance(should_block, bool)
        assert isinstance(violations, list)
        assert isinstance(result, dict)


class TestExtractMessagesText:
    """Tests for extract_messages_text function."""

    def test_string_content(self):
        """Test extracting text from string content messages."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import extract_messages_text

        messages = [
            {"content": "Hello"},
            {"content": "World"},
        ]

        text = extract_messages_text(messages)

        assert "Hello" in text
        assert "World" in text

    def test_list_content(self):
        """Test extracting text from list content messages."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import extract_messages_text

        messages = [
            {"content": [{"text": "First"}, {"text": "Second"}]},
        ]

        text = extract_messages_text(messages)

        assert "First" in text
        assert "Second" in text

    def test_empty_messages(self):
        """Test empty messages list."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import extract_messages_text

        messages = []

        text = extract_messages_text(messages)

        assert text == ""


class TestHookFunctions:
    """Tests for hook functions."""

    def test_pre_model_hook_empty_state(self):
        """Test pre_model_hook with empty state."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import enkrypt_pre_model_hook

        state = {"messages": []}

        result = enkrypt_pre_model_hook(state)

        # Should return None when no messages
        assert result is None

    def test_post_model_hook_empty_state(self):
        """Test post_model_hook with empty state."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import enkrypt_post_model_hook

        state = {"messages": []}

        result = enkrypt_post_model_hook(state)

        # Should return None when no messages
        assert result is None

    def test_create_pre_model_hook_factory(self):
        """Test pre_model_hook factory function."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import create_pre_model_hook

        hook = create_pre_model_hook(block_on_violation=True)

        assert callable(hook)

        # Test with empty state
        result = hook({"messages": []})
        assert result is None

    def test_create_post_model_hook_factory(self):
        """Test post_model_hook factory function."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import create_post_model_hook

        hook = create_post_model_hook(block_on_violation=True)

        assert callable(hook)

        # Test with empty state
        result = hook({"messages": []})
        assert result is None


class TestMetrics:
    """Tests for metrics functions."""

    def test_get_metrics(self):
        """Test get_metrics returns dict."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import get_metrics

        metrics = get_metrics()

        assert isinstance(metrics, dict)

    def test_reset_metrics(self):
        """Test reset_metrics works."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph import reset_metrics, get_metrics

        # Reset and check it doesn't error
        reset_metrics()
        metrics = get_metrics()

        assert isinstance(metrics, dict)


class TestGuardrailsState:
    """Tests for GuardrailsState class."""

    def test_add_violation(self):
        """Test adding a violation."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import _guardrails_state

        _guardrails_state.clear_violations()
        _guardrails_state.add_violation({"detector": "test"})

        violations = _guardrails_state.get_violations()

        assert len(violations) == 1
        assert violations[0]["detector"] == "test"

        # Cleanup
        _guardrails_state.clear_violations()

    def test_clear_violations(self):
        """Test clearing violations."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import _guardrails_state

        _guardrails_state.add_violation({"detector": "test"})
        _guardrails_state.clear_violations()

        violations = _guardrails_state.get_violations()

        assert len(violations) == 0

    def test_increment_event(self):
        """Test event counter increment."""
        from enkryptai_agent_security.sdk.framework_hooks.langgraph_hook import _guardrails_state

        _guardrails_state.reset()
        first = _guardrails_state.increment_event()
        second = _guardrails_state.increment_event()

        assert second == first + 1

        # Cleanup
        _guardrails_state.reset()


class TestImports:
    """Tests to verify module imports work correctly."""

    def test_import_enkrypt_guardrails(self):
        """Test importing enkrypt_guardrails module."""
        import enkryptai_agent_security.sdk.framework_hooks.langgraph as enkrypt_guardrails

        assert hasattr(enkrypt_guardrails, 'check_with_enkrypt_api')
        assert hasattr(enkrypt_guardrails, 'is_sensitive_tool')
        assert hasattr(enkrypt_guardrails, 'format_violation_message')

    def test_import_enkrypt_guardrails_hook(self):
        """Test importing enkrypt_guardrails_hook module."""
        import enkryptai_agent_security.sdk.framework_hooks.langgraph_hook as enkrypt_guardrails_hook

        assert hasattr(enkrypt_guardrails_hook, 'enkrypt_pre_model_hook')
        assert hasattr(enkrypt_guardrails_hook, 'enkrypt_post_model_hook')
        assert hasattr(enkrypt_guardrails_hook, 'create_pre_model_hook')
        assert hasattr(enkrypt_guardrails_hook, 'create_post_model_hook')
        assert hasattr(enkrypt_guardrails_hook, 'create_protected_agent')
        assert hasattr(enkrypt_guardrails_hook, 'wrap_tools')
        assert hasattr(enkrypt_guardrails_hook, 'EnkryptToolWrapper')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
