#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails LangChain integration.

Run with: pytest tests/sdk/framework_hooks/langchain/test_enkrypt_guardrails.py -v
"""
import pytest


from enkryptai_agent_security.sdk.framework_hooks.langchain import (
    format_violation_message,
    is_sensitive_tool,
    analyze_content,
    extract_prompts_text,
    extract_messages_text,
    extract_chain_inputs_text,
    extract_chain_outputs_text,
    extract_retriever_query_text,
    extract_retriever_documents_text,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
)


# ============================================================================
# TEST: VIOLATION MESSAGE FORMATTING
# ============================================================================

class TestFormatViolationMessage:
    """Tests for format_violation_message function."""

    def test_empty_violations(self):
        """Test formatting empty violations."""
        message = format_violation_message([])
        assert message == ""

    def test_injection_attack_message(self):
        """Test formatting injection attack message."""
        violations = [{"detector": "injection_attack", "attack_score": 0.95}]
        message = format_violation_message(violations)
        assert "Injection attack" in message
        assert "95.0%" in message

    def test_pii_message(self):
        """Test formatting PII message."""
        violations = [{"detector": "pii", "entities": ["email", "ssn"]}]
        message = format_violation_message(violations)
        assert "PII" in message

    def test_toxicity_message(self):
        """Test formatting toxicity message."""
        violations = [{"detector": "toxicity", "toxicity_types": ["hate"], "score": 0.8}]
        message = format_violation_message(violations)
        assert "Toxic" in message
        assert "hate" in message


# ============================================================================
# TEST: SENSITIVE TOOL DETECTION
# ============================================================================

class TestIsSensitiveTool:
    """Tests for is_sensitive_tool function."""

    def test_exact_match(self):
        """Test exact tool name match."""
        import enkryptai_agent_security.sdk.framework_hooks.langchain as mod
        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["execute_sql", "bash", "python_repl"]

        assert is_sensitive_tool("execute_sql") is True
        assert is_sensitive_tool("bash") is True
        assert is_sensitive_tool("python_repl") is True

        mod._core.sensitive_tools = original

    def test_wildcard_prefix_match(self):
        """Test wildcard prefix matching."""
        import enkryptai_agent_security.sdk.framework_hooks.langchain as mod
        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["shell_*", "delete_*"]

        assert is_sensitive_tool("shell_exec") is True
        assert is_sensitive_tool("shell_command") is True
        assert is_sensitive_tool("delete_file") is True
        assert is_sensitive_tool("delete_user") is True

        mod._core.sensitive_tools = original

    def test_safe_tool(self):
        """Test safe tool is not matched."""
        assert is_sensitive_tool("search") is False
        assert is_sensitive_tool("calculator") is False
        assert is_sensitive_tool("get_weather") is False

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        import enkryptai_agent_security.sdk.framework_hooks.langchain as mod
        original = mod._core.sensitive_tools
        mod._core.sensitive_tools = ["execute_sql", "bash"]

        assert is_sensitive_tool("BASH") is True
        assert is_sensitive_tool("Execute_SQL") is True

        mod._core.sensitive_tools = original


# ============================================================================
# TEST: CONTENT ANALYSIS
# ============================================================================

class TestAnalyzeContent:
    """Tests for analyze_content function."""

    def test_no_sensitive_data(self):
        """Test content with no sensitive data."""
        analysis = analyze_content("Hello, how are you today?")
        assert analysis["sensitive_data_hints"] == []
        assert analysis["content_length"] == 25

    def test_password_detected(self):
        """Test password reference detection."""
        analysis = analyze_content("My password is secret123")
        assert "password reference" in analysis["sensitive_data_hints"]

    def test_api_key_detected(self):
        """Test API key reference detection."""
        analysis = analyze_content("Set the api_key to abc123")
        assert "API key reference" in analysis["sensitive_data_hints"]

    def test_multiple_sensitive_patterns(self):
        """Test multiple sensitive patterns."""
        analysis = analyze_content("password: abc, api_key: xyz, token: 123")
        assert len(analysis["sensitive_data_hints"]) >= 3


# ============================================================================
# TEST: TEXT EXTRACTION
# ============================================================================

class TestExtractPromptsText:
    """Tests for extract_prompts_text function."""

    def test_string_prompts(self):
        """Test extracting from string prompts."""
        prompts = ["Hello", "World"]
        text = extract_prompts_text(prompts)
        assert "Hello" in text
        assert "World" in text

    def test_empty_prompts(self):
        """Test empty prompts."""
        assert extract_prompts_text([]) == ""
        assert extract_prompts_text(None) == ""


class TestExtractMessagesText:
    """Tests for extract_messages_text function."""

    def test_dict_messages(self):
        """Test extracting from dict messages."""
        messages = [
            {"content": "Hello"},
            {"content": "World"}
        ]
        text = extract_messages_text(messages)
        assert "Hello" in text
        assert "World" in text

    def test_empty_messages(self):
        """Test empty messages."""
        assert extract_messages_text([]) == ""


class TestExtractChainInputsText:
    """Tests for extract_chain_inputs_text function."""

    def test_string_inputs(self):
        """Test extracting from string inputs."""
        inputs = {"question": "What is AI?", "context": "Technology"}
        text = extract_chain_inputs_text(inputs)
        assert "What is AI?" in text
        assert "Technology" in text

    def test_empty_inputs(self):
        """Test empty inputs."""
        assert extract_chain_inputs_text({}) == ""


class TestExtractChainOutputsText:
    """Tests for extract_chain_outputs_text function."""

    def test_string_outputs(self):
        """Test extracting from string outputs."""
        outputs = {"answer": "AI is artificial intelligence"}
        text = extract_chain_outputs_text(outputs)
        assert "AI is artificial intelligence" in text


class TestExtractRetrieverQueryText:
    """Tests for extract_retriever_query_text function."""

    def test_string_query(self):
        """Test extracting from string query."""
        text = extract_retriever_query_text("What is machine learning?")
        assert text == "What is machine learning?"


class TestExtractRetrieverDocumentsText:
    """Tests for extract_retriever_documents_text function."""

    def test_dict_documents(self):
        """Test extracting from dict documents."""
        docs = [
            {"page_content": "Document 1 content"},
            {"page_content": "Document 2 content"}
        ]
        text = extract_retriever_documents_text(docs)
        assert "Document 1 content" in text
        assert "Document 2 content" in text

    def test_empty_documents(self):
        """Test empty documents."""
        assert extract_retriever_documents_text([]) == ""


# ============================================================================
# TEST: POLICY FUNCTIONS
# ============================================================================

class TestPolicyFunctions:
    """Tests for policy-related functions."""

    def test_is_hook_enabled_default(self):
        """Test hook enabled check with default."""
        # Unknown hooks should be disabled by default
        assert is_hook_enabled("nonexistent_hook") is False

    def test_get_hook_block_list_default(self):
        """Test getting default block list."""
        block_list = get_hook_block_list("nonexistent_hook")
        assert block_list == []

    def test_get_hook_guardrail_name_default(self):
        """Test getting default guardrail name."""
        name = get_hook_guardrail_name("nonexistent_hook")
        assert isinstance(name, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
