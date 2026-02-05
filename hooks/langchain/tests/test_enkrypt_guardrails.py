#!/usr/bin/env python
"""
Unit tests for Enkrypt AI Guardrails LangChain integration.

Run with: pytest tests/test_enkrypt_guardrails.py -v
"""
import json
import pytest
import sys
import os

# Add parent directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enkrypt_guardrails import (
    parse_enkrypt_response,
    format_violation_message,
    is_sensitive_tool,
    analyze_content,
    extract_prompts_text,
    extract_messages_text,
    extract_chain_inputs_text,
    extract_chain_outputs_text,
    extract_retriever_query_text,
    extract_retriever_documents_text,
    get_hook_policy,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    get_source_event,
)


# ============================================================================
# TEST: RESPONSE PARSING
# ============================================================================

class TestParseEnkryptResponse:
    """Tests for parse_enkrypt_response function."""

    def test_empty_response(self):
        """Test parsing empty response."""
        result = {"summary": {}, "details": {}}
        violations = parse_enkrypt_response(result, ["injection_attack"])
        assert violations == []

    def test_injection_attack_detected(self):
        """Test parsing injection attack detection."""
        result = {
            "summary": {"injection_attack": 1},
            "details": {"injection_attack": {"attack": 0.95}}
        }
        violations = parse_enkrypt_response(result, ["injection_attack"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "injection_attack"
        assert violations[0]["blocked"] is True
        assert violations[0]["attack_score"] == 0.95

    def test_injection_not_in_block_list(self):
        """Test injection not blocked when not in block list."""
        result = {
            "summary": {"injection_attack": 1},
            "details": {"injection_attack": {"attack": 0.95}}
        }
        violations = parse_enkrypt_response(result, ["pii"])  # injection not in list
        assert violations == []

    def test_pii_detected(self):
        """Test parsing PII detection."""
        result = {
            "summary": {"pii": 1},
            "details": {"pii": {"pii": {"email": ["test@example.com"], "ssn": ["123-45-6789"]}}}
        }
        violations = parse_enkrypt_response(result, ["pii"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "pii"
        assert "email" in violations[0]["entities"]
        assert "ssn" in violations[0]["entities"]

    def test_toxicity_detected(self):
        """Test parsing toxicity detection."""
        result = {
            "summary": {"toxicity": ["hate", "threat"]},
            "details": {"toxicity": {"toxicity": 0.85}}
        }
        violations = parse_enkrypt_response(result, ["toxicity"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "toxicity"
        assert violations[0]["toxicity_types"] == ["hate", "threat"]
        assert violations[0]["score"] == 0.85

    def test_nsfw_detected(self):
        """Test parsing NSFW detection."""
        result = {
            "summary": {"nsfw": 1},
            "details": {"nsfw": {"nsfw": 0.92}}
        }
        violations = parse_enkrypt_response(result, ["nsfw"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "nsfw"
        assert violations[0]["nsfw_score"] == 0.92

    def test_keyword_detected(self):
        """Test parsing keyword detection."""
        result = {
            "summary": {"keyword_detected": 1},
            "details": {"keyword_detector": {"detected_keywords": ["banned_word"]}}
        }
        violations = parse_enkrypt_response(result, ["keyword_detector"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "keyword_detector"
        assert "banned_word" in violations[0]["matched_keywords"]

    def test_policy_violation_detected(self):
        """Test parsing policy violation detection."""
        result = {
            "summary": {"policy_violation": 1},
            "details": {"policy_violation": {
                "violating_policy": "No financial advice",
                "explanation": "User requested stock tips"
            }}
        }
        violations = parse_enkrypt_response(result, ["policy_violation"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "policy_violation"
        assert violations[0]["violating_policy"] == "No financial advice"

    def test_multiple_violations(self):
        """Test parsing multiple violations."""
        result = {
            "summary": {
                "injection_attack": 1,
                "pii": 1,
                "toxicity": ["insult"]
            },
            "details": {
                "injection_attack": {"attack": 0.9},
                "pii": {"pii": {"email": ["test@test.com"]}},
                "toxicity": {"toxicity": 0.7}
            }
        }
        violations = parse_enkrypt_response(result, ["injection_attack", "pii", "toxicity"])
        assert len(violations) == 3
        detectors = [v["detector"] for v in violations]
        assert "injection_attack" in detectors
        assert "pii" in detectors
        assert "toxicity" in detectors

    def test_on_topic_off_topic(self):
        """Test on_topic=0 means off-topic (violation)."""
        result = {
            "summary": {"on_topic": 0},
            "details": {}
        }
        violations = parse_enkrypt_response(result, ["topic_detector"])
        assert len(violations) == 1
        assert violations[0]["detector"] == "topic_detector"

    def test_on_topic_on_topic(self):
        """Test on_topic=1 means on-topic (no violation)."""
        result = {
            "summary": {"on_topic": 1},
            "details": {}
        }
        violations = parse_enkrypt_response(result, ["topic_detector"])
        assert violations == []


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
        message = format_violation_message(violations, "on_llm_start")
        assert "Injection attack" in message
        assert "95.0%" in message

    def test_pii_message(self):
        """Test formatting PII message."""
        violations = [{"detector": "pii", "entities": ["email", "ssn"]}]
        message = format_violation_message(violations, "on_llm_start")
        assert "PII" in message

    def test_toxicity_message(self):
        """Test formatting toxicity message."""
        violations = [{"detector": "toxicity", "toxicity_types": ["hate"], "score": 0.8}]
        message = format_violation_message(violations, "on_llm_start")
        assert "Toxic" in message
        assert "hate" in message


# ============================================================================
# TEST: SENSITIVE TOOL DETECTION
# ============================================================================

class TestIsSensitiveTool:
    """Tests for is_sensitive_tool function."""

    def test_exact_match(self):
        """Test exact tool name match."""
        # Note: depends on SENSITIVE_TOOLS config
        # These tests assume default config
        assert is_sensitive_tool("execute_sql") is True
        assert is_sensitive_tool("bash") is True
        assert is_sensitive_tool("python_repl") is True

    def test_wildcard_prefix_match(self):
        """Test wildcard prefix matching."""
        # shell_* should match shell_exec, shell_command, etc.
        assert is_sensitive_tool("shell_exec") is True
        assert is_sensitive_tool("shell_command") is True
        assert is_sensitive_tool("delete_file") is True
        assert is_sensitive_tool("delete_user") is True

    def test_safe_tool(self):
        """Test safe tool is not matched."""
        assert is_sensitive_tool("search") is False
        assert is_sensitive_tool("calculator") is False
        assert is_sensitive_tool("get_weather") is False

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        assert is_sensitive_tool("BASH") is True
        assert is_sensitive_tool("Execute_SQL") is True


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
# TEST: SOURCE EVENT MAPPING
# ============================================================================

class TestGetSourceEvent:
    """Tests for get_source_event function."""

    def test_known_hooks(self):
        """Test known hook mappings."""
        assert get_source_event("on_llm_start") == "llm-start"
        assert get_source_event("on_llm_end") == "llm-end"
        assert get_source_event("on_tool_start") == "tool-start"
        assert get_source_event("on_agent_action") == "agent-action"
        assert get_source_event("on_retriever_start") == "retriever-start"

    def test_unknown_hook(self):
        """Test unknown hook falls back to formatted name."""
        assert get_source_event("custom_hook") == "custom-hook"


# ============================================================================
# TEST: POLICY FUNCTIONS
# ============================================================================

class TestPolicyFunctions:
    """Tests for policy-related functions."""

    def test_get_hook_policy_default(self):
        """Test getting default hook policy."""
        policy = get_hook_policy("nonexistent_hook")
        assert policy == {}

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
        assert "nonexistent_hook" in name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
