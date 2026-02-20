"""Tests for payload sanitization."""

from enkrypt_agent_sdk.redaction import PayloadPolicy, sanitize_attributes


class TestSanitizeAttributes:
    def test_redact_keys(self):
        policy = PayloadPolicy()
        result = sanitize_attributes({"password": "secret123", "name": "Alice"}, policy)
        assert result["password"] == "[REDACTED]"
        assert result["name"] == "Alice"

    def test_redact_patterns(self):
        policy = PayloadPolicy()
        result = sanitize_attributes(
            {"message": "my api_key=sk-12345 is here"}, policy,
        )
        assert "sk-12345" not in result["message"]
        assert "[REDACTED]" in result["message"]

    def test_truncate_long_strings(self):
        policy = PayloadPolicy(max_str_len=10)
        result = sanitize_attributes({"text": "A" * 100}, policy)
        assert "truncated" in result["text"]
        assert len(result["text"]) < 100

    def test_max_attr_count(self):
        policy = PayloadPolicy(max_attr_count=3)
        attrs = {f"key_{i}": f"val_{i}" for i in range(10)}
        result = sanitize_attributes(attrs, policy)
        assert len(result) == 3

    def test_drop_keys(self):
        policy = PayloadPolicy(drop_keys={"internal"})
        result = sanitize_attributes({"internal": "x", "public": "y"}, policy)
        assert "internal" not in result
        assert result["public"] == "y"

    def test_nested_dict(self):
        policy = PayloadPolicy()
        result = sanitize_attributes(
            {"outer": {"password": "secret", "name": "Bob"}}, policy,
        )
        assert result["outer"]["password"] == "[REDACTED]"
        assert result["outer"]["name"] == "Bob"

    def test_credit_card_pattern(self):
        policy = PayloadPolicy()
        result = sanitize_attributes(
            {"data": "Card: 4111-1111-1111-1111"}, policy,
        )
        assert "4111" not in result["data"]
