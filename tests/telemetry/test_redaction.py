"""Tests for telemetry/redaction.py — sensitive data masking."""

from enkryptai_agent_security.telemetry.redaction import (
    PayloadPolicy,
    mask_key_value,
    mask_sensitive_data,
    mask_sensitive_env_vars,
    mask_sensitive_headers,
    sanitize_attributes,
)


class TestMaskKeyValue:
    def test_short_value(self):
        assert mask_key_value("abc") == "****"
        assert mask_key_value("ab") == "****"
        assert mask_key_value("") == "****"

    def test_long_value(self):
        assert mask_key_value("abcdef") == "ab****ef"

    def test_exact_four_chars(self):
        assert mask_key_value("abcd") == "****"

    def test_five_chars(self):
        assert mask_key_value("abcde") == "ab****de"


class TestMaskSensitiveHeaders:
    def test_masks_authorization(self):
        headers = {"Authorization": "Bearer sk-12345678"}
        result = mask_sensitive_headers(headers)
        assert result["Authorization"] != "Bearer sk-12345678"
        assert "****" in result["Authorization"]

    def test_preserves_nonsensitive(self):
        headers = {"Content-Type": "application/json", "Accept": "text/html"}
        result = mask_sensitive_headers(headers)
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "text/html"

    def test_empty_headers(self):
        assert mask_sensitive_headers({}) == {}

    def test_case_insensitive_matching(self):
        headers = {"AUTHORIZATION": "secret123"}
        result = mask_sensitive_headers(headers)
        assert "****" in result["AUTHORIZATION"]

    def test_cookie_masked(self):
        headers = {"Cookie": "session=abc123def456"}
        result = mask_sensitive_headers(headers)
        assert "****" in result["Cookie"]


class TestMaskSensitiveEnvVars:
    def test_masks_api_key(self):
        env = {"OPENAI_API_KEY": "sk-1234567890abcdef"}
        result = mask_sensitive_env_vars(env)
        assert "****" in result["OPENAI_API_KEY"]

    def test_masks_token(self):
        env = {"ACCESS_TOKEN": "my-secret-token"}
        result = mask_sensitive_env_vars(env)
        assert "****" in result["ACCESS_TOKEN"]

    def test_preserves_nonsensitive(self):
        env = {"HOME": "/home/user", "PATH": "/usr/bin"}
        result = mask_sensitive_env_vars(env)
        assert result["HOME"] == "/home/user"
        assert result["PATH"] == "/usr/bin"

    def test_empty(self):
        assert mask_sensitive_env_vars({}) == {}

    def test_password_masked(self):
        env = {"DB_PASSWORD": "hunter2"}
        result = mask_sensitive_env_vars(env)
        assert "****" in result["DB_PASSWORD"]


class TestMaskSensitiveData:
    def test_masks_known_keys(self):
        data = {"api_key": "sk-abcdef123456", "name": "test"}
        result = mask_sensitive_data(data)
        assert "****" in result["api_key"]
        assert result["name"] == "test"

    def test_nested_dict(self):
        data = {"config": {"password": "secret123", "host": "localhost"}}
        result = mask_sensitive_data(data)
        assert "****" in result["config"]["password"]
        assert result["config"]["host"] == "localhost"

    def test_empty(self):
        assert mask_sensitive_data({}) == {}

    def test_custom_sensitive_keys(self):
        data = {"custom_field": "sensitive_value", "safe_field": "ok"}
        result = mask_sensitive_data(data, sensitive_keys=["custom_field"])
        assert "****" in result["custom_field"]
        assert result["safe_field"] == "ok"


class TestPayloadPolicy:
    def test_defaults(self):
        p = PayloadPolicy()
        assert p.max_str_len == 4096
        assert p.max_attr_count == 64
        assert len(p.redact_patterns) > 0
        assert len(p.redact_keys) > 0


class TestSanitizeAttributes:
    def test_redacts_sensitive_keys(self):
        attrs = {"password": "secret", "name": "test"}
        result = sanitize_attributes(attrs)
        assert result["password"] == "[REDACTED]"
        assert result["name"] == "test"

    def test_truncates_long_strings(self):
        policy = PayloadPolicy(max_str_len=10)
        attrs = {"data": "a" * 100}
        result = sanitize_attributes(attrs, policy)
        assert len(result["data"]) < 100
        assert "truncated" in result["data"]

    def test_max_attr_count(self):
        policy = PayloadPolicy(max_attr_count=3)
        attrs = {f"key_{i}": f"value_{i}" for i in range(10)}
        result = sanitize_attributes(attrs, policy)
        assert len(result) == 3

    def test_drop_keys(self):
        policy = PayloadPolicy(drop_keys={"internal"})
        attrs = {"internal": "hidden", "public": "visible"}
        result = sanitize_attributes(attrs, policy)
        assert "internal" not in result
        assert result["public"] == "visible"

    def test_redacts_patterns_in_strings(self):
        attrs = {"log": "user password=hunter2 connected"}
        result = sanitize_attributes(attrs)
        assert "hunter2" not in result["log"]
        assert "[REDACTED]" in result["log"]

    def test_nested_dict_sanitized(self):
        attrs = {"config": {"token": "secret123"}}
        result = sanitize_attributes(attrs)
        assert result["config"]["token"] == "[REDACTED]"

    def test_list_values_sanitized(self):
        policy = PayloadPolicy(max_str_len=5)
        attrs = {"items": ["short", "a" * 100]}
        result = sanitize_attributes(attrs, policy)
        assert isinstance(result["items"], list)
        assert len(result["items"]) == 2

    def test_default_policy_used(self):
        attrs = {"api_key": "secret"}
        result = sanitize_attributes(attrs)
        assert result["api_key"] == "[REDACTED]"


class TestRegexPatterns:
    """Test all 6 default regex patterns in _DEFAULT_PATTERNS."""

    def test_credit_card_dashes(self):
        attrs = {"msg": "card 4111-1111-1111-1111 here"}
        result = sanitize_attributes(attrs)
        assert "4111-1111-1111-1111" not in result["msg"]
        assert "[REDACTED]" in result["msg"]

    def test_credit_card_no_dashes(self):
        attrs = {"msg": "card 4111111111111111 here"}
        result = sanitize_attributes(attrs)
        assert "4111111111111111" not in result["msg"]

    def test_credit_card_spaces(self):
        attrs = {"msg": "card 4111 1111 1111 1111 here"}
        result = sanitize_attributes(attrs)
        assert "4111 1111 1111 1111" not in result["msg"]

    def test_ssn_pattern(self):
        attrs = {"msg": "ssn 123-45-6789 here"}
        result = sanitize_attributes(attrs)
        assert "123-45-6789" not in result["msg"]

    def test_bearer_token(self):
        attrs = {"msg": "Bearer eyJhbGciOiJIUzI1NiJ9"}
        result = sanitize_attributes(attrs)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result["msg"]

    def test_password_equals(self):
        attrs = {"msg": "password=hunter2"}
        result = sanitize_attributes(attrs)
        assert "hunter2" not in result["msg"]

    def test_api_key_colon(self):
        attrs = {"msg": "api_key: sk-abc123"}
        result = sanitize_attributes(attrs)
        assert "sk-abc123" not in result["msg"]

    def test_nonmatching_passes_through(self):
        attrs = {"msg": "hello world 12345"}
        result = sanitize_attributes(attrs)
        assert result["msg"] == "hello world 12345"


class TestAllowKeys:
    """Test PayloadPolicy.allow_keys whitelist behavior."""

    def test_allow_keys_whitelist(self):
        policy = PayloadPolicy(allow_keys={"name"})
        attrs = {"name": "ok", "other": "dropped"}
        result = sanitize_attributes(attrs, policy)
        assert "name" in result
        assert "other" not in result

    def test_empty_allow_keys_passes_all(self):
        policy = PayloadPolicy()
        attrs = {"name": "ok", "other": "also_ok"}
        result = sanitize_attributes(attrs, policy)
        assert "name" in result
        assert "other" in result

    def test_allow_keys_plus_redact_keys(self):
        policy = PayloadPolicy(allow_keys={"password", "name"})
        attrs = {"password": "secret", "name": "test"}
        result = sanitize_attributes(attrs, policy)
        assert result["password"] == "[REDACTED]"
        assert result["name"] == "test"


class TestEdgeCases:
    """Edge cases for sanitize_attributes value handling."""

    def test_none_value_preserved(self):
        attrs = {"key": None}
        result = sanitize_attributes(attrs)
        assert result["key"] is None

    def test_int_value_preserved(self):
        attrs = {"count": 42}
        result = sanitize_attributes(attrs)
        assert result["count"] == 42

    def test_bool_value_preserved(self):
        attrs = {"flag": True}
        result = sanitize_attributes(attrs)
        assert result["flag"] is True

    def test_empty_string_preserved(self):
        attrs = {"data": ""}
        result = sanitize_attributes(attrs)
        assert result["data"] == ""
