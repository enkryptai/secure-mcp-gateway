"""Tests for encoding detection — ported from Sentry patterns."""

from enkrypt_agent_sdk.encoding import decode, decode_if_encoded, is_encoded


class TestIsEncoded:
    def test_base64(self):
        assert is_encoded("SGVsbG8gV29ybGQh") == "base64"

    def test_hex_via_decode(self):
        # Pure hex strings are a subset of base64, so is_encoded detects base64 first
        # (same behavior as Sentry). The hex decode function works correctly when called directly.
        assert is_encoded("48656c6c6f0a") in ("base64", "hex")

    def test_url_encoding(self):
        assert is_encoded("Hello%20World%21") == "url"

    def test_plain_text_not_encoded(self):
        assert is_encoded("Hello World!") is None

    def test_empty_string(self):
        assert is_encoded("") is None

    def test_short_string_not_base64(self):
        assert is_encoded("Hi") is None


class TestDecode:
    def test_base64_decode(self):
        assert decode("base64", "SGVsbG8gV29ybGQh") == "Hello World!"

    def test_hex_decode(self):
        assert decode("hex", "48656c6c6f0a") == "Hello\n"

    def test_url_decode(self):
        assert decode("url", "Hello%20World%21") == "Hello World!"

    def test_unknown_format(self):
        assert decode("unknown", "test") is None


class TestDecodeIfEncoded:
    def test_base64_roundtrip(self):
        decoded, fmt = decode_if_encoded("SGVsbG8gV29ybGQh")
        assert fmt == "base64"
        assert decoded == "Hello World!"

    def test_plain_text_passthrough(self):
        decoded, fmt = decode_if_encoded("Just plain text")
        assert fmt is None
        assert decoded == "Just plain text"
