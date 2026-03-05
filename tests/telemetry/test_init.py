"""Tests for telemetry/__init__.py — public API surface."""

import enkryptai_agent_security.telemetry as telemetry_mod


class TestPublicAPI:
    def test_all_exports_importable(self):
        for name in telemetry_mod.__all__:
            assert hasattr(telemetry_mod, name), f"{name} in __all__ but not importable"

    def test_init_telemetry_importable(self):
        from enkryptai_agent_security.telemetry import init_telemetry
        assert callable(init_telemetry)

    def test_span_attributes_importable(self):
        from enkryptai_agent_security.telemetry import SpanAttributes
        assert hasattr(SpanAttributes, "GUARDRAIL_NAME")

    def test_sanitize_importable(self):
        from enkryptai_agent_security.telemetry import sanitize_attributes
        assert callable(sanitize_attributes)

    def test_all_list_is_sorted(self):
        assert telemetry_mod.__all__ == sorted(telemetry_mod.__all__), \
            "__all__ should be alphabetically sorted"
