"""Tests for auto_secure initialization (no framework dependencies needed)."""

from enkrypt_agent_sdk import _state
from enkrypt_agent_sdk.auto import auto_secure, available_frameworks
from enkrypt_agent_sdk.config import SDKConfig


class TestAutoSecure:
    def setup_method(self):
        _state.reset()

    def test_returns_dict(self):
        results = auto_secure(SDKConfig())
        assert isinstance(results, dict)
        for key in ("langchain", "openai_agents", "anthropic"):
            assert key in results

    def test_initializes_state(self):
        auto_secure(SDKConfig())
        assert _state.get_observer() is not None
        assert _state.get_guard_engine() is not None
        assert _state.get_config() is not None

    def test_idempotent(self):
        auto_secure(SDKConfig())
        obs1 = _state.get_observer()
        auto_secure(SDKConfig())
        obs2 = _state.get_observer()
        assert obs1 is obs2

    def test_selective_frameworks(self):
        results = auto_secure(SDKConfig(frameworks=["langchain"]))
        assert "anthropic" not in results

    def teardown_method(self):
        _state.reset()


class TestAvailableFrameworks:
    def test_returns_list(self):
        result = available_frameworks()
        assert isinstance(result, list)
