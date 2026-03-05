"""Tests for telemetry/openllmetry.py — OpenLLMetry detection helpers."""

from unittest.mock import MagicMock, patch

from enkryptai_agent_security.telemetry.openllmetry import (
    any_llm_instrumentor_active,
    get_active_instrumentors,
    has_traceloop_sdk,
    init_openllmetry,
    is_instrumentor_active,
)


class TestHasTraceloopSdk:
    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.util.find_spec", return_value=None)
    def test_returns_false_when_not_installed(self, mock_find):
        assert has_traceloop_sdk() is False
        mock_find.assert_called_with("traceloop")

    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.util.find_spec")
    def test_returns_true_when_installed(self, mock_find):
        mock_find.return_value = MagicMock()  # truthy ModuleSpec
        assert has_traceloop_sdk() is True


class TestIsInstrumentorActive:
    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.import_module", side_effect=ImportError)
    def test_returns_false_when_module_not_found(self, _):
        assert is_instrumentor_active("nonexistent.module", "SomeClass") is False

    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.import_module")
    def test_returns_false_when_class_not_found(self, mock_import):
        mock_mod = MagicMock(spec=[])  # empty module, no attributes
        mock_import.return_value = mock_mod
        assert is_instrumentor_active("some.module", "MissingClass") is False

    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.import_module")
    def test_returns_false_when_not_instrumented(self, mock_import):
        mock_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_instrumented_by_opentelemetry = False
        mock_cls.return_value = mock_instance
        mock_mod = MagicMock()
        mock_mod.MyInstrumentor = mock_cls
        mock_import.return_value = mock_mod
        assert is_instrumentor_active("some.module", "MyInstrumentor") is False

    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.import_module")
    def test_returns_true_when_instrumented(self, mock_import):
        mock_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_instrumented_by_opentelemetry = True
        mock_cls.return_value = mock_instance
        mock_mod = MagicMock()
        mock_mod.MyInstrumentor = mock_cls
        mock_import.return_value = mock_mod
        assert is_instrumentor_active("some.module", "MyInstrumentor") is True

    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.import_module", side_effect=RuntimeError("boom"))
    def test_handles_generic_exception(self, _):
        assert is_instrumentor_active("some.module", "SomeClass") is False


class TestGetActiveInstrumentors:
    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.util.find_spec", return_value=None)
    def test_returns_empty_when_none_installed(self, _):
        result = get_active_instrumentors()
        assert result == {}

    @patch("enkryptai_agent_security.telemetry.openllmetry.is_instrumentor_active", return_value=False)
    @patch("enkryptai_agent_security.telemetry.openllmetry.importlib.util.find_spec")
    def test_includes_only_installed(self, mock_find, mock_active):
        # Only "openai" package is installed (first in _KNOWN_INSTRUMENTORS)
        def find_side_effect(name):
            if name == "opentelemetry.instrumentation.openai_v2":
                return MagicMock()
            return None
        mock_find.side_effect = find_side_effect
        result = get_active_instrumentors()
        assert "openai" in result
        assert len(result) == 1


class TestAnyLlmInstrumentorActive:
    @patch("enkryptai_agent_security.telemetry.openllmetry.is_instrumentor_active", return_value=False)
    def test_returns_false_when_none_active(self, _):
        assert any_llm_instrumentor_active() is False

    @patch("enkryptai_agent_security.telemetry.openllmetry.is_instrumentor_active")
    def test_returns_true_when_one_active(self, mock_active):
        # First instrumentor is active
        mock_active.return_value = True
        assert any_llm_instrumentor_active() is True


class TestInitOpenllmetry:
    @patch("enkryptai_agent_security.telemetry.openllmetry.has_traceloop_sdk", return_value=False)
    def test_returns_false_when_traceloop_not_installed(self, _):
        assert init_openllmetry() is False
