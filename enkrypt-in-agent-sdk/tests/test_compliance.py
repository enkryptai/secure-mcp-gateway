"""Tests for compliance mapping — ported from Sentry."""

from enkrypt_agent_sdk.compliance import get_all_compliance_mappings, get_compliance_mapping


class TestComplianceMapping:
    def test_injection_attack_mapping(self):
        m = get_compliance_mapping("injection_attack")
        assert m is not None
        assert "owasp_llm_2025" in m
        assert any("Prompt Injection" in s for s in m["owasp_llm_2025"])

    def test_pii_mapping(self):
        m = get_compliance_mapping("pii")
        assert m is not None
        assert "nist_ai_rmf" in m

    def test_toxicity_mapping(self):
        m = get_compliance_mapping("toxicity")
        assert m is not None

    def test_unknown_detector(self):
        assert get_compliance_mapping("nonexistent_detector") is None

    def test_all_mappings_not_empty(self):
        all_maps = get_all_compliance_mappings()
        assert len(all_maps) >= 10
        for name, mapping in all_maps.items():
            assert isinstance(mapping, dict)
            assert "owasp_llm_2025" in mapping or "nist_ai_rmf" in mapping
