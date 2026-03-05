"""Tests for guardrails/types.py — violation types, actions, and result models."""

from enkryptai_agent_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)


class TestViolationType:
    def test_all_members(self):
        expected = {
            "PII", "INJECTION_ATTACK", "TOXICITY", "NSFW",
            "KEYWORD_VIOLATION", "POLICY_VIOLATION", "BIAS",
            "SPONGE_ATTACK", "TOPIC_VIOLATION", "RELEVANCY_FAILURE",
            "ADHERENCE_FAILURE", "HALLUCINATION", "CUSTOM",
        }
        assert set(ViolationType.__members__.keys()) == expected

    def test_string_values(self):
        assert ViolationType.PII == "pii"
        assert ViolationType.INJECTION_ATTACK == "injection_attack"
        assert ViolationType.KEYWORD_VIOLATION == "keyword_violation"
        assert ViolationType.TOPIC_VIOLATION == "topic_violation"

    def test_is_string_enum(self):
        assert isinstance(ViolationType.PII, str)


class TestGuardrailAction:
    def test_all_members(self):
        assert set(GuardrailAction.__members__.keys()) == {"ALLOW", "BLOCK", "WARN", "MODIFY"}

    def test_string_values(self):
        assert GuardrailAction.ALLOW == "allow"
        assert GuardrailAction.BLOCK == "block"


class TestGuardrailViolation:
    def test_creation(self):
        v = GuardrailViolation(
            detector="pii",
            violation_type=ViolationType.PII,
            action=GuardrailAction.BLOCK,
            severity=1.0,
            message="PII detected",
        )
        assert v.detector == "pii"
        assert v.severity == 1.0
        assert v.details == {}

    def test_frozen(self):
        v = GuardrailViolation(
            detector="test", violation_type=ViolationType.CUSTOM,
            action=GuardrailAction.WARN, severity=0.5, message="test",
        )
        try:
            v.detector = "changed"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass


class TestGuardrailResult:
    def test_safe_result(self):
        r = GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True)
        assert r.is_safe is True
        assert r.violations == ()
        assert r.raw_response == {}

    def test_blocked_result(self):
        v = GuardrailViolation(
            detector="toxicity", violation_type=ViolationType.TOXICITY,
            action=GuardrailAction.BLOCK, severity=1.0, message="toxic",
        )
        r = GuardrailResult(
            action=GuardrailAction.BLOCK, is_safe=False, violations=(v,),
        )
        assert r.is_safe is False
        assert len(r.violations) == 1
        assert r.violations[0].detector == "toxicity"

    def test_frozen(self):
        r = GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True)
        try:
            r.is_safe = False
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass
