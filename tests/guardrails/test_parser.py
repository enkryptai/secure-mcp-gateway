"""Tests for guardrails/parser.py — Enkrypt API response parsing."""

from enkryptai_agent_security.guardrails.parser import _detector_fired, parse_detect_response
from enkryptai_agent_security.guardrails.types import GuardrailAction, ViolationType


class TestDetectorFired:
    def test_int_zero_is_safe(self):
        assert _detector_fired("nsfw", 0) is False

    def test_int_one_is_violation(self):
        assert _detector_fired("nsfw", 1) is True

    def test_int_greater_than_one(self):
        assert _detector_fired("toxicity", 3) is True

    def test_on_topic_inverted_zero_is_violation(self):
        assert _detector_fired("on_topic", 0) is True

    def test_on_topic_one_is_safe(self):
        assert _detector_fired("on_topic", 1) is False

    def test_bool_true(self):
        assert _detector_fired("pii", True) is True

    def test_bool_false(self):
        assert _detector_fired("pii", False) is False

    def test_list_nonempty(self):
        assert _detector_fired("toxicity", ["hate"]) is True

    def test_list_empty(self):
        assert _detector_fired("toxicity", []) is False

    def test_none(self):
        assert _detector_fired("nsfw", None) is False


class TestParseDetectResponse:
    def test_empty_response(self):
        result = parse_detect_response({}, [])
        assert result.is_safe is True
        assert result.action == GuardrailAction.ALLOW
        assert len(result.violations) == 0

    def test_single_violation_in_block_list(self):
        data = {
            "summary": {"injection_attack": 1},
            "details": {"injection_attack": {"score": 0.95}},
        }
        result = parse_detect_response(data, ["injection_attack"])
        assert result.is_safe is False
        assert result.action == GuardrailAction.BLOCK
        assert len(result.violations) == 1
        v = result.violations[0]
        assert v.detector == "injection_attack"
        assert v.violation_type == ViolationType.INJECTION_ATTACK
        assert v.action == GuardrailAction.BLOCK
        assert v.severity == 1.0

    def test_violation_not_in_block_list_is_warn(self):
        data = {"summary": {"toxicity": 1}, "details": {}}
        result = parse_detect_response(data, ["injection_attack"])
        assert result.is_safe is True
        assert result.action == GuardrailAction.ALLOW
        assert len(result.violations) == 1
        assert result.violations[0].action == GuardrailAction.WARN
        assert result.violations[0].severity == 0.5

    def test_multiple_violations(self):
        data = {
            "summary": {"pii": 1, "toxicity": 1, "nsfw": 0},
            "details": {},
        }
        result = parse_detect_response(data, ["pii", "toxicity"])
        assert result.is_safe is False
        assert result.action == GuardrailAction.BLOCK
        detectors = {v.detector for v in result.violations}
        assert "pii" in detectors
        assert "toxicity" in detectors
        assert "nsfw" not in detectors

    def test_keyword_detected_alias(self):
        data = {
            "summary": {"keyword_detected": 1},
            "details": {"keyword_detector": {"words": ["hack"]}},
        }
        result = parse_detect_response(data, ["keyword_detector"])
        assert result.is_safe is False
        assert result.violations[0].detector == "keyword_detector"
        assert result.violations[0].details == {"words": ["hack"]}

    def test_keyword_detected_in_block_list_by_alias(self):
        data = {"summary": {"keyword_detected": 1}, "details": {}}
        result = parse_detect_response(data, ["keyword_detected"])
        assert result.is_safe is False

    def test_on_topic_violation(self):
        data = {"summary": {"on_topic": 0}, "details": {"topic_detector": {"topic": "off-topic"}}}
        result = parse_detect_response(data, ["topic_detector"])
        assert result.is_safe is False
        v = result.violations[0]
        assert v.detector == "topic_detector"
        assert v.violation_type == ViolationType.TOPIC_VIOLATION

    def test_on_topic_safe(self):
        data = {"summary": {"on_topic": 1}, "details": {}}
        result = parse_detect_response(data, ["topic_detector"])
        assert result.is_safe is True
        assert len(result.violations) == 0

    def test_toxicity_list_value(self):
        data = {"summary": {"toxicity": ["hate_speech", "threat"]}, "details": {}}
        result = parse_detect_response(data, ["toxicity"])
        assert result.is_safe is False
        assert result.violations[0].detector == "toxicity"

    def test_raw_response_preserved(self):
        data = {"summary": {"nsfw": 0}, "details": {}, "meta": "preserved"}
        result = parse_detect_response(data, [])
        assert result.raw_response == data

    def test_detail_fallback_to_summary_key(self):
        data = {
            "summary": {"bias": 1},
            "details": {"bias": {"category": "gender"}},
        }
        result = parse_detect_response(data, ["bias"])
        assert result.violations[0].details == {"category": "gender"}
