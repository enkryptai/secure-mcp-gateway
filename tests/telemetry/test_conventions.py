"""Tests for telemetry/conventions.py — semantic naming constants."""

from enkryptai_agent_security.telemetry.conventions import (
    METRIC_DESCRIPTIONS,
    GenAIAttributes,
    GenAIMetrics,
    MetricNames,
    SourceEvent,
    SourceProduct,
    SpanAttributes,
    SpanNames,
)


class TestSpanAttributes:
    def test_guardrail_attributes_exist(self):
        assert SpanAttributes.GUARDRAIL_NAME == "enkrypt.guardrail.name"
        assert SpanAttributes.GUARDRAIL_ACTION == "enkrypt.guardrail.action"
        assert SpanAttributes.GUARDRAIL_VIOLATIONS == "enkrypt.guardrail.violations"
        assert SpanAttributes.GUARDRAIL_DETECTOR == "enkrypt.guardrail.detector"

    def test_tool_attributes_exist(self):
        assert SpanAttributes.TOOL_NAME == "enkrypt.tool.name"
        assert SpanAttributes.TOOL_SERVER == "enkrypt.tool.server"

    def test_identity_attributes_exist(self):
        assert SpanAttributes.SERVER_NAME == "enkrypt.server.name"
        assert SpanAttributes.PROJECT_ID == "enkrypt.project.id"
        assert SpanAttributes.USER_ID == "enkrypt.user.id"
        assert SpanAttributes.CONFIG_ID == "enkrypt.config.id"

    def test_source_attributes_exist(self):
        assert SpanAttributes.SOURCE_PRODUCT == "enkrypt.source.product"
        assert SpanAttributes.SOURCE_EVENT == "enkrypt.source.event"

    def test_error_attributes_exist(self):
        assert SpanAttributes.ERROR_CODE == "enkrypt.error.code"
        assert SpanAttributes.ERROR_MESSAGE == "enkrypt.error.message"


class TestSpanNames:
    def test_core_spans(self):
        assert SpanNames.GUARDRAIL_CHECK == "enkrypt.guardrail.check"
        assert SpanNames.TOOL_EXECUTE == "enkrypt.tool.execute"
        assert SpanNames.AUTH == "enkrypt.auth"

    def test_discovery_spans(self):
        assert SpanNames.DISCOVERY == "enkrypt.discovery"
        assert SpanNames.DISCOVERY_CACHE_CHECK == "enkrypt.discovery.cache_check"

    def test_pii_spans(self):
        assert SpanNames.PII_REDACT == "enkrypt.pii.redact"
        assert SpanNames.PII_RESTORE == "enkrypt.pii.restore"


class TestMetricNames:
    def test_guardrail_metrics(self):
        assert MetricNames.GUARDRAIL_CHECKS == "enkrypt.guardrail.checks"
        assert MetricNames.GUARDRAIL_BLOCKS == "enkrypt.guardrail.blocks"
        assert MetricNames.GUARDRAIL_DURATION == "enkrypt.guardrail.duration"

    def test_tool_metrics(self):
        assert MetricNames.TOOL_CALLS == "enkrypt.tool.calls"
        assert MetricNames.TOOL_DURATION == "enkrypt.tool.duration"
        assert MetricNames.TOOL_ERRORS == "enkrypt.tool.errors"

    def test_all_metrics_have_descriptions(self):
        metric_names = [
            v for k, v in MetricNames.__dict__.items()
            if not k.startswith("_")
        ]
        for name in metric_names:
            assert name in METRIC_DESCRIPTIONS, f"Missing description for {name}"


class TestSourceIdentifiers:
    def test_products(self):
        assert SourceProduct.GATEWAY == "gateway"
        assert SourceProduct.SDK == "sdk"
        assert SourceProduct.HOOKS == "hooks"

    def test_events(self):
        assert SourceEvent.PRE_LLM == "pre_llm"
        assert SourceEvent.PRE_TOOL == "pre_tool"
        assert SourceEvent.POST_TOOL == "post_tool"
        assert SourceEvent.POST_LLM == "post_llm"
        assert SourceEvent.REGISTRATION == "registration"


class TestGenAIConventions:
    def test_genai_attributes(self):
        assert GenAIAttributes.SYSTEM == "gen_ai.system"
        assert GenAIAttributes.REQUEST_MODEL == "gen_ai.request.model"
        assert GenAIAttributes.USAGE_INPUT_TOKENS == "gen_ai.usage.input_tokens"

    def test_genai_metrics(self):
        assert GenAIMetrics.CLIENT_OPERATION_DURATION == "gen_ai.client.operation.duration"
        assert GenAIMetrics.CLIENT_TOKEN_USAGE == "gen_ai.client.token.usage"


def _get_class_values(cls):
    """Collect all public string values from a class."""
    return [v for k, v in cls.__dict__.items() if not k.startswith("_") and isinstance(v, str)]


class TestUniqueness:
    def test_no_duplicate_span_attribute_values(self):
        values = _get_class_values(SpanAttributes)
        assert len(values) == len(set(values)), f"Duplicate SpanAttributes: {values}"

    def test_no_duplicate_span_name_values(self):
        values = _get_class_values(SpanNames)
        assert len(values) == len(set(values)), f"Duplicate SpanNames: {values}"

    def test_no_duplicate_metric_name_values(self):
        values = _get_class_values(MetricNames)
        assert len(values) == len(set(values)), f"Duplicate MetricNames: {values}"


import re

_NAMING_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$")


class TestNamingConventionCompliance:
    def test_span_attributes_dot_separated(self):
        for v in _get_class_values(SpanAttributes):
            assert _NAMING_RE.match(v), f"SpanAttribute {v!r} violates naming convention"

    def test_span_names_dot_separated(self):
        for v in _get_class_values(SpanNames):
            assert _NAMING_RE.match(v), f"SpanName {v!r} violates naming convention"

    def test_metric_names_dot_separated(self):
        for v in _get_class_values(MetricNames):
            assert _NAMING_RE.match(v), f"MetricName {v!r} violates naming convention"

    def test_metric_names_no_total_suffix(self):
        for v in _get_class_values(MetricNames):
            assert not v.endswith("_total"), f"MetricName {v!r} should not end with _total"

    def test_genai_attributes_prefix(self):
        for v in _get_class_values(GenAIAttributes):
            assert v.startswith("gen_ai."), f"GenAIAttribute {v!r} should start with gen_ai."

    def test_genai_metrics_prefix(self):
        for v in _get_class_values(GenAIMetrics):
            assert v.startswith("gen_ai."), f"GenAIMetric {v!r} should start with gen_ai."


class TestMetricDescriptionQuality:
    def test_descriptions_are_nonempty_strings(self):
        for key, desc in METRIC_DESCRIPTIONS.items():
            assert isinstance(desc, str), f"Description for {key} is not a string"
            assert len(desc) > 0, f"Description for {key} is empty"
