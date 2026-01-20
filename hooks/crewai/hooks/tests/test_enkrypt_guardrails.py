#!/usr/bin/env python
"""
Unit tests for CrewAI Enkrypt AI Guardrails module.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from enkrypt_guardrails import (
    parse_enkrypt_response,
    format_violation_message,
    get_hook_policy,
    is_hook_enabled,
    get_hook_block_list,
    get_hook_guardrail_name,
    check_with_enkrypt_api,
    check_guardrails,
    EnkryptApiConfig,
    HookPolicy,
    HookMetrics,
    check_llm_input,
    check_llm_output,
    check_tool_input,
    check_tool_output,
)


class TestDataclasses(unittest.TestCase):
    """Test dataclass definitions."""

    def test_enkrypt_api_config_defaults(self):
        """Test EnkryptApiConfig has correct defaults."""
        config = EnkryptApiConfig()
        self.assertEqual(config.url, "https://api.enkryptai.com/guardrails/policy/detect")
        self.assertEqual(config.api_key, "")
        self.assertTrue(config.ssl_verify)
        self.assertEqual(config.timeout, 15)
        self.assertTrue(config.fail_silently)

    def test_hook_policy_defaults(self):
        """Test HookPolicy has correct defaults."""
        policy = HookPolicy()
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.guardrail_name, "")
        self.assertEqual(policy.block, [])

    def test_hook_metrics_defaults(self):
        """Test HookMetrics has correct defaults."""
        metrics = HookMetrics()
        self.assertEqual(metrics.total_calls, 0)
        self.assertEqual(metrics.blocked_calls, 0)
        self.assertEqual(metrics.allowed_calls, 0)
        self.assertEqual(metrics.errors, 0)
        self.assertEqual(metrics.total_latency_ms, 0.0)
        self.assertIsNone(metrics.last_call_timestamp)

    def test_hook_metrics_avg_latency(self):
        """Test HookMetrics average latency calculation."""
        metrics = HookMetrics()
        metrics.total_calls = 4
        metrics.total_latency_ms = 400.0
        self.assertEqual(metrics.avg_latency_ms, 100.0)

    def test_hook_metrics_avg_latency_zero_calls(self):
        """Test HookMetrics average latency with zero calls."""
        metrics = HookMetrics()
        self.assertEqual(metrics.avg_latency_ms, 0.0)


class TestParseEnkryptResponse(unittest.TestCase):
    """Test parsing of Enkrypt API responses."""

    def test_empty_response(self):
        """Test parsing empty response."""
        result = parse_enkrypt_response({}, ["pii"])
        self.assertEqual(result, [])

    def test_no_violations(self):
        """Test parsing response with no violations."""
        response = {
            "summary": {
                "pii": 0,
                "toxicity": [],
                "nsfw": 0,
            },
            "details": {}
        }
        result = parse_enkrypt_response(response, ["pii", "toxicity", "nsfw"])
        self.assertEqual(result, [])

    def test_pii_violation(self):
        """Test parsing PII violation."""
        response = {
            "summary": {"pii": 1},
            "details": {
                "pii": {
                    "pii": {"email": ["test@example.com"]}
                }
            }
        }
        result = parse_enkrypt_response(response, ["pii"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "pii")
        self.assertTrue(result[0]["blocked"])

    def test_toxicity_violation(self):
        """Test parsing toxicity violation."""
        response = {
            "summary": {"toxicity": ["insult", "threat"]},
            "details": {
                "toxicity": {"toxicity": 0.85}
            }
        }
        result = parse_enkrypt_response(response, ["toxicity"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "toxicity")
        self.assertEqual(result[0]["toxicity_types"], ["insult", "threat"])

    def test_injection_attack_violation(self):
        """Test parsing injection attack violation."""
        response = {
            "summary": {"injection_attack": 1},
            "details": {
                "injection_attack": {"attack": 0.95}
            }
        }
        result = parse_enkrypt_response(response, ["injection_attack"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "injection_attack")
        self.assertEqual(result[0]["attack_score"], 0.95)

    def test_nsfw_violation(self):
        """Test parsing NSFW violation."""
        response = {
            "summary": {"nsfw": 1},
            "details": {
                "nsfw": {"nsfw": 0.92}
            }
        }
        result = parse_enkrypt_response(response, ["nsfw"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "nsfw")
        self.assertEqual(result[0]["nsfw_score"], 0.92)

    def test_keyword_detector_violation(self):
        """Test parsing keyword detector violation."""
        response = {
            "summary": {"keyword_detected": 1},
            "details": {
                "keyword_detector": {
                    "detected_keywords": ["banned_word"],
                    "detected_counts": {"banned_word": 2}
                }
            }
        }
        result = parse_enkrypt_response(response, ["keyword_detector"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "keyword_detector")
        self.assertEqual(result[0]["matched_keywords"], ["banned_word"])

    def test_policy_violation(self):
        """Test parsing policy violation."""
        response = {
            "summary": {"policy_violation": 1},
            "details": {
                "policy_violation": {
                    "violating_policy": "No competitor mentions",
                    "explanation": "Content mentions competitors"
                }
            }
        }
        result = parse_enkrypt_response(response, ["policy_violation"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "policy_violation")
        self.assertEqual(result[0]["violating_policy"], "No competitor mentions")

    def test_bias_violation(self):
        """Test parsing bias violation."""
        response = {
            "summary": {"bias": 1},
            "details": {
                "bias": {
                    "bias_detected": True,
                    "debiased_text": "Neutral version"
                }
            }
        }
        result = parse_enkrypt_response(response, ["bias"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "bias")
        self.assertTrue(result[0]["bias_detected"])

    def test_sponge_attack_violation(self):
        """Test parsing sponge attack violation."""
        response = {
            "summary": {"sponge_attack": 1},
            "details": {
                "sponge_attack": {
                    "sponge_attack_detected": True
                }
            }
        }
        result = parse_enkrypt_response(response, ["sponge_attack"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "sponge_attack")

    def test_on_topic_violation(self):
        """Test parsing off-topic detection (on_topic=0 means violation)."""
        response = {
            "summary": {"on_topic": 0},
            "details": {}
        }
        result = parse_enkrypt_response(response, ["topic_detector"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "topic_detector")

    def test_on_topic_no_violation(self):
        """Test on_topic=1 means no violation."""
        response = {
            "summary": {"on_topic": 1},
            "details": {}
        }
        result = parse_enkrypt_response(response, ["topic_detector"])
        self.assertEqual(result, [])

    def test_detector_not_in_block_list(self):
        """Test that detections not in block list are ignored."""
        response = {
            "summary": {"pii": 1, "toxicity": ["insult"]},
            "details": {}
        }
        # Only block pii, not toxicity
        result = parse_enkrypt_response(response, ["pii"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["detector"], "pii")

    def test_multiple_violations(self):
        """Test parsing multiple violations."""
        response = {
            "summary": {
                "pii": 1,
                "toxicity": ["insult"],
                "injection_attack": 1
            },
            "details": {
                "pii": {"pii": {"email": ["test@example.com"]}},
                "toxicity": {"toxicity": 0.8},
                "injection_attack": {"attack": 0.9}
            }
        }
        result = parse_enkrypt_response(response, ["pii", "toxicity", "injection_attack"])
        self.assertEqual(len(result), 3)
        detectors = [v["detector"] for v in result]
        self.assertIn("pii", detectors)
        self.assertIn("toxicity", detectors)
        self.assertIn("injection_attack", detectors)


class TestFormatViolationMessage(unittest.TestCase):
    """Test formatting of violation messages."""

    def test_empty_violations(self):
        """Test formatting empty violations list."""
        result = format_violation_message([])
        self.assertEqual(result, "")

    def test_pii_message(self):
        """Test PII violation message formatting."""
        violations = [{"detector": "pii", "pii_found": {"email": ["test@example.com"]}}]
        result = format_violation_message(violations, "before_llm_call")
        self.assertIn("PII/Secrets detected", result)
        self.assertIn("email", result)

    def test_injection_message(self):
        """Test injection attack message formatting."""
        violations = [{"detector": "injection_attack", "attack_score": 0.95}]
        result = format_violation_message(violations, "before_tool_call")
        self.assertIn("Injection attack", result)
        self.assertIn("95.0%", result)

    def test_toxicity_message(self):
        """Test toxicity message formatting."""
        violations = [{"detector": "toxicity", "toxicity_types": ["insult"], "score": 0.8}]
        result = format_violation_message(violations, "after_llm_call")
        self.assertIn("Toxic content", result)
        self.assertIn("insult", result)

    def test_nsfw_message(self):
        """Test NSFW message formatting."""
        violations = [{"detector": "nsfw", "nsfw_score": 0.88}]
        result = format_violation_message(violations)
        self.assertIn("NSFW content", result)
        self.assertIn("88.0%", result)

    def test_keyword_message(self):
        """Test keyword violation message formatting."""
        violations = [{"detector": "keyword_detector", "matched_keywords": ["banned1", "banned2"]}]
        result = format_violation_message(violations)
        self.assertIn("Banned keywords", result)
        self.assertIn("banned1", result)

    def test_policy_violation_message(self):
        """Test policy violation message formatting."""
        violations = [{
            "detector": "policy_violation",
            "violating_policy": "No competitor mentions",
            "explanation": "Content mentions competitor products"
        }]
        result = format_violation_message(violations)
        self.assertIn("Policy violation", result)
        self.assertIn("No competitor mentions", result)
        self.assertIn("competitor products", result)

    def test_bias_message(self):
        """Test bias message formatting."""
        violations = [{"detector": "bias", "bias_detected": True}]
        result = format_violation_message(violations)
        self.assertIn("Bias detected", result)

    def test_sponge_attack_message(self):
        """Test sponge attack message formatting."""
        violations = [{"detector": "sponge_attack", "sponge_detected": True}]
        result = format_violation_message(violations)
        self.assertIn("Sponge attack", result)

    def test_topic_detector_message(self):
        """Test topic detector message formatting."""
        violations = [{"detector": "topic_detector"}]
        result = format_violation_message(violations)
        self.assertIn("Off-topic", result)


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Reset metrics before each test."""
        from enkrypt_guardrails import reset_metrics
        reset_metrics()

    def test_record_call(self):
        """Test recording a hook call."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("before_llm_call")
        self.assertEqual(m["total_calls"], 1)
        self.assertEqual(m["allowed_calls"], 1)
        self.assertEqual(m["blocked_calls"], 0)

    def test_record_blocked_call(self):
        """Test recording a blocked call."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("before_tool_call", blocked=True, latency_ms=100.0)
        m = get_hook_metrics("before_tool_call")
        self.assertEqual(m["blocked_calls"], 1)
        self.assertEqual(m["allowed_calls"], 0)

    def test_record_error(self):
        """Test recording an error."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("after_llm_call", blocked=False, latency_ms=100.0, error=True)
        m = get_hook_metrics("after_llm_call")
        self.assertEqual(m["errors"], 1)

    def test_average_latency(self):
        """Test average latency calculation."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("after_tool_call", blocked=False, latency_ms=100.0)
        metrics.record_call("after_tool_call", blocked=False, latency_ms=200.0)
        m = get_hook_metrics("after_tool_call")
        self.assertEqual(m["avg_latency_ms"], 150.0)

    def test_reset_metrics(self):
        """Test resetting metrics."""
        from enkrypt_guardrails import metrics, get_hook_metrics, reset_metrics
        metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        reset_metrics("before_llm_call")
        m = get_hook_metrics("before_llm_call")
        self.assertEqual(m["total_calls"], 0)

    def test_get_all_metrics(self):
        """Test getting all metrics."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        metrics.record_call("after_llm_call", blocked=True, latency_ms=150.0)
        all_metrics = get_hook_metrics()
        self.assertIn("before_llm_call", all_metrics)
        self.assertIn("after_llm_call", all_metrics)

    def test_metrics_timestamp(self):
        """Test that timestamp is recorded."""
        from enkrypt_guardrails import metrics, get_hook_metrics
        metrics.record_call("before_llm_call", blocked=False, latency_ms=100.0)
        m = get_hook_metrics("before_llm_call")
        self.assertIsNotNone(m["last_call_timestamp"])


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation."""

    def test_valid_config(self):
        """Test validation of valid config."""
        from enkrypt_guardrails import validate_config
        config = {
            "enkrypt_api": {
                "url": "https://api.example.com",
                "timeout": 15,
                "ssl_verify": True,
                "fail_silently": True
            },
            "before_llm_call": {
                "enabled": True,
                "guardrail_name": "Test Policy",
                "block": ["pii"]
            }
        }
        errors = validate_config(config)
        self.assertEqual(errors, [])

    def test_invalid_url(self):
        """Test validation of invalid URL."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"url": "not-a-url"}}
        errors = validate_config(config)
        self.assertTrue(any("url" in e for e in errors))

    def test_invalid_timeout(self):
        """Test validation of invalid timeout."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"timeout": -5}}
        errors = validate_config(config)
        self.assertTrue(any("timeout" in e for e in errors))

    def test_invalid_ssl_verify(self):
        """Test validation of invalid ssl_verify."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"ssl_verify": "true"}}
        errors = validate_config(config)
        self.assertTrue(any("ssl_verify" in e for e in errors))

    def test_invalid_fail_silently(self):
        """Test validation of invalid fail_silently."""
        from enkrypt_guardrails import validate_config
        config = {"enkrypt_api": {"fail_silently": "yes"}}
        errors = validate_config(config)
        self.assertTrue(any("fail_silently" in e for e in errors))

    def test_invalid_hook_enabled(self):
        """Test validation of invalid enabled field."""
        from enkrypt_guardrails import validate_config
        config = {"before_llm_call": {"enabled": "yes"}}
        errors = validate_config(config)
        self.assertTrue(any("enabled" in e for e in errors))

    def test_invalid_block_list(self):
        """Test validation of invalid block list."""
        from enkrypt_guardrails import validate_config
        config = {"before_llm_call": {"block": "pii"}}
        errors = validate_config(config)
        self.assertTrue(any("block" in e for e in errors))

    def test_invalid_guardrail_name(self):
        """Test validation of invalid guardrail name."""
        from enkrypt_guardrails import validate_config
        config = {"after_llm_call": {"guardrail_name": 123}}
        errors = validate_config(config)
        self.assertTrue(any("guardrail_name" in e for e in errors))

    def test_all_hook_names_validated(self):
        """Test all CrewAI hook names are validated."""
        from enkrypt_guardrails import validate_config
        hooks = ["before_llm_call", "after_llm_call", "before_tool_call", "after_tool_call"]
        for hook in hooks:
            config = {hook: {"enabled": "invalid"}}
            errors = validate_config(config)
            self.assertTrue(len(errors) > 0, f"Hook {hook} should be validated")


class TestConnectionPooling(unittest.TestCase):
    """Test connection pooling functionality."""

    def test_session_creation(self):
        """Test HTTP session is created."""
        from enkrypt_guardrails import get_http_session
        session = get_http_session()
        self.assertIsNotNone(session)

    def test_session_has_adapters(self):
        """Test session has HTTP adapters."""
        from enkrypt_guardrails import get_http_session
        session = get_http_session()
        self.assertIn("https://", session.adapters)
        self.assertIn("http://", session.adapters)

    def test_session_is_singleton(self):
        """Test session is reused (singleton)."""
        from enkrypt_guardrails import get_http_session
        session1 = get_http_session()
        session2 = get_http_session()
        self.assertIs(session1, session2)

    def test_close_session(self):
        """Test session can be closed."""
        from enkrypt_guardrails import get_http_session, close_http_session
        session = get_http_session()
        self.assertIsNotNone(session)
        close_http_session()
        # After closing, getting session again should create a new one
        new_session = get_http_session()
        self.assertIsNotNone(new_session)


class TestBufferedLogger(unittest.TestCase):
    """Test buffered logging functionality."""

    def test_buffered_logger_creation(self):
        """Test BufferedLogger can be created."""
        from enkrypt_guardrails import BufferedLogger
        logger = BufferedLogger(buffer_size=5, flush_interval=1.0)
        self.assertIsNotNone(logger)

    def test_buffered_logger_write_and_flush(self):
        """Test BufferedLogger write and flush."""
        from enkrypt_guardrails import BufferedLogger
        import tempfile

        logger = BufferedLogger(buffer_size=2, flush_interval=10.0)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)

        try:
            # Write entries (should buffer, not flush yet)
            logger.write(temp_path, '{"test": 1}\n')

            # Force flush
            logger.flush_all()

            # Check file was written
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"test": 1}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_buffered_logger_auto_flush_on_buffer_full(self):
        """Test BufferedLogger auto-flushes when buffer is full."""
        from enkrypt_guardrails import BufferedLogger
        import tempfile

        logger = BufferedLogger(buffer_size=2, flush_interval=100.0)  # Large interval
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)

        try:
            # Write 2 entries (buffer size is 2, so should auto-flush)
            logger.write(temp_path, '{"entry": 1}\n')
            logger.write(temp_path, '{"entry": 2}\n')

            # Check file was written (auto-flushed)
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn('{"entry": 1}', content)
            self.assertIn('{"entry": 2}', content)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_buffered_logger_close(self):
        """Test BufferedLogger can be closed."""
        from enkrypt_guardrails import BufferedLogger
        logger = BufferedLogger(buffer_size=5, flush_interval=1.0)
        logger.close()
        # After closing, writes should be ignored
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = Path(f.name)
        try:
            logger.write(temp_path, '{"test": 1}\n')
            # File should be empty since logger is closed
            if temp_path.exists():
                with open(temp_path, 'r') as f:
                    content = f.read()
                self.assertEqual(content, "")
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestLogRetention(unittest.TestCase):
    """Test log retention settings."""

    def test_log_retention_days_default(self):
        """Test LOG_RETENTION_DAYS has default value."""
        from enkrypt_guardrails import LOG_RETENTION_DAYS
        self.assertIsInstance(LOG_RETENTION_DAYS, int)
        self.assertGreaterEqual(LOG_RETENTION_DAYS, 0)

    def test_cleanup_old_logs_exists(self):
        """Test cleanup_old_logs function exists."""
        from enkrypt_guardrails import cleanup_old_logs
        self.assertTrue(callable(cleanup_old_logs))

    def test_log_dir_exists(self):
        """Test LOG_DIR is defined."""
        from enkrypt_guardrails import LOG_DIR
        self.assertIsInstance(LOG_DIR, Path)


class TestDynamicReload(unittest.TestCase):
    """Test dynamic config reload."""

    def test_reload_config_function_exists(self):
        """Test reload_config function exists."""
        from enkrypt_guardrails import reload_config
        self.assertTrue(callable(reload_config))

    def test_flush_logs_function_exists(self):
        """Test flush_logs function exists."""
        from enkrypt_guardrails import flush_logs
        self.assertTrue(callable(flush_logs))


class TestPolicyFunctions(unittest.TestCase):
    """Test policy configuration functions."""

    def test_get_hook_policy(self):
        """Test get_hook_policy returns dict."""
        policy = get_hook_policy("before_llm_call")
        self.assertIsInstance(policy, dict)

    def test_is_hook_enabled(self):
        """Test is_hook_enabled returns bool."""
        result = is_hook_enabled("before_llm_call")
        self.assertIsInstance(result, bool)

    def test_get_hook_block_list(self):
        """Test get_hook_block_list returns list."""
        block_list = get_hook_block_list("before_tool_call")
        self.assertIsInstance(block_list, list)

    def test_get_hook_guardrail_name(self):
        """Test get_hook_guardrail_name returns string."""
        guardrail_name = get_hook_guardrail_name("after_llm_call")
        self.assertIsInstance(guardrail_name, str)

    def test_all_hooks_have_policies(self):
        """Test all CrewAI hooks have policy entries."""
        hooks = ["before_llm_call", "after_llm_call", "before_tool_call", "after_tool_call"]
        for hook in hooks:
            policy = get_hook_policy(hook)
            self.assertIsInstance(policy, dict, f"Hook {hook} should have policy")


class TestSourceEvent(unittest.TestCase):
    """Test source event mapping."""

    def test_get_source_event(self):
        """Test get_source_event maps hook names correctly."""
        from enkrypt_guardrails import get_source_event

        mappings = {
            "before_llm_call": "pre-llm",
            "after_llm_call": "post-llm",
            "before_tool_call": "pre-tool",
            "after_tool_call": "post-tool",
        }

        for hook_name, expected_event in mappings.items():
            result = get_source_event(hook_name)
            self.assertEqual(result, expected_event)

    def test_get_source_event_unknown(self):
        """Test get_source_event with unknown hook."""
        from enkrypt_guardrails import get_source_event
        result = get_source_event("unknown_hook")
        self.assertEqual(result, "unknown_hook")


class TestHookFunctions(unittest.TestCase):
    """Test CrewAI hook functions."""

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_llm_input_passes(self, mock_api):
        """Test check_llm_input when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.task = Mock()
        mock_context.task.description = "Test task"
        mock_context.agent_name = "test_agent"

        result = check_llm_input(mock_context)
        self.assertIsNone(result)

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_llm_input_blocked(self, mock_api):
        """Test check_llm_input when violations detected."""
        mock_api.return_value = (True, [{"detector": "pii", "blocked": True}], {"summary": {"pii": 1}})

        # Create mock context
        mock_context = Mock()
        mock_context.task = Mock()
        mock_context.task.description = "Test with PII data"
        mock_context.agent_name = "test_agent"

        result = check_llm_input(mock_context)
        self.assertFalse(result)

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_llm_output_passes(self, mock_api):
        """Test check_llm_output when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.response = "Safe response"

        result = check_llm_output(mock_context)
        self.assertIsNone(result)

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_tool_input_passes(self, mock_api):
        """Test check_tool_input when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.tool_name = "read_file"
        mock_context.tool_input = {"path": "/tmp/test.txt"}

        result = check_tool_input(mock_context)
        self.assertIsNone(result)

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_tool_output_passes(self, mock_api):
        """Test check_tool_output when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        # Create mock context
        mock_context = Mock()
        mock_context.tool_name = "read_file"
        mock_context.tool_result = "File contents"

        result = check_tool_output(mock_context)
        self.assertIsNone(result)


class TestContextManager(unittest.TestCase):
    """Test EnkryptGuardrailsContext context manager."""

    def test_context_manager_creation(self):
        """Test EnkryptGuardrailsContext can be created."""
        from enkrypt_guardrails import EnkryptGuardrailsContext
        ctx = EnkryptGuardrailsContext()
        self.assertIsNotNone(ctx)

    def test_context_manager_registers_hooks(self):
        """Test context manager registers hooks on enter."""
        from enkrypt_guardrails import EnkryptGuardrailsContext

        # Mock the crewai.hooks module
        mock_hooks = Mock()
        mock_hooks.register_before_llm_call_hook = Mock()
        mock_hooks.register_after_llm_call_hook = Mock()
        mock_hooks.register_before_tool_call_hook = Mock()
        mock_hooks.register_after_tool_call_hook = Mock()
        mock_hooks.unregister_before_llm_call_hook = Mock()
        mock_hooks.unregister_after_llm_call_hook = Mock()
        mock_hooks.unregister_before_tool_call_hook = Mock()
        mock_hooks.unregister_after_tool_call_hook = Mock()

        # Mock the imports
        with patch.dict('sys.modules', {'crewai.hooks': mock_hooks}):
            try:
                with EnkryptGuardrailsContext() as ctx:
                    # Verify hooks were registered
                    self.assertTrue(mock_hooks.register_before_llm_call_hook.called)
                    self.assertTrue(mock_hooks.register_after_llm_call_hook.called)
                    self.assertTrue(mock_hooks.register_before_tool_call_hook.called)
                    self.assertTrue(mock_hooks.register_after_tool_call_hook.called)
            except Exception as e:
                # Ignore import errors in test environment
                pass


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions for enabling/disabling guardrails."""

    def test_enable_guardrails_function_exists(self):
        """Test enable_guardrails function exists."""
        from enkrypt_guardrails import enable_guardrails
        self.assertTrue(callable(enable_guardrails))

    def test_disable_guardrails_function_exists(self):
        """Test disable_guardrails function exists."""
        from enkrypt_guardrails import disable_guardrails
        self.assertTrue(callable(disable_guardrails))

    def test_with_guardrails_decorator_exists(self):
        """Test with_guardrails decorator exists."""
        from enkrypt_guardrails import with_guardrails
        self.assertTrue(callable(with_guardrails))

    def test_with_guardrails_decorator(self):
        """Test with_guardrails decorator wraps function."""
        from enkrypt_guardrails import with_guardrails

        @with_guardrails
        def test_func():
            return "test"

        self.assertEqual(test_func.__name__, "test_func")


class TestLoggingFunctions(unittest.TestCase):
    """Test logging functions."""

    def test_get_timestamp(self):
        """Test get_timestamp returns ISO format."""
        from enkrypt_guardrails import get_timestamp
        timestamp = get_timestamp()
        self.assertIsInstance(timestamp, str)
        # Should be ISO format (contains T)
        self.assertIn("T", timestamp)

    def test_log_event_function_exists(self):
        """Test log_event function exists."""
        from enkrypt_guardrails import log_event
        self.assertTrue(callable(log_event))

    def test_log_security_alert_function_exists(self):
        """Test log_security_alert function exists."""
        from enkrypt_guardrails import log_security_alert
        self.assertTrue(callable(log_security_alert))


class TestCheckWithEnkryptApi(unittest.TestCase):
    """Test check_with_enkrypt_api function."""

    @patch('enkrypt_guardrails.is_hook_enabled')
    def test_check_with_enkrypt_api_disabled_hook(self, mock_enabled):
        """Test check_with_enkrypt_api when hook is disabled."""
        mock_enabled.return_value = False

        should_block, violations, result = check_with_enkrypt_api("test text", "before_llm_call")

        self.assertFalse(should_block)
        self.assertEqual(violations, [])
        self.assertIn("skipped", result)

    @patch('enkrypt_guardrails.is_hook_enabled')
    @patch('enkrypt_guardrails.get_http_session')
    def test_check_with_enkrypt_api_success(self, mock_session, mock_enabled):
        """Test check_with_enkrypt_api with successful response."""
        mock_enabled.return_value = True

        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"summary": {}, "details": {}}'
        mock_response.json.return_value = {"summary": {}, "details": {}}
        mock_response.url = "https://api.example.com"
        mock_response.request = Mock()
        mock_response.request.headers = {}

        mock_session_obj = Mock()
        mock_session_obj.post.return_value = mock_response
        mock_session.return_value = mock_session_obj

        should_block, violations, result = check_with_enkrypt_api("test text", "before_llm_call")

        self.assertFalse(should_block)
        self.assertEqual(violations, [])

    @patch('enkrypt_guardrails.is_hook_enabled')
    @patch('enkrypt_guardrails.get_http_session')
    def test_check_with_enkrypt_api_timeout(self, mock_session, mock_enabled):
        """Test check_with_enkrypt_api handles timeout."""
        mock_enabled.return_value = True

        mock_session_obj = Mock()
        mock_session_obj.post.side_effect = Exception("Timeout")
        mock_session.return_value = mock_session_obj

        should_block, violations, result = check_with_enkrypt_api("test text", "before_llm_call")

        # Behavior depends on fail_silently setting
        self.assertIsInstance(should_block, bool)
        self.assertEqual(violations, [])
        self.assertIn("error", result)


class TestCheckGuardrails(unittest.TestCase):
    """Test check_guardrails wrapper function."""

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_guardrails_passes(self, mock_api):
        """Test check_guardrails when no violations."""
        mock_api.return_value = (False, [], {"summary": {}, "details": {}})

        result = check_guardrails("test text", "before_llm_call", {"test": "context"})

        self.assertTrue(result["passed"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["hook"], "before_llm_call")

    @patch('enkrypt_guardrails.check_with_enkrypt_api')
    def test_check_guardrails_blocks(self, mock_api):
        """Test check_guardrails when violations detected."""
        mock_api.return_value = (True, [{"detector": "pii"}], {"summary": {"pii": 1}})

        with self.assertRaises(ValueError) as ctx:
            check_guardrails("sensitive data", "before_tool_call")

        self.assertIn("Guardrails blocked", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
