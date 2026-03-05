"""Tests for config/loader.py — unified config loading."""

import json
import os
from unittest.mock import patch

import pytest

from enkryptai_agent_security.config.loader import (
    _apply_env_overrides,
    _config_from_dict,
    _invalidate_cache,
    from_gateway_config,
    load_config,
    to_gateway_config,
)
from enkryptai_agent_security.config.models import (
    EnkryptApiConfig,
    EnkryptConfig,
    ExporterType,
    GuardrailPolicy,
    TelemetryConfig,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Ensure loader cache is clean for each test."""
    _invalidate_cache()
    yield
    _invalidate_cache()


class TestConfigFromDict:
    def test_empty_dict(self):
        cfg = _config_from_dict({})
        assert cfg.api.api_key == ""

    def test_full_dict(self):
        data = {
            "api": {"api_key": "ek_123", "base_url": "https://custom.com", "timeout": 30.0},
            "telemetry": {"enabled": True, "exporter": "otlp_grpc", "endpoint": "localhost:4317"},
            "sdk": {
                "checkpoints": {"pre_llm": False, "pre_tool": True, "post_tool": False, "post_llm": False},
                "guardrails": {
                    "pre_llm": {"enabled": True, "guardrail_name": "Policy1", "block": ["pii"]},
                },
            },
        }
        cfg = _config_from_dict(data)
        assert cfg.api.api_key == "ek_123"
        assert cfg.api.timeout == 30.0
        assert cfg.telemetry.exporter == ExporterType.OTLP_GRPC
        sdk = cfg.get_sdk()
        assert sdk.checkpoints["pre_llm"] is False
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.block == ["pii"]

    def test_migration_old_top_level_guardrails(self):
        """Old configs with top-level input/output_guardrails migrate to sdk.guardrails."""
        data = {
            "input_guardrails": {"enabled": True, "guardrail_name": "InPolicy", "block": ["pii"]},
            "output_guardrails": {"enabled": True, "guardrail_name": "OutPolicy", "block": ["toxicity"]},
        }
        cfg = _config_from_dict(data)
        sdk = cfg.get_sdk()
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.guardrail_name == "InPolicy"
        assert sdk.guardrails.pre_tool is not None
        assert sdk.guardrails.pre_tool.block == ["pii"]
        assert sdk.guardrails.post_tool is not None
        assert sdk.guardrails.post_tool.guardrail_name == "OutPolicy"
        assert sdk.guardrails.post_llm is not None
        assert sdk.guardrails.post_llm.block == ["toxicity"]

    def test_unknown_exporter_falls_back_to_none(self):
        data = {"telemetry": {"exporter": "invalid_exporter"}}
        cfg = _config_from_dict(data)
        assert cfg.telemetry.exporter == ExporterType.NONE

    def test_extra_keys_preserved(self):
        data = {"custom_key": "custom_value"}
        cfg = _config_from_dict(data)
        assert cfg.extra["custom_key"] == "custom_value"

    def test_hooks_section_parsed(self):
        data = {
            "hooks": {
                "cursor": {
                    "sensitive_tools": ["Bash"],
                    "beforeSubmitPrompt": {"enabled": True, "guardrail_name": "Test", "block": []},
                }
            }
        }
        cfg = _config_from_dict(data)
        hooks = cfg.get_hooks()
        assert "cursor" in hooks
        assert hooks["cursor"].sensitive_tools == ["Bash"]


class TestEnvOverrides:
    def test_api_key_override(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_API_KEY": "env_key"}):
            result = _apply_env_overrides(cfg)
        assert result.api.api_key == "env_key"

    def test_base_url_strips_endpoint(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_BASE_URL": "https://api.example.com/guardrails/policy/detect"}):
            result = _apply_env_overrides(cfg)
        assert result.api.base_url == "https://api.example.com"

    def test_base_url_strips_trailing_slash(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_BASE_URL": "https://api.example.com/"}):
            result = _apply_env_overrides(cfg)
        assert result.api.base_url == "https://api.example.com"

    def test_legacy_api_url_env(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_API_URL": "https://legacy.com"}, clear=False):
            env = os.environ.copy()
            env.pop("ENKRYPT_BASE_URL", None)
            with patch.dict(os.environ, env, clear=True):
                result = _apply_env_overrides(cfg)
        assert result.api.base_url == "https://legacy.com"

    def test_fail_open_override(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_FAIL_OPEN": "false"}):
            result = _apply_env_overrides(cfg)
        assert result.api.fail_open is False

    def test_guardrail_name_override(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_GUARDRAIL_NAME": "MyGuardrail"}):
            result = _apply_env_overrides(cfg)
        sdk = result.get_sdk()
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.guardrail_name == "MyGuardrail"
        assert sdk.guardrails.post_tool is not None
        assert sdk.guardrails.post_tool.guardrail_name == "MyGuardrail"

    def test_block_list_override(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_BLOCK_LIST": "pii, toxicity, nsfw"}):
            result = _apply_env_overrides(cfg)
        sdk = result.get_sdk()
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.block == ["pii", "toxicity", "nsfw"]

    def test_telemetry_overrides(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {
            "ENKRYPT_TELEMETRY_ENABLED": "true",
            "ENKRYPT_TELEMETRY_EXPORTER": "otlp_http",
            "ENKRYPT_TELEMETRY_ENDPOINT": "http://collector:4318",
            "ENKRYPT_TELEMETRY_SERVICE_NAME": "my-service",
        }):
            result = _apply_env_overrides(cfg)
        assert result.telemetry.enabled is True
        assert result.telemetry.exporter == ExporterType.OTLP_HTTP
        assert result.telemetry.endpoint == "http://collector:4318"
        assert result.telemetry.service_name == "my-service"

    def test_checkpoint_overrides(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_CHECK_POST_LLM": "true"}):
            result = _apply_env_overrides(cfg)
        sdk = result.get_sdk()
        assert sdk.checkpoints["post_llm"] is True

    def test_invalid_timeout_ignored(self):
        cfg = EnkryptConfig()
        with patch.dict(os.environ, {"ENKRYPT_TIMEOUT": "not_a_number"}):
            result = _apply_env_overrides(cfg)
        assert result.api.timeout == 15.0


class TestLoadConfig:
    def test_default_no_file(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = load_config(apply_env=False)
        assert isinstance(cfg, EnkryptConfig)

    def test_explicit_config_object(self):
        explicit = EnkryptConfig(api=EnkryptApiConfig(api_key="explicit"))
        result = load_config(config=explicit, apply_env=False)
        assert result.api.api_key == "explicit"

    def test_load_from_file(self, tmp_path):
        config_file = tmp_path / "test_config.json"
        config_file.write_text(json.dumps({
            "api": {"api_key": "file_key"},
            "sdk": {"guardrails": {"pre_llm": {"enabled": True, "guardrail_name": "Test"}}},
        }))
        result = load_config(config_path=str(config_file), apply_env=False, use_cache=False)
        assert result.api.api_key == "file_key"
        sdk = result.get_sdk()
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.enabled is True

    def test_env_overrides_file(self, tmp_path):
        config_file = tmp_path / "test_config.json"
        config_file.write_text(json.dumps({"api": {"api_key": "file_key"}}))
        with patch.dict(os.environ, {"ENKRYPT_API_KEY": "env_key"}):
            result = load_config(config_path=str(config_file), use_cache=False)
        assert result.api.api_key == "env_key"

    def test_cache_returns_same_object(self, tmp_path):
        config_file = tmp_path / "test_config.json"
        config_file.write_text(json.dumps({"api": {"api_key": "cached"}}))
        r1 = load_config(config_path=str(config_file), apply_env=False)
        r2 = load_config(config_path=str(config_file), apply_env=False)
        assert r1 is r2

    def test_nonexistent_file_returns_defaults(self):
        result = load_config(config_path="/nonexistent/path.json", apply_env=False)
        assert result.api.api_key == ""


class TestGatewayConfigAdapter:
    def test_from_gateway_config(self):
        gateway_dict = {
            "common_mcp_gateway_config": {"enkrypt_log_level": "DEBUG"},
            "plugins": {
                "guardrails": {"provider": "enkrypt", "config": {"api_key": "gw_key", "base_url": "https://gw.api"}},
                "auth": {"provider": "local_apikey", "config": {}},
                "telemetry": {"provider": "opentelemetry", "config": {"url": "localhost:4317", "insecure": True}},
            },
        }
        cfg = from_gateway_config(gateway_dict)
        assert cfg.api.api_key == "gw_key"
        assert cfg.api.base_url == "https://gw.api"
        assert cfg.telemetry.enabled is True
        assert cfg.telemetry.exporter == ExporterType.OTLP_GRPC
        assert cfg.telemetry.endpoint == "localhost:4317"
        assert "gateway" in cfg.extra

    def test_to_gateway_config_roundtrip(self):
        gateway_dict = {
            "common_mcp_gateway_config": {"enkrypt_log_level": "INFO"},
            "plugins": {
                "guardrails": {"provider": "enkrypt", "config": {"api_key": "key1", "base_url": "https://a.com"}},
                "auth": {"provider": "local_apikey", "config": {}},
                "telemetry": {"provider": "opentelemetry", "config": {"url": "localhost:4317", "insecure": True}},
            },
        }
        cfg = from_gateway_config(gateway_dict)
        result = to_gateway_config(cfg)
        assert result["plugins"]["guardrails"]["config"]["api_key"] == "key1"
        assert result["common_mcp_gateway_config"]["enkrypt_log_level"] == "INFO"
