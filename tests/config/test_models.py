"""Tests for config/models.py — shared dataclasses and serialization."""

from enkryptai_agent_security.config.models import (
    AgentConfig,
    CheckpointPolicies,
    DEFAULT_CHECKPOINTS,
    EnkryptApiConfig,
    EnkryptConfig,
    ExporterType,
    GuardrailPolicy,
    HookPlatformConfig,
    HookPolicy,
    ProviderKeysConfig,
    SDKSection,
    TelemetryConfig,
    agent_config_from_dict,
    checkpoint_policies_from_dict,
    hook_platform_from_dict,
    provider_keys_from_dict,
    sdk_section_from_dict,
)


class TestEnkryptApiConfig:
    def test_defaults(self):
        cfg = EnkryptApiConfig()
        assert cfg.api_key == ""
        assert cfg.base_url == "https://api.enkryptai.com"
        assert cfg.fail_open is True
        assert cfg.timeout == 15.0
        assert cfg.ssl_verify is True

    def test_custom_values(self):
        cfg = EnkryptApiConfig(
            api_key="ek_test", base_url="https://custom.api", fail_open=False
        )
        assert cfg.api_key == "ek_test"
        assert cfg.base_url == "https://custom.api"
        assert cfg.fail_open is False


class TestGuardrailPolicy:
    def test_defaults(self):
        p = GuardrailPolicy()
        assert p.enabled is False
        assert p.guardrail_name == ""
        assert p.block == []
        assert p.pii_redaction is False
        assert p.additional_config == {}

    def test_with_values(self):
        p = GuardrailPolicy(
            enabled=True,
            guardrail_name="My Policy",
            block=["injection_attack", "pii"],
            pii_redaction=True,
        )
        assert p.enabled is True
        assert p.block == ["injection_attack", "pii"]

    def test_mutable_defaults_isolated(self):
        p1 = GuardrailPolicy()
        p2 = GuardrailPolicy()
        p1.block.append("toxicity")
        assert p2.block == []


class TestTelemetryConfig:
    def test_defaults(self):
        t = TelemetryConfig()
        assert t.enabled is False
        assert t.exporter == ExporterType.NONE
        assert t.service_name == "enkryptai-agent-security"

    def test_exporter_enum(self):
        assert ExporterType.OTLP_GRPC.value == "otlp_grpc"
        assert ExporterType.OTLP_HTTP.value == "otlp_http"
        assert ExporterType.CONSOLE.value == "console"
        assert ExporterType.NONE.value == "none"


class TestSDKSection:
    def test_defaults(self):
        sdk = SDKSection()
        assert sdk.checkpoints == DEFAULT_CHECKPOINTS
        assert sdk.frameworks is None
        assert sdk.payload_policy == {"max_str_len": 4096, "max_attr_count": 64}

    def test_mutable_defaults_isolated(self):
        s1 = SDKSection()
        s2 = SDKSection()
        s1.checkpoints["pre_llm"] = False
        assert s2.checkpoints["pre_llm"] is True

    def test_from_dict(self):
        data = {
            "provider_keys": {"OPENAI_API_KEY": "sk-test"},
            "checkpoints": {"pre_llm": False, "pre_tool": True, "post_tool": True, "post_llm": False},
            "frameworks": ["langchain"],
        }
        sdk = sdk_section_from_dict(data)
        assert sdk.provider_keys.OPENAI_API_KEY == "sk-test"
        assert sdk.checkpoints["pre_llm"] is False
        assert sdk.frameworks == ["langchain"]


class TestProviderKeysConfig:
    def test_defaults_empty(self):
        pk = ProviderKeysConfig()
        assert pk.OPENAI_API_KEY == ""
        assert pk.ANTHROPIC_API_KEY == ""

    def test_from_dict(self):
        pk = provider_keys_from_dict({"OPENAI_API_KEY": "sk-123", "unknown_field": "ignored"})
        assert pk.OPENAI_API_KEY == "sk-123"
        assert pk.ANTHROPIC_API_KEY == ""


class TestHookModels:
    def test_hook_policy_defaults(self):
        hp = HookPolicy()
        assert hp.enabled is False
        assert hp.guardrail_name == ""
        assert hp.block == []

    def test_hook_platform_from_dict(self):
        data = {
            "sensitive_tools": ["Bash", "Write"],
            "sensitive_file_patterns": ["*.env"],
            "beforeSubmitPrompt": {
                "enabled": True,
                "guardrail_name": "Test",
                "block": ["injection_attack"],
            },
        }
        hpc = hook_platform_from_dict(data)
        assert hpc.sensitive_tools == ["Bash", "Write"]
        assert hpc.sensitive_file_patterns == ["*.env"]
        assert "beforeSubmitPrompt" in hpc.policies
        assert hpc.policies["beforeSubmitPrompt"].enabled is True
        assert hpc.policies["beforeSubmitPrompt"].block == ["injection_attack"]


class TestDefaultCheckpoints:
    def test_expected_keys(self):
        assert set(DEFAULT_CHECKPOINTS.keys()) == {"pre_llm", "pre_tool", "post_tool", "post_llm"}
        assert DEFAULT_CHECKPOINTS["pre_llm"] is True
        assert DEFAULT_CHECKPOINTS["pre_tool"] is True
        assert DEFAULT_CHECKPOINTS["post_tool"] is False
        assert DEFAULT_CHECKPOINTS["post_llm"] is False


class TestEnkryptConfig:
    def test_defaults(self):
        cfg = EnkryptConfig()
        assert cfg.api.api_key == ""
        assert cfg.telemetry.enabled is False
        assert cfg.extra == {}

    def test_get_sdk_returns_default(self):
        cfg = EnkryptConfig()
        sdk = cfg.get_sdk()
        assert isinstance(sdk, SDKSection)
        assert sdk.checkpoints == DEFAULT_CHECKPOINTS

    def test_get_sdk_from_dict(self):
        cfg = EnkryptConfig(extra={
            "sdk": {"checkpoints": {"pre_llm": False, "pre_tool": False, "post_tool": True, "post_llm": True}}
        })
        sdk = cfg.get_sdk()
        assert sdk.checkpoints["pre_llm"] is False
        assert sdk.checkpoints["post_tool"] is True

    def test_get_sdk_from_section(self):
        section = SDKSection(frameworks=["openai"])
        cfg = EnkryptConfig(extra={"sdk": section})
        sdk = cfg.get_sdk()
        assert sdk.frameworks == ["openai"]

    def test_get_hooks_empty(self):
        cfg = EnkryptConfig()
        assert cfg.get_hooks() == {}

    def test_get_hook_platform(self):
        hpc = HookPlatformConfig(sensitive_tools=["Bash"])
        cfg = EnkryptConfig(extra={"hooks": {"cursor": hpc}})
        result = cfg.get_hook_platform("cursor")
        assert result is not None
        assert result.sensitive_tools == ["Bash"]
        assert cfg.get_hook_platform("nonexistent") is None

    def test_to_dict_roundtrip(self):
        cfg = EnkryptConfig(
            api=EnkryptApiConfig(api_key="test_key"),
            telemetry=TelemetryConfig(enabled=True, exporter=ExporterType.OTLP_GRPC),
        )
        d = cfg.to_dict()
        assert d["api"]["api_key"] == "test_key"
        assert d["telemetry"]["exporter"] == "otlp_grpc"


class TestCheckpointPolicies:
    def test_defaults_all_none(self):
        cp = CheckpointPolicies()
        assert cp.pre_llm is None
        assert cp.pre_tool is None
        assert cp.post_tool is None
        assert cp.post_llm is None

    def test_from_dict_partial(self):
        data = {
            "pre_llm": {"guardrail_name": "LLM Policy", "block": ["injection_attack", "bias"]},
            "pre_tool": {"guardrail_name": "Tool Policy", "block": ["injection_attack"]},
        }
        cp = checkpoint_policies_from_dict(data)
        assert cp.pre_llm is not None
        assert cp.pre_llm.guardrail_name == "LLM Policy"
        assert cp.pre_llm.block == ["injection_attack", "bias"]
        assert cp.pre_tool is not None
        assert cp.pre_tool.block == ["injection_attack"]
        assert cp.post_tool is None
        assert cp.post_llm is None

    def test_from_dict_empty(self):
        cp = checkpoint_policies_from_dict({})
        assert cp.pre_llm is None


class TestAgentConfig:
    def test_defaults(self):
        ac = AgentConfig()
        assert ac.checkpoints == {}
        assert ac.guardrails.pre_llm is None

    def test_from_dict(self):
        data = {
            "checkpoints": {"pre_llm": True, "pre_tool": False},
            "guardrails": {
                "pre_llm": {"guardrail_name": "Strict", "block": ["pii", "toxicity"]},
            },
        }
        ac = agent_config_from_dict(data)
        assert ac.checkpoints == {"pre_llm": True, "pre_tool": False}
        assert ac.guardrails.pre_llm is not None
        assert ac.guardrails.pre_llm.block == ["pii", "toxicity"]
        assert ac.guardrails.pre_tool is None


class TestSDKSectionWithAgents:
    def test_from_dict_with_guardrails_and_agents(self):
        data = {
            "checkpoints": {"pre_llm": True, "pre_tool": True, "post_tool": False, "post_llm": False},
            "guardrails": {
                "pre_llm": {"guardrail_name": "LLM", "block": ["bias"]},
            },
            "agents": {
                "customer_agent": {
                    "checkpoints": {"post_tool": True},
                    "guardrails": {
                        "pre_llm": {"guardrail_name": "Customer LLM", "block": ["pii", "bias"]},
                    },
                },
            },
        }
        sdk = sdk_section_from_dict(data)
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.block == ["bias"]
        assert "customer_agent" in sdk.agents
        agent = sdk.agents["customer_agent"]
        assert agent.checkpoints == {"post_tool": True}
        assert agent.guardrails.pre_llm is not None
        assert agent.guardrails.pre_llm.block == ["pii", "bias"]

    def test_backwards_compat_checkpoint_policies_key(self):
        """Old configs using 'checkpoint_policies' key should still work."""
        data = {
            "checkpoint_policies": {
                "pre_llm": {"guardrail_name": "Old", "block": ["pii"]},
            },
            "agents": {
                "agent_x": {
                    "checkpoint_policies": {
                        "pre_tool": {"guardrail_name": "OldAgent", "block": ["bias"]},
                    },
                },
            },
        }
        sdk = sdk_section_from_dict(data)
        assert sdk.guardrails.pre_llm is not None
        assert sdk.guardrails.pre_llm.guardrail_name == "Old"
        assert sdk.agents["agent_x"].guardrails.pre_tool is not None
        assert sdk.agents["agent_x"].guardrails.pre_tool.guardrail_name == "OldAgent"

    def test_to_dict_roundtrip_with_agents(self):
        sdk = SDKSection(
            guardrails=CheckpointPolicies(
                pre_llm=GuardrailPolicy(enabled=True, guardrail_name="LLM", block=["bias"]),
            ),
            agents={
                "agent_a": AgentConfig(
                    checkpoints={"pre_llm": False},
                    guardrails=CheckpointPolicies(
                        pre_tool=GuardrailPolicy(enabled=True, guardrail_name="Tool", block=["pii"]),
                    ),
                ),
            },
        )
        cfg = EnkryptConfig(extra={"sdk": sdk})
        d = cfg.to_dict()
        assert d["sdk"]["guardrails"]["pre_llm"]["guardrail_name"] == "LLM"
        assert d["sdk"]["agents"]["agent_a"]["checkpoints"] == {"pre_llm": False}
        assert d["sdk"]["agents"]["agent_a"]["guardrails"]["pre_tool"]["block"] == ["pii"]
