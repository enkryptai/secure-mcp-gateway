"""Tests for auto_secure initialization (no framework dependencies needed)."""

from enkryptai_agent_security.sdk import _state
from enkryptai_agent_security.sdk.auto import auto_secure, available_frameworks
from enkryptai_agent_security.sdk.config import AgentSDKConfig, GuardrailConfig, SDKConfig


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


class TestAutoSecurePerAgent:
    def setup_method(self):
        _state.reset()

    def test_per_agent_engines_created(self):
        cfg = SDKConfig(
            agents={
                "agent_a": AgentSDKConfig(checkpoints={"pre_llm": False}),
                "agent_b": AgentSDKConfig(checkpoints={"post_tool": True}),
            }
        )
        auto_secure(cfg)
        default = _state.get_guard_engine()
        agent_a = _state.get_guard_engine("agent_a")
        agent_b = _state.get_guard_engine("agent_b")
        assert default is not None
        assert agent_a is not None
        assert agent_b is not None
        assert agent_a is not default
        assert agent_b is not default
        # agent_a has pre_llm disabled
        assert agent_a.check_pre_llm is False
        # agent_b has post_tool enabled
        assert agent_b.check_post_tool is True

    def test_unknown_agent_returns_default(self):
        auto_secure(SDKConfig())
        default = _state.get_guard_engine()
        unknown = _state.get_guard_engine("nonexistent")
        assert unknown is default

    def teardown_method(self):
        _state.reset()


class TestAutoSecureAgentId:
    def setup_method(self):
        _state.reset()

    def test_agent_id_stored_in_config(self):
        auto_secure(SDKConfig(agent_id="my-app"))
        cfg = _state.get_config()
        assert cfg is not None
        assert cfg.agent_id == "my-app"

    def test_agent_id_default_empty(self):
        auto_secure(SDKConfig())
        cfg = _state.get_config()
        assert cfg is not None
        assert cfg.agent_id == ""

    def test_agent_id_keyword_arg(self):
        auto_secure(agent_id="billing-agent")
        cfg = _state.get_config()
        assert cfg is not None
        assert cfg.agent_id == "billing-agent"

    def teardown_method(self):
        _state.reset()


class TestAvailableFrameworks:
    def test_returns_list(self):
        result = available_frameworks()
        assert isinstance(result, list)


class TestSDKConfigPolicyForCheckpoint:
    def test_global_guardrail_policy(self):
        cfg = SDKConfig(
            guardrails={
                "pre_llm": GuardrailConfig(
                    enabled=True, guardrail_name="LLM Policy", block=["pii"]
                ),
                "pre_tool": GuardrailConfig(
                    enabled=True, guardrail_name="Tool Policy", block=["injection_attack"]
                ),
            },
        )
        policy = cfg.policy_for_checkpoint("pre_llm")
        assert policy["policy_name"] == "LLM Policy"
        assert policy["block"] == ["pii"]
        policy2 = cfg.policy_for_checkpoint("pre_tool")
        assert policy2["policy_name"] == "Tool Policy"

    def test_unconfigured_checkpoint_returns_empty(self):
        cfg = SDKConfig(
            guardrails={
                "pre_llm": GuardrailConfig(enabled=True, guardrail_name="Only LLM", block=["pii"]),
            },
        )
        # pre_tool not configured → empty dict (disabled)
        policy = cfg.policy_for_checkpoint("pre_tool")
        assert policy == {}
        # post_llm not configured → empty dict (disabled)
        policy2 = cfg.policy_for_checkpoint("post_llm")
        assert policy2 == {}

    def test_agent_guardrail_overrides_global(self):
        cfg = SDKConfig(
            guardrails={
                "pre_llm": GuardrailConfig(
                    enabled=True, guardrail_name="Global LLM", block=["bias"]
                ),
                "pre_tool": GuardrailConfig(
                    enabled=True, guardrail_name="Global Tool", block=["pii"]
                ),
            },
            agents={
                "strict_agent": AgentSDKConfig(
                    guardrails={
                        "pre_llm": GuardrailConfig(
                            enabled=True, guardrail_name="Agent LLM", block=["bias", "toxicity", "pii"]
                        ),
                    },
                ),
            },
        )
        # Default agent uses global policy
        policy = cfg.policy_for_checkpoint("pre_llm")
        assert policy["policy_name"] == "Global LLM"
        # Named agent uses agent-specific policy
        policy2 = cfg.policy_for_checkpoint("pre_llm", agent_name="strict_agent")
        assert policy2["policy_name"] == "Agent LLM"
        assert policy2["block"] == ["bias", "toxicity", "pii"]
        # Named agent, different checkpoint, falls back to global
        policy3 = cfg.policy_for_checkpoint("pre_tool", agent_name="strict_agent")
        assert policy3["policy_name"] == "Global Tool"
        # Named agent, unconfigured checkpoint → empty (disabled)
        policy4 = cfg.policy_for_checkpoint("post_llm", agent_name="strict_agent")
        assert policy4 == {}

    def test_checkpoints_for_agent(self):
        cfg = SDKConfig(
            checkpoints={"pre_llm": True, "pre_tool": True, "post_tool": False, "post_llm": False},
            agents={
                "verbose": AgentSDKConfig(checkpoints={"post_tool": True, "post_llm": True}),
            },
        )
        merged = cfg.checkpoints_for_agent("verbose")
        assert merged == {"pre_llm": True, "pre_tool": True, "post_tool": True, "post_llm": True}
        # Default (no agent)
        default = cfg.checkpoints_for_agent(None)
        assert default == {"pre_llm": True, "pre_tool": True, "post_tool": False, "post_llm": False}
