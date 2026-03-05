"""SDK configuration — a single dataclass that fully describes what the SDK does.

Users pass this to ``auto_secure()`` or construct it manually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from enkryptai_agent_security.config.models import ExporterType

if TYPE_CHECKING:
    from enkryptai_agent_security.config.models import EnkryptConfig

from enkryptai_agent_security.telemetry.redaction import PayloadPolicy


@dataclass
class GuardrailConfig:
    """Mirrors the per-server policy shape from the Secure MCP Gateway config."""

    enabled: bool = False
    guardrail_name: str = ""
    block: list[str] = field(default_factory=list)
    additional_config: dict[str, Any] = field(default_factory=dict)

    @property
    def policy_name(self) -> str:
        """Deprecated alias for ``guardrail_name``."""
        return self.guardrail_name

    @policy_name.setter
    def policy_name(self, value: str) -> None:
        self.guardrail_name = value

    def to_policy_dict(self) -> dict[str, Any]:
        """Flatten into the dict shape guardrail providers expect."""
        return {
            "enabled": self.enabled,
            "policy_name": self.guardrail_name,
            "block": self.block,
            "additional_config": self.additional_config,
        }


@dataclass
class AgentSDKConfig:
    """Per-agent overrides within SDKConfig."""

    checkpoints: dict[str, bool] = field(default_factory=dict)
    guardrails: dict[str, GuardrailConfig] = field(default_factory=dict)


@dataclass
class SDKConfig:
    """Top-level configuration for the Enkrypt In-Agent SDK."""

    # Identity
    service_name: str = "enkrypt-agent-sdk"
    agent_id: str = ""

    # Enkrypt AI platform credentials
    enkrypt_api_key: str = ""
    enkrypt_base_url: str = "https://api.enkryptai.com"

    # Telemetry
    exporter: ExporterType = ExporterType.CONSOLE
    otlp_endpoint: str = ""
    otlp_headers: dict[str, str] = field(default_factory=dict)

    # Payload safety
    payload_policy: PayloadPolicy = field(default_factory=PayloadPolicy)

    # Behaviour
    guardrail_timeout_seconds: float = 15.0
    fail_open: bool = True

    # Checkpoint configuration (which pipeline stages run guardrails)
    checkpoints: dict[str, bool] = field(default_factory=lambda: {
        "pre_llm": True,
        "pre_tool": True,
        "post_tool": False,
        "post_llm": False,
    })

    # Framework selection (None = auto-detect all)
    frameworks: list[str] | None = None

    # LLM provider API keys (injected into env at startup)
    provider_keys: dict[str, str] = field(default_factory=dict)

    # Per-checkpoint guardrail policies (keyed by checkpoint name)
    guardrails: dict[str, GuardrailConfig] = field(default_factory=dict)

    # Per-agent overrides (keyed by agent name)
    agents: dict[str, AgentSDKConfig] = field(default_factory=dict)

    def policy_for_checkpoint(
        self, checkpoint: str, *, agent_name: str | None = None,
    ) -> dict[str, Any]:
        """Resolve the guardrail policy dict for a checkpoint.

        Fallback chain:
          1. agent's guardrails[checkpoint]
          2. global guardrails[checkpoint]
          3. disabled (empty dict)
        """
        # 1. Agent-specific override
        if agent_name and agent_name in self.agents:
            agent_cfg = self.agents[agent_name]
            if checkpoint in agent_cfg.guardrails:
                return agent_cfg.guardrails[checkpoint].to_policy_dict()

        # 2. Global per-checkpoint
        if checkpoint in self.guardrails:
            return self.guardrails[checkpoint].to_policy_dict()

        # 3. Disabled
        return {}

    def checkpoints_for_agent(self, agent_name: str | None = None) -> dict[str, bool]:
        """Resolve checkpoint enable/disable flags for an agent.

        Agent-specific flags are merged on top of the global defaults.
        """
        merged = dict(self.checkpoints)
        if agent_name and agent_name in self.agents:
            merged.update(self.agents[agent_name].checkpoints)
        return merged

    def inject_provider_keys(self) -> None:
        """Set non-empty provider keys as env vars (env takes precedence)."""
        import os
        for key, val in self.provider_keys.items():
            if val and not os.environ.get(key):
                os.environ[key] = val

    # ------------------------------------------------------------------
    # Bridge to/from the shared EnkryptConfig model
    # ------------------------------------------------------------------

    @classmethod
    def from_enkrypt_config(cls, ec: "EnkryptConfig") -> "SDKConfig":
        """Build an SDKConfig from a shared EnkryptConfig."""
        sdk_section = ec.get_sdk()
        pk_dict: dict[str, str] = {}
        for k, v in sdk_section.provider_keys.__dict__.items():
            if v:
                pk_dict[k] = v

        # Convert CheckpointPolicies → flat dict[str, GuardrailConfig]
        gr_policies: dict[str, GuardrailConfig] = {}
        for name in ("pre_llm", "pre_tool", "post_tool", "post_llm"):
            gp = getattr(sdk_section.guardrails, name)
            if gp is not None:
                gr_policies[name] = GuardrailConfig(
                    enabled=gp.enabled,
                    guardrail_name=gp.guardrail_name,
                    block=gp.block,
                    additional_config=gp.additional_config,
                )

        # Convert per-agent configs
        agents: dict[str, AgentSDKConfig] = {}
        for agent_name, ac in sdk_section.agents.items():
            agent_gr: dict[str, GuardrailConfig] = {}
            for name in ("pre_llm", "pre_tool", "post_tool", "post_llm"):
                gp = getattr(ac.guardrails, name)
                if gp is not None:
                    agent_gr[name] = GuardrailConfig(
                        enabled=gp.enabled,
                        guardrail_name=gp.guardrail_name,
                        block=gp.block,
                        additional_config=gp.additional_config,
                    )
            agents[agent_name] = AgentSDKConfig(
                checkpoints=dict(ac.checkpoints),
                guardrails=agent_gr,
            )

        return cls(
            service_name=ec.telemetry.service_name or "enkrypt-agent-sdk",
            enkrypt_api_key=ec.api.api_key,
            enkrypt_base_url=ec.api.base_url,
            exporter=ec.telemetry.exporter,
            otlp_endpoint=ec.telemetry.endpoint,
            otlp_headers=ec.telemetry.headers,
            fail_open=ec.api.fail_open,
            guardrail_timeout_seconds=ec.api.timeout,
            checkpoints=dict(sdk_section.checkpoints),
            guardrails=gr_policies,
            agents=agents,
            frameworks=sdk_section.frameworks,
            provider_keys=pk_dict,
        )

    def to_enkrypt_config(self) -> "EnkryptConfig":
        """Convert this SDKConfig to a shared EnkryptConfig."""
        from enkryptai_agent_security.config.models import (
            AgentConfig,
            CheckpointPolicies,
            EnkryptApiConfig,
            EnkryptConfig,
            GuardrailPolicy,
            SDKSection,
            TelemetryConfig,
            ProviderKeysConfig,
        )

        def _gc_to_gp(gc: GuardrailConfig) -> GuardrailPolicy:
            return GuardrailPolicy(
                enabled=gc.enabled,
                guardrail_name=gc.guardrail_name,
                block=gc.block,
                additional_config=gc.additional_config,
            )

        def _dict_to_cp(d: dict[str, GuardrailConfig]) -> CheckpointPolicies:
            cp = CheckpointPolicies()
            for name, gc in d.items():
                setattr(cp, name, _gc_to_gp(gc))
            return cp

        pk = ProviderKeysConfig(**{
            k: self.provider_keys.get(k, "")
            for k in ProviderKeysConfig.__dataclass_fields__
        })

        agents = {
            name: AgentConfig(
                checkpoints=dict(ac.checkpoints),
                guardrails=_dict_to_cp(ac.guardrails),
            )
            for name, ac in self.agents.items()
        }

        return EnkryptConfig(
            api=EnkryptApiConfig(
                api_key=self.enkrypt_api_key,
                base_url=self.enkrypt_base_url,
                fail_open=self.fail_open,
                timeout=self.guardrail_timeout_seconds,
            ),
            telemetry=TelemetryConfig(
                exporter=self.exporter,
                endpoint=self.otlp_endpoint,
                service_name=self.service_name,
                headers=self.otlp_headers,
            ),
            extra={"sdk": SDKSection(
                provider_keys=pk,
                checkpoints=self.checkpoints,
                guardrails=_dict_to_cp(self.guardrails),
                agents=agents,
                frameworks=self.frameworks,
            )},
        )

    @classmethod
    def auto_load(cls) -> "SDKConfig":
        """Load config from shared config file + env vars, then convert to SDKConfig."""
        from enkryptai_agent_security.config import load_config

        ec = load_config()
        return cls.from_enkrypt_config(ec)
