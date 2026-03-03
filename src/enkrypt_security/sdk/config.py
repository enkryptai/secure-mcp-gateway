"""SDK configuration — a single dataclass that fully describes what the SDK does.

Users pass this to ``auto_secure()`` or construct it manually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from enkrypt_security.config.models import ExporterType

if TYPE_CHECKING:
    from enkrypt_security.config.models import EnkryptConfig

from enkrypt_security.telemetry.redaction import PayloadPolicy


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


@dataclass
class SDKConfig:
    """Top-level configuration for the Enkrypt In-Agent SDK."""

    # Identity
    service_name: str = "enkrypt-agent-sdk"

    # Enkrypt AI platform credentials
    enkrypt_api_key: str = ""
    enkrypt_base_url: str = "https://api.enkryptai.com"

    # Guardrail policies
    input_guardrails: GuardrailConfig = field(default_factory=GuardrailConfig)
    output_guardrails: GuardrailConfig = field(default_factory=GuardrailConfig)

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

    def input_policy_dict(self) -> dict[str, Any]:
        """Flatten ``input_guardrails`` into the dict shape providers expect."""
        return {
            "enabled": self.input_guardrails.enabled,
            "policy_name": self.input_guardrails.guardrail_name,
            "block": self.input_guardrails.block,
            "additional_config": self.input_guardrails.additional_config,
        }

    def output_policy_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.output_guardrails.enabled,
            "policy_name": self.output_guardrails.guardrail_name,
            "block": self.output_guardrails.block,
            "additional_config": self.output_guardrails.additional_config,
        }

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

        return cls(
            service_name=ec.telemetry.service_name or "enkrypt-agent-sdk",
            enkrypt_api_key=ec.api.api_key,
            enkrypt_base_url=ec.api.base_url,
            input_guardrails=GuardrailConfig(
                enabled=ec.input_guardrails.enabled,
                guardrail_name=ec.input_guardrails.guardrail_name,
                block=ec.input_guardrails.block,
                additional_config=ec.input_guardrails.additional_config,
            ),
            output_guardrails=GuardrailConfig(
                enabled=ec.output_guardrails.enabled,
                guardrail_name=ec.output_guardrails.guardrail_name,
                block=ec.output_guardrails.block,
                additional_config=ec.output_guardrails.additional_config,
            ),
            exporter=ec.telemetry.exporter,
            otlp_endpoint=ec.telemetry.endpoint,
            otlp_headers=ec.telemetry.headers,
            fail_open=ec.api.fail_open,
            guardrail_timeout_seconds=ec.api.timeout,
            checkpoints=dict(sdk_section.checkpoints),
            frameworks=sdk_section.frameworks,
            provider_keys=pk_dict,
        )

    def to_enkrypt_config(self) -> "EnkryptConfig":
        """Convert this SDKConfig to a shared EnkryptConfig."""
        from enkrypt_security.config.models import (
            EnkryptApiConfig,
            EnkryptConfig,
            GuardrailPolicy,
            SDKSection,
            TelemetryConfig,
            ProviderKeysConfig,
        )

        pk = ProviderKeysConfig(**{
            k: self.provider_keys.get(k, "")
            for k in ProviderKeysConfig.__dataclass_fields__
        })

        return EnkryptConfig(
            api=EnkryptApiConfig(
                api_key=self.enkrypt_api_key,
                base_url=self.enkrypt_base_url,
                fail_open=self.fail_open,
                timeout=self.guardrail_timeout_seconds,
            ),
            input_guardrails=GuardrailPolicy(
                enabled=self.input_guardrails.enabled,
                guardrail_name=self.input_guardrails.guardrail_name,
                block=self.input_guardrails.block,
                additional_config=self.input_guardrails.additional_config,
            ),
            output_guardrails=GuardrailPolicy(
                enabled=self.output_guardrails.enabled,
                guardrail_name=self.output_guardrails.guardrail_name,
                block=self.output_guardrails.block,
                additional_config=self.output_guardrails.additional_config,
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
                frameworks=self.frameworks,
            )},
        )

    @classmethod
    def auto_load(cls) -> "SDKConfig":
        """Load config from shared config file + env vars, then convert to SDKConfig."""
        from enkrypt_security.config import load_config

        ec = load_config()
        return cls.from_enkrypt_config(ec)
