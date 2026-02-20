"""SDK configuration — a single dataclass that fully describes what the SDK does.

Users pass this to ``auto_secure()`` or construct it manually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from enkrypt_agent_sdk.otel_setup import ExporterType
from enkrypt_agent_sdk.redaction import PayloadPolicy


@dataclass
class GuardrailConfig:
    """Mirrors the per-server policy shape from the Secure MCP Gateway config."""

    enabled: bool = False
    policy_name: str = ""
    block: list[str] = field(default_factory=list)
    additional_config: dict[str, Any] = field(default_factory=dict)


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

    def input_policy_dict(self) -> dict[str, Any]:
        """Flatten ``input_guardrails`` into the dict shape providers expect."""
        return {
            "enabled": self.input_guardrails.enabled,
            "policy_name": self.input_guardrails.policy_name,
            "block": self.input_guardrails.block,
            "additional_config": self.input_guardrails.additional_config,
        }

    def output_policy_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.output_guardrails.enabled,
            "policy_name": self.output_guardrails.policy_name,
            "block": self.output_guardrails.block,
            "additional_config": self.output_guardrails.additional_config,
        }
