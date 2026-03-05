"""Enkrypt configuration — unified models and loader.

Usage::

    from enkryptai_agent_security.config import load_config, EnkryptConfig

    # Auto-discover from file + env vars
    config = load_config()

    # Or build programmatically
    config = EnkryptConfig(
        api=EnkryptApiConfig(api_key="ek_...", base_url="https://api.enkryptai.com"),
        input_guardrails=GuardrailPolicy(
            enabled=True,
            guardrail_name="My Policy",
            block=["injection_attack", "pii"],
        ),
    )
"""

from enkryptai_agent_security.config.loader import (
    from_gateway_config,
    load_config,
    to_gateway_config,
)
from enkryptai_agent_security.config.models import (
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
)

__all__ = [
    "DEFAULT_CHECKPOINTS",
    "EnkryptApiConfig",
    "EnkryptConfig",
    "ExporterType",
    "GuardrailPolicy",
    "HookPlatformConfig",
    "HookPolicy",
    "ProviderKeysConfig",
    "SDKSection",
    "TelemetryConfig",
    "from_gateway_config",
    "load_config",
    "to_gateway_config",
]
