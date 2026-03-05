"""Unified configuration models shared across Gateway, SDK, and Hooks.

Field naming is standardized:
  - ``guardrail_name``  (not ``policy_name``)
  - ``fail_open``       (not ``fail_silently``)
  - ``base_url``        (domain only, client appends endpoint paths)
  - ``timeout``         (seconds, one name everywhere)
  - ``ssl_verify``      (exposed in all products)

Product-specific sections live under dedicated keys:
  - ``gateway`` — MCP gateway settings
  - ``sdk``     — in-agent SDK settings (checkpoints, provider keys, …)
  - ``hooks``   — per-platform hook policies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# =========================================================================
# Enums
# =========================================================================

class ExporterType(str, Enum):
    """Telemetry export destination."""

    NONE = "none"
    CONSOLE = "console"
    OTLP_GRPC = "otlp_grpc"
    OTLP_HTTP = "otlp_http"


# =========================================================================
# Shared / top-level models
# =========================================================================

@dataclass
class EnkryptApiConfig:
    """Enkrypt API connection settings — shared by all products."""

    api_key: str = ""
    base_url: str = "https://api.enkryptai.com"
    fail_open: bool = True
    timeout: float = 15.0
    ssl_verify: bool = True


@dataclass
class GuardrailPolicy:
    """Guardrail configuration for a single checkpoint or hook event."""

    enabled: bool = False
    guardrail_name: str = ""
    block: list[str] = field(default_factory=list)
    pii_redaction: bool = False
    additional_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class TelemetryConfig:
    """Telemetry / observability settings."""

    enabled: bool = False
    exporter: ExporterType = ExporterType.NONE
    endpoint: str = ""
    service_name: str = "enkryptai-agent-security"
    headers: dict[str, str] = field(default_factory=dict)
    insecure: bool = False


# =========================================================================
# SDK-specific models
# =========================================================================

@dataclass
class ProviderKeysConfig:
    """LLM provider API keys that the SDK injects into env vars at startup."""

    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = ""
    AZURE_OPENAI_API_KEY: str = ""
    AZURE_OPENAI_ENDPOINT: str = ""
    GOOGLE_API_KEY: str = ""


DEFAULT_CHECKPOINTS: dict[str, bool] = {
    "pre_llm": True,
    "pre_tool": True,
    "post_tool": False,
    "post_llm": False,
}


@dataclass
class CheckpointPolicies:
    """Per-checkpoint guardrail policies for the SDK.

    Each field maps to a checkpoint in the SDK pipeline.
    ``None`` means the checkpoint has no guardrail (disabled).
    """

    pre_llm: GuardrailPolicy | None = None
    pre_tool: GuardrailPolicy | None = None
    post_tool: GuardrailPolicy | None = None
    post_llm: GuardrailPolicy | None = None


@dataclass
class AgentConfig:
    """Per-agent overrides within the SDK section.

    Each named agent can specify its own checkpoint enable/disable flags
    and its own per-checkpoint guardrail policies.  Anything left unset
    falls back to the SDK-level defaults.
    """

    checkpoints: dict[str, bool] = field(default_factory=dict)
    guardrails: CheckpointPolicies = field(default_factory=CheckpointPolicies)


@dataclass
class SDKSection:
    """SDK-specific configuration stored under ``EnkryptConfig.extra["sdk"]``."""

    provider_keys: ProviderKeysConfig = field(default_factory=ProviderKeysConfig)
    checkpoints: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CHECKPOINTS))
    guardrails: CheckpointPolicies = field(default_factory=CheckpointPolicies)
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    frameworks: list[str] | None = None
    payload_policy: dict[str, Any] = field(
        default_factory=lambda: {"max_str_len": 4096, "max_attr_count": 64}
    )


# =========================================================================
# Hooks-specific models
# =========================================================================

@dataclass
class HookPolicy:
    """A single hook-point guardrail policy (e.g. ``beforeSubmitPrompt``)."""

    enabled: bool = False
    guardrail_name: str = ""
    block: list[str] = field(default_factory=list)


@dataclass
class HookPlatformConfig:
    """Per-platform hook configuration stored under ``hooks.<platform>``."""

    sensitive_tools: list[str] = field(default_factory=list)
    sensitive_file_patterns: list[str] = field(default_factory=list)
    policies: dict[str, HookPolicy] = field(default_factory=dict)


# =========================================================================
# Top-level config
# =========================================================================

@dataclass
class EnkryptConfig:
    """Top-level configuration consumed by all Enkrypt security products.

    Product-specific sections are accessible via typed helpers
    *and* via the raw ``extra`` dict for forward-compatibility.
    """

    api: EnkryptApiConfig = field(default_factory=EnkryptApiConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)

    extra: dict[str, Any] = field(default_factory=dict)

    # -- typed accessors for product sections --

    def get_sdk(self) -> SDKSection:
        raw = self.extra.get("sdk")
        if isinstance(raw, SDKSection):
            return raw
        if isinstance(raw, dict):
            return sdk_section_from_dict(raw)
        return SDKSection()

    def get_hooks(self) -> dict[str, HookPlatformConfig]:
        raw = self.extra.get("hooks")
        if not isinstance(raw, dict):
            return {}
        result: dict[str, HookPlatformConfig] = {}
        for platform, val in raw.items():
            if isinstance(val, HookPlatformConfig):
                result[platform] = val
            elif isinstance(val, dict):
                result[platform] = hook_platform_from_dict(val)
        return result

    def get_hook_platform(self, platform: str) -> HookPlatformConfig | None:
        return self.get_hooks().get(platform)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON export."""
        d: dict[str, Any] = {
            "api": _api_to_dict(self.api),
            "telemetry": _telemetry_to_dict(self.telemetry),
        }
        for key, val in self.extra.items():
            if key == "sdk" and isinstance(val, SDKSection):
                d["sdk"] = _sdk_to_dict(val)
            elif key == "hooks" and isinstance(val, dict):
                d["hooks"] = _hooks_to_dict(val)
            else:
                d[key] = val
        return d


# =========================================================================
# Serialisation helpers
# =========================================================================

def _api_to_dict(c: EnkryptApiConfig) -> dict[str, Any]:
    return {
        "api_key": c.api_key,
        "base_url": c.base_url,
        "fail_open": c.fail_open,
        "timeout": c.timeout,
        "ssl_verify": c.ssl_verify,
    }


def _guardrail_to_dict(p: GuardrailPolicy) -> dict[str, Any]:
    d: dict[str, Any] = {
        "enabled": p.enabled,
        "guardrail_name": p.guardrail_name,
        "block": p.block,
        "pii_redaction": p.pii_redaction,
    }
    if p.additional_config:
        d["additional_config"] = p.additional_config
    return d


def _telemetry_to_dict(t: TelemetryConfig) -> dict[str, Any]:
    d: dict[str, Any] = {
        "enabled": t.enabled,
        "exporter": t.exporter.value,
        "endpoint": t.endpoint,
        "service_name": t.service_name,
    }
    if t.headers:
        d["headers"] = t.headers
    if t.insecure:
        d["insecure"] = t.insecure
    return d


def _provider_keys_to_dict(pk: ProviderKeysConfig) -> dict[str, str]:
    return {k: v for k, v in pk.__dict__.items() if v}


def _checkpoint_policies_to_dict(cp: CheckpointPolicies) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for name in ("pre_llm", "pre_tool", "post_tool", "post_llm"):
        policy = getattr(cp, name)
        if policy is not None:
            d[name] = _guardrail_to_dict(policy)
    return d


def _agent_config_to_dict(ac: AgentConfig) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if ac.checkpoints:
        d["checkpoints"] = ac.checkpoints
    cp = _checkpoint_policies_to_dict(ac.guardrails)
    if cp:
        d["guardrails"] = cp
    return d


def _sdk_to_dict(s: SDKSection) -> dict[str, Any]:
    d: dict[str, Any] = {
        "provider_keys": _provider_keys_to_dict(s.provider_keys),
        "checkpoints": s.checkpoints,
    }
    cp = _checkpoint_policies_to_dict(s.guardrails)
    if cp:
        d["guardrails"] = cp
    if s.agents:
        d["agents"] = {name: _agent_config_to_dict(ac) for name, ac in s.agents.items()}
    if s.frameworks is not None:
        d["frameworks"] = s.frameworks
    if s.payload_policy:
        d["payload_policy"] = s.payload_policy
    return d


def _hook_policy_to_dict(hp: HookPolicy) -> dict[str, Any]:
    return {"enabled": hp.enabled, "guardrail_name": hp.guardrail_name, "block": hp.block}


def _hook_platform_to_dict(hpc: HookPlatformConfig) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if hpc.sensitive_tools:
        d["sensitive_tools"] = hpc.sensitive_tools
    if hpc.sensitive_file_patterns:
        d["sensitive_file_patterns"] = hpc.sensitive_file_patterns
    for name, policy in hpc.policies.items():
        d[name] = _hook_policy_to_dict(policy)
    return d


def _hooks_to_dict(hooks: dict[str, Any]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for platform, val in hooks.items():
        if isinstance(val, HookPlatformConfig):
            d[platform] = _hook_platform_to_dict(val)
        elif isinstance(val, dict):
            d[platform] = val
        else:
            d[platform] = val
    return d


# =========================================================================
# Deserialization helpers
# =========================================================================

def provider_keys_from_dict(data: dict[str, Any]) -> ProviderKeysConfig:
    return ProviderKeysConfig(**{
        k: str(data.get(k, ""))
        for k in ProviderKeysConfig.__dataclass_fields__
    })


def _guardrail_policy_from_dict(data: dict[str, Any]) -> GuardrailPolicy:
    return GuardrailPolicy(
        enabled=bool(data.get("enabled", True)),
        guardrail_name=str(data.get("guardrail_name", "")),
        block=list(data.get("block", [])),
        pii_redaction=bool(data.get("pii_redaction", False)),
        additional_config=dict(data.get("additional_config", {})),
    )


def checkpoint_policies_from_dict(data: dict[str, Any]) -> CheckpointPolicies:
    cp = CheckpointPolicies()
    for name in ("pre_llm", "pre_tool", "post_tool", "post_llm"):
        raw = data.get(name)
        if isinstance(raw, dict):
            setattr(cp, name, _guardrail_policy_from_dict(raw))
    return cp


def agent_config_from_dict(data: dict[str, Any]) -> AgentConfig:
    raw_gr = data.get("guardrails") or data.get("checkpoint_policies", {})
    return AgentConfig(
        checkpoints=data.get("checkpoints", {}),
        guardrails=checkpoint_policies_from_dict(raw_gr),
    )


def sdk_section_from_dict(data: dict[str, Any]) -> SDKSection:
    pk = provider_keys_from_dict(data.get("provider_keys", {}))
    agents_raw = data.get("agents", {})
    agents = {name: agent_config_from_dict(v) for name, v in agents_raw.items() if isinstance(v, dict)}
    return SDKSection(
        provider_keys=pk,
        checkpoints=data.get("checkpoints", dict(DEFAULT_CHECKPOINTS)),
        guardrails=checkpoint_policies_from_dict(data.get("guardrails") or data.get("checkpoint_policies", {})),
        agents=agents,
        frameworks=data.get("frameworks"),
        payload_policy=data.get("payload_policy", {"max_str_len": 4096, "max_attr_count": 64}),
    )


def hook_policy_from_dict(data: dict[str, Any]) -> HookPolicy:
    return HookPolicy(
        enabled=bool(data.get("enabled", False)),
        guardrail_name=str(data.get("guardrail_name", "")),
        block=list(data.get("block", [])),
    )


def hook_platform_from_dict(data: dict[str, Any]) -> HookPlatformConfig:
    _META_KEYS = {"sensitive_tools", "sensitive_file_patterns"}
    policies: dict[str, HookPolicy] = {}
    for k, v in data.items():
        if k not in _META_KEYS and isinstance(v, dict):
            policies[k] = hook_policy_from_dict(v)
    return HookPlatformConfig(
        sensitive_tools=list(data.get("sensitive_tools", [])),
        sensitive_file_patterns=list(data.get("sensitive_file_patterns", [])),
        policies=policies,
    )
