"""``auto_secure()`` — the one-liner entry point for the Enkrypt In-Agent SDK.

Initialises telemetry, guardrails, and auto-patches every detected framework
in a single call.  Modelled after AgentSight's ``auto_instrument()`` but
adds guardrail enforcement to the instrumentation.

Usage — keyword-argument shorthand::

    from enkrypt_agent_sdk import auto_secure

    auto_secure(
        enkrypt_api_key="ek-...",
        guardrail_policy="Sample Airline Guardrail",
        block=["injection_attack", "pii", "toxicity"],
        pii_redaction=True,
    )

Usage — explicit config::

    from enkrypt_agent_sdk import auto_secure, SDKConfig, GuardrailConfig

    auto_secure(SDKConfig(
        enkrypt_api_key="ek-...",
        input_guardrails=GuardrailConfig(enabled=True, policy_name="My Policy",
                                         block=["injection_attack"]),
    ))
"""

from __future__ import annotations

import importlib
import os
from typing import Any, Sequence

from enkrypt_agent_sdk import _state
from enkrypt_agent_sdk.config import GuardrailConfig, SDKConfig
from enkrypt_agent_sdk.otel_setup import ExporterType
from enkrypt_agent_sdk.redaction import PayloadPolicy

# Registry: framework_name → (import_probe_module, patch_module_path)
_REGISTRY: dict[str, tuple[str, str]] = {
    "langchain": ("langchain_core", "enkrypt_agent_sdk._patch.langchain"),
    "langgraph": ("langgraph", "enkrypt_agent_sdk._patch.langgraph"),
    "openai_agents": ("agents", "enkrypt_agent_sdk._patch.openai_agents"),
    "anthropic": ("anthropic", "enkrypt_agent_sdk._patch.anthropic"),
    "crewai": ("crewai", "enkrypt_agent_sdk._patch.crewai"),
    "pydantic_ai": ("pydantic_ai", "enkrypt_agent_sdk._patch.pydantic_ai"),
    "llamaindex": ("llama_index.core", "enkrypt_agent_sdk._patch.llamaindex"),
    "google_adk": ("google.adk", "enkrypt_agent_sdk._patch.google_adk"),
    "bedrock_agents": ("botocore", "enkrypt_agent_sdk._patch.bedrock_agents"),
    "autogen": ("autogen_agentchat", "enkrypt_agent_sdk._patch.autogen"),
    "semantic_kernel": ("semantic_kernel", "enkrypt_agent_sdk._patch.semantic_kernel"),
    "haystack": ("haystack", "enkrypt_agent_sdk._patch.haystack"),
    "smolagents": ("smolagents", "enkrypt_agent_sdk._patch.smolagents"),
    "phidata": ("phi", "enkrypt_agent_sdk._patch.phidata"),
}


def auto_secure(
    config: SDKConfig | None = None,
    *,
    enkrypt_api_key: str = "",
    guardrail_policy: str = "",
    block: list[str] | None = None,
    pii_redaction: bool = False,
    service_name: str = "enkrypt-agent-sdk",
    exporter: ExporterType = ExporterType.NONE,
    otlp_endpoint: str = "",
    frameworks: list[str] | None = None,
    payload_policy: PayloadPolicy | None = None,
    fail_open: bool = True,
    guardrail_timeout: float = 15.0,
    enkrypt_base_url: str = "",
    checkpoints: dict[str, bool] | None = None,
) -> dict[str, bool]:
    """Initialise the SDK and auto-patch all detected frameworks.

    Accepts either an explicit :class:`SDKConfig`, **or** keyword arguments
    for the most common settings (the keyword form shown in the document).

    Environment variable fallbacks (used when a keyword argument is empty):

    - ``ENKRYPT_API_KEY``          → *enkrypt_api_key*
    - ``ENKRYPT_GUARDRAIL_POLICY`` → *guardrail_policy*
    - ``ENKRYPT_BLOCK_LIST``       → *block*  (comma-separated)
    - ``ENKRYPT_BASE_URL``         → *enkrypt_base_url*

    Returns a dict of ``{framework_name: was_installed}``.
    """
    if config is not None:
        cfg = config
    else:
        _api_key = enkrypt_api_key or os.environ.get("ENKRYPT_API_KEY", "")
        _policy = guardrail_policy or os.environ.get("ENKRYPT_GUARDRAIL_POLICY", "")
        _base_url = (enkrypt_base_url
                     or os.environ.get("ENKRYPT_BASE_URL", "https://api.enkryptai.com"))
        _block = block
        if _block is None:
            raw = os.environ.get("ENKRYPT_BLOCK_LIST", "")
            _block = [b.strip() for b in raw.split(",") if b.strip()] if raw else []

        guardrail_cfg = GuardrailConfig(
            enabled=bool(_policy or _block),
            policy_name=_policy,
            block=_block,
            additional_config={"pii_redaction": pii_redaction} if pii_redaction else {},
        )
        cp = checkpoints or {
            "pre_llm": True,
            "pre_tool": True,
            "post_tool": False,
            "post_llm": False,
        }
        cfg = SDKConfig(
            service_name=service_name,
            enkrypt_api_key=_api_key,
            enkrypt_base_url=_base_url,
            input_guardrails=guardrail_cfg,
            output_guardrails=guardrail_cfg,
            exporter=exporter,
            otlp_endpoint=otlp_endpoint,
            payload_policy=payload_policy or PayloadPolicy(),
            guardrail_timeout_seconds=guardrail_timeout,
            fail_open=fail_open,
            frameworks=frameworks,
            checkpoints=cp,
        )
    observer, guard_engine = _state.initialize(cfg)

    frameworks = cfg.frameworks
    if frameworks is None:
        frameworks = list(_REGISTRY.keys())

    results: dict[str, bool] = {}
    for name in frameworks:
        if name not in _REGISTRY:
            results[name] = False
            continue
        if _state.is_instrumented(name):
            results[name] = True
            continue
        probe, patch_path = _REGISTRY[name]
        if not _framework_available(probe):
            results[name] = False
            continue
        ok = _install_framework(name, patch_path, observer, guard_engine)
        results[name] = ok
        if ok:
            _state.mark_instrumented(name)

    return results


def unsecure(frameworks: Sequence[str] | None = None) -> None:
    """Remove patches for the given frameworks (or all if ``None``)."""
    targets = frameworks or list(_REGISTRY.keys())
    for name in targets:
        if name not in _REGISTRY or not _state.is_instrumented(name):
            continue
        _, patch_path = _REGISTRY[name]
        try:
            mod = importlib.import_module(patch_path)
            mod.uninstall()  # type: ignore[attr-defined]
        except Exception:
            pass
    _state.shutdown()


def available_frameworks() -> list[str]:
    """Return framework names that are importable in the current environment."""
    return [name for name, (probe, _) in _REGISTRY.items() if _framework_available(probe)]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _framework_available(import_probe: str) -> bool:
    try:
        importlib.import_module(import_probe)
        return True
    except Exception:
        return False


def _install_framework(
    name: str,
    patch_module_path: str,
    observer: Any,
    guard_engine: Any,
) -> bool:
    try:
        mod = importlib.import_module(patch_module_path)
        mod.install(observer, guard_engine)  # type: ignore[attr-defined]
        return True
    except Exception:
        return False
