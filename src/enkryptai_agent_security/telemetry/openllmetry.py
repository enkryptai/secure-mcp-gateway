"""OpenLLMetry detection and integration helpers.

OpenLLMetry (https://github.com/traceloop/openllmetry) instruments 14+ LLM
providers and frameworks with standard OTel ``gen_ai.*`` spans.  Enkrypt
complements it: OpenLLMetry = "what did the LLM do", Enkrypt = "was it safe."

When OpenLLMetry instrumentors are active, the SDK should defer LLM
observability to them and only add guardrail spans (avoids duplicate spans).
When they are NOT installed, the SDK creates its own basic LLM spans.

This module provides the detection logic so the SDK (and other products)
can make that decision at runtime.
"""

from __future__ import annotations

import importlib.util
import logging
from typing import Any

logger = logging.getLogger("enkryptai_agent_security.telemetry.openllmetry")

# Known OpenLLMetry instrumentor classes, keyed by the library they patch.
# Each entry: (package_name, module_path, class_name)
_KNOWN_INSTRUMENTORS: list[tuple[str, str, str]] = [
    (
        "openai",
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
    ),
    (
        "anthropic",
        "opentelemetry.instrumentation.anthropic",
        "AnthropicInstrumentor",
    ),
    (
        "langchain",
        "opentelemetry.instrumentation.langchain",
        "LangchainInstrumentor",
    ),
    (
        "cohere",
        "opentelemetry.instrumentation.cohere",
        "CohereInstrumentor",
    ),
    (
        "bedrock",
        "opentelemetry.instrumentation.bedrock",
        "BedrockInstrumentor",
    ),
    (
        "crewai",
        "opentelemetry.instrumentation.crewai",
        "CrewAIInstrumentor",
    ),
]


def has_traceloop_sdk() -> bool:
    """Check if the ``traceloop-sdk`` package is installed."""
    return importlib.util.find_spec("traceloop") is not None


def is_instrumentor_active(module_path: str, class_name: str) -> bool:
    """Check if a specific OTel instrumentor has been activated.

    Uses the ``is_instrumented_by_opentelemetry`` property from
    ``BaseInstrumentor``.  Returns ``False`` if the instrumentor
    package is not installed.
    """
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name, None)
        if cls is None:
            return False
        instance = cls()
        return getattr(instance, "is_instrumented_by_opentelemetry", False)
    except (ImportError, Exception):
        return False


def get_active_instrumentors() -> dict[str, bool]:
    """Return which OpenLLMetry instrumentors are currently active.

    Returns a dict like ``{"openai": True, "anthropic": False, ...}``.
    Only includes instrumentors whose packages are installed.
    """
    result: dict[str, bool] = {}
    for lib_name, module_path, class_name in _KNOWN_INSTRUMENTORS:
        if importlib.util.find_spec(module_path) is not None:
            result[lib_name] = is_instrumentor_active(module_path, class_name)
    return result


def any_llm_instrumentor_active() -> bool:
    """Check if ANY OpenLLMetry LLM instrumentor is active.

    This is the key check the SDK uses to decide whether to create its
    own ``agent.llm_call`` spans or defer to OpenLLMetry.

    Decision logic in the SDK observer::

        if any_llm_instrumentor_active():
            # OpenLLMetry handles LLM spans → only create guardrail spans
            pass
        else:
            # No LLM observability → create our own basic LLM spans
            create_llm_span(...)
    """
    for _, module_path, class_name in _KNOWN_INSTRUMENTORS:
        if is_instrumentor_active(module_path, class_name):
            return True
    return False


def init_openllmetry(
    *,
    app_name: str = "enkryptai-agent-security",
    disable_batch: bool = False,
    api_key: str | None = None,
    api_endpoint: str | None = None,
) -> bool:
    """Initialise OpenLLMetry via ``Traceloop.init()`` if available.

    This is a convenience wrapper.  Users can also call ``Traceloop.init()``
    directly — our detection helpers work either way.

    Returns ``True`` if initialisation succeeded, ``False`` if traceloop-sdk
    is not installed.
    """
    if not has_traceloop_sdk():
        logger.debug("traceloop-sdk not installed, skipping OpenLLMetry init")
        return False

    try:
        from traceloop.sdk import Traceloop

        kwargs: dict[str, Any] = {"app_name": app_name}
        if disable_batch:
            kwargs["disable_batch"] = True
        if api_key:
            kwargs["api_key"] = api_key
        if api_endpoint:
            kwargs["api_endpoint"] = api_endpoint

        Traceloop.init(**kwargs)
        logger.info("OpenLLMetry initialised via Traceloop.init(app_name=%s)", app_name)
        return True
    except Exception as exc:
        logger.warning("Failed to initialise OpenLLMetry: %s", exc)
        return False
