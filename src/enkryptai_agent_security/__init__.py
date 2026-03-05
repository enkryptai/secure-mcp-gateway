"""Enkrypt Security — unified security library for MCP Gateway, Agent SDK, and Hooks.

Quick start (guardrails only)::

    from enkryptai_agent_security.guardrails import EnkryptGuardrailClient

    client = EnkryptGuardrailClient(
        api_key="ek-...",
        guardrail_name="My Policy",
        block=["injection_attack", "pii", "toxicity"],
    )
    result = client.check_input("some user text")
    if not result.is_safe:
        print("Blocked:", [v.detector for v in result.violations])

Quick start (with telemetry)::

    from enkryptai_agent_security.telemetry import init_telemetry, SpanAttributes

    ctx = init_telemetry(service_name="my-app", exporter="otlp_grpc",
                         endpoint="http://localhost:4317")
    tracer = ctx.tracer

Quick start (hooks)::

    from enkryptai_agent_security.hooks import HooksCore

    core = HooksCore.from_config_file("guardrails_config.json")
    blocked, violations, raw = core.check(text, "on_llm_start")
"""

from enkryptai_agent_security.version import __version__

__all__ = ["__version__"]
