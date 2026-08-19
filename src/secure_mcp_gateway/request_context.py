"""Per-request execution context shared across plugins.

This module exists as a side-effect-free home for ContextVars that must be
written by the gateway request pipeline and read deep inside plugin code
(guardrails, telemetry, etc.) **without** the plugins having to import the
execution service.

The execution service eagerly initialises telemetry at module load (it calls
``telemetry_manager.get_tracer()`` at import time), so any module that
imports it transitively can only be imported after telemetry has been
initialised. That coupling is fine for runtime, but it breaks plugin unit
tests, ad-hoc REPLs, and one-shot diagnostic scripts. Keeping this module
dependency-free preserves the ability to ``import secure_mcp_gateway.plugins.guardrails.enkrypt_provider``
from a bare interpreter.
"""

from __future__ import annotations

from contextvars import ContextVar

# Per-request Enkrypt apikey forwarded to downstream guardrail/PII API calls.
#
# Set by ``SecureToolExecutionService._execute_tools_with_guardrails`` right
# after the caller is authenticated; read by ``EnkryptInputGuardrail.validate``
# / ``EnkryptOutputGuardrail.validate`` / ``EnkryptPIIHandler.*`` via the
# ``_effective_apikey`` helper.
#
# Why a ContextVar instead of threading a parameter through ~6 function
# signatures: each asyncio Task gets its own copy and the value is naturally
# bounded by the request's task tree, so we don't need manual reset, don't
# leak across requests, and don't churn every helper signature. The
# guardrail provider stays decoupled from FastMCP context.
#
# Defaults to ``""`` so existing tests, single-tenant local installs, and
# any code path that hasn't been migrated to set the contextvar continue to
# use the provider's static ``self.api_key`` fallback.
request_apikey_var: ContextVar[str] = ContextVar("request_apikey", default="")


__all__ = ["request_apikey_var"]
