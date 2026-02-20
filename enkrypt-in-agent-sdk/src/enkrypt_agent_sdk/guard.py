"""Core guardrail engine — orchestrates input/output checks and PII handling.

This is the "brain" that sits between the framework adapters and the Enkrypt
guardrail API.  It decides whether a request/response should be allowed,
blocked, or modified.

Integrates Sentry's encoding detection to automatically decode base64, hex,
URL-encoded, and other obfuscated payloads before running guardrail checks.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from enkrypt_agent_sdk.encoding import decode_if_encoded
from enkrypt_agent_sdk.events import AgentEvent, EventName, GuardrailAction, GuardrailVerdict
from enkrypt_agent_sdk.exceptions import (
    GuardrailAPIError,
    GuardrailBlockedError,
    GuardrailTimeoutError,
)
from enkrypt_agent_sdk.guardrails.base import (
    GuardrailFactory,
    GuardrailRegistry,
    GuardrailRequest,
    GuardrailResponse,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
)


class GuardEngine:
    """Stateless engine that runs guardrail checks and returns verdicts.

    A single instance is shared across all adapter hooks.  Thread-safety
    comes from the fact that each call creates its own ``GuardrailRequest``
    and ``aiohttp.ClientSession`` (inside the provider).

    Accepts either a :class:`GuardrailRegistry` **or** convenience keyword
    arguments (``enkrypt_api_key``, ``guardrail_policy``) for quick setup
    matching the document's ``AgentGuard(...)`` shorthand.

    Checkpoints control WHERE guardrails run in the pipeline::

        guard = GuardEngine(registry, ..., checkpoints={
            "pre_llm":    True,   # Check user input BEFORE it reaches the LLM
            "pre_tool":   True,   # Check tool input BEFORE tool executes
            "post_tool":  True,   # Check tool output AFTER tool executes
            "post_llm":   True,   # Check LLM response BEFORE it reaches the user
        })
    """

    def __init__(
        self,
        registry: GuardrailRegistry | None = None,
        *,
        input_policy: dict[str, Any] | None = None,
        output_policy: dict[str, Any] | None = None,
        timeout_seconds: float = 15.0,
        fail_open: bool = True,
        enkrypt_api_key: str = "",
        enkrypt_base_url: str = "https://api.enkryptai.com",
        guardrail_policy: str = "",
        block: list[str] | None = None,
        checkpoints: dict[str, bool] | None = None,
    ) -> None:
        if registry is None:
            from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry as _Reg
            from enkrypt_agent_sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
            registry = _Reg()
            if enkrypt_api_key:
                registry.register(EnkryptGuardrailProvider(enkrypt_api_key, enkrypt_base_url))
            if guardrail_policy or block:
                input_policy = input_policy or {
                    "enabled": True,
                    "policy_name": guardrail_policy,
                    "block": block or [],
                }
                output_policy = output_policy or {
                    "enabled": True,
                    "policy_name": guardrail_policy,
                    "block": block or [],
                }

        self._factory = GuardrailFactory(registry)
        self._input_policy = input_policy or {}
        self._output_policy = output_policy or {}
        self._timeout = timeout_seconds
        self._fail_open = fail_open
        self._decode_encoded = True

        defaults = {"pre_llm": True, "pre_tool": True, "post_tool": False, "post_llm": False}
        cp = {**defaults, **(checkpoints or {})}
        self.check_pre_llm: bool = cp["pre_llm"]
        self.check_pre_tool: bool = cp["pre_tool"]
        self.check_post_tool: bool = cp["post_tool"]
        self.check_post_llm: bool = cp["post_llm"]

        self._input_guard: InputGuardrail | None = self._factory.create_input_guardrail(self._input_policy)
        self._output_guard: OutputGuardrail | None = self._factory.create_output_guardrail(self._output_policy)
        self._pii_handler: PIIHandler | None = self._factory.create_pii_handler(self._input_policy)

    @property
    def has_input_guard(self) -> bool:
        return self._input_guard is not None

    @property
    def has_output_guard(self) -> bool:
        return self._output_guard is not None

    @property
    def has_pii_handler(self) -> bool:
        return self._pii_handler is not None

    # ------------------------------------------------------------------
    # Input checking
    # ------------------------------------------------------------------

    async def check_input(self, content: str, *, tool_name: str | None = None) -> GuardrailVerdict:
        """Check input content and return a verdict.

        If the content appears to be encoded (base64, hex, URL, etc.) the
        decoded version is checked as well — this mirrors Sentry's
        ``AllDetectors.predict`` flow that decodes before detection.

        Raises :class:`GuardrailBlockedError` when the policy says BLOCK.
        """
        import logging
        log = logging.getLogger("enkrypt_agent_sdk.guard")

        if self._input_guard is None:
            log.debug("[GuardEngine] No input guard configured, skipping")
            return GuardrailVerdict()

        check_content = content
        if self._decode_encoded:
            decoded, fmt = decode_if_encoded(content)
            if fmt is not None:
                log.debug("[GuardEngine] Decoded %s content: %s -> %s", fmt, content[:50], decoded[:50])
                check_content = decoded

        log.debug("[GuardEngine] check_input(tool=%s, content=%s...)", tool_name, check_content[:80])

        request = GuardrailRequest(content=check_content, tool_name=tool_name)
        try:
            response = await asyncio.wait_for(
                self._input_guard.validate(request),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            log.warning("[GuardEngine] Guardrail TIMEOUT (%.0fs) - fail_open=%s", self._timeout, self._fail_open)
            if self._fail_open:
                return GuardrailVerdict(action=GuardrailAction.WARN, violations=("timeout",))
            raise GuardrailTimeoutError("Input guardrail timed out", timeout_seconds=self._timeout)
        except Exception as exc:
            log.warning("[GuardEngine] Guardrail ERROR: %s - fail_open=%s", exc, self._fail_open)
            if self._fail_open:
                return GuardrailVerdict(action=GuardrailAction.WARN, violations=("api_error",))
            raise GuardrailAPIError(f"Input guardrail API error: {exc}", cause=exc) from exc

        verdict = self._to_verdict(response)
        log.debug("[GuardEngine] Verdict: safe=%s action=%s violations=%s",
                  verdict.is_safe, verdict.action, verdict.violations)
        return verdict

    # ------------------------------------------------------------------
    # Output checking
    # ------------------------------------------------------------------

    async def check_output(
        self,
        response_content: str,
        original_input: str,
        *,
        tool_name: str | None = None,
    ) -> GuardrailVerdict:
        if self._output_guard is None:
            return GuardrailVerdict()

        check_content = response_content
        if self._decode_encoded:
            decoded, fmt = decode_if_encoded(response_content)
            if fmt is not None:
                check_content = decoded

        request = GuardrailRequest(content=original_input, tool_name=tool_name)
        try:
            response = await asyncio.wait_for(
                self._output_guard.validate(check_content, request),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            if self._fail_open:
                return GuardrailVerdict(action=GuardrailAction.WARN, violations=("timeout",))
            raise GuardrailTimeoutError("Output guardrail timed out", timeout_seconds=self._timeout)
        except Exception as exc:
            if self._fail_open:
                return GuardrailVerdict(action=GuardrailAction.WARN, violations=("api_error",))
            raise GuardrailAPIError(f"Output guardrail API error: {exc}", cause=exc) from exc

        return self._to_verdict(response)

    # ------------------------------------------------------------------
    # PII
    # ------------------------------------------------------------------

    async def redact_pii(self, content: str) -> tuple[str, dict[str, Any]]:
        if self._pii_handler is None:
            return content, {}
        return await self._pii_handler.redact_pii(content)

    async def restore_pii(self, content: str, mapping: dict[str, Any]) -> str:
        if self._pii_handler is None or not mapping:
            return content
        return await self._pii_handler.restore_pii(content, mapping)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_verdict(response: GuardrailResponse) -> GuardrailVerdict:
        action_map = {
            "allow": GuardrailAction.ALLOW,
            "block": GuardrailAction.BLOCK,
            "warn": GuardrailAction.WARN,
            "modify": GuardrailAction.MODIFY,
        }
        action = action_map.get(response.action.value, GuardrailAction.ALLOW)
        violation_names = tuple(v.violation_type.value for v in response.violations)
        return GuardrailVerdict(
            action=action,
            violations=violation_names,
            modified_content=response.modified_content,
            processing_time_ms=response.processing_time_ms,
        )
