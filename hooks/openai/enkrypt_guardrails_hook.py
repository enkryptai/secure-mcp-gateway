#!/usr/bin/env python
"""
Enkrypt AI Guardrails Hook Provider for OpenAI Agents SDK

This module provides RunHooks and AgentHooks implementations that integrate
Enkrypt AI guardrails with the OpenAI Agents SDK.

Features:
- User prompt validation (injection attacks, PII, toxicity)
- Tool input/output auditing
- LLM response monitoring
- Agent handoff monitoring
- Sensitive tool blocking
- Comprehensive logging and metrics

Usage:
    from agents import Agent, Runner
    from enkrypt_guardrails_hook import EnkryptRunHooks

    # Create hooks instance
    hooks = EnkryptRunHooks()

    # Run agent with hooks
    result = await Runner.run(
        agent,
        hooks=hooks,
        input="Your prompt here"
    )
"""
import json
import logging
from typing import Any, Optional, List

# OpenAI Agents SDK imports
try:
    from agents import Agent, Runner, Tool
    from agents.lifecycle import RunHooksBase, AgentHooksBase
    from agents.run_context import RunContextWrapper
    from agents.items import TResponseInputItem
    from agents.result import ModelResponse
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    OPENAI_AGENTS_AVAILABLE = False
    # Define stub classes for testing without openai-agents installed
    class RunHooksBase:
        pass
    class AgentHooksBase:
        pass
    class RunContextWrapper:
        pass
    class TResponseInputItem:
        pass
    class ModelResponse:
        pass
    class Agent:
        pass
    class Tool:
        pass

# Local imports
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    is_hook_enabled,
    get_hook_guardrail_name,
    is_sensitive_tool,
    analyze_content,
    log_event,
    log_to_combined,
    log_security_alert,
    flush_logs,
    get_metrics,
    SENSITIVE_TOOLS,
)

logger = logging.getLogger(__name__)


class GuardrailsViolationError(Exception):
    """Exception raised when a guardrails violation is detected and blocking is enabled."""

    def __init__(self, message: str, violations: list = None):
        super().__init__(message)
        self.violations = violations or []


class EnkryptRunHooks(RunHooksBase):
    """
    Enkrypt AI Guardrails Run Hooks for OpenAI Agents SDK.

    This class provides comprehensive security guardrails for agent runs:

    1. on_agent_start: Validates agent context before execution
    2. on_agent_end: Audits agent output
    3. on_llm_start: Checks prompts before LLM calls
    4. on_llm_end: Monitors LLM responses
    5. on_tool_start: Validates tool inputs and can block dangerous calls
    6. on_tool_end: Audits tool outputs for sensitive data
    7. on_handoff: Monitors agent handoffs

    Example:
        ```python
        from agents import Agent, Runner
        from enkrypt_guardrails_hook import EnkryptRunHooks

        hooks = EnkryptRunHooks()

        agent = Agent(
            name="My Agent",
            instructions="You are a helpful assistant."
        )

        result = await Runner.run(
            agent,
            hooks=hooks,
            input="Hello, what can you help me with?"
        )
        ```
    """

    def __init__(
        self,
        block_on_violation: bool = True,
        log_only_mode: bool = False,
        check_llm_inputs: bool = True,
        check_llm_outputs: bool = True,
        check_tool_results: bool = True,
        sensitive_tools: Optional[List[str]] = None,
    ):
        """
        Initialize the Enkrypt Guardrails Run Hooks.

        Args:
            block_on_violation: If True, block requests that violate policies.
                               If False, only log violations.
            log_only_mode: If True, never block, only log (overrides block_on_violation)
            check_llm_inputs: Check LLM inputs via on_llm_start
            check_llm_outputs: Check LLM outputs via on_llm_end
            check_tool_results: Check tool results via on_tool_end
            sensitive_tools: Additional list of sensitive tool name patterns to block
        """
        self.block_on_violation = block_on_violation
        self.log_only_mode = log_only_mode
        self.check_llm_inputs = check_llm_inputs
        self.check_llm_outputs = check_llm_outputs
        self.check_tool_results = check_tool_results

        # Merge sensitive tools from config and constructor
        self._sensitive_tools = list(SENSITIVE_TOOLS)
        if sensitive_tools:
            self._sensitive_tools.extend(sensitive_tools)

        # Track violations per run for reporting
        self._current_violations: List[dict] = []
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._event_counter = 0

    async def on_agent_start(
        self,
        context: RunContextWrapper,
        agent: "Agent"
    ) -> None:
        """
        Called before the agent is invoked.

        This hook validates the agent context and can block execution
        if security policies are violated.
        """
        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")

        log_event("on_agent_start", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "usage": self._get_usage_dict(context),
        })

        # Reset violations for new agent
        self._current_violations = []

        logger.info(f"Agent '{agent_name}' starting (event #{self._event_counter})")

    async def on_agent_end(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        output: Any
    ) -> None:
        """
        Called when the agent produces a final output.

        This hook audits the final output for security issues.
        """
        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")

        # Convert output to string for checking
        output_text = str(output) if output else ""

        violations = []
        if is_hook_enabled("on_agent_end") and output_text:
            should_block, violations, api_result = check_with_enkrypt_api(
                output_text,
                hook_name="on_agent_end"
            )

            if violations:
                self._current_violations.extend(violations)
                log_security_alert("agent_output_violation", {
                    "agent_name": agent_name,
                    "violations": violations,
                    "output_preview": output_text[:300] + "..." if len(output_text) > 300 else output_text,
                }, {})

        log_event("on_agent_end", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "output_preview": output_text[:200] if output_text else None,
            "violations": violations,
            "total_violations_in_run": len(self._current_violations),
            "usage": self._get_usage_dict(context),
        })

        # Flush logs at end of agent
        flush_logs()

        logger.info(f"Agent '{agent_name}' ended (event #{self._event_counter})")

    async def on_llm_start(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        system_prompt: Optional[str],
        input_items: List["TResponseInputItem"]
    ) -> None:
        """
        Called just before invoking the LLM.

        This hook validates the system prompt and input items.
        """
        if not self.check_llm_inputs:
            return

        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")

        # Extract text from input items
        input_texts = []
        if system_prompt:
            input_texts.append(f"[System] {system_prompt}")

        for item in input_items or []:
            if hasattr(item, "content"):
                content = item.content
                if isinstance(content, str):
                    input_texts.append(content)
                elif isinstance(content, list):
                    for c in content:
                        if isinstance(c, dict) and "text" in c:
                            input_texts.append(c["text"])
                        elif isinstance(c, str):
                            input_texts.append(c)

        combined_text = "\n".join(input_texts)

        violations = []
        if is_hook_enabled("on_llm_start") and combined_text:
            should_block, violations, api_result = check_with_enkrypt_api(
                combined_text,
                hook_name="on_llm_start"
            )

            if violations:
                self._current_violations.extend(violations)
                violation_message = format_violation_message(violations, hook_name="on_llm_start")

                log_security_alert("llm_input_violation", {
                    "agent_name": agent_name,
                    "violations": violations,
                    "input_preview": combined_text[:200] + "..." if len(combined_text) > 200 else combined_text,
                }, {})

                if should_block and self.block_on_violation and not self.log_only_mode:
                    raise GuardrailsViolationError(
                        f"LLM input blocked by Enkrypt AI Guardrails:\n\n{violation_message}",
                        violations=violations
                    )

        log_event("on_llm_start", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "has_system_prompt": system_prompt is not None,
            "input_items_count": len(input_items) if input_items else 0,
            "violations": violations,
            "usage": self._get_usage_dict(context),
        })

    async def on_llm_end(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        response: "ModelResponse"
    ) -> None:
        """
        Called immediately after the LLM call returns.

        This hook audits the LLM response for policy violations.
        """
        if not self.check_llm_outputs:
            return

        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")

        # Extract response text
        response_text = ""
        if hasattr(response, "output"):
            output = response.output
            if isinstance(output, str):
                response_text = output
            elif isinstance(output, list):
                for item in output:
                    if hasattr(item, "content"):
                        if isinstance(item.content, str):
                            response_text += item.content + "\n"
                        elif isinstance(item.content, list):
                            for c in item.content:
                                if isinstance(c, dict) and "text" in c:
                                    response_text += c["text"] + "\n"

        violations = []
        if is_hook_enabled("on_llm_end") and response_text:
            should_block, violations, api_result = check_with_enkrypt_api(
                response_text,
                hook_name="on_llm_end"
            )

            if violations:
                self._current_violations.extend(violations)

                log_security_alert("llm_response_violation", {
                    "agent_name": agent_name,
                    "violations": violations,
                    "response_preview": response_text[:300] + "..." if len(response_text) > 300 else response_text,
                }, {})

        # Update token counts if available
        if hasattr(response, "usage"):
            usage = response.usage
            if hasattr(usage, "input_tokens"):
                self._total_input_tokens += usage.input_tokens
            if hasattr(usage, "output_tokens"):
                self._total_output_tokens += usage.output_tokens

        log_event("on_llm_end", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "response_preview": response_text[:200] if response_text else None,
            "violations": violations,
            "usage": self._get_usage_dict(context),
        })

    async def on_tool_start(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        tool: "Tool"
    ) -> None:
        """
        Called immediately before a tool is invoked.

        This hook validates tool inputs and can block dangerous tool calls.
        """
        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")
        tool_name = getattr(tool, "name", "unknown")

        # Check if tool is sensitive
        if self._is_tool_sensitive(tool_name):
            log_security_alert("sensitive_tool_call", {
                "agent_name": agent_name,
                "tool_name": tool_name,
            }, {})

        # Get tool input if available
        tool_input = ""
        if hasattr(tool, "input"):
            tool_input = json.dumps(tool.input) if isinstance(tool.input, dict) else str(tool.input)
        elif hasattr(tool, "args"):
            tool_input = json.dumps(tool.args) if isinstance(tool.args, dict) else str(tool.args)

        violations = []
        if is_hook_enabled("on_tool_start") and tool_input:
            should_block, violations, api_result = check_with_enkrypt_api(
                tool_input,
                hook_name="on_tool_start"
            )

            if violations:
                self._current_violations.extend(violations)
                violation_message = format_violation_message(violations, hook_name="on_tool_start")

                log_security_alert("tool_input_violation", {
                    "agent_name": agent_name,
                    "tool_name": tool_name,
                    "violations": violations,
                    "input_preview": tool_input[:200] + "..." if len(tool_input) > 200 else tool_input,
                }, {})

                if should_block and self.block_on_violation and not self.log_only_mode:
                    raise GuardrailsViolationError(
                        f"Tool '{tool_name}' blocked by Enkrypt AI Guardrails:\n\n{violation_message}",
                        violations=violations
                    )

        log_event("on_tool_start", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "is_sensitive": self._is_tool_sensitive(tool_name),
            "violations": violations,
            "usage": self._get_usage_dict(context),
        })

    async def on_tool_end(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        tool: "Tool",
        result: str
    ) -> None:
        """
        Called immediately after a tool is invoked.

        This hook audits tool outputs for sensitive data.
        """
        if not self.check_tool_results:
            return

        self._event_counter += 1
        agent_name = getattr(agent, "name", "unnamed")
        tool_name = getattr(tool, "name", "unknown")

        violations = []
        if is_hook_enabled("on_tool_end") and result:
            should_block, violations, api_result = check_with_enkrypt_api(
                result,
                hook_name="on_tool_end"
            )

            if violations:
                self._current_violations.extend(violations)

                log_security_alert("tool_output_violation", {
                    "agent_name": agent_name,
                    "tool_name": tool_name,
                    "violations": violations,
                    "output_preview": result[:200] + "..." if len(result) > 200 else result,
                }, {})

        log_event("on_tool_end", {
            "event_number": self._event_counter,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "result_preview": result[:100] if result else None,
            "violations": violations,
            "usage": self._get_usage_dict(context),
        })

    async def on_handoff(
        self,
        context: RunContextWrapper,
        from_agent: "Agent",
        to_agent: "Agent"
    ) -> None:
        """
        Called when a handoff occurs between agents.

        This hook logs and monitors agent handoffs.
        """
        self._event_counter += 1
        from_name = getattr(from_agent, "name", "unnamed")
        to_name = getattr(to_agent, "name", "unnamed")

        log_event("on_handoff", {
            "event_number": self._event_counter,
            "from_agent": from_name,
            "to_agent": to_name,
            "usage": self._get_usage_dict(context),
        })

        log_security_alert("agent_handoff", {
            "from_agent": from_name,
            "to_agent": to_name,
        }, {})

        logger.info(f"Handoff: {from_name} -> {to_name} (event #{self._event_counter})")

    def _is_tool_sensitive(self, tool_name: str) -> bool:
        """Check if a tool is considered sensitive."""
        return is_sensitive_tool(tool_name)

    def _get_usage_dict(self, context: RunContextWrapper) -> dict:
        """Extract usage information from context."""
        usage = {}
        if hasattr(context, "usage"):
            ctx_usage = context.usage
            if hasattr(ctx_usage, "input_tokens"):
                usage["input_tokens"] = ctx_usage.input_tokens
            if hasattr(ctx_usage, "output_tokens"):
                usage["output_tokens"] = ctx_usage.output_tokens
            if hasattr(ctx_usage, "total_tokens"):
                usage["total_tokens"] = ctx_usage.total_tokens
            if hasattr(ctx_usage, "requests"):
                usage["requests"] = ctx_usage.requests
        return usage

    def get_current_violations(self) -> List[dict]:
        """Get violations detected in the current run."""
        return self._current_violations.copy()

    def get_token_usage(self) -> dict:
        """Get total token usage tracked by hooks."""
        return {
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "event_count": self._event_counter,
        }

    def get_metrics(self) -> dict:
        """Get guardrails metrics."""
        return get_metrics()

    def reset(self):
        """Reset tracking state for a new run."""
        self._current_violations = []
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._event_counter = 0


class EnkryptAgentHooks(AgentHooksBase):
    """
    Enkrypt AI Guardrails Agent Hooks for specific agents.

    This class provides per-agent hooks that can be set on individual agents
    for fine-grained control over guardrails behavior.

    Example:
        ```python
        from agents import Agent
        from enkrypt_guardrails_hook import EnkryptAgentHooks

        agent = Agent(
            name="Secure Agent",
            instructions="You are a helpful assistant.",
            hooks=EnkryptAgentHooks()
        )
        ```
    """

    def __init__(
        self,
        block_on_violation: bool = True,
        log_only_mode: bool = False,
    ):
        """
        Initialize agent-specific hooks.

        Args:
            block_on_violation: If True, block on violations
            log_only_mode: If True, only log, never block
        """
        self.block_on_violation = block_on_violation
        self.log_only_mode = log_only_mode
        self._violations: List[dict] = []

    async def on_start(
        self,
        context: RunContextWrapper,
        agent: "Agent"
    ) -> None:
        """Called when this agent starts."""
        agent_name = getattr(agent, "name", "unnamed")
        self._violations = []

        log_event("agent_on_start", {
            "agent_name": agent_name,
        })

    async def on_end(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        output: Any
    ) -> None:
        """Called when this agent produces output."""
        agent_name = getattr(agent, "name", "unnamed")
        output_text = str(output) if output else ""

        if is_hook_enabled("on_agent_end") and output_text:
            should_block, violations, api_result = check_with_enkrypt_api(
                output_text,
                hook_name="on_agent_end"
            )

            if violations:
                self._violations.extend(violations)
                log_security_alert("agent_output_violation", {
                    "agent_name": agent_name,
                    "violations": violations,
                }, {})

        log_event("agent_on_end", {
            "agent_name": agent_name,
            "violations_count": len(self._violations),
        })
        flush_logs()

    async def on_tool_start(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        tool: "Tool"
    ) -> None:
        """Called before this agent uses a tool."""
        agent_name = getattr(agent, "name", "unnamed")
        tool_name = getattr(tool, "name", "unknown")

        log_event("agent_on_tool_start", {
            "agent_name": agent_name,
            "tool_name": tool_name,
        })

    async def on_tool_end(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        tool: "Tool",
        result: str
    ) -> None:
        """Called after this agent uses a tool."""
        agent_name = getattr(agent, "name", "unnamed")
        tool_name = getattr(tool, "name", "unknown")

        log_event("agent_on_tool_end", {
            "agent_name": agent_name,
            "tool_name": tool_name,
            "result_length": len(result) if result else 0,
        })

    async def on_handoff(
        self,
        context: RunContextWrapper,
        agent: "Agent",
        source: "Agent"
    ) -> None:
        """Called when this agent receives a handoff."""
        agent_name = getattr(agent, "name", "unnamed")
        source_name = getattr(source, "name", "unnamed")

        log_event("agent_on_handoff", {
            "agent_name": agent_name,
            "from_agent": source_name,
        })

    def get_violations(self) -> List[dict]:
        """Get violations for this agent."""
        return self._violations.copy()


class EnkryptBlockingRunHooks(EnkryptRunHooks):
    """
    A stricter version of run hooks that always blocks on violations.
    Use this when security is critical and false positives are acceptable.
    """

    def __init__(self, **kwargs):
        kwargs["block_on_violation"] = True
        kwargs["log_only_mode"] = False
        super().__init__(**kwargs)


class EnkryptAuditRunHooks(EnkryptRunHooks):
    """
    An audit-only version of run hooks that never blocks.
    Use this for monitoring and logging without impacting agent functionality.
    """

    def __init__(self, **kwargs):
        kwargs["block_on_violation"] = False
        kwargs["log_only_mode"] = True
        super().__init__(**kwargs)


# Convenience function for creating a protected agent
async def run_with_guardrails(
    agent: "Agent",
    input: str,
    blocking: bool = True,
    **runner_kwargs
) -> Any:
    """
    Run an agent with Enkrypt guardrails protection.

    Args:
        agent: The agent to run
        input: The input prompt
        blocking: If True, block on violations. If False, audit-only mode.
        **runner_kwargs: Additional arguments for Runner.run()

    Returns:
        The agent result

    Example:
        ```python
        from agents import Agent
        from enkrypt_guardrails_hook import run_with_guardrails

        agent = Agent(
            name="My Agent",
            instructions="You are a helpful assistant."
        )

        result = await run_with_guardrails(
            agent,
            input="What is the capital of France?",
            blocking=True
        )
        ```
    """
    if not OPENAI_AGENTS_AVAILABLE:
        raise ImportError("openai-agents package is not installed")

    # Select hooks based on blocking mode
    if blocking:
        hooks = EnkryptBlockingRunHooks()
    else:
        hooks = EnkryptAuditRunHooks()

    return await Runner.run(
        agent,
        hooks=hooks,
        input=input,
        **runner_kwargs
    )
