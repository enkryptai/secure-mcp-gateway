#!/usr/bin/env python
"""
Enkrypt AI Guardrails Hook Provider for Strands Agents

This module provides a HookProvider implementation that integrates Enkrypt AI
guardrails with any Strands Agent, regardless of the model provider being used.

Features:
- User prompt validation (injection attacks, PII, toxicity)
- Tool input/output auditing
- Model response monitoring
- Sensitive tool blocking
- Comprehensive logging and metrics

Usage:
    from strands import Agent
    from enkrypt_guardrails_hook import EnkryptGuardrailsHook

    agent = Agent(
        hooks=[EnkryptGuardrailsHook()]
    )
"""
import json
import logging
from typing import Any, Optional

# Strands imports
try:
    from strands.hooks import HookProvider, HookRegistry
    from strands.hooks.events import (
        MessageAddedEvent,
        BeforeInvocationEvent,
        AfterInvocationEvent,
        BeforeModelCallEvent,
        AfterModelCallEvent,
        BeforeToolCallEvent,
        AfterToolCallEvent,
    )
    STRANDS_AVAILABLE = True
except ImportError:
    STRANDS_AVAILABLE = False
    # Define stub classes for testing without strands installed
    class HookProvider:
        pass
    class HookRegistry:
        def add_callback(self, *args, **kwargs):
            pass

# Local imports
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    is_hook_enabled,
    get_hook_policy_name,
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


class EnkryptGuardrailsHook(HookProvider):
    """
    Enkrypt AI Guardrails Hook Provider for Strands Agents.

    This hook provides comprehensive security guardrails for Strands agents:

    1. MessageAdded: Checks all messages (user prompts, assistant responses)
    2. BeforeToolCall: Validates tool inputs and can block dangerous tool calls
    3. AfterToolCall: Audits tool outputs for sensitive data
    4. AfterModelCall: Monitors model responses

    The hook works with ANY model provider in Strands, not just Amazon Bedrock.
    This makes it a universal guardrails solution.

    Example:
        ```python
        from strands import Agent
        from enkrypt_guardrails_hook import EnkryptGuardrailsHook

        # Create agent with Enkrypt guardrails
        agent = Agent(
            hooks=[EnkryptGuardrailsHook()]
        )

        # The agent is now protected against:
        # - Prompt injection attacks
        # - PII/secrets in prompts and responses
        # - Toxic content
        # - Dangerous tool calls
        ```
    """

    def __init__(
        self,
        block_on_violation: bool = True,
        log_only_mode: bool = False,
        check_user_messages: bool = True,
        check_assistant_messages: bool = True,
        check_tool_results: bool = True,
        sensitive_tools: Optional[list] = None,
    ):
        """
        Initialize the Enkrypt Guardrails Hook.

        Args:
            block_on_violation: If True, block requests that violate policies.
                               If False, only log violations.
            log_only_mode: If True, never block, only log (overrides block_on_violation)
            check_user_messages: Check user messages via MessageAddedEvent
            check_assistant_messages: Check assistant messages via MessageAddedEvent
            check_tool_results: Check tool results via AfterToolCallEvent
            sensitive_tools: Additional list of sensitive tool name patterns to block
        """
        self.block_on_violation = block_on_violation
        self.log_only_mode = log_only_mode
        self.check_user_messages = check_user_messages
        self.check_assistant_messages = check_assistant_messages
        self.check_tool_results = check_tool_results

        # Merge sensitive tools from config and constructor
        self._sensitive_tools = list(SENSITIVE_TOOLS)
        if sensitive_tools:
            self._sensitive_tools.extend(sensitive_tools)

        # Track violations per invocation for reporting
        self._current_violations = []

    def register_hooks(self, registry: HookRegistry) -> None:
        """Register all hook callbacks with the Strands hook registry."""

        # Message monitoring - catches all messages including user prompts
        registry.add_callback(MessageAddedEvent, self._on_message_added)

        # Invocation lifecycle
        registry.add_callback(BeforeInvocationEvent, self._on_before_invocation)
        registry.add_callback(AfterInvocationEvent, self._on_after_invocation)

        # Model call monitoring
        registry.add_callback(AfterModelCallEvent, self._on_after_model_call)

        # Tool call monitoring - critical for security
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_call)
        registry.add_callback(AfterToolCallEvent, self._on_after_tool_call)

        logger.info("Enkrypt Guardrails Hook registered successfully")

    def _on_before_invocation(self, event: "BeforeInvocationEvent") -> None:
        """
        Called at the start of each agent invocation.
        Reset violation tracking for the new request.
        """
        self._current_violations = []
        log_event("BeforeInvocation", {
            "agent_name": getattr(event.agent, "name", "unnamed"),
        })

    def _on_after_invocation(self, event: "AfterInvocationEvent") -> None:
        """
        Called at the end of each agent invocation.
        Log summary of any violations detected during the request.
        """
        if self._current_violations:
            log_security_alert("invocation_violations_summary", {
                "total_violations": len(self._current_violations),
                "violations": self._current_violations,
            }, {})

        log_event("AfterInvocation", {
            "agent_name": getattr(event.agent, "name", "unnamed"),
            "violations_count": len(self._current_violations),
        })
        flush_logs()

    def _on_message_added(self, event: "MessageAddedEvent") -> None:
        """
        Called when any message is added to the conversation.
        This is the primary hook for checking user prompts.

        Note: BeforeInvocationEvent doesn't expose user messages yet (issue #1006),
        so we use MessageAddedEvent as the workaround.
        """
        message = event.message
        role = message.get("role", "")

        # Skip if role-based checking is disabled
        if role == "user" and not self.check_user_messages:
            return
        if role == "assistant" and not self.check_assistant_messages:
            return

        # Extract text content from message
        content = message.get("content", [])
        text_parts = []

        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    if "text" in item:
                        text_parts.append(item["text"])
                    elif "toolResult" in item:
                        # Tool results are handled by AfterToolCallEvent
                        continue
                elif isinstance(item, str):
                    text_parts.append(item)

        if not text_parts:
            return

        combined_text = "\n".join(text_parts)

        # Check with Enkrypt API
        should_block, violations, api_result = check_with_enkrypt_api(
            combined_text,
            hook_name="MessageAdded"
        )

        if violations:
            self._current_violations.extend(violations)

            violation_message = format_violation_message(violations, hook_name="MessageAdded")

            log_security_alert("message_violation", {
                "role": role,
                "violations": violations,
                "text_preview": combined_text[:200] + "..." if len(combined_text) > 200 else combined_text,
            }, {"message": message})

            if should_block and self.block_on_violation and not self.log_only_mode:
                # Raise an exception to block the message from being processed
                # This stops the agent loop and returns an error to the caller
                logger.warning(
                    f"Guardrails violation detected in {role} message: {violation_message}"
                )
                raise GuardrailsViolationError(
                    f"Message blocked by Enkrypt AI Guardrails:\n\n{violation_message}",
                    violations=violations
                )

    def _on_before_tool_call(self, event: "BeforeToolCallEvent") -> None:
        """
        Called before each tool is executed.
        Can block dangerous tool calls by setting event.cancel_tool.
        """
        # tool_use is a ToolUse object with name, input, toolUseId attributes
        tool_use = event.tool_use
        tool_name = getattr(tool_use, 'name', '') or (tool_use.get('name', '') if isinstance(tool_use, dict) else '')
        tool_input = getattr(tool_use, 'input', {}) or (tool_use.get('input', {}) if isinstance(tool_use, dict) else {})

        # Check if tool is in sensitive tools list
        if self._is_tool_sensitive(tool_name):
            log_security_alert("sensitive_tool_call", {
                "tool_name": tool_name,
                "input_preview": str(tool_input)[:200],
            }, {"tool_use": event.tool_use})

        # Convert tool input to text for checking
        if isinstance(tool_input, dict):
            input_text = json.dumps(tool_input)
        else:
            input_text = str(tool_input)

        # Check tool input with Enkrypt API
        should_block, violations, api_result = check_with_enkrypt_api(
            input_text,
            hook_name="BeforeToolCall"
        )

        if violations:
            self._current_violations.extend(violations)

            violation_message = format_violation_message(violations, hook_name="BeforeToolCall")

            log_security_alert("tool_input_violation", {
                "tool_name": tool_name,
                "violations": violations,
                "input_preview": input_text[:200] + "..." if len(input_text) > 200 else input_text,
            }, {"tool_use": event.tool_use})

            if should_block and self.block_on_violation and not self.log_only_mode:
                # Cancel the tool call with a message
                event.cancel_tool = (
                    f"Tool call blocked by Enkrypt AI Guardrails:\n\n{violation_message}\n\n"
                    f"The tool '{tool_name}' cannot be executed due to security policy violations."
                )
                logger.warning(f"Blocked tool call to '{tool_name}': {violation_message}")

    def _on_after_tool_call(self, event: "AfterToolCallEvent") -> None:
        """
        Called after each tool execution completes.
        Audits tool results for sensitive data.
        """
        if not self.check_tool_results:
            return

        # tool_use is a ToolUse object with name, input, toolUseId attributes
        tool_use = event.tool_use
        tool_name = getattr(tool_use, 'name', '') or (tool_use.get('name', '') if isinstance(tool_use, dict) else '')
        result = event.result

        # Extract text from tool result
        result_text = ""
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        result_text += item["text"] + "\n"
            elif isinstance(content, str):
                result_text = content
        elif isinstance(result, str):
            result_text = result

        if not result_text.strip():
            return

        # Check tool result with Enkrypt API
        should_block, violations, api_result = check_with_enkrypt_api(
            result_text,
            hook_name="AfterToolCall"
        )

        if violations:
            self._current_violations.extend(violations)

            log_security_alert("tool_output_violation", {
                "tool_name": tool_name,
                "violations": violations,
                "output_preview": result_text[:200] + "..." if len(result_text) > 200 else result_text,
            }, {"tool_use": event.tool_use})

            # For tool results, we can modify the result to redact sensitive info
            # or add a warning to the result
            if should_block and self.block_on_violation and not self.log_only_mode:
                violation_message = format_violation_message(violations, hook_name="AfterToolCall")

                # Modify the result to include a warning
                warning_text = (
                    f"\n\n[SECURITY WARNING: Tool output contains potentially sensitive information. "
                    f"Violations: {', '.join(v['detector'] for v in violations)}]\n"
                )

                if isinstance(event.result, dict) and "content" in event.result:
                    if isinstance(event.result["content"], list):
                        event.result["content"].append({"text": warning_text})
                    else:
                        event.result["content"] = [
                            {"text": str(event.result["content"])},
                            {"text": warning_text}
                        ]

    def _on_after_model_call(self, event: "AfterModelCallEvent") -> None:
        """
        Called after each model inference completes.
        Can request retry if response violates policies.
        """
        # If there was an exception, don't process
        if event.exception:
            return

        # Extract model response text from stop_response
        # AfterModelCallEvent has stop_response (ModelStopResponse) with message attribute
        stop_response = getattr(event, 'stop_response', None)
        if not stop_response:
            return

        response_text = ""

        # Get message from stop_response
        message = getattr(stop_response, 'message', None)
        if message:
            # Message content can be a list of content blocks or a dict
            content = message.get("content", []) if isinstance(message, dict) else getattr(message, 'content', [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        response_text += item["text"] + "\n"
                    elif isinstance(item, str):
                        response_text += item + "\n"
            elif isinstance(content, str):
                response_text = content

        if not response_text.strip():
            return

        # Check model response with Enkrypt API
        should_block, violations, api_result = check_with_enkrypt_api(
            response_text,
            hook_name="AfterModelCall"
        )

        if violations:
            self._current_violations.extend(violations)

            log_security_alert("model_response_violation", {
                "violations": violations,
                "response_preview": response_text[:300] + "..." if len(response_text) > 300 else response_text,
            }, {})

            # Note: We could request a retry here with event.retry = True
            # But this might cause infinite loops if the model keeps producing violations
            # For now, we just log the violation

    def _is_tool_sensitive(self, tool_name: str) -> bool:
        """Check if a tool is considered sensitive."""
        return is_sensitive_tool(tool_name)

    def get_current_violations(self) -> list:
        """Get violations detected in the current invocation."""
        return self._current_violations.copy()

    def get_metrics(self) -> dict:
        """Get guardrails metrics."""
        return get_metrics()


class EnkryptGuardrailsBlockingHook(EnkryptGuardrailsHook):
    """
    A stricter version of the guardrails hook that always blocks on violations.
    Use this when security is critical and false positives are acceptable.
    """

    def __init__(self, **kwargs):
        kwargs["block_on_violation"] = True
        kwargs["log_only_mode"] = False
        super().__init__(**kwargs)


class EnkryptGuardrailsAuditHook(EnkryptGuardrailsHook):
    """
    An audit-only version of the guardrails hook that never blocks.
    Use this for monitoring and logging without impacting agent functionality.
    """

    def __init__(self, **kwargs):
        kwargs["block_on_violation"] = False
        kwargs["log_only_mode"] = True
        super().__init__(**kwargs)


# Convenience function for creating a protected agent
def create_protected_agent(
    model: Any = None,
    tools: list = None,
    system_prompt: str = None,
    blocking: bool = True,
    **agent_kwargs
) -> "Agent":
    """
    Create a Strands Agent with Enkrypt guardrails protection.

    Args:
        model: Model provider to use (default: Bedrock)
        tools: List of tools for the agent
        system_prompt: System prompt for the agent
        blocking: If True, block on violations. If False, audit-only mode.
        **agent_kwargs: Additional arguments for Agent constructor

    Returns:
        A Strands Agent with Enkrypt guardrails enabled

    Example:
        ```python
        from enkrypt_guardrails_hook import create_protected_agent

        agent = create_protected_agent(
            system_prompt="You are a helpful assistant.",
            blocking=True
        )
        ```
    """
    if not STRANDS_AVAILABLE:
        raise ImportError("strands-agents package is not installed")

    from strands import Agent

    # Select hook based on blocking mode
    if blocking:
        hook = EnkryptGuardrailsBlockingHook()
    else:
        hook = EnkryptGuardrailsAuditHook()

    # Build agent kwargs
    kwargs = {
        "hooks": [hook],
        **agent_kwargs
    }

    if model is not None:
        kwargs["model"] = model
    if tools is not None:
        kwargs["tools"] = tools
    if system_prompt is not None:
        kwargs["system_prompt"] = system_prompt

    return Agent(**kwargs)
