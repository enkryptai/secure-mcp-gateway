#!/usr/bin/env python
"""
Enkrypt AI Guardrails Hook Provider for LangGraph/LangChain Agents

This module provides pre_model_hook and post_model_hook implementations
for LangGraph's create_react_agent, plus tool wrappers for comprehensive protection.

Features:
- Pre-model input validation (injection attacks, PII, toxicity)
- Post-model output monitoring
- Tool input/output auditing
- Sensitive tool blocking
- Comprehensive logging and metrics

Usage with create_react_agent:
    from langgraph.prebuilt import create_react_agent
    from enkrypt_guardrails_hook import enkrypt_pre_model_hook, enkrypt_post_model_hook

    agent = create_react_agent(
        model,
        tools,
        pre_model_hook=enkrypt_pre_model_hook,
        post_model_hook=enkrypt_post_model_hook,
    )
"""
import json
import logging
from typing import Any, Optional, List, Dict, Callable, Sequence, Union

# LangGraph/LangChain imports
try:
    from langchain_core.messages import (
        BaseMessage,
        HumanMessage,
        AIMessage,
        SystemMessage,
        ToolMessage,
    )
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import create_react_agent as _create_react_agent
    from langgraph.prebuilt.chat_agent_executor import AgentState
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    # Define stub classes for testing without langgraph installed
    class BaseMessage:
        content: str = ""
    class HumanMessage(BaseMessage):
        pass
    class AIMessage(BaseMessage):
        tool_calls: list = []
    class SystemMessage(BaseMessage):
        pass
    class ToolMessage(BaseMessage):
        pass
    class BaseTool:
        name: str = ""
    class AgentState:
        pass

# Local imports
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    is_hook_enabled,
    get_hook_policy_name,
    is_sensitive_tool,
    analyze_content,
    extract_messages_text,
    extract_tool_calls_text,
    log_event,
    log_to_combined,
    log_security_alert,
    flush_logs,
    get_metrics,
    SENSITIVE_TOOLS,
)

logger = logging.getLogger(__name__)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class GuardrailsViolationError(Exception):
    """Exception raised when a guardrails violation is detected and blocking is enabled."""

    def __init__(self, message: str, violations: list = None):
        super().__init__(message)
        self.violations = violations or []


class GuardrailsBlockedResponse:
    """
    A marker class that can be returned from pre_model_hook to indicate
    the request should be blocked. The agent will use this as the response
    instead of calling the LLM.
    """

    def __init__(self, message: str, violations: list = None):
        self.message = message
        self.violations = violations or []

    def to_ai_message(self) -> "AIMessage":
        """Convert to an AIMessage for the agent state."""
        if LANGGRAPH_AVAILABLE:
            return AIMessage(content=self.message)
        return None


# ============================================================================
# GLOBAL STATE FOR TRACKING
# ============================================================================

class GuardrailsState:
    """Thread-local state for tracking violations across hooks."""

    def __init__(self):
        self._violations: List[dict] = []
        self._event_counter: int = 0

    def add_violation(self, violation: dict):
        self._violations.append(violation)

    def add_violations(self, violations: List[dict]):
        self._violations.extend(violations)

    def get_violations(self) -> List[dict]:
        return self._violations.copy()

    def clear_violations(self):
        self._violations = []

    def increment_event(self) -> int:
        self._event_counter += 1
        return self._event_counter

    def reset(self):
        self._violations = []
        self._event_counter = 0


# Global state instance
_guardrails_state = GuardrailsState()


# ============================================================================
# PRE-MODEL HOOK
# ============================================================================

def enkrypt_pre_model_hook(
    state: Dict[str, Any],
    *,
    block_on_violation: bool = True,
    log_only_mode: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Pre-model hook for LangGraph create_react_agent.

    This hook is called BEFORE the LLM is invoked. It scans the input messages
    for security issues like prompt injection, PII, toxicity, etc.

    Args:
        state: The current agent state containing messages
        block_on_violation: If True, block requests that violate policies
        log_only_mode: If True, never block, only log

    Returns:
        Modified state dict, or None to proceed without changes.
        Can return a state with blocked response to stop LLM call.

    Usage:
        from functools import partial
        from enkrypt_guardrails_hook import enkrypt_pre_model_hook

        pre_hook = partial(enkrypt_pre_model_hook, block_on_violation=True)
        agent = create_react_agent(model, tools, pre_model_hook=pre_hook)
    """
    event_num = _guardrails_state.increment_event()

    # Extract messages from state
    messages = state.get("messages", [])
    if not messages:
        log_event("pre_model_hook", {
            "event_number": event_num,
            "skipped": "no messages",
        })
        return None

    # Extract text from all messages for checking
    combined_text = extract_messages_text(messages)

    if not combined_text.strip():
        log_event("pre_model_hook", {
            "event_number": event_num,
            "skipped": "empty message content",
        })
        return None

    # Check with Enkrypt API
    violations = []
    api_result = None

    if is_hook_enabled("pre_model_hook"):
        should_block, violations, api_result = check_with_enkrypt_api(
            combined_text,
            hook_name="pre_model_hook"
        )

        if violations:
            _guardrails_state.add_violations(violations)
            violation_message = format_violation_message(violations, hook_name="pre_model_hook")

            log_security_alert("pre_model_violation", {
                "event_number": event_num,
                "violations": violations,
                "input_preview": combined_text[:200] + "..." if len(combined_text) > 200 else combined_text,
            }, {"messages_count": len(messages)})

            if should_block and block_on_violation and not log_only_mode:
                logger.warning(f"Pre-model hook blocked input: {violation_message}")

                # Return a modified state that indicates blocking
                # The LLM call will be skipped and this response used instead
                blocked_response = (
                    f"I cannot process this request due to security policy violations:\n\n"
                    f"{violation_message}\n\n"
                    f"Please rephrase your request without the flagged content."
                )

                # Add a system message indicating the block
                if LANGGRAPH_AVAILABLE:
                    blocked_ai_message = AIMessage(content=blocked_response)
                    return {
                        "messages": list(messages) + [blocked_ai_message],
                        "_guardrails_blocked": True,
                        "_guardrails_violations": violations,
                    }

    log_event("pre_model_hook", {
        "event_number": event_num,
        "messages_count": len(messages),
        "text_length": len(combined_text),
        "violations_count": len(violations),
        "api_result": api_result,
    })

    return None  # Continue with LLM call


def create_pre_model_hook(
    block_on_violation: bool = True,
    log_only_mode: bool = False,
) -> Callable:
    """
    Factory function to create a pre_model_hook with custom settings.

    Args:
        block_on_violation: If True, block on violations
        log_only_mode: If True, only log, never block

    Returns:
        A pre_model_hook function for use with create_react_agent

    Example:
        pre_hook = create_pre_model_hook(block_on_violation=True)
        agent = create_react_agent(model, tools, pre_model_hook=pre_hook)
    """
    def hook(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return enkrypt_pre_model_hook(
            state,
            block_on_violation=block_on_violation,
            log_only_mode=log_only_mode,
        )
    return hook


# ============================================================================
# POST-MODEL HOOK
# ============================================================================

def enkrypt_post_model_hook(
    state: Dict[str, Any],
    *,
    block_on_violation: bool = True,
    log_only_mode: bool = False,
    modify_response: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Post-model hook for LangGraph create_react_agent.

    This hook is called AFTER the LLM responds. It scans the LLM output
    for security issues like PII, toxicity, etc.

    Args:
        state: The current agent state containing messages
        block_on_violation: If True, modify/block responses that violate policies
        log_only_mode: If True, never modify, only log
        modify_response: If True, append warnings to violating responses

    Returns:
        Modified state dict, or None to proceed without changes.

    Usage:
        from functools import partial
        from enkrypt_guardrails_hook import enkrypt_post_model_hook

        post_hook = partial(enkrypt_post_model_hook, block_on_violation=True)
        agent = create_react_agent(model, tools, post_model_hook=post_hook)
    """
    event_num = _guardrails_state.increment_event()

    # Extract messages from state
    messages = state.get("messages", [])
    if not messages:
        log_event("post_model_hook", {
            "event_number": event_num,
            "skipped": "no messages",
        })
        return None

    # Get the last message (should be AI response)
    last_message = messages[-1]
    if not LANGGRAPH_AVAILABLE:
        return None

    # Only process AI messages
    if not isinstance(last_message, AIMessage):
        log_event("post_model_hook", {
            "event_number": event_num,
            "skipped": f"last message is not AIMessage, got {type(last_message).__name__}",
        })
        return None

    # Extract content from AI message
    response_text = ""
    if hasattr(last_message, "content"):
        content = last_message.content
        if isinstance(content, str):
            response_text = content
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and "text" in item:
                    response_text += item["text"] + "\n"
                elif isinstance(item, str):
                    response_text += item + "\n"

    # Also check tool calls if present
    tool_calls_text = extract_tool_calls_text(last_message)
    if tool_calls_text:
        response_text += "\n" + tool_calls_text

    if not response_text.strip():
        log_event("post_model_hook", {
            "event_number": event_num,
            "skipped": "empty response content",
        })
        return None

    # Check with Enkrypt API
    violations = []
    api_result = None

    if is_hook_enabled("post_model_hook"):
        should_block, violations, api_result = check_with_enkrypt_api(
            response_text,
            hook_name="post_model_hook"
        )

        if violations:
            _guardrails_state.add_violations(violations)
            violation_message = format_violation_message(violations, hook_name="post_model_hook")

            log_security_alert("post_model_violation", {
                "event_number": event_num,
                "violations": violations,
                "response_preview": response_text[:300] + "..." if len(response_text) > 300 else response_text,
            }, {})

            if should_block and not log_only_mode and modify_response:
                logger.warning(f"Post-model hook detected violation: {violation_message}")

                # Modify the response to include a warning
                warning_text = (
                    f"\n\n[SECURITY WARNING: Response may contain sensitive content. "
                    f"Violations detected: {', '.join(v['detector'] for v in violations)}]"
                )

                # Create modified AI message
                modified_content = response_text + warning_text
                modified_message = AIMessage(
                    content=modified_content,
                    tool_calls=getattr(last_message, "tool_calls", []),
                )

                # Return modified state
                modified_messages = list(messages[:-1]) + [modified_message]
                return {
                    "messages": modified_messages,
                    "_guardrails_warnings": violations,
                }

    log_event("post_model_hook", {
        "event_number": event_num,
        "response_length": len(response_text),
        "violations_count": len(violations),
        "api_result": api_result,
    })

    return None  # Continue without modification


def create_post_model_hook(
    block_on_violation: bool = True,
    log_only_mode: bool = False,
    modify_response: bool = True,
) -> Callable:
    """
    Factory function to create a post_model_hook with custom settings.

    Args:
        block_on_violation: If True, modify responses on violations
        log_only_mode: If True, only log, never modify
        modify_response: If True, append warnings to violating responses

    Returns:
        A post_model_hook function for use with create_react_agent

    Example:
        post_hook = create_post_model_hook(block_on_violation=True)
        agent = create_react_agent(model, tools, post_model_hook=post_hook)
    """
    def hook(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return enkrypt_post_model_hook(
            state,
            block_on_violation=block_on_violation,
            log_only_mode=log_only_mode,
            modify_response=modify_response,
        )
    return hook


# ============================================================================
# TOOL WRAPPERS
# ============================================================================

class EnkryptToolWrapper:
    """
    Wrapper for LangChain tools that adds Enkrypt guardrails protection.

    This wrapper checks tool inputs before execution and tool outputs after,
    blocking or modifying as needed based on policy.

    Example:
        from langchain_community.tools import DuckDuckGoSearchRun
        from enkrypt_guardrails_hook import EnkryptToolWrapper

        search_tool = DuckDuckGoSearchRun()
        protected_tool = EnkryptToolWrapper(search_tool).tool
    """

    def __init__(
        self,
        tool: "BaseTool",
        block_on_violation: bool = True,
        log_only_mode: bool = False,
        check_inputs: bool = True,
        check_outputs: bool = True,
    ):
        """
        Initialize the tool wrapper.

        Args:
            tool: The LangChain tool to wrap
            block_on_violation: If True, block tool calls that violate policies
            log_only_mode: If True, never block, only log
            check_inputs: Check tool inputs before execution
            check_outputs: Check tool outputs after execution
        """
        self._original_tool = tool
        self.block_on_violation = block_on_violation
        self.log_only_mode = log_only_mode
        self.check_inputs = check_inputs
        self.check_outputs = check_outputs
        self._violations: List[dict] = []

    @property
    def tool(self) -> "BaseTool":
        """Get the wrapped tool with guardrails applied."""
        if not LANGGRAPH_AVAILABLE:
            return self._original_tool

        # Create a wrapper function
        original_run = self._original_tool._run if hasattr(self._original_tool, '_run') else None
        original_arun = self._original_tool._arun if hasattr(self._original_tool, '_arun') else None

        wrapper = self

        class ProtectedTool(type(self._original_tool)):
            def _run(self_inner, *args, **kwargs):
                return wrapper._protected_run(original_run, *args, **kwargs)

            async def _arun(self_inner, *args, **kwargs):
                return await wrapper._protected_arun(original_arun, *args, **kwargs)

        # Copy attributes from original tool
        # Include args_schema if the original tool has one
        init_kwargs = {
            "name": self._original_tool.name,
            "description": self._original_tool.description,
        }

        # Copy args_schema if present (required by some tools)
        if hasattr(self._original_tool, 'args_schema') and self._original_tool.args_schema is not None:
            init_kwargs["args_schema"] = self._original_tool.args_schema

        # Copy other important attributes
        if hasattr(self._original_tool, 'return_direct'):
            init_kwargs["return_direct"] = self._original_tool.return_direct
        if hasattr(self._original_tool, 'verbose'):
            init_kwargs["verbose"] = self._original_tool.verbose

        protected = ProtectedTool(**init_kwargs)
        return protected

    def _protected_run(self, original_run: Callable, *args, **kwargs) -> str:
        """Synchronous protected run."""
        tool_name = self._original_tool.name
        event_num = _guardrails_state.increment_event()

        # Check inputs
        if self.check_inputs:
            input_text = self._format_input(args, kwargs)
            violations = self._check_input(input_text, tool_name, event_num)

            if violations and self.block_on_violation and not self.log_only_mode:
                violation_message = format_violation_message(violations, hook_name="before_tool_call")
                return f"Tool call blocked: {violation_message}"

        # Execute original tool
        try:
            result = original_run(*args, **kwargs) if original_run else ""
        except Exception as e:
            log_event("tool_error", {
                "tool_name": tool_name,
                "error": str(e),
            })
            raise

        # Check outputs
        if self.check_outputs and result:
            result = self._check_output(result, tool_name, event_num)

        return result

    async def _protected_arun(self, original_arun: Callable, *args, **kwargs) -> str:
        """Async protected run."""
        tool_name = self._original_tool.name
        event_num = _guardrails_state.increment_event()

        # Check inputs
        if self.check_inputs:
            input_text = self._format_input(args, kwargs)
            violations = self._check_input(input_text, tool_name, event_num)

            if violations and self.block_on_violation and not self.log_only_mode:
                violation_message = format_violation_message(violations, hook_name="before_tool_call")
                return f"Tool call blocked: {violation_message}"

        # Execute original tool
        try:
            result = await original_arun(*args, **kwargs) if original_arun else ""
        except Exception as e:
            log_event("tool_error", {
                "tool_name": tool_name,
                "error": str(e),
            })
            raise

        # Check outputs
        if self.check_outputs and result:
            result = self._check_output(result, tool_name, event_num)

        return result

    def _format_input(self, args: tuple, kwargs: dict) -> str:
        """Format tool input as text for checking."""
        parts = []
        for arg in args:
            if isinstance(arg, str):
                parts.append(arg)
            else:
                parts.append(json.dumps(arg) if arg else "")
        for key, value in kwargs.items():
            if isinstance(value, str):
                parts.append(f"{key}: {value}")
            else:
                parts.append(f"{key}: {json.dumps(value)}")
        return "\n".join(parts)

    def _check_input(self, input_text: str, tool_name: str, event_num: int) -> List[dict]:
        """Check tool input and return violations."""
        if not input_text.strip():
            return []

        # Check if tool is sensitive
        if is_sensitive_tool(tool_name):
            log_security_alert("sensitive_tool_call", {
                "event_number": event_num,
                "tool_name": tool_name,
                "input_preview": input_text[:200],
            }, {})

        violations = []
        if is_hook_enabled("before_tool_call"):
            should_block, violations, api_result = check_with_enkrypt_api(
                input_text,
                hook_name="before_tool_call"
            )

            if violations:
                _guardrails_state.add_violations(violations)
                log_security_alert("tool_input_violation", {
                    "event_number": event_num,
                    "tool_name": tool_name,
                    "violations": violations,
                    "input_preview": input_text[:200],
                }, {})

        log_event("before_tool_call", {
            "event_number": event_num,
            "tool_name": tool_name,
            "input_length": len(input_text),
            "violations_count": len(violations),
        })

        return violations

    def _check_output(self, result: str, tool_name: str, event_num: int) -> str:
        """Check tool output and optionally modify it."""
        if not result.strip():
            return result

        violations = []
        if is_hook_enabled("after_tool_call"):
            should_block, violations, api_result = check_with_enkrypt_api(
                result,
                hook_name="after_tool_call"
            )

            if violations:
                _guardrails_state.add_violations(violations)
                log_security_alert("tool_output_violation", {
                    "event_number": event_num,
                    "tool_name": tool_name,
                    "violations": violations,
                    "output_preview": result[:200],
                }, {})

                if self.block_on_violation and not self.log_only_mode:
                    # Append warning to result
                    warning = (
                        f"\n\n[SECURITY WARNING: Tool output may contain sensitive content. "
                        f"Violations: {', '.join(v['detector'] for v in violations)}]"
                    )
                    result = result + warning

        log_event("after_tool_call", {
            "event_number": event_num,
            "tool_name": tool_name,
            "output_length": len(result),
            "violations_count": len(violations),
        })

        return result

    def get_violations(self) -> List[dict]:
        """Get violations detected by this wrapper."""
        return self._violations.copy()


def wrap_tools(
    tools: List["BaseTool"],
    block_on_violation: bool = True,
    log_only_mode: bool = False,
) -> List["BaseTool"]:
    """
    Wrap a list of tools with Enkrypt guardrails protection.

    Args:
        tools: List of LangChain tools to wrap
        block_on_violation: If True, block tool calls that violate policies
        log_only_mode: If True, never block, only log

    Returns:
        List of wrapped tools

    Example:
        from langchain_community.tools import DuckDuckGoSearchRun
        from enkrypt_guardrails_hook import wrap_tools

        tools = [DuckDuckGoSearchRun()]
        protected_tools = wrap_tools(tools)
    """
    wrapped = []
    for tool in tools:
        wrapper = EnkryptToolWrapper(
            tool,
            block_on_violation=block_on_violation,
            log_only_mode=log_only_mode,
        )
        wrapped.append(wrapper.tool)
    return wrapped


# ============================================================================
# CONVENIENCE AGENT FACTORY
# ============================================================================

def create_protected_agent(
    model: Any,
    tools: List["BaseTool"],
    *,
    block_on_violation: bool = True,
    log_only_mode: bool = False,
    wrap_agent_tools: bool = True,
    **agent_kwargs
) -> Any:
    """
    Create a LangGraph React agent with Enkrypt guardrails protection.

    This is a convenience function that creates an agent with:
    - pre_model_hook for input validation
    - post_model_hook for output monitoring
    - Optionally wrapped tools for tool-level protection

    Args:
        model: The LLM model to use
        tools: List of tools for the agent
        block_on_violation: If True, block on violations
        log_only_mode: If True, only log, never block
        wrap_agent_tools: If True, wrap tools with guardrails
        **agent_kwargs: Additional arguments for create_react_agent

    Returns:
        A LangGraph agent with Enkrypt guardrails

    Example:
        from langchain_openai import ChatOpenAI
        from langchain_community.tools import DuckDuckGoSearchRun
        from enkrypt_guardrails_hook import create_protected_agent

        model = ChatOpenAI(model="gpt-4")
        tools = [DuckDuckGoSearchRun()]

        agent = create_protected_agent(
            model,
            tools,
            block_on_violation=True,
        )

        # Invoke the agent
        result = agent.invoke({"messages": [("user", "What is the weather?")]})
    """
    if not LANGGRAPH_AVAILABLE:
        raise ImportError("langgraph and langchain packages are not installed")

    # Create hooks
    pre_hook = create_pre_model_hook(
        block_on_violation=block_on_violation,
        log_only_mode=log_only_mode,
    )
    post_hook = create_post_model_hook(
        block_on_violation=block_on_violation,
        log_only_mode=log_only_mode,
    )

    # Optionally wrap tools
    if wrap_agent_tools and tools:
        tools = wrap_tools(
            tools,
            block_on_violation=block_on_violation,
            log_only_mode=log_only_mode,
        )

    # Clear state for new agent
    _guardrails_state.reset()

    # Create agent with hooks
    return _create_react_agent(
        model,
        tools,
        pre_model_hook=pre_hook,
        post_model_hook=post_hook,
        **agent_kwargs
    )


# ============================================================================
# AUDIT-ONLY AND BLOCKING VARIANTS
# ============================================================================

def create_blocking_agent(
    model: Any,
    tools: List["BaseTool"],
    **agent_kwargs
) -> Any:
    """
    Create a strictly blocking agent that always blocks on violations.

    This is the most secure option - any violation will block the request.

    Example:
        agent = create_blocking_agent(model, tools)
    """
    return create_protected_agent(
        model,
        tools,
        block_on_violation=True,
        log_only_mode=False,
        wrap_agent_tools=True,
        **agent_kwargs
    )


def create_audit_only_agent(
    model: Any,
    tools: List["BaseTool"],
    **agent_kwargs
) -> Any:
    """
    Create an audit-only agent that logs violations but never blocks.

    Useful for monitoring and understanding violation patterns before
    enabling blocking mode.

    Example:
        agent = create_audit_only_agent(model, tools)
    """
    return create_protected_agent(
        model,
        tools,
        block_on_violation=False,
        log_only_mode=True,
        wrap_agent_tools=True,
        **agent_kwargs
    )


# ============================================================================
# STATE AND METRICS ACCESS
# ============================================================================

def get_current_violations() -> List[dict]:
    """Get all violations detected in the current session."""
    return _guardrails_state.get_violations()


def clear_violations():
    """Clear the current violations list."""
    _guardrails_state.clear_violations()


def get_guardrails_metrics() -> Dict[str, Any]:
    """Get guardrails metrics."""
    return get_metrics()


def reset_state():
    """Reset all guardrails state."""
    _guardrails_state.reset()
    flush_logs()


# ============================================================================
# STANDALONE CHECKING FUNCTIONS
# ============================================================================

def check_input(text: str) -> tuple:
    """
    Standalone function to check input text.

    Args:
        text: The text to check

    Returns:
        Tuple of (should_block, violations, result)
    """
    return check_with_enkrypt_api(text, hook_name="pre_model_hook")


def check_output(text: str) -> tuple:
    """
    Standalone function to check output text.

    Args:
        text: The text to check

    Returns:
        Tuple of (should_block, violations, result)
    """
    return check_with_enkrypt_api(text, hook_name="post_model_hook")


def check_tool_input(text: str, tool_name: str = "") -> tuple:
    """
    Standalone function to check tool input.

    Args:
        text: The tool input text to check
        tool_name: Optional tool name for sensitive tool detection

    Returns:
        Tuple of (should_block, violations, result)
    """
    if tool_name and is_sensitive_tool(tool_name):
        log_security_alert("sensitive_tool_check", {
            "tool_name": tool_name,
            "input_preview": text[:100],
        }, {})
    return check_with_enkrypt_api(text, hook_name="before_tool_call")


def check_tool_output(text: str) -> tuple:
    """
    Standalone function to check tool output.

    Args:
        text: The tool output text to check

    Returns:
        Tuple of (should_block, violations, result)
    """
    return check_with_enkrypt_api(text, hook_name="after_tool_call")
