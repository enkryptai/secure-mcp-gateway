#!/usr/bin/env python
"""
Enkrypt AI Guardrails Callback Handler for LangChain

This module provides a BaseCallbackHandler implementation that integrates
Enkrypt AI guardrails with any LangChain component (LLMs, chains, agents, tools, retrievers).

Features:
- Input validation at LLM/chain/tool/retriever start
- Output monitoring at LLM/chain/tool/retriever end
- Agent action monitoring
- Sensitive tool blocking
- Comprehensive logging and metrics

Usage:
    from langchain_openai import ChatOpenAI
    from enkrypt_guardrails_handler import EnkryptGuardrailsHandler

    # Create handler
    handler = EnkryptGuardrailsHandler()

    # Use with any LangChain component
    llm = ChatOpenAI(callbacks=[handler])
    chain = some_chain.with_config(callbacks=[handler])
    agent = create_react_agent(llm, tools, callbacks=[handler])
"""
import json
import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

# LangChain imports
try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.agents import AgentAction, AgentFinish
    from langchain_core.outputs import LLMResult, ChatGeneration, Generation
    from langchain_core.messages import BaseMessage
    from langchain_core.documents import Document
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    # Define stub classes for testing without langchain installed
    class BaseCallbackHandler:
        pass
    class AgentAction:
        tool: str = ""
        tool_input: Any = ""
        log: str = ""
    class AgentFinish:
        return_values: dict = {}
        log: str = ""
    class LLMResult:
        generations: list = []
        llm_output: dict = {}
    class ChatGeneration:
        text: str = ""
        message: Any = None
    class Generation:
        text: str = ""
    class BaseMessage:
        content: str = ""
    class Document:
        page_content: str = ""
        metadata: dict = {}

# Local imports
from enkrypt_guardrails import (
    check_with_enkrypt_api,
    format_violation_message,
    is_hook_enabled,
    get_hook_guardrail_name,
    is_sensitive_tool,
    analyze_content,
    extract_prompts_text,
    extract_messages_text,
    extract_chain_inputs_text,
    extract_chain_outputs_text,
    extract_retriever_query_text,
    extract_retriever_documents_text,
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

    def __init__(self, message: str, violations: list = None, hook_name: str = ""):
        super().__init__(message)
        self.violations = violations or []
        self.hook_name = hook_name


class SensitiveToolBlockedError(Exception):
    """Exception raised when a sensitive tool is blocked."""

    def __init__(self, tool_name: str, reason: str = ""):
        super().__init__(f"Sensitive tool '{tool_name}' blocked: {reason}")
        self.tool_name = tool_name
        self.reason = reason


# ============================================================================
# ENKRYPT GUARDRAILS CALLBACK HANDLER
# ============================================================================

class EnkryptGuardrailsHandler(BaseCallbackHandler):
    """
    LangChain callback handler that integrates Enkrypt AI guardrails.

    This handler provides guardrails protection at multiple points:
    - on_llm_start: Validate prompts before LLM call
    - on_llm_end: Monitor LLM responses
    - on_chat_model_start: Validate chat messages before call
    - on_chain_start: Validate chain inputs
    - on_chain_end: Monitor chain outputs
    - on_tool_start: Validate tool inputs
    - on_tool_end: Monitor tool outputs
    - on_agent_action: Monitor agent decisions
    - on_agent_finish: Monitor agent final output
    - on_retriever_start: Validate retriever queries
    - on_retriever_end: Monitor retrieved documents

    Args:
        raise_on_violation: If True, raise GuardrailsViolationError on violation.
                           If False, just log the violation.
        block_sensitive_tools: If True, block calls to sensitive tools.
        audit_only: If True, only log violations without blocking.
    """

    def __init__(
        self,
        raise_on_violation: bool = True,
        block_sensitive_tools: bool = True,
        audit_only: bool = False,
    ):
        super().__init__()
        self.raise_on_violation = raise_on_violation
        self.block_sensitive_tools = block_sensitive_tools
        self.audit_only = audit_only

        # Control which callbacks to process
        self.ignore_llm = False
        self.ignore_chain = False
        self.ignore_agent = False
        self.ignore_retriever = False
        self.ignore_chat_model = False

    def _handle_violation(
        self,
        hook_name: str,
        violations: list,
        context: dict,
    ) -> None:
        """Handle a guardrails violation."""
        message = format_violation_message(violations, hook_name)

        # Log the violation
        log_security_alert(
            alert_type=f"{hook_name}_violation",
            details={
                "violations": violations,
                "message": message,
            },
            data=context,
        )

        log_to_combined(hook_name, context, {
            "blocked": not self.audit_only,
            "violations": violations,
        })

        # Raise if configured to do so
        if self.raise_on_violation and not self.audit_only:
            raise GuardrailsViolationError(
                message=f"Guardrails violation in {hook_name}: {message}",
                violations=violations,
                hook_name=hook_name,
            )

    # =========================================================================
    # LLM CALLBACKS
    # =========================================================================

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Run when LLM starts. Validate prompts for injection attacks, PII, etc."""
        hook_name = "on_llm_start"

        if not is_hook_enabled(hook_name):
            return

        text = extract_prompts_text(prompts)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "prompts_count": len(prompts),
            "text_length": len(text),
            "tags": tags,
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when LLM ends. Monitor response for PII, toxicity, etc."""
        hook_name = "on_llm_end"

        if not is_hook_enabled(hook_name):
            return

        # Extract text from generations
        text_parts = []
        for gen_list in response.generations:
            for gen in gen_list:
                if hasattr(gen, "text"):
                    text_parts.append(gen.text)
                elif hasattr(gen, "message") and hasattr(gen.message, "content"):
                    text_parts.append(str(gen.message.content))

        text = "\n".join(text_parts)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "generations_count": len(response.generations),
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when LLM errors."""
        hook_name = "on_llm_error"

        log_event(hook_name, {
            "run_id": str(run_id),
            "error": str(error),
            "error_type": type(error).__name__,
        })

    # =========================================================================
    # CHAT MODEL CALLBACKS
    # =========================================================================

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Run when chat model starts. Validate messages for injection attacks, PII, etc."""
        hook_name = "on_chat_model_start"

        if not is_hook_enabled(hook_name):
            return

        # Flatten messages and extract text
        flat_messages = []
        for msg_list in messages:
            flat_messages.extend(msg_list)

        text = extract_messages_text(flat_messages)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "messages_count": len(flat_messages),
            "text_length": len(text),
            "tags": tags,
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    # =========================================================================
    # CHAIN CALLBACKS
    # =========================================================================

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Run when chain starts. Validate inputs."""
        hook_name = "on_chain_start"

        if not is_hook_enabled(hook_name):
            return

        text = extract_chain_inputs_text(inputs)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "chain_name": serialized.get("name", "unknown"),
            "input_keys": list(inputs.keys()),
            "text_length": len(text),
            "tags": tags,
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when chain ends. Monitor outputs."""
        hook_name = "on_chain_end"

        if not is_hook_enabled(hook_name):
            return

        text = extract_chain_outputs_text(outputs)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "output_keys": list(outputs.keys()),
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when chain errors."""
        hook_name = "on_chain_error"

        log_event(hook_name, {
            "run_id": str(run_id),
            "error": str(error),
            "error_type": type(error).__name__,
        })

    # =========================================================================
    # TOOL CALLBACKS
    # =========================================================================

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Run when tool starts. Validate tool inputs and block sensitive tools."""
        hook_name = "on_tool_start"

        tool_name = serialized.get("name", "unknown")

        # Check for sensitive tool
        if self.block_sensitive_tools and is_sensitive_tool(tool_name):
            log_security_alert(
                alert_type="sensitive_tool_blocked",
                details={
                    "tool_name": tool_name,
                    "input_preview": input_str[:100] if input_str else "",
                },
                data={"run_id": str(run_id)},
            )
            if not self.audit_only:
                raise SensitiveToolBlockedError(
                    tool_name=tool_name,
                    reason="Tool is in sensitive tools list",
                )

        if not is_hook_enabled(hook_name):
            return

        text = input_str if isinstance(input_str, str) else json.dumps(input_str)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "tool_name": tool_name,
            "text_length": len(text),
            "tags": tags,
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when tool ends. Monitor tool output for PII, etc."""
        hook_name = "on_tool_end"

        if not is_hook_enabled(hook_name):
            return

        text = str(output) if output else ""
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when tool errors."""
        hook_name = "on_tool_error"

        log_event(hook_name, {
            "run_id": str(run_id),
            "error": str(error),
            "error_type": type(error).__name__,
        })

    # =========================================================================
    # AGENT CALLBACKS
    # =========================================================================

    def on_agent_action(
        self,
        action: AgentAction,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when agent takes an action. Monitor agent decisions."""
        hook_name = "on_agent_action"

        if not is_hook_enabled(hook_name):
            return

        # Extract tool input as text
        tool_input = action.tool_input
        if isinstance(tool_input, dict):
            text = json.dumps(tool_input)
        else:
            text = str(tool_input)

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "tool": action.tool,
            "log_preview": action.log[:100] if action.log else "",
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_agent_finish(
        self,
        finish: AgentFinish,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when agent finishes. Monitor final output."""
        hook_name = "on_agent_finish"

        if not is_hook_enabled(hook_name):
            return

        # Extract return values as text
        return_values = finish.return_values
        if isinstance(return_values, dict):
            text = json.dumps(return_values)
        else:
            text = str(return_values)

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "log_preview": finish.log[:100] if finish.log else "",
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    # =========================================================================
    # RETRIEVER CALLBACKS
    # =========================================================================

    def on_retriever_start(
        self,
        serialized: Dict[str, Any],
        query: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Run when retriever starts. Validate query for injection attacks."""
        hook_name = "on_retriever_start"

        if not is_hook_enabled(hook_name):
            return

        text = extract_retriever_query_text(query)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "retriever_name": serialized.get("name", "unknown"),
            "text_length": len(text),
            "tags": tags,
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_retriever_end(
        self,
        documents: List[Document],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when retriever ends. Monitor retrieved documents for sensitive data."""
        hook_name = "on_retriever_end"

        if not is_hook_enabled(hook_name):
            return

        text = extract_retriever_documents_text(documents)
        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "documents_count": len(documents),
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)

    def on_retriever_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run when retriever errors."""
        hook_name = "on_retriever_error"

        log_event(hook_name, {
            "run_id": str(run_id),
            "error": str(error),
            "error_type": type(error).__name__,
        })

    # =========================================================================
    # TEXT CALLBACK
    # =========================================================================

    def on_text(
        self,
        text: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Run on arbitrary text. Can be used for custom monitoring."""
        hook_name = "on_text"

        if not is_hook_enabled(hook_name):
            return

        if not text:
            return

        context = {
            "run_id": str(run_id),
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "text_length": len(text),
        }

        log_event(hook_name, {"context": context, "text_preview": text[:200]})

        should_block, violations, result = check_with_enkrypt_api(text, hook_name)

        if should_block and violations:
            self._handle_violation(hook_name, violations, context)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_guardrails_handler(
    raise_on_violation: bool = True,
    block_sensitive_tools: bool = True,
    audit_only: bool = False,
) -> EnkryptGuardrailsHandler:
    """
    Create an EnkryptGuardrailsHandler with the specified configuration.

    Args:
        raise_on_violation: If True, raise exceptions on violations.
        block_sensitive_tools: If True, block sensitive tool calls.
        audit_only: If True, only log violations without blocking.

    Returns:
        Configured EnkryptGuardrailsHandler instance.

    Example:
        from langchain_openai import ChatOpenAI
        from enkrypt_guardrails_handler import create_guardrails_handler

        handler = create_guardrails_handler()
        llm = ChatOpenAI(callbacks=[handler])
    """
    return EnkryptGuardrailsHandler(
        raise_on_violation=raise_on_violation,
        block_sensitive_tools=block_sensitive_tools,
        audit_only=audit_only,
    )


def get_guardrails_metrics(hook_name: Optional[str] = None) -> Dict[str, Any]:
    """Get metrics for guardrails hooks."""
    return get_metrics(hook_name)


def flush_guardrails_logs():
    """Flush all guardrails log buffers."""
    flush_logs()
