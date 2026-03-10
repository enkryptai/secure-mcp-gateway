# Agent Framework Events Reference

This document maps every hook/callback event available in each supported agent framework to whether Enkrypt AI guardrails integrate with it.

## Integration Types

| Type | Description | Frameworks |
|------|-------------|------------|
| **Wrapper** | Python class that implements the framework's callback/hook interface at runtime | LangChain, LangGraph, OpenAI Agents SDK, Strands |
| **Provider-only** | Provider functions called directly by framework callbacks (no separate wrapper class) | CrewAI |
| **Script** | Standalone Python scripts invoked via stdio/env-vars by the host IDE/agent | Claude, Claude Code, Copilot, Cursor, Kiro |
| **Middleware** | TypeScript middleware for Vercel AI SDK's language-model wrapper pattern | Vercel AI SDK |

---

## Summary

| Framework | Type | Integrated | Defined but Not Implemented | Not Used (Framework-Available) |
|-----------|------|:----------:|:---------------------------:|:------------------------------:|
| LangChain | Wrapper | 16 | 0 | 2 |
| LangGraph | Wrapper | 6 | 0 | 2+ |
| OpenAI Agents SDK | Wrapper | 12 | 0 | 3 |
| Strands | Wrapper | 6 | 1 | 0 |
| CrewAI | Provider | 4 | 0 | 3+ |
| Claude (Desktop) | Script | 4 | 0 | 2 |
| Claude Code | Script | 10 | 2 | 0 |
| Copilot | Script | 4 | 0 | 2 |
| Cursor | Script | 5 | 0 | 2 |
| Kiro | Script | 5 | 1 | 0 |
| Vercel AI SDK | Middleware | 3 | 0 | 0 |

**Legend**

- **Integrated** -- event is configured in the provider AND has a working implementation (wrapper method or script file).
- **Defined but Not Implemented** -- event appears in the provider's hook-names list but has no corresponding script or is imported but never registered.
- **Not Used** -- event is available in the upstream framework but Enkrypt does not hook into it at all.

---

## Wrapper-Based Frameworks

### LangChain

> Provider: `src/enkryptai_agent_security/sdk/framework_hooks/langchain.py`
> Wrapper: `src/enkryptai_agent_security/sdk/framework_hooks/langchain_handler.py`

| Event | Status | Description |
|-------|--------|-------------|
| `on_llm_start` | Integrated | Validate LLM prompts before call |
| `on_llm_end` | Integrated | Monitor LLM responses |
| `on_llm_error` | Integrated | Log LLM errors |
| `on_chat_model_start` | Integrated | Validate chat messages before call |
| `on_chain_start` | Integrated | Validate chain inputs |
| `on_chain_end` | Integrated | Monitor chain outputs |
| `on_chain_error` | Integrated | Log chain errors |
| `on_tool_start` | Integrated | Validate tool inputs, block sensitive tools |
| `on_tool_end` | Integrated | Monitor tool outputs |
| `on_tool_error` | Integrated | Log tool errors |
| `on_agent_action` | Integrated | Monitor agent decisions (tool selection) |
| `on_agent_finish` | Integrated | Monitor agent final output |
| `on_retriever_start` | Integrated | Validate retriever queries |
| `on_retriever_end` | Integrated | Monitor retrieved documents |
| `on_retriever_error` | Integrated | Log retriever errors |
| `on_text` | Integrated | Generic text monitoring |
| `on_llm_new_token` | Not used | Streaming token-by-token callback |
| `on_retry` | Not used | Retry logic callback |

---

### LangGraph

> Provider: `src/enkryptai_agent_security/sdk/framework_hooks/langgraph.py`
> Wrapper: `src/enkryptai_agent_security/sdk/framework_hooks/langgraph_hook.py`

| Event | Status | Description |
|-------|--------|-------------|
| `pre_model_hook` | Integrated | Pre-LLM input validation (injection, PII, toxicity) |
| `post_model_hook` | Integrated | Post-LLM response monitoring |
| `before_tool_call` | Integrated | Tool input validation (via `EnkryptToolWrapper`) |
| `after_tool_call` | Integrated | Tool output auditing (via `EnkryptToolWrapper`) |
| `on_agent_action` | Integrated | Agent tool-selection monitoring (provider-level) |
| `on_agent_finish` | Integrated | Agent final-output monitoring (provider-level) |
| Node-level callbacks | Not used | Per-node start/end events in LangGraph |
| Graph-level callbacks | Not used | Graph traversal start/end events |

---

### OpenAI Agents SDK

> Provider: `src/enkryptai_agent_security/sdk/framework_hooks/openai_agents.py`
> Wrapper: `src/enkryptai_agent_security/sdk/framework_hooks/openai_hook.py`

**EnkryptRunHooks** (global, applies to entire run):

| Event | Status | Description |
|-------|--------|-------------|
| `on_agent_start` | Integrated | Validate agent context before execution |
| `on_agent_end` | Integrated | Audit agent final output |
| `on_llm_start` | Integrated | Check prompts before LLM calls |
| `on_llm_end` | Integrated | Monitor LLM responses |
| `on_tool_start` | Integrated | Validate tool inputs, block dangerous calls |
| `on_tool_end` | Integrated | Audit tool outputs |
| `on_handoff` | Integrated | Monitor agent handoffs (multi-agent) |

**EnkryptAgentHooks** (per-agent):

| Event | Status | Description |
|-------|--------|-------------|
| `on_start` | Integrated | Called when this agent starts |
| `on_end` | Integrated | Called when this agent produces output |
| `on_tool_start` | Integrated | Tool invocation on this agent |
| `on_tool_end` | Integrated | Tool completion on this agent |
| `on_handoff` | Integrated | Handoff to/from this agent |

**Not used:**

| Event | Notes |
|-------|-------|
| `on_tool_error` | Error-specific hook for tool failures |
| `on_api_error` | API-level error callback |
| `on_retry` | Retry logic callback |

---

### Strands

> Provider: `src/enkryptai_agent_security/sdk/framework_hooks/strands.py`
> Wrapper: `src/enkryptai_agent_security/sdk/framework_hooks/strands_hook.py`

| Event | Status | Description |
|-------|--------|-------------|
| `MessageAdded` | Integrated | Check all messages (user/assistant) |
| `BeforeInvocation` | Integrated | Reset violation tracking at invocation start |
| `AfterInvocation` | Integrated | Log invocation summary |
| `AfterModelCall` | Integrated | Monitor model responses (can request retry) |
| `BeforeToolCall` | Integrated | Validate tool inputs, can cancel tool |
| `AfterToolCall` | Integrated | Audit tool results |
| `BeforeModelCall` | **Defined, not implemented** | Imported in wrapper (line 34) and listed in provider's `STRANDS_HOOK_NAMES`, but NOT registered in `register_hooks()` (line 142) |

---

### CrewAI

> Provider: `src/enkryptai_agent_security/sdk/framework_hooks/crewai.py`
> No separate wrapper file -- provider functions are called directly.

| Event | Status | Description |
|-------|--------|-------------|
| `before_llm_call` | Integrated | LLM input validation |
| `after_llm_call` | Integrated | LLM output monitoring |
| `before_tool_call` | Integrated | Tool input validation |
| `after_tool_call` | Integrated | Tool output auditing |
| Error callbacks | Not used | `on_tool_error`, `on_llm_error` |
| Agent lifecycle | Not used | `on_agent_start`, `on_agent_end` |
| Retry | Not used | `on_retry` |

---

## Script-Based Frameworks

### Claude (Desktop)

> Provider: `src/enkryptai_agent_security/hooks/providers/claude.py`
> Scripts: `src/enkryptai_agent_security/hooks/scripts/claude/`

| Event | Status | Script |
|-------|--------|--------|
| `UserPromptSubmit` | Integrated | `user_prompt_submit.py` |
| `PreToolUse` | Integrated | `pre_tool_use.py` |
| `PostToolUse` | Integrated | `post_tool_use.py` |
| `Stop` | Integrated | `stop.py` |
| `SessionStart` | Not used | Available in Claude Desktop but not in `CLAUDE_HOOK_NAMES` |
| `SessionEnd` | Not used | Available in Claude Desktop but not in `CLAUDE_HOOK_NAMES` |

---

### Claude Code

> Provider: `src/enkryptai_agent_security/hooks/providers/claude_code.py`
> Scripts: `src/enkryptai_agent_security/hooks/scripts/claude_code/`

| Event | Status | Script |
|-------|--------|--------|
| `SessionStart` | Integrated | `session_start.py` |
| `UserPromptSubmit` | Integrated | `user_prompt_submit.py` |
| `PreToolUse` | Integrated | `pre_tool_use.py` |
| `PermissionRequest` | Integrated | `permission_request.py` |
| `PostToolUse` | Integrated | `post_tool_use.py` |
| `SubagentStop` | Integrated | `subagent_stop.py` |
| `Stop` | Integrated | `stop.py` |
| `PreCompact` | Integrated | `pre_compact.py` |
| `SessionEnd` | Integrated | `session_end.py` |
| `Notification` | Integrated | `notification.py` |
| `PostToolUseFailure` | **Defined, not implemented** | In `HOOK_EVENTS` but no script file exists |
| `SubagentStart` | **Defined, not implemented** | In `HOOK_EVENTS` but no script file exists |

Note: `setup.py` also exists in the scripts directory but is an installation helper, not an event hook.

---

### Copilot

> Provider: `src/enkryptai_agent_security/hooks/providers/copilot.py`
> Scripts: `src/enkryptai_agent_security/hooks/scripts/copilot/`

| Event | Status | Script |
|-------|--------|--------|
| `userPromptSubmitted` | Integrated | `user_prompt_submitted.py` |
| `preToolUse` | Integrated | `pre_tool_use.py` |
| `postToolUse` | Integrated | `post_tool_use.py` |
| `errorOccurred` | Integrated | `error_occurred.py` |
| `sessionStarted` | Not used | Script exists (`session_start.py`) but event is NOT in `COPILOT_HOOK_NAMES` |
| `sessionEnded` | Not used | Script exists (`session_end.py`) but event is NOT in `COPILOT_HOOK_NAMES` |

---

### Cursor

> Provider: `src/enkryptai_agent_security/hooks/providers/cursor.py`
> Scripts: `src/enkryptai_agent_security/hooks/scripts/cursor/`

| Event | Status | Script |
|-------|--------|--------|
| `beforeSubmitPrompt` | Integrated | `before_submit_prompt.py` |
| `beforeMCPExecution` | Integrated | `before_mcp_execution.py` |
| `afterMCPExecution` | Integrated | `after_mcp_execution.py` |
| `afterAgentResponse` | Integrated | `after_agent_response.py` |
| `stop` | Integrated | `stop.py` |
| `onError` | Not used | Available in Cursor but not configured |
| `onRetry` | Not used | Available in Cursor but not configured |

---

### Kiro

> Provider: `src/enkryptai_agent_security/hooks/providers/kiro.py`
> Scripts: `src/enkryptai_agent_security/hooks/scripts/kiro/`

| Event | Status | Script |
|-------|--------|--------|
| `PromptSubmit` | Integrated | `prompt_submit.py` |
| `AgentStop` | Integrated | `agent_stop.py` |
| `FileSave` | Integrated | `file_save.py` |
| `FileCreate` | Integrated | `file_create.py` |
| `Manual` | Integrated | `manual_security_scan.py` |
| `FileDelete` | **Defined, not implemented** | In `KIRO_HOOK_NAMES` but no script file exists |

---

## Middleware-Based Frameworks

### Vercel AI SDK

> Source: `hooks/vercel-ai-sdk/src/enkrypt-middleware.ts`

| Hook | Status | Description |
|------|--------|-------------|
| `transformParams` | Integrated | Pre-request input validation |
| `wrapGenerate` | Integrated | Post-generation output scanning |
| `wrapStream` | Integrated | Streaming output scanning |

Tool calls are checked within `wrapGenerate` and `wrapStream` rather than via separate tool-level hooks.
