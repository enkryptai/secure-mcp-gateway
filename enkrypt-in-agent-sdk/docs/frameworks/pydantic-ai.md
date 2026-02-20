# PydanticAI Integration Guide

## What is PydanticAI?

PydanticAI is a type-safe agent framework built on Pydantic. It makes building agents feel like writing regular Python functions with type hints. The key idea: your agent returns structured, validated data instead of raw text.

Key concepts:
- **Agent** - Wraps an LLM with tools and a system prompt
- **`agent.run()`** - Sends a message and returns a typed result
- **`agent.run_sync()`** - Synchronous version
- **`RunResult`** - The response, including `all_messages()` for the full conversation

## What the Enkrypt SDK Does for PydanticAI

1. **Patches `Agent.run()` and `Agent.run_sync()`** - Intercepts agent execution with **pre_llm** and **post_llm** checkpoints for guardrail enforcement
2. **Provides `PydanticAIAdapter`** - Context managers for detailed tracking
3. **Post-hoc message replay** - Reconstruct events from `RunResult.all_messages()`
4. **Blocks unsafe execution** - User prompts are checked at pre_llm before the agent runs, and agent responses are checked at post_llm before returning

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install pydantic-ai
```

## Step 2: Add Enkrypt Security

```python
from enkrypt_agent_sdk import auto_secure

auto_secure(
    enkrypt_api_key="ek-your-key-here",
    guardrail_policy="My Safety Policy",
    block=["injection_attack", "pii", "toxicity"],
)
```

## Step 3: Use PydanticAI Normally

```python
from pydantic_ai import Agent

agent = Agent(
    "openai:gpt-4",
    system_prompt="You are a helpful assistant.",
)

# Async run - automatically protected by guardrail checkpoints
result = await agent.run("What is the capital of France?")
print(result.data)  # "Paris"
# User prompt checked at pre_llm checkpoint before execution
# Agent response checked at post_llm checkpoint before returning

# Sync run - also protected
result = agent.run_sync("What is 2 + 2?")
print(result.data)  # "4"
```

## Manual Adapter with Context Managers

For more control, use the `PydanticAIAdapter`:

```python
from enkrypt_agent_sdk.adapters.pydantic_ai import PydanticAIAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = PydanticAIAdapter(observer, agent_id="my-agent")

# Sync usage
with adapter.observe_run(task="Answer a question") as ctx:
    result = agent.run_sync("What is AI?")
    ctx.set_result(result)

# Async usage
async with adapter.aobserve_run(task="Summarize text") as ctx:
    result = await agent.run("Summarize this article...")
    ctx.set_result(result)
```

## Guardrail Checkpoints

The Enkrypt SDK enforces guardrails at **2 checkpoints**:

1. **pre_llm** - User prompts are checked before the agent runs
2. **post_llm** - Agent responses are checked before returning to the caller

If a guardrail violation is detected, a `GuardrailBlockedError` is raised, preventing unsafe execution.

## Post-Hoc Message Replay

A unique feature: you can reconstruct events from a completed run's message history. This is useful when you want observability without wrapping every call:

```python
# After a run completes
result = await agent.run("Explain quantum computing")

# Replay the conversation to emit events
adapter.replay_messages(result.all_messages())
# This emits tool_call and llm_call events for every interaction
# that happened during the run
```

The replay method recognizes:
- `model-text-response` - Emits `LLM_CALL_START` + `LLM_CALL_END`
- `tool-return` / `tool-call` - Emits `TOOL_CALL_START` + `TOOL_CALL_END`
- `request` / `system-prompt` - Skipped (not observable events)

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `agent.run()` starts | `agent.lifecycle.start` | Task captured |
| User prompt checked | `pre_llm` checkpoint | Guardrail enforcement |
| Agent response checked | `post_llm` checkpoint | Guardrail enforcement |
| `agent.run()` ends | `agent.lifecycle.end` | Result, message count |
| LLM response (via replay) | `agent.llm.call.start/end` | Model, output |
| Tool call (via replay) | `agent.tool.call.start/end` | Tool name, output |

## GuardrailBlockedError Handling

When guardrails block execution, catch `GuardrailBlockedError`:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    result = await agent.run("User prompt here")
    print(result.data)
except GuardrailBlockedError as e:
    print(f"Guardrail violation: {e.violation_type}")
    print(f"Blocked at checkpoint: {e.checkpoint}")
    print(f"Reason: {e.message}")
    # Handle blocked execution appropriately
```

## Full Working Example

```python
"""Complete PydanticAI + Enkrypt SDK example."""

from enkrypt_agent_sdk.adapters.pydantic_ai import PydanticAIAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = PydanticAIAdapter(observer, agent_id="math-agent")

# Track a run with context manager
try:
    with adapter.observe_run(task="Math question") as ctx:
        # In real code: result = agent.run_sync("What is 15 * 7?")
        ctx.set_result("105")
    print("Run tracked successfully!")
except GuardrailBlockedError as e:
    print(f"Execution blocked: {e.message}")
```

## Troubleshooting

**Q: I get `ImportError: No module named 'pydantic_ai'`?**
Install it: `pip install pydantic-ai`

**Q: Both `run()` and `run_sync()` are tracked?**
Yes! The auto-patch wraps both methods.

**Q: What if I'm using PydanticAI tools?**
Tool calls are captured via the message replay feature. Call `adapter.replay_messages(result.all_messages())` after each run to get tool-level events.
