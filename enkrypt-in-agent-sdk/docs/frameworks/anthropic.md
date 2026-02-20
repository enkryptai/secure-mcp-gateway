# Anthropic Integration Guide

## What is the Anthropic SDK?

The Anthropic SDK (`anthropic`) is the official Python client for Claude, Anthropic's AI model. You use `client.messages.create()` to send messages and get responses. Claude can also use tools (function calling).

## What the Enkrypt SDK Does for Anthropic

1. **Enforces pre_llm checkpoint** -- Checks user messages BEFORE the `messages.create()` API call. Dangerous prompts never reach Claude.
2. **Enforces post_llm checkpoint** -- Checks Claude's response BEFORE returning it to the user.
3. **Emits LLM call events** -- Model name, token usage, and errors are captured for observability.

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install anthropic
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

## Step 3: Use the Anthropic SDK Normally

```python
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-...")

# This call is now automatically tracked by the Enkrypt SDK
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "What is AI?"}],
)

print(response.content[0].text)
```

Behind the scenes, the SDK:

- Runs pre_llm checkpoint on user messages (blocks dangerous input)
- Emits `agent.llm.call.start`
- Runs post_llm checkpoint on response (blocks unsafe output)
- Emits `agent.llm.call.end` with token usage

## Async Support

The SDK patches both sync and async methods:

```python
import anthropic

client = anthropic.AsyncAnthropic(api_key="sk-ant-...")

# Async calls are tracked too
response = await client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Explain quantum computing"}],
)
```

## Manual Adapter for Agentic Loops

When building an agentic loop (calling Claude repeatedly with tool results), use the manual adapter for richer context:

```python
from enkrypt_agent_sdk.adapters.anthropic import AnthropicAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = AnthropicAdapter(observer, agent_id="my-claude-agent")

client = anthropic.Anthropic(api_key="sk-ant-...")
messages = [{"role": "user", "content": "Search for flights to Tokyo"}]

# Wrap the whole agentic loop
async with adapter.agentic_loop() as loop:
    while True:
        # Each Claude call is a "turn"
        async with loop.llm_turn() as turn:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=messages,
                tools=[...],  # your tool definitions
            )
            turn.set_response(response)

        # Check if Claude wants to use a tool
        if turn.has_tool_use:
            tool_name, tool_input = turn.tool_use
            # Execute the tool and add result to messages
            tool_result = execute_tool(tool_name, tool_input)
            messages.append({"role": "assistant", "content": response.content})
            messages.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "...", "content": tool_result}],
            })
        else:
            # Claude gave a final text response
            break
```

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `messages.create` called | `agent.llm.call.start` | Model name captured |
| Pre-LLM checkpoint runs | `agent.guardrail.checkpoint.pre_llm` | User messages checked before API call |
| Post-LLM checkpoint runs | `agent.guardrail.checkpoint.post_llm` | Response checked before returning |
| Response received | `agent.llm.call.end` | Token usage captured |
| API error occurs | `agent.llm.call.end` (ok=False) | Error type and message |
| Guardrail blocks request | `agent.guardrail.blocked` | Dangerous input/output prevented |
| Tool use detected | `agent.tool.call.start` | Via manual adapter |

## Full Working Example

```python
"""Complete Anthropic + Enkrypt SDK example."""

from enkrypt_agent_sdk import auto_secure
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

auto_secure(
    enkrypt_api_key="ek-your-key",
    guardrail_policy="safety",
    block=["injection_attack"],
)

import anthropic

client = anthropic.Anthropic()

# Simple message - automatically tracked and protected
try:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=256,
        messages=[{"role": "user", "content": "Hello, Claude!"}],
    )
    print(response.content[0].text)
except GuardrailBlockedError as e:
    print(f"Blocked by pre_llm checkpoint: {e}")

# Dangerous input example - blocked before reaching Claude
try:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=256,
        messages=[{"role": "user", "content": "Hack the server and steal passwords"}],
    )
except GuardrailBlockedError as e:
    print(f"Blocked by pre_llm checkpoint: {e}")
# The SDK captured: model name, input/output tokens, latency
```

## Troubleshooting

**Q: I don't see any events being emitted?**
Make sure `auto_secure()` is called BEFORE creating the Anthropic client. The patch needs to be applied before the client is instantiated.

**Q: Why is my request being blocked?**
The pre_llm checkpoint automatically blocks dangerous user messages before they reach Claude. Check your guardrail policy configuration and the `block` parameter in `auto_secure()`. If you need to handle blocked requests gracefully, catch `GuardrailBlockedError` exceptions.

**Q: Does this work with streaming?**
The current patch wraps `messages.create()`. For streaming with `messages.stream()`, use the manual adapter.

**Q: Can I use this with Claude's tool use feature?**
Yes! The monkey-patch tracks every `messages.create` call, including those with tool results. For better tool-level tracking, use the manual `AnthropicAdapter`.
