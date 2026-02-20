# Semantic Kernel Integration Guide

## What is Semantic Kernel?

Semantic Kernel (SK) is Microsoft's **AI orchestration framework**. It connects LLMs to your existing code through "plugins" (collections of functions). SK handles the planning, execution, and chaining of these functions.

Key concepts:
- **Kernel** - The central orchestrator
- **Plugin** - A collection of functions the AI can call
- **Function** - A single operation (native or LLM-based)
- **Filters** - Intercept function invocations (this is how the SDK hooks in)

## What the Enkrypt SDK Does for Semantic Kernel

SK uses a **filter protocol** instead of callbacks. The SDK provides `EnkryptSKFilter`, which implements the function invocation filter interface, plus patches `ChatCompletionClientBase` for LLM checkpoint enforcement.

1. **`EnkryptSKFilter`** - Registered as a function invocation filter for **pre_tool** and **post_tool** checkpoints
2. **Patches `ChatCompletionClientBase.get_chat_message_contents`** - Intercepts LLM calls with **pre_llm** and **post_llm** checkpoints
3. **Auto-distinguishes LLM calls** - Functions from `ChatCompletion` or `TextCompletion` plugins are tracked as LLM calls; others as tool calls
4. **Checkpoint Enforcement** - User messages in chat history are checked at **pre_llm** before the LLM call; LLM responses are checked at **post_llm** before returning. Tool invocations are checked at **pre_tool** and **post_tool**. When violations are detected, `GuardrailBlockedError` is raised to halt execution.
5. **Error tracking** - Captures failures in function execution

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install semantic-kernel
```

## Step 2: Register the Filter

Semantic Kernel uses explicit filter registration (not monkey-patching), so you need one extra line:

```python
from enkrypt_agent_sdk import auto_secure
from enkrypt_agent_sdk._patch.semantic_kernel import get_filter

# Initialize the SDK
auto_secure(
    enkrypt_api_key="ek-your-key-here",
    guardrail_policy="My Safety Policy",
    block=["injection_attack"],
)

# Get the filter and register it with your kernel
from semantic_kernel import Kernel
kernel = Kernel()

sk_filter = get_filter()
if sk_filter:
    kernel.add_filter("function_invocation", sk_filter)
```

## Step 3: Use Semantic Kernel Normally

```python
from semantic_kernel.functions import kernel_function
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

class WeatherPlugin:
    @kernel_function(description="Get the weather")
    def get_weather(self, city: str) -> str:
        return f"72F and sunny in {city}"

kernel.add_plugin(WeatherPlugin(), "WeatherPlugin")

# When functions are invoked, the filter emits events and enforces guardrails
try:
    result = await kernel.invoke(
        plugin_name="WeatherPlugin",
        function_name="get_weather",
        city="London",
    )
except GuardrailBlockedError as e:
    print(f"Request blocked by guardrails: {e}")
    print(f"Violations: {e.violations}")
```

## How Checkpoint Enforcement Works

### LLM Calls (Chat Completion)

The patch intercepts `ChatCompletionClientBase.get_chat_message_contents`:

1. **pre_llm checkpoint**: User messages in chat history are checked **before** the LLM call
   - If violations detected → `GuardrailBlockedError` raised, LLM never called
   - If safe → LLM call proceeds

2. **LLM execution**: Normal Semantic Kernel chat completion

3. **post_llm checkpoint**: LLM response is checked **before** returning
   - If violations detected → `GuardrailBlockedError` raised, response blocked
   - If safe → response returned

### Tool/Function Calls

The `EnkryptSKFilter` inspects each function invocation:

```python
async def on_function_invocation(self, context, next_handler):
    # Check if this is an LLM call or a tool call
    plugin_name = context.function.plugin_name

    if plugin_name in ("ChatCompletion", "TextCompletion", "TextGeneration"):
        # Track as LLM call
        # Emit: agent.llm.call.start -> execute -> agent.llm.call.end
    else:
        # Track as tool/function call
        # pre_tool checkpoint: Check tool input before execution
        # Execute tool
        # post_tool checkpoint: Check tool output after execution
        # Emit: agent.tool.call.start -> execute -> agent.tool.call.end

    await next_handler(context)  # Continue the filter chain
```

The filter enforces **pre_tool** and **post_tool** checkpoints for function invocations.

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| User message checked (LLM) | `pre_llm` checkpoint | Guardrail enforcement before LLM call |
| Chat completion called | `agent.llm.call.start/end` | Model name, output |
| LLM response checked | `post_llm` checkpoint | Guardrail enforcement before returning |
| Tool input checked | `pre_tool` checkpoint | Guardrail enforcement before tool execution |
| Regular function invoked | `agent.tool.call.start/end` | Plugin.Function name, input, output |
| Tool output checked | `post_tool` checkpoint | Guardrail enforcement after tool execution |
| Function fails | `agent.tool.call.end` (ok=False) | Error type and message |

## Full Working Example

```python
"""Complete Semantic Kernel + Enkrypt SDK example."""

from enkrypt_agent_sdk.adapters.semantic_kernel import EnkryptSKFilter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

# Set up
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
sk_filter = EnkryptSKFilter(observer, agent_id="my-sk-agent")

# Simulate a function invocation
from dataclasses import dataclass
from typing import Any

@dataclass
class MockFunction:
    name: str = "get_weather"
    plugin_name: str = "WeatherPlugin"

@dataclass
class MockResult:
    value: str = "72F in London"

@dataclass
class MockContext:
    function: Any = None
    arguments: str = "city=London"
    result: Any = None

import asyncio

async def demo():
    ctx = MockContext(function=MockFunction(), result=MockResult())
    await sk_filter.on_function_invocation(ctx, lambda c: None)

asyncio.run(demo())
print("Function invocation tracked!")
```

## Handling Guardrail Blocks

When guardrails detect violations, `GuardrailBlockedError` is raised:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    result = await kernel.invoke(...)
except GuardrailBlockedError as e:
    # Access violation details
    checkpoint = e.violations[0]['checkpoint']  # 'pre_llm', 'post_llm', 'pre_tool', 'post_tool'
    violation_types = [v['type'] for v in e.violations]
    print(f"Blocked at {checkpoint} checkpoint")
    print(f"Violation types: {violation_types}")
    # Handle blocked request appropriately
```

The exception includes:
- `violations`: List of violation details with `type`, `checkpoint`, and `name`
- Error message describing what was blocked

## Troubleshooting

**Q: Why do I need to call `get_filter()` separately?**
Semantic Kernel uses an explicit filter registration model (`kernel.add_filter()`). The SDK can't automatically inject filters into a kernel it doesn't have a reference to. This is why you need to call `get_filter()` and register it yourself.

**Q: `get_filter()` returns `None`?**
Make sure you called `auto_secure()` first. The filter is only created when the SDK is initialized.

**Q: Does this work with SK planners?**
Yes! SK planners call functions through the kernel, and all function invocations go through the filter chain.

**Q: Why is my LLM call not executing?**
If `get_chat_message_contents` raises `GuardrailBlockedError`, the user message was blocked at the **pre_llm** checkpoint. Check your guardrail policy configuration and the violation details in the exception.

**Q: Why is my LLM response not returned?**
If the LLM call completes but no response is returned, check for `GuardrailBlockedError` at the **post_llm** checkpoint. The response was blocked before being returned.

**Q: Why is my function not executing?**
If function invocation raises `GuardrailBlockedError`, the tool input was blocked at the **pre_tool** checkpoint. Check the violation details to see what was detected.
