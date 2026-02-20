# Phidata / Agno Integration Guide

## What is Phidata?

Phidata (also known as Agno) is a framework for building AI agents with **memory, knowledge, and tools**. It focuses on making agents that are production-ready with built-in support for databases, APIs, and various AI models.

Key concepts:
- **Agent** - An AI assistant with tools and knowledge
- **Tool** - Functions the agent can use (web search, SQL, APIs, etc.)
- **Knowledge** - Data sources the agent can reference
- **`agent.run()`** - Executes the agent with a message

## What the Enkrypt SDK Does for Phidata

1. **Patches `Agent.run()`** - Intercepts agent runs with **pre_llm** and **post_llm** guardrail checkpoints for enforcement/blocking
2. **Patches `Agent.print_response()`** - Intercepts print responses with a **pre_llm** checkpoint to check user messages before execution
3. **Supports both `phi` and `agno`** - The SDK tries `phi.agent.Agent` first, then `agno.agent.Agent`
4. **Provides `PhidataAdapter`** - Context managers with tool and LLM tracking
5. **Checkpoint Enforcement** - User messages are checked at **pre_llm** before the agent runs; agent responses are checked at **post_llm** before returning. When violations are detected, `GuardrailBlockedError` is raised to halt execution.

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install phidata
# Or if using Agno:
pip install agno
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

## Step 3: Use Phidata Normally

```python
from phi.agent import Agent
from phi.tools.duckduckgo import DuckDuckGo
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

agent = Agent(
    name="Research Agent",
    tools=[DuckDuckGo()],
    instructions="You are a helpful research assistant.",
)

# Run the agent - automatically tracked and protected!
try:
    result = agent.run("What are the latest developments in AI?")
    print(result)
except GuardrailBlockedError as e:
    print(f"Request blocked by guardrails: {e}")
    print(f"Violations: {e.violations}")
```

## Manual Adapter

For detailed tracking:

```python
from enkrypt_agent_sdk.adapters.phidata import PhidataAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = PhidataAdapter(observer, agent_id="research-agent")

with adapter.observe_run(task="Research quantum computing") as ctx:
    # Record tool calls
    ctx.record_tool_call("arxiv_search", "quantum computing", "Found 10 papers")
    ctx.record_tool_call("web_search", "quantum computing news", "3 recent articles")

    # Record LLM calls
    ctx.record_llm_call("gpt-4o", input_tokens=300, output_tokens=150)

    ctx.set_result("Research complete: 10 papers and 3 articles analyzed")

# Async version
async with adapter.aobserve_run(task="Async research") as ctx:
    # Same API as sync
    ctx.record_tool_call("web_search", "AI agents", "5 results")
    ctx.set_result("Done")
```

## Checkpoint Enforcement Flow

When `agent.run()` or `agent.print_response()` is called:

1. **pre_llm checkpoint**: User message is checked **before** the agent runs
   - If violations detected → `GuardrailBlockedError` raised, agent never executes
   - If safe → execution continues

2. **Agent execution**: Normal Phidata agent processing

3. **post_llm checkpoint**: Agent response is checked **before** returning to user
   - If violations detected → `GuardrailBlockedError` raised, response blocked
   - If safe → response returned

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `agent.run()` starts | `agent.lifecycle.start` | Agent name captured |
| User message checked | `pre_llm` checkpoint | Guardrail enforcement before execution |
| Tool used | `agent.tool.call.start/end` | Tool name, input/output |
| LLM called | `agent.llm.call.start/end` | Model, tokens |
| Response checked | `post_llm` checkpoint | Guardrail enforcement before returning |
| Run ends | `agent.lifecycle.end` | Result (or error if blocked) |

## Handling Guardrail Blocks

When guardrails detect violations, `GuardrailBlockedError` is raised:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    result = agent.run("User message here")
except GuardrailBlockedError as e:
    # Access violation details
    print(f"Blocked at checkpoint: {e.violations[0]['checkpoint']}")
    print(f"Violation types: {[v['type'] for v in e.violations]}")
    # Handle blocked request appropriately
```

The exception includes:
- `violations`: List of violation details with `type`, `checkpoint`, and `name`
- Error message describing what was blocked

## Troubleshooting

**Q: The SDK doesn't detect Phidata?**
Check which package you have: `pip list | grep phi` or `pip list | grep agno`. The SDK looks for `phi` first, then `agno`.

**Q: I'm using Agno (the renamed version). Does it work?**
Yes! The SDK automatically falls back to `agno.agent.Agent` if `phi.agent.Agent` is not found.

**Q: Why is my agent not running?**
If `agent.run()` raises `GuardrailBlockedError`, the user message was blocked at the **pre_llm** checkpoint. Check your guardrail policy configuration and the violation details in the exception.

**Q: Why is my response not returned?**
If execution completes but no response is returned, check for `GuardrailBlockedError` at the **post_llm** checkpoint. The response was blocked before being returned to the user.
