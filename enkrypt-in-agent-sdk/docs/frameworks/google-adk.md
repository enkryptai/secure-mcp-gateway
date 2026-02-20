# Google ADK Integration Guide

## What is Google ADK?

Google's Agent Development Kit (ADK) is a framework for building AI agents powered by Google's Gemini models. It provides tools for creating agents that can use Google's AI services.

Key concepts:
- **Agent** - An AI agent with capabilities
- **Runner** - Executes agents and manages conversation state
- **Tools** - Functions the agent can call (similar to function calling)

## What the Enkrypt SDK Does for Google ADK

1. **Patches `Runner.run()` and `Runner.run_async()`** - Intercepts agent execution with checkpoint enforcement
2. **Pre-LLM checkpoint** - User content is checked at `pre_llm` checkpoint before the ADK agent runs
3. **Provides `GoogleADKAdapter`** - Context managers with helpers for recording tools and LLM calls
4. **Automatic detection** - `auto_secure()` detects `google.adk` and patches it

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install google-adk
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

## Step 3: Use Google ADK Normally

```python
from google.adk.agents import Agent
from google.adk.runners import Runner
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

agent = Agent(
    model="gemini-2.0-flash",
    name="travel-planner",
    instruction="You help people plan trips.",
)

runner = Runner(agent=agent, app_name="my-app", session_service=...)

try:
    # User content is checked at pre_llm checkpoint before the agent runs
    response = await runner.run(user_id="user1", session_id="s1", new_message="Plan a trip to Tokyo")
except GuardrailBlockedError as e:
    # Handle blocked requests
    print(f"Request blocked: {e}")
    # GuardrailBlockedError: Input blocked at pre_llm checkpoint: ('injection_attack',)
```

## Manual Adapter

For detailed control over what's tracked:

```python
from enkrypt_agent_sdk.adapters.google_adk import GoogleADKAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = GoogleADKAdapter(observer, agent_id="travel-planner")

# Wrap the agent run
with adapter.observe_run(task="Plan a trip") as ctx:
    # Your agent execution here
    response = await runner.run(...)

    # Record individual tool calls
    adapter.record_tool_call(ctx.run_id, "flight_search", {"from": "SFO"}, "Found 3 flights")

    # Record LLM calls
    adapter.record_llm_call(ctx.run_id, "gemini-pro", input_tokens=200, output_tokens=80)

    ctx.set_result(response)
```

## Checkpoint Architecture

The SDK uses a **checkpoint-based enforcement** system:

1. **Pre-LLM Checkpoint**: User content (`new_message`) is checked before the ADK agent processes it
   - If blocked, `GuardrailBlockedError` is raised immediately
   - The agent never sees blocked content

2. **Post-LLM Checkpoint**: Not currently implemented due to the streaming API nature of Google ADK
   - ADK returns streaming responses that make post-LLM validation challenging
   - Future versions may add support for buffered validation

## Events Emitted

| What Happens | Enkrypt Event |
|---|---|
| Agent run starts | `agent.lifecycle.start` |
| Pre-LLM checkpoint | `agent.guardrail.check` (or `agent.guardrail.block` if blocked) |
| Tool called | `agent.tool.call.start/end` |
| LLM called | `agent.llm.call.start/end` |
| Agent run ends | `agent.lifecycle.end` |

## GuardrailBlockedError Handling

When guardrails block a request at the pre-LLM checkpoint, a `GuardrailBlockedError` is raised:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    response = await runner.run(user_id="user1", session_id="s1", new_message="...")
except GuardrailBlockedError as e:
    # Access blocked reasons
    print(f"Blocked reasons: {e.blocked_reasons}")
    # Access the checkpoint where blocking occurred
    print(f"Checkpoint: {e.checkpoint}")  # Will be "pre_llm"
    # Handle gracefully - return safe response, log, etc.
    response = {"error": "Request blocked by security policy"}
```

## Troubleshooting

**Q: `ImportError: No module named 'google.adk'`?**
Install it: `pip install google-adk`. Note: requires a Google Cloud project.

**Q: The auto-patch doesn't seem to work?**
Google ADK's `Runner.run()` is async. Make sure you're using `await` when calling it.

**Q: Why isn't post-LLM validation working?**
Post-LLM checkpoint validation is not currently implemented due to Google ADK's streaming API architecture. Only pre-LLM validation is enforced.
