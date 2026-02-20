# smolagents (HuggingFace) Integration Guide

## What is smolagents?

smolagents is HuggingFace's lightweight agent framework. It's designed for building agents that can write and execute code, use tools, and work with HuggingFace models. The "smol" in the name means it's intentionally simple and small.

Key concepts:
- **CodeAgent** - An agent that writes Python code to solve tasks
- **ToolCallingAgent** - An agent that uses function calling
- **Tool** - A function the agent can use
- **`agent.run()`** - Executes the agent with a task

## What the Enkrypt SDK Does for smolagents

1. **Patches `Agent.run()`** - Intercepts agent execution with **pre_llm** and **post_llm** checkpoint enforcement
2. **Patches `Tool.forward()`** - Intercepts tool execution with **pre_tool** and **post_tool** checkpoint enforcement
3. **All 4 checkpoints available** - User tasks are checked before the agent runs, tool inputs are checked before tool forward executes
4. **Provides `SmolagentsAdapter`** - Context managers with step, tool, and LLM tracking

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install smolagents
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

## Step 3: Use smolagents Normally

```python
from smolagents import CodeAgent, HfApiModel
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

model = HfApiModel()
agent = CodeAgent(tools=[], model=model)

# Run the agent - checkpoint enforcement is automatic!
try:
    result = agent.run("What is 15 * 7?")
    print(result)
except GuardrailBlockedError as e:
    print(f"Request blocked at checkpoint: {e}")
    print(f"Violations: {e.violations}")
```

The SDK automatically:
- **Checks user tasks** before the agent runs (pre_llm checkpoint)
- **Checks tool inputs** before tool forward executes (pre_tool checkpoint)
- **Checks tool outputs** after tool forward completes (post_tool checkpoint)
- **Checks agent outputs** after execution completes (post_llm checkpoint)

## Manual Adapter

For detailed step-by-step tracking:

```python
from enkrypt_agent_sdk.adapters.smolagents import SmolagentsAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = SmolagentsAdapter(observer, agent_id="code-agent")

with adapter.observe_run(task="Analyze data") as ctx:
    # Record each thinking step
    ctx.record_step(thought="I should search for the data first")

    # Record tool calls
    ctx.record_tool_call("web_search", "AI news 2025", "5 articles found")

    # Record LLM calls
    ctx.record_llm_call("llama-3", input_tokens=100, output_tokens=50)

    # Record another step
    ctx.record_step(thought="Now I'll analyze the results", code="print(data.describe())")

    ctx.set_result("Analysis complete: AI adoption increased 40%")
# ctx._result_attrs["total_steps"] == 2
```

## Checkpoint Enforcement

The SDK enforces guardrails at four checkpoints:

| Checkpoint | When | What's Checked |
|---|---|---|
| **pre_llm** | Before `Agent.run()` executes | User task text |
| **pre_tool** | Before `Tool.forward()` executes | Tool input arguments |
| **post_tool** | After `Tool.forward()` completes | Tool output/result |
| **post_llm** | After `Agent.run()` completes | Agent output text |

If any checkpoint fails, `GuardrailBlockedError` is raised and execution stops at that checkpoint.

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `agent.run()` starts | `agent.lifecycle.start` | Task captured |
| Agent thinks | `agent.step.start/end` | Thought and code |
| Tool used | `agent.tool.call.start/end` | Tool name, input/output |
| LLM called | `agent.llm.call.start/end` | Model, tokens |
| Run ends | `agent.lifecycle.end` | Total steps, result |

## Troubleshooting

**Q: I get an error about `huggingface_hub`?**
This is a known issue with certain versions of `huggingface_hub`. Try: `pip install --upgrade huggingface_hub`

**Q: Which agent class is patched?**
The SDK first tries `CodeAgent`, then falls back to `ToolCallingAgent`. Whichever is available gets patched. Both `Agent.run()` and `Tool.forward()` are patched for checkpoint enforcement.

**Q: What happens when a guardrail blocks a request?**
A `GuardrailBlockedError` is raised at the checkpoint where the violation was detected. You can catch this exception to handle blocked requests gracefully:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    result = agent.run("user task")
except GuardrailBlockedError as e:
    print(f"Blocked at checkpoint: {e}")
    print(f"Violations: {e.violations}")
```
