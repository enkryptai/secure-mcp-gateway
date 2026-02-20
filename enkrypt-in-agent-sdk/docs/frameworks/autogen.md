# AutoGen Integration Guide

## What is AutoGen?

AutoGen is Microsoft's framework for building **multi-agent conversations**. Multiple AI agents chat with each other to solve problems. One agent might be a "coder," another a "reviewer," and they go back and forth until the task is done.

Key concepts:
- **ConversableAgent** - An agent that can send and receive messages
- **AssistantAgent** - An AI-powered agent (backed by an LLM)
- **UserProxyAgent** - Represents the human user (can auto-reply or ask for input)
- **GroupChat** - Multiple agents in a group conversation
- **`initiate_chat()`** - Starts a conversation between agents

## What the Enkrypt SDK Does for AutoGen

1. **Patches `ConversableAgent.initiate_chat()`** - Intercepts conversations with **pre_llm** and **post_llm** guardrail checkpoints
2. **Patches `a_initiate_chat()`** - Async version with the same checkpoint enforcement
3. **Provides `AutoGenAdapter`** - Context managers with turn and tool tracking

**Guardrail Checkpoints:**
- **pre_llm checkpoint**: The initial message is checked before the chat starts. If blocked, `GuardrailBlockedError` is raised and the conversation never begins.
- **post_llm checkpoint**: The chat result/summary is checked before returning. If blocked, `GuardrailBlockedError` is raised and the result is not returned.

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install pyautogen
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

## Step 3: Use AutoGen Normally

```python
from autogen import AssistantAgent, UserProxyAgent
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

assistant = AssistantAgent(
    name="coder",
    llm_config={"model": "gpt-4"},
)

user_proxy = UserProxyAgent(
    name="user",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=3,
)

# Start a conversation - automatically tracked and protected!
try:
    user_proxy.initiate_chat(assistant, message="Write a Python function to sort a list")
except GuardrailBlockedError as e:
    print(f"Conversation blocked: {e.reason}")
    # Handle blocked conversation appropriately
```

## Manual Adapter for Detailed Tracking

```python
from enkrypt_agent_sdk.adapters.autogen import AutoGenAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = AutoGenAdapter(observer, agent_id="code-review-team")

with adapter.observe_chat(task="Code review") as ctx:
    # Track individual conversation turns
    ctx.record_turn("user", "coder", "Please review this code")
    ctx.record_llm_call("gpt-4", input_tokens=150, output_tokens=60)
    ctx.record_turn("coder", "user", "The code looks good. LGTM!")

    # Track tool usage
    ctx.record_tool_call("code_analyzer", "main.py", "No issues found")

    ctx.set_result("Code review completed")

# After the context exits, you can check:
# ctx._result_attrs["total_turns"] == 2
```

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `initiate_chat()` called | `agent.lifecycle.start` | Sender and recipient captured |
| Initial message checked | `agent.guardrail.pre_llm` | Guardrail checkpoint before chat starts (may block) |
| Message exchanged | `agent.step.start/end` | Turn number, sender, recipient |
| Tool used | `agent.tool.call.start/end` | Tool name, input/output |
| LLM called | `agent.llm.call.start/end` | Model, token counts |
| Chat result checked | `agent.guardrail.post_llm` | Guardrail checkpoint before returning result (may block) |
| Chat ends | `agent.lifecycle.end` | Total turns, result |

**Note**: The guardrail checkpoints actively enforce blocking. If a checkpoint fails, `GuardrailBlockedError` is raised and the operation is halted.

## Troubleshooting

**Q: I get `ImportError: No module named 'autogen'`?**
Install it: `pip install pyautogen` (note: the package name is `pyautogen`, not `autogen`)

**Q: My agents use code execution. Is that tracked?**
The auto-patch tracks the overall chat with checkpoint enforcement. For tracking code execution within agents, use the manual adapter's `record_tool_call()` method.

**Q: What happens if a guardrail blocks my conversation?**
A `GuardrailBlockedError` exception is raised. Catch it to handle blocked conversations gracefully. The conversation will not proceed if blocked at the pre_llm checkpoint, and results will not be returned if blocked at the post_llm checkpoint.
