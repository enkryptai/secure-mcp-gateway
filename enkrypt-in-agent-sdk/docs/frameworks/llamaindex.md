# LlamaIndex Integration Guide

## What is LlamaIndex?

LlamaIndex (formerly GPT Index) is the go-to framework for building **RAG (Retrieval-Augmented Generation)** applications. It helps you connect LLMs to your data by indexing documents and retrieving relevant information at query time.

Key concepts:
- **Index** - A structured store of your documents
- **Query Engine** - Answers questions using the index
- **Retriever** - Finds relevant documents
- **CallbackManager** - Hooks into every operation for observability

## What the Enkrypt SDK Does for LlamaIndex

1. **Injects into the global CallbackManager** - Every query, retrieval, and LLM call is tracked
2. **Provides `EnkryptLlamaIndexHandler`** - A callback handler that emits Enkrypt events
3. **Patches `AgentRunner.chat()`** - Intercepts agent chat with **pre_llm** and **post_llm** checkpoint enforcement
4. **Patches `BaseTool.call()`** - Intercepts tool execution with **pre_tool** and **post_tool** checkpoint enforcement
5. **All 4 checkpoints available** - User messages are checked before agent chat, tool inputs are checked before tool execution
6. **Tracks retrievals** - See how many documents were retrieved and from where

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install llama-index-core
# Plus your choice of LLM and embedding providers:
pip install llama-index-llms-openai llama-index-embeddings-openai
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

The SDK automatically adds the `EnkryptLlamaIndexHandler` to `Settings.callback_manager`.

## Step 3: Use LlamaIndex Normally

```python
from llama_index.core import VectorStoreIndex, Document
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

# Create an index from documents
documents = [
    Document(text="AI agents can use tools to interact with the world."),
    Document(text="LlamaIndex helps you build RAG applications."),
]
index = VectorStoreIndex.from_documents(documents)

# Query it - the Enkrypt SDK enforces checkpoints automatically
query_engine = index.as_query_engine()
try:
    response = query_engine.query("What can AI agents do?")
    print(response)
except GuardrailBlockedError as e:
    print(f"Request blocked at checkpoint: {e}")
    print(f"Violations: {e.violations}")
```

The SDK automatically:
- **Checks user messages** before they reach the agent (pre_llm checkpoint)
- **Checks tool inputs** before tools execute (pre_tool checkpoint)
- **Checks tool outputs** after tools complete (post_tool checkpoint)
- **Checks agent responses** before returning to user (post_llm checkpoint)
- Captures the query text, retrieved documents, LLM calls, token usage, and final response

## Manual Adapter

If you want to use the handler directly:

```python
from enkrypt_agent_sdk.adapters.llamaindex import EnkryptLlamaIndexHandler
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter
from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
handler = EnkryptLlamaIndexHandler(observer, agent_id="my-rag-agent")

# Register the handler
Settings.callback_manager = CallbackManager([handler])

# Now all LlamaIndex operations are tracked
```

## Checkpoint Enforcement

The SDK enforces guardrails at four checkpoints:

| Checkpoint | When | What's Checked |
|---|---|---|
| **pre_llm** | Before `AgentRunner.chat()` executes | User message/query text |
| **pre_tool** | Before `BaseTool.call()` executes | Tool input arguments |
| **post_tool** | After `BaseTool.call()` completes | Tool output/result |
| **post_llm** | After `AgentRunner.chat()` completes | Agent response text |

If any checkpoint fails, `GuardrailBlockedError` is raised and execution stops at that checkpoint.

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| Query starts | `agent.step.start` | Query text captured |
| Documents retrieved | `agent.tool.call.start/end` | Number of nodes captured |
| LLM called | `agent.llm.call.start/end` | Model name, token usage |
| Tool/function called | `agent.tool.call.start/end` | Tool name, output |
| Query completes | `agent.step.end` | Response captured |

## How the Callback Handler Maps Events

The handler inspects the `event_type` string from LlamaIndex:

| LlamaIndex Event Type | Contains | Maps To |
|---|---|---|
| `QUERY` | Query text | Step start/end |
| `RETRIEVE` | Document nodes | Tool call (retriever) |
| `LLM` | Prompts, completion | LLM call |
| `FUNCTION_CALL` / `TOOL` | Tool name, result | Tool call |

## Troubleshooting

**Q: I don't see retrieval events?**
Make sure you're using a retrieval-based query engine (like `VectorStoreIndex.as_query_engine()`). Simple LLM calls won't trigger retrieval events.

**Q: The handler isn't capturing events?**
Check that `Settings.callback_manager` is set. You can verify: `print(Settings.callback_manager.handlers)` should show the `EnkryptLlamaIndexHandler`.

**Q: Does this work with LlamaIndex agents?**
Yes! LlamaIndex agents use the same callback system, so tool calls and LLM calls within agents are tracked. The SDK patches `AgentRunner.chat()` to enforce pre_llm/post_llm checkpoints and `BaseTool.call()` to enforce pre_tool/post_tool checkpoints.

**Q: What happens when a guardrail blocks a request?**
A `GuardrailBlockedError` is raised at the checkpoint where the violation was detected. You can catch this exception to handle blocked requests gracefully:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    response = agent.chat("user message")
except GuardrailBlockedError as e:
    print(f"Blocked at checkpoint: {e}")
    print(f"Violations: {e.violations}")
```
