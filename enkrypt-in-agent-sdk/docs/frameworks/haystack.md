# Haystack Integration Guide

## What is Haystack?

Haystack (by deepset) is a framework for building **NLP pipelines**, especially RAG systems. You connect components like retrievers, readers, and generators into a pipeline, and data flows through them.

Key concepts:
- **Pipeline** - A directed graph of components
- **Component** - A single processing step (embedder, retriever, generator, etc.)
- **`pipeline.run()`** - Executes the pipeline with input data

## What the Enkrypt SDK Does for Haystack

1. **Patches `Pipeline.run()`** - Intercepts pipeline execution with **pre_llm** and **post_llm** guardrail checkpoints
2. **Patches `OpenAIChatGenerator.run()`** - Intercepts generator calls with checkpoint enforcement at the component level
3. **Provides `HaystackAdapter`** - Context managers with helpers for recording components, retrievals, and LLM generations

**Guardrail Checkpoints:**
- **pre_llm checkpoint**: User text in pipeline inputs is checked before pipeline execution begins. If blocked, `GuardrailBlockedError` is raised and the pipeline does not run.
- **post_llm checkpoint**: Generator outputs are checked before returning results. If blocked, `GuardrailBlockedError` is raised and the output is not returned.

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install haystack-ai
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

## Step 3: Use Haystack Normally

```python
from haystack import Pipeline
from haystack.components.generators import OpenAIGenerator
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

# Build a pipeline
pipeline = Pipeline()
pipeline.add_component("generator", OpenAIGenerator(model="gpt-4"))

# Run it - automatically tracked and protected!
try:
    result = pipeline.run(data={"generator": {"prompt": "What is AI?"}})
    print(result["generator"]["replies"][0])
except GuardrailBlockedError as e:
    print(f"Pipeline execution blocked: {e.reason}")
    # Handle blocked execution appropriately
```

## Manual Adapter for Detailed Tracking

For per-component tracking:

```python
from enkrypt_agent_sdk.adapters.haystack import HaystackAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = HaystackAdapter(observer, agent_id="rag-pipeline")

with adapter.observe_pipeline(pipeline_name="my-rag-pipeline") as ctx:
    # Record each component's execution
    ctx.record_component("text_embedder", "What is AI?", "[0.1, 0.2, ...]")

    # Record document retrieval
    ctx.record_retrieval("bm25_retriever", num_documents=5)

    # Record LLM generation
    ctx.record_generation(
        model="gpt-4",
        input_tokens=200,
        output_tokens=100,
        output="AI is the simulation of human intelligence...",
    )

    ctx.set_result("Pipeline completed successfully")
```

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `pipeline.run()` starts | `agent.lifecycle.start` | Pipeline name |
| Pipeline inputs checked | `agent.guardrail.pre_llm` | Guardrail checkpoint before execution (may block) |
| Component runs | `agent.step.start/end` | Component name, input/output |
| Retriever returns docs | `agent.tool.call.start/end` | Number of documents |
| LLM generates text | `agent.llm.call.start/end` | Model, tokens, output |
| Generator output checked | `agent.guardrail.post_llm` | Guardrail checkpoint before returning (may block) |
| Pipeline ends | `agent.lifecycle.end` | Result |

**Note**: The guardrail checkpoints actively enforce blocking. If a checkpoint fails, `GuardrailBlockedError` is raised and the operation is halted. Both `Pipeline.run()` and `OpenAIChatGenerator.run()` are protected with checkpoint enforcement.

## Troubleshooting

**Q: I only see lifecycle events, not per-component events?**
The auto-patch wraps `Pipeline.run()` and `OpenAIChatGenerator.run()` for lifecycle tracking with checkpoint enforcement. For per-component events, use the manual `HaystackAdapter` with `record_component()`, `record_retrieval()`, and `record_generation()`.

**Q: What happens if a guardrail blocks my pipeline execution?**
A `GuardrailBlockedError` exception is raised. Catch it to handle blocked executions gracefully. The pipeline will not run if blocked at the pre_llm checkpoint, and generator outputs will not be returned if blocked at the post_llm checkpoint.

**Q: Does this work with Haystack 1.x?**
No, this is built for Haystack 2.x (`haystack-ai` package). The API changed significantly between versions.
