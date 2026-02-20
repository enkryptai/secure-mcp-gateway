# Amazon Bedrock Agents Integration Guide

## What is Amazon Bedrock Agents?

Amazon Bedrock Agents is AWS's managed service for building AI agents. You define agents in the AWS console, and they can use knowledge bases and action groups (tools). The agent runs in AWS, and you interact with it via the Bedrock Agent Runtime API.

Key concepts:
- **Agent** - Defined in AWS Console with instructions and tools
- **Action Groups** - Tools the agent can call (Lambda functions or APIs)
- **Knowledge Bases** - Document stores for RAG
- **Traces** - Detailed execution traces from the agent runtime

## What the Enkrypt SDK Does for Bedrock Agents

**Important**: Bedrock Agents are **not auto-patchable** due to the AWS API structure. The patch module is a **stub** - Bedrock Agents run remotely on AWS, so there's no local code to intercept.

Security is handled via the **GenericAgentAdapter** directly, and **manual integration** with `GuardEngine` is required for guardrail checks.

1. **`BedrockAgentsAdapter`** - Processes trace events from `invoke_agent()` responses (observability only)
2. **`process_trace()`** - Converts a single trace into lifecycle + tool + LLM events
3. **`process_traces()`** - Handles multiple traces from streaming responses
4. **Manual Guardrail Integration** - You must call `guard.check_input()` and `guard.check_output()` manually

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install boto3
```

## Step 2: Set Up Guardrails Manually

Since Bedrock Agents run remotely, guardrails must be applied manually using `GuardEngine`:

```python
import boto3
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.enkrypt_provider import EnkryptGuardrailProvider
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

# Set up guardrails
registry = GuardrailRegistry()
registry.register(EnkryptGuardrailProvider(api_key="ek-your-key-here"))
guard = GuardEngine(
    registry,
    input_policy={
        "enabled": True,
        "policy_name": "My Safety Policy",
        "block": ["injection_attack", "pii", "toxicity"],
    },
    output_policy={
        "enabled": True,
        "policy_name": "My Safety Policy",
        "block": ["pii", "policy_violation"],
    },
)
```

## Step 3: Use the Adapter (Observability Only)

The `BedrockAgentsAdapter` is for **observability only** - it processes traces but does not enforce guardrails:

```python
from enkrypt_agent_sdk.adapters.bedrock_agents import BedrockAgentsAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

# Set up the adapter for observability
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = BedrockAgentsAdapter(observer, agent_id="my-bedrock-agent")

# Call Bedrock Agent with manual guardrail checks
client = boto3.client("bedrock-agent-runtime", region_name="us-east-1")
input_text = "Book a flight to Tokyo"

# Check input before sending to Bedrock
try:
    input_result = await guard.check_input(input_text, policy=guard._input_policy)
    if input_result.blocked:
        raise GuardrailBlockedError(
            f"Input blocked: {input_result.blocked_reasons}",
            blocked_reasons=input_result.blocked_reasons,
            checkpoint="pre_llm",
        )
except GuardrailBlockedError:
    raise

# If input passes, invoke the agent
response = client.invoke_agent(
    agentId="YOUR_AGENT_ID",
    agentAliasId="YOUR_ALIAS_ID",
    sessionId="session-123",
    inputText=input_text,
    enableTrace=True,  # Important! Must enable traces
)

# Process the streaming response for observability
output_text = ""
for event in response["completion"]:
    if "chunk" in event:
        output_text += event["chunk"]["bytes"].decode()
    if "trace" in event:
        adapter.process_trace(event["trace"])

# Check output after receiving response
output_result = await guard.check_output(input_text, output_text, policy=guard._output_policy)
if output_result.blocked:
    # Handle blocked output - log, sanitize, or reject
    print(f"Output blocked: {output_result.blocked_reasons}")
```

## Understanding Bedrock Traces

A Bedrock trace contains an `orchestrationTrace` with several components:

```python
trace = {
    "orchestrationTrace": {
        "modelInvocationInput": {
            "foundationModel": "anthropic.claude-3-sonnet"
        },
        "rationale": {
            "text": "I need to search for flights to Tokyo"
        },
        "invocationInput": {
            "actionGroupInvocationInput": {
                "apiPath": "/search_flights",
                "parameters": [{"name": "destination", "value": "Tokyo"}]
            }
        }
    }
}
```

The adapter maps each piece:

| Trace Component | Enkrypt Event | What It Captures |
|---|---|---|
| `modelInvocationInput` | `agent.llm.call.start/end` | Model name |
| `rationale` | `agent.step.start/end` | Agent's reasoning |
| `actionGroupInvocationInput` | `agent.tool.call.start/end` | API path, parameters |
| `knowledgeBaseLookupInput` | `agent.tool.call.start/end` | KB query text |

## Processing Multiple Traces

For streaming responses with multiple traces:

```python
traces = []
for event in response["completion"]:
    if "trace" in event:
        traces.append(event["trace"])

# Process all at once
adapter.process_traces(traces)
```

## Full Working Example

```python
"""Complete Bedrock Agents + Enkrypt SDK example."""

from enkrypt_agent_sdk.adapters.bedrock_agents import BedrockAgentsAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = BedrockAgentsAdapter(observer, agent_id="flight-agent")

# Simulate a Bedrock trace
mock_trace = {
    "orchestrationTrace": {
        "modelInvocationInput": {"foundationModel": "anthropic.claude-3"},
        "rationale": {"text": "I should search for available flights"},
        "invocationInput": {
            "actionGroupInvocationInput": {
                "apiPath": "/search_flights",
                "parameters": [{"name": "dest", "value": "Tokyo"}],
            }
        },
    }
}

run_id = adapter.process_trace(mock_trace)
print(f"Trace processed with run_id: {run_id}")
```

## Troubleshooting

**Q: Why isn't there a monkey-patch for Bedrock?**
Bedrock Agents run remotely on AWS. There's no local code to patch. The patch module is a stub - Bedrock Agents are not auto-patchable due to the AWS API structure.

**Q: I'm not getting traces in the response?**
Make sure you set `enableTrace=True` in your `invoke_agent()` call.

**Q: Can I use `auto_secure()` with Bedrock?**
Yes, `auto_secure()` detects `botocore` and enables the adapter for observability. However, **guardrails must be applied manually** - you need to call `guard.check_input()` before invoking the agent and `guard.check_output()` after receiving the response. The adapter only processes traces for observability; it does not enforce guardrails automatically.

**Q: How do I apply guardrails manually?**
1. Set up `GuardEngine` with your policies
2. Call `await guard.check_input(user_input)` before `invoke_agent()`
3. Call `await guard.check_output(user_input, agent_output)` after receiving the response
4. Handle `GuardrailBlockedError` appropriately
