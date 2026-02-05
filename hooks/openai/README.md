# Enkrypt AI Guardrails for OpenAI Agents SDK

This integration provides comprehensive security guardrails for the [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/), enabling you to protect your AI agents against prompt injection, PII leakage, toxicity, and other security threats.

## Features

- **Prompt Injection Detection**: Block malicious prompts designed to manipulate agent behavior
- **PII/Secrets Detection**: Prevent sensitive data from being processed or leaked
- **Toxicity Filtering**: Filter harmful, offensive, or inappropriate content
- **Tool Call Monitoring**: Audit and protect tool inputs/outputs
- **LLM Response Monitoring**: Validate model outputs for policy compliance
- **Agent Handoff Tracking**: Monitor multi-agent workflows
- **Comprehensive Logging**: Full audit trail for compliance and debugging
- **Metrics Collection**: Track guardrails performance and violations

## Installation

1. Install the required dependencies:

```bash
pip install openai-agents requests
```

2. Copy the hooks files to your project:

```bash
cp -r hooks/openai /path/to/your/project/
```

3. Configure your guardrails:

```bash
cd /path/to/your/project/openai
cp guardrails_config_example.json guardrails_config.json
# Edit guardrails_config.json with your Enkrypt API key and policy settings
```

## Quick Start

### Basic Usage with RunHooks

```python
import asyncio
from agents import Agent, Runner
from enkrypt_guardrails_hook import EnkryptRunHooks

async def main():
    # Create hooks instance
    hooks = EnkryptRunHooks(
        block_on_violation=True,  # Block on security violations
        log_only_mode=False,      # Set True for audit-only mode
    )

    # Create your agent
    agent = Agent(
        name="Secure Assistant",
        instructions="You are a helpful assistant."
    )

    # Run with guardrails protection
    result = await Runner.run(
        agent,
        hooks=hooks,
        input="What is the capital of France?"
    )

    print(result.final_output)

asyncio.run(main())
```

### Using Pre-configured Hook Variants

```python
from enkrypt_guardrails_hook import (
    EnkryptBlockingRunHooks,  # Always blocks on violations
    EnkryptAuditRunHooks,     # Never blocks, only logs
)

# Strict security mode
blocking_hooks = EnkryptBlockingRunHooks()

# Monitoring/audit mode
audit_hooks = EnkryptAuditRunHooks()
```

### Convenience Function

```python
from enkrypt_guardrails_hook import run_with_guardrails

result = await run_with_guardrails(
    agent,
    input="Your prompt here",
    blocking=True  # or False for audit-only
)
```

## Configuration

Create `guardrails_config.json` in the same directory as the hook files:

```json
{
  "enkrypt_api": {
    "url": "https://api.enkryptai.com/guardrails/policy/detect",
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "ssl_verify": true,
    "timeout": 15,
    "fail_silently": true
  },
  "on_agent_start": {
    "enabled": true,
    "guardrail_name": "Your Guardrail Name",
    "block": ["injection_attack", "pii", "toxicity"]
  },
  "on_llm_end": {
    "enabled": true,
    "guardrail_name": "Your Guardrail Name",
    "block": ["pii", "toxicity", "nsfw"]
  },
  "on_tool_start": {
    "enabled": true,
    "guardrail_name": "Your Guardrail Name",
    "block": ["injection_attack", "pii"]
  }
}
```

### Environment Variables

You can override configuration with environment variables:

| Variable | Description |
|----------|-------------|
| `ENKRYPT_API_URL` | Enkrypt API endpoint |
| `ENKRYPT_API_KEY` | Your Enkrypt API key |
| `OPENAI_GUARDRAILS_LOG_DIR` | Custom log directory |
| `OPENAI_GUARDRAILS_LOG_RETENTION_DAYS` | Log retention period |

## Hook Events

The following OpenAI Agents SDK lifecycle events are monitored:

| Hook | Description | Can Block |
|------|-------------|-----------|
| `on_agent_start` | Before agent execution begins | Yes |
| `on_agent_end` | After agent produces output | No (audit) |
| `on_llm_start` | Before LLM call | Yes |
| `on_llm_end` | After LLM response | No (audit) |
| `on_tool_start` | Before tool execution | Yes |
| `on_tool_end` | After tool execution | No (audit) |
| `on_handoff` | When agent handoff occurs | No (audit) |

## Available Detectors

Configure these in the `block` array for each hook:

| Detector | Description |
|----------|-------------|
| `injection_attack` | Prompt injection attempts |
| `pii` | Personal Identifiable Information |
| `toxicity` | Toxic/harmful content |
| `nsfw` | Not Safe For Work content |
| `keyword_detector` | Custom banned keywords |
| `policy_violation` | Custom policy violations |
| `bias` | Biased content |
| `sponge_attack` | Resource exhaustion attacks |
| `topic_detector` | Off-topic content |

## Multi-Agent Support

The hooks fully support multi-agent workflows with handoffs:

```python
from agents import Agent, Runner
from enkrypt_guardrails_hook import EnkryptRunHooks

# Create specialized agents
math_agent = Agent(name="Math Agent", instructions="...")
writer_agent = Agent(name="Writer Agent", instructions="...")

# Router agent with handoffs
router = Agent(
    name="Router",
    instructions="Route to appropriate specialist",
    handoffs=[math_agent, writer_agent]
)

# Guardrails monitor all agents and handoffs
hooks = EnkryptRunHooks()
result = await Runner.run(router, hooks=hooks, input="Calculate 5 + 3")
```

## Handling Violations

```python
from enkrypt_guardrails_hook import (
    EnkryptRunHooks,
    GuardrailsViolationError
)

hooks = EnkryptRunHooks(block_on_violation=True)

try:
    result = await Runner.run(agent, hooks=hooks, input=user_input)
except GuardrailsViolationError as e:
    print(f"Blocked: {e}")
    print(f"Violations: {e.violations}")
```

## Metrics and Monitoring

```python
# Get violation history
violations = hooks.get_current_violations()

# Get token usage tracking
usage = hooks.get_token_usage()
print(f"Input tokens: {usage['total_input_tokens']}")
print(f"Output tokens: {usage['total_output_tokens']}")
print(f"Events processed: {usage['event_count']}")

# Get guardrails metrics
metrics = hooks.get_metrics()
for hook_name, data in metrics.items():
    print(f"{hook_name}: {data['blocked_calls']} blocked / {data['total_calls']} total")
```

## Logs

Logs are written to `~/openai_agents/guardrails_logs/` by default:

| File | Contents |
|------|----------|
| `on_agent_start.jsonl` | Agent start events |
| `on_llm_end.jsonl` | LLM response events |
| `on_tool_start.jsonl` | Tool call events |
| `combined_audit.jsonl` | All events combined |
| `security_alerts.jsonl` | Security violations only |

## Examples

See the `examples/` directory for complete examples:

- `basic_agent.py` - Simple agent with guardrails
- `demo_injection_attack.py` - Injection attack detection
- `demo_pii_detection.py` - PII detection demo
- `demo_tool_protection.py` - Tool monitoring demo
- `demo_multi_agent.py` - Multi-agent with handoffs

## Testing

Run tests with pytest:

```bash
cd hooks/openai
pip install pytest
pytest tests/ -v
```

## Comparison with Strands Integration

| Feature | OpenAI Agents SDK | Strands SDK |
|---------|------------------|-------------|
| Hook Base Class | `RunHooksBase` | `HookProvider` |
| Agent Hooks | `AgentHooksBase` | N/A |
| Event Names | `on_*` pattern | `*Event` pattern |
| Blocking | Via exception | Via `cancel_tool` |
| Handoffs | `on_handoff` | N/A |

## License

This integration is part of the Enkrypt Secure MCP Gateway project.
