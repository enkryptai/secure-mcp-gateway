# Enkrypt AI Guardrails for Strands Agents

Universal security guardrails for Strands Agents that work with **ANY model provider** - not just Amazon Bedrock.

## Why Enkrypt Guardrails?

Strands Agents SDK has native guardrails support, but **only for Amazon Bedrock**. If you're using OpenAI, Anthropic, Ollama, LiteLLM, or any other provider, you have no built-in protection.

**Enkrypt Guardrails solve this** by providing universal protection via the Strands Hooks system:

| Feature | Bedrock Native | Enkrypt Guardrails |
|---------|----------------|-------------------|
| Works with Bedrock | Yes | Yes |
| Works with OpenAI | No | **Yes** |
| Works with Anthropic | No | **Yes** |
| Works with Ollama | No | **Yes** |
| Works with LiteLLM | No | **Yes** |
| Tool Call Monitoring | No | **Yes** |
| Custom Policies | Limited | **Extensive** |

## Features

- **Prompt Injection Detection**: Block jailbreak attempts, instruction overrides, and manipulation
- **PII/Secrets Detection**: Detect email, SSN, credit cards, API keys, passwords
- **Toxicity Filtering**: Block harmful, offensive, or inappropriate content
- **Tool Call Protection**: Monitor and block dangerous tool executions
- **Keyword Detection**: Block specific words or phrases
- **Policy Enforcement**: Custom business rule enforcement
- **Comprehensive Logging**: Audit trail for all security events

## Quick Start

### 1. Install Dependencies

```bash
cd hooks/strands
pip install -r requirements.txt
```

### 2. Configure Enkrypt API Key

```bash
cp guardrails_config_example.json guardrails_config.json
# Edit guardrails_config.json with your API key
```

Or set environment variable:

```bash
export ENKRYPT_API_KEY="your-api-key"
```

### 3. Use with Your Agent

```python
from strands import Agent
from enkrypt_guardrails_hook import EnkryptGuardrailsHook

# Create a protected agent
agent = Agent(
    system_prompt="You are a helpful assistant.",
    hooks=[EnkryptGuardrailsHook()]
)

# The agent is now protected!
response = agent("What is the capital of France?")
```

## Hook Events

The guardrails hook monitors these Strands lifecycle events:

| Event | Purpose | Action |
|-------|---------|--------|
| `MessageAddedEvent` | Check user prompts & responses | Block/Log |
| `BeforeToolCallEvent` | Validate tool inputs | Block (`event.cancel_tool`) |
| `AfterToolCallEvent` | Audit tool outputs | Log/Warn |
| `AfterModelCallEvent` | Monitor model responses | Log |
| `BeforeInvocationEvent` | Reset per-request state | Track |
| `AfterInvocationEvent` | Log summary | Report |

## Configuration

### `guardrails_config.json`

```json
{
  "enkrypt_api": {
    "url": "https://api.enkryptai.com/guardrails/policy/detect",
    "api_key": "YOUR_API_KEY",
    "ssl_verify": true,
    "timeout": 15,
    "fail_silently": true
  },
  "MessageAdded": {
    "enabled": true,
    "guardrail_name": "Your Guardrail Name",
    "block": ["injection_attack", "pii", "toxicity"]
  },
  "BeforeToolCall": {
    "enabled": true,
    "guardrail_name": "Your Guardrail Name",
    "block": ["injection_attack", "pii"]
  },
  "sensitive_tools": [
    "execute_sql",
    "run_command",
    "shell_*"
  ]
}
```

### Available Detectors

| Detector | Description |
|----------|-------------|
| `injection_attack` | Prompt injection attempts |
| `pii` | Personal information & secrets |
| `toxicity` | Toxic/harmful content |
| `nsfw` | Adult content |
| `keyword_detector` | Banned keywords |
| `policy_violation` | Custom policy rules |
| `bias` | Biased content |
| `topic_detector` | Off-topic content |
| `sponge_attack` | Resource exhaustion |

## Usage Modes

### Blocking Mode (Default)

Block requests that violate policies:

```python
from enkrypt_guardrails_hook import EnkryptGuardrailsBlockingHook

agent = Agent(hooks=[EnkryptGuardrailsBlockingHook()])
```

### Audit-Only Mode

Log violations without blocking:

```python
from enkrypt_guardrails_hook import EnkryptGuardrailsAuditHook

agent = Agent(hooks=[EnkryptGuardrailsAuditHook()])
```

### Custom Configuration

```python
from enkrypt_guardrails_hook import EnkryptGuardrailsHook

hook = EnkryptGuardrailsHook(
    block_on_violation=True,
    log_only_mode=False,
    check_user_messages=True,
    check_assistant_messages=True,
    check_tool_results=True,
    sensitive_tools=["my_dangerous_tool", "another_risky_*"]
)

agent = Agent(hooks=[hook])
```

### Convenience Function

```python
from enkrypt_guardrails_hook import create_protected_agent

agent = create_protected_agent(
    system_prompt="You are a helpful assistant.",
    blocking=True
)
```

## Examples

Run the example demos to see guardrails in action:

```bash
# Basic protected agent
python examples/basic_agent.py

# Prompt injection attack detection
python examples/demo_injection_attack.py

# PII detection
python examples/demo_pii_detection.py

# Tool call protection
python examples/demo_tool_protection.py

# Multi-provider support
python examples/demo_multi_provider.py --provider openai
```

## Audit Logs

All security events are logged to `~/strands/guardrails_logs/`:

| Log File | Contents |
|----------|----------|
| `MessageAdded.jsonl` | User/assistant message checks |
| `BeforeToolCall.jsonl` | Tool input validation |
| `AfterToolCall.jsonl` | Tool output audits |
| `security_alerts.jsonl` | All security violations |
| `combined_audit.jsonl` | Complete audit trail |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENKRYPT_API_KEY` | - | Enkrypt API key |
| `ENKRYPT_API_URL` | `https://api.enkryptai.com/...` | API endpoint |
| `STRANDS_GUARDRAILS_LOG_DIR` | `~/strands/guardrails_logs` | Log directory |
| `STRANDS_GUARDRAILS_LOG_RETENTION_DAYS` | `7` | Log retention |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Strands Agent                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  Agent Loop                           │  │
│  │   ┌─────────┐    ┌─────────┐    ┌─────────────────┐   │  │
│  │   │  User   │───▶│  Model  │───▶│     Tools       │   │  │
│  │   │ Message │    │  Call   │    │   Execution     │   │  │
│  │   └────┬────┘    └────┬────┘    └────────┬────────┘   │  │
│  │        │              │                  │            │  │
│  └────────┼──────────────┼──────────────────┼────────────┘  │
│           │              │                  │               │
│  ┌────────▼──────────────▼──────────────────▼────────────┐  │
│  │           EnkryptGuardrailsHook (HookProvider)        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │  │
│  │  │ MessageAdded │  │AfterModelCall│  │BeforeToolCall│ │  │
│  │  │    Event     │  │    Event     │  │    Event    │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │  │
│  │         │                 │                 │         │  │
│  │         └────────────┬────┴─────────────────┘         │  │
│  │                      │                                │  │
│  │              ┌───────▼────────┐                       │  │
│  │              │  Enkrypt API   │                       │  │
│  │              │  Guardrails    │                       │  │
│  │              └───────┬────────┘                       │  │
│  │                      │                                │  │
│  │         ┌────────────┴────────────┐                   │  │
│  │         ▼                         ▼                   │  │
│  │  ┌─────────────┐          ┌─────────────┐             │  │
│  │  │    ALLOW    │          │    BLOCK    │             │  │
│  │  │  (continue) │          │(cancel_tool)│             │  │
│  │  └─────────────┘          └─────────────┘             │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Testing

Run the unit tests:

```bash
pytest tests/ -v
```

## Comparison with Bedrock Native Guardrails

| Aspect | Bedrock Native | Enkrypt Hook |
|--------|----------------|--------------|
| **Setup** | Create in AWS Console | JSON config file |
| **Providers** | Bedrock only | All providers |
| **Tool Monitoring** | Not supported | Full support |
| **Custom Detectors** | Limited | Extensive |
| **On-Premise** | AWS only | Self-hostable |
| **Cost** | AWS pricing | Enkrypt pricing |
| **Latency** | Integrated | Extra API call |

## Best Practices

1. **Enable MessageAdded for prompt checking** - This is the primary protection point
2. **Enable BeforeToolCall for tool protection** - Prevent dangerous tool executions
3. **Use sensitive_tools list** - Flag tools that need extra scrutiny
4. **Review audit logs regularly** - Check `security_alerts.jsonl`
5. **Test with examples first** - Run the demo scripts to validate setup
6. **Use blocking mode in production** - Audit-only is for development

## Troubleshooting

### API Key Issues

```python
# Check if API key is loaded
from enkrypt_guardrails import ENKRYPT_API_KEY
print(f"API key length: {len(ENKRYPT_API_KEY)}")
```

### Hook Not Triggering

```python
# Verify hook is registered
agent = Agent(hooks=[EnkryptGuardrailsHook()])
print(f"Hooks: {agent.hooks}")
```

### No Logs Generated

Check log directory permissions:

```bash
ls -la ~/strands/guardrails_logs/
```

## Resources

- [Strands Agents Documentation](https://strandsagents.com)
- [Strands Hooks Guide](https://strandsagents.com/latest/documentation/docs/user-guide/concepts/agents/hooks/)
- [Enkrypt AI Documentation](https://docs.enkryptai.com)
- [Enkrypt AI Dashboard](https://app.enkryptai.com)

## Support

- **Enkrypt AI Support**: support@enkryptai.com
- **Documentation**: [docs.enkryptai.com](https://docs.enkryptai.com)

## License

This integration is provided as-is for use with Enkrypt AI guardrails.
