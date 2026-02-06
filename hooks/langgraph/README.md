# Enkrypt AI Guardrails for LangGraph/LangChain

Comprehensive security guardrails integration for LangGraph agents using `create_react_agent` with `pre_model_hook` and `post_model_hook` support.

## Features

- **Pre-Model Hook**: Scans all inputs BEFORE they reach the LLM
  - Prompt injection detection
  - PII/secrets detection
  - Toxicity filtering
  - Keyword blocking

- **Post-Model Hook**: Monitors LLM outputs AFTER generation
  - PII leakage detection
  - Toxic response filtering
  - NSFW content blocking

- **Tool Protection**: Wraps tools with input/output scanning
  - Sensitive tool detection
  - Tool argument validation
  - Tool result auditing

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure guardrails config
cp guardrails_config_example.json guardrails_config.json
# Edit guardrails_config.json with your Enkrypt API key
```

## Quick Start

### Basic Usage with create_react_agent

```python
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from enkrypt_guardrails_hook import create_pre_model_hook, create_post_model_hook
from langgraph.prebuilt import create_react_agent

# Define your tools
@tool
def search(query: str) -> str:
    """Search for information."""
    return f"Results for {query}"

# Create model and tools
model = ChatOpenAI(model="gpt-4")
tools = [search]

# Create hooks
pre_hook = create_pre_model_hook(block_on_violation=True)
post_hook = create_post_model_hook(block_on_violation=True)

# Create agent with guardrails
agent = create_react_agent(
    model,
    tools,
    pre_model_hook=pre_hook,
    post_model_hook=post_hook,
)

# Use the agent
result = agent.invoke({"messages": [("user", "Search for LangGraph docs")]})
```

### Using the Convenience Function

```python
from enkrypt_guardrails_hook import create_protected_agent

# Create a fully protected agent in one call
agent = create_protected_agent(
    model,
    tools,
    block_on_violation=True,   # Block on security violations
    wrap_agent_tools=True,      # Also protect tool calls
)
```

### Audit-Only Mode

```python
from enkrypt_guardrails_hook import create_audit_only_agent

# Create agent that logs violations but never blocks
agent = create_audit_only_agent(model, tools)
```

### Tool Wrapping

```python
from enkrypt_guardrails_hook import wrap_tools, EnkryptToolWrapper

# Wrap multiple tools
protected_tools = wrap_tools(tools, block_on_violation=True)

# Or wrap individually
wrapper = EnkryptToolWrapper(
    my_tool,
    block_on_violation=True,
    check_inputs=True,
    check_outputs=True,
)
protected_tool = wrapper.tool
```

## Configuration

Edit `guardrails_config.json`:

```json
{
  "enkrypt_api": {
    "url": "https://api.enkryptai.com/guardrails/policy/detect",
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "ssl_verify": true,
    "timeout": 15,
    "fail_silently": true
  },
  "pre_model_hook": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["injection_attack", "pii", "toxicity", "nsfw"]
  },
  "post_model_hook": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["pii", "toxicity", "nsfw"]
  },
  "before_tool_call": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["injection_attack", "pii"]
  },
  "after_tool_call": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["pii"]
  }
}
```

### Environment Variables

```powershell
# Required
$env:ENKRYPT_API_KEY = "your-enkrypt-api-key"

# Optional
$env:ENKRYPT_API_URL = "https://api.enkryptai.com/guardrails/policy/detect"
$env:LANGGRAPH_GUARDRAILS_LOG_DIR = "C:\logs\langgraph"
```

## Hook Events

### pre_model_hook

Called **before** the LLM is invoked. Can block requests by returning a modified state.

```python
def enkrypt_pre_model_hook(state, *, block_on_violation=True):
    """
    Scans input messages for:
    - Prompt injection attempts
    - PII/secrets
    - Toxic content
    - Banned keywords

    Returns modified state with block response if violation detected.
    """
```

### post_model_hook

Called **after** the LLM responds. Can modify responses to add warnings.

```python
def enkrypt_post_model_hook(state, *, block_on_violation=True):
    """
    Scans LLM output for:
    - PII leakage
    - Toxic responses
    - NSFW content

    Can append security warnings to responses.
    """
```

### Tool Hooks

Tool wrappers provide `before_tool_call` and `after_tool_call` protection.

## Examples

Run the demo scripts:

```powershell
cd hooks/langgraph

# Basic agent demo
python examples/basic_agent.py

# Prompt injection detection
python examples/demo_injection_attack.py

# PII detection
python examples/demo_pii_detection.py

# Tool protection
python examples/demo_tool_protection.py
```

## Logging

Logs are written to `~/langgraph/guardrails_logs/`:

- `pre_model_hook.jsonl` - Pre-model hook events
- `post_model_hook.jsonl` - Post-model hook events
- `before_tool_call.jsonl` - Tool input checks
- `after_tool_call.jsonl` - Tool output checks
- `security_alerts.jsonl` - Security violations
- `combined_audit.jsonl` - All events combined

## Metrics

```python
from enkrypt_guardrails_hook import get_guardrails_metrics

metrics = get_guardrails_metrics()
# {
#   "pre_model_hook": {
#     "total_calls": 10,
#     "blocked_calls": 2,
#     "avg_latency_ms": 150.5
#   },
#   ...
# }
```

## Testing

```bash
cd hooks/langgraph
pytest tests/ -v
```

## Architecture

```
LangGraph Agent
    │
    ├─► pre_model_hook ─► Enkrypt API ─► Block/Allow ─► LLM
    │                                                     │
    │                                                     ▼
    ├─► Tool Call ─► before_tool_call ─► Tool ─► after_tool_call
    │                                                     │
    │                                                     ▼
    └─► post_model_hook ─► Enkrypt API ─► Modify/Pass ─► Response
```

## Supported Detectors

| Detector | Description | Pre-Model | Post-Model | Tool |
|----------|-------------|-----------|------------|------|
| `injection_attack` | Prompt injection attempts | ✓ | | ✓ |
| `pii` | Personal identifiable info | ✓ | ✓ | ✓ |
| `toxicity` | Toxic/harmful content | ✓ | ✓ | |
| `nsfw` | Adult content | ✓ | ✓ | |
| `keyword_detector` | Banned keywords | ✓ | ✓ | ✓ |
| `policy_violation` | Custom policy rules | ✓ | ✓ | ✓ |
| `bias` | Biased content | ✓ | ✓ | |
| `topic_detector` | Off-topic content | ✓ | | |

## Directory Structure

```
hooks/langgraph/
├── .gitignore
├── README.md
├── requirements.txt
├── guardrails_config_example.json
├── enkrypt_guardrails.py          # Core API client
├── enkrypt_guardrails_hook.py     # LangGraph hooks
├── examples/
│   ├── __init__.py
│   ├── basic_agent.py
│   ├── demo_injection_attack.py
│   ├── demo_pii_detection.py
│   └── demo_tool_protection.py
└── tests/
    ├── __init__.py
    └── test_enkrypt_guardrails.py
```

## Related

- [OpenAI Agents SDK Hooks](../openai/README.md)
- [Strands Agents Hooks](../strands/README.md)
- [Cursor IDE Hooks](../cursor/README.md)
- [Claude Code Hooks](../claude/README.md)
- [Kiro Hooks](../kiro/hooks/README.md)

## License

See repository root for license information.
