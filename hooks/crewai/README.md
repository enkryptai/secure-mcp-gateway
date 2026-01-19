# Enkrypt AI Guardrails for CrewAI Hooks

Protect your CrewAI agents, LLM calls, and tool executions using Enkrypt AI guardrails.

## 🧭 What runs when

|Hook|When it runs|Purpose|
|---|---|---|
|`before_llm_call`|Before LLM request is sent|Block unsafe prompts (injection/PII/etc.)|
|`after_llm_call`|After LLM response is received|Audit LLM outputs (logging/blocking)|
|`before_tool_call`|Before a tool executes|Block/validate tool inputs|
|`after_tool_call`|After a tool returns|Audit tool outputs (logging/blocking)|

## 🚀 Quick start

### Prerequisites

- Python 3.8+
- CrewAI installed
- An Enkrypt API key

### 1) Create a Python venv and install dependencies

From the repo root:

```bash
cd hooks/crewai
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r hooks/requirements.txt
```

### 2) Configure Enkrypt (guardrails_config_example.json → guardrails_config.json)

- Copy `hooks/crewai/hooks/guardrails_config_example.json` → `hooks/crewai/hooks/guardrails_config.json`
- Put your key in one of these ways:
  - Edit `hooks/crewai/hooks/guardrails_config.json`, OR
  - Set `ENKRYPT_API_KEY` in your environment

> `guardrails_config.json` is gitignored on purpose. Keep keys local.

### 3) Integrate with Your CrewAI Project

There are three ways to use Enkrypt Guardrails with CrewAI:

#### Option A: Context Manager (Recommended)

```python
from enkrypt_guardrails import EnkryptGuardrailsContext

# Wrap your crew execution
with EnkryptGuardrailsContext():
    crew = MyCrew().crew()
    result = crew.kickoff(inputs={"topic": "AI Safety"})
```

#### Option B: Decorator

```python
from enkrypt_guardrails import with_guardrails

@with_guardrails
def run_my_crew():
    crew = MyCrew().crew()
    return crew.kickoff(inputs={"topic": "AI Safety"})

result = run_my_crew()
```

#### Option C: Global Enable/Disable

```python
from enkrypt_guardrails import enable_guardrails, disable_guardrails

# Enable globally
enable_guardrails()

# Run your crews
crew = MyCrew().crew()
result = crew.kickoff(inputs={"topic": "AI Safety"})

# Disable when done
disable_guardrails()
```

### 4) Test

Try running a crew with a prompt that should trigger guardrails:

```python
from enkrypt_guardrails import EnkryptGuardrailsContext

with EnkryptGuardrailsContext():
    crew = MyCrew().crew()
    # This should be blocked if you have PII detection enabled
    result = crew.kickoff(inputs={
        "topic": "My email is test@example.com and SSN is 123-45-6789"
    })
```

You should see a block message if your `before_llm_call` policy is enabled with PII detection.

## 📁 Repo layout

```text
hooks/crewai/
├── venv/                               # Local venv (gitignored)
└── hooks/
    ├── guardrails_config_example.json  # Template config (commit-safe)
    ├── guardrails_config.json          # Local config (gitignored)
    ├── enkrypt_guardrails.py           # Core module with API integration
    ├── requirements.txt                # Python dependencies
    ├── README.md                       # This documentation
    └── tests/
        ├── __init__.py
        └── test_enkrypt_guardrails.py  # Unit tests (84 tests)
```

## ⚙️ Configuration reference

### `guardrails_config.json`

Start from `guardrails_config_example.json`. Full configuration reference:

#### `enkrypt_api` section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `https://api.enkryptai.com/guardrails/policy/detect` | Enkrypt guardrails API endpoint |
| `api_key` | string | `""` | Your Enkrypt API key (or set `ENKRYPT_API_KEY` env var) |
| `ssl_verify` | boolean | `true` | Enable/disable SSL certificate verification |
| `timeout` | integer | `15` | API request timeout in seconds |
| `fail_silently` | boolean | `true` | If true, allow requests on API errors; if false, block on errors |

#### Hook policy sections

Each hook (`before_llm_call`, `after_llm_call`, `before_tool_call`, `after_tool_call`) has:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable guardrails for this hook |
| `policy_name` | string | `""` | Enkrypt policy name to use (must exist in Enkrypt dashboard) |
| `block` | array | `[]` | List of detectors that should trigger blocking |

Example configuration:

```json
{
  "enkrypt_api": {
    "url": "https://api.enkryptai.com/guardrails/policy/detect",
    "api_key": "YOUR_API_KEY_HERE",
    "ssl_verify": true,
    "timeout": 15,
    "fail_silently": true
  },
  "before_llm_call": {
    "enabled": true,
    "policy_name": "My Agent Policy",
    "block": ["pii", "injection_attack", "policy_violation"]
  },
  "after_llm_call": {
    "enabled": true,
    "policy_name": "My Agent Policy",
    "block": ["pii", "policy_violation"]
  },
  "before_tool_call": {
    "enabled": true,
    "policy_name": "My Tool Policy",
    "block": ["injection_attack"]
  },
  "after_tool_call": {
    "enabled": false,
    "policy_name": "My Tool Policy",
    "block": []
  }
}
```

---

## 🔧 Detector Reference

|Detector|Description|Use Case|
|---|---|---|
|`injection_attack`|Detects prompt injection attempts|Block malicious inputs|
|`toxicity`|Detects toxic, harmful, or offensive content|Ensure professional tone|
|`nsfw`|Detects adult/inappropriate content|Content moderation|
|`pii`|Detects personal info & secrets|Data protection|
|`bias`|Detects biased content|Fair AI responses|
|`sponge_attack`|Detects resource exhaustion attacks|DoS prevention|
|`keyword_detector`|Blocks specific keywords|Custom filtering|
|`topic_detector`|Detects off-topic content|Stay on task|
|`policy_violation`|Custom policy enforcement|Business rules|

### Available Detectors in Block List

When configuring the `block` array, you can use:

- `pii` - Personal Identifiable Information
- `injection_attack` - Prompt injection attacks
- `toxicity` - Toxic content
- `nsfw` - Not Safe For Work content
- `keyword_detector` - Banned keywords
- `policy_violation` - Custom policy violations
- `bias` - Biased content
- `sponge_attack` - Resource exhaustion attacks
- `topic_detector` - Off-topic detection

---

## 📊 Audit Logs

All hook events are logged to `~/crewai/hooks_logs/`:

|Log File|Contents|
|---|---|
|`before_llm_call.jsonl`|LLM input validation events|
|`after_llm_call.jsonl`|LLM output audit events|
|`before_tool_call.jsonl`|Tool input validation events|
|`after_tool_call.jsonl`|Tool output audit events|
|`security_alerts.jsonl`|Security-related alerts|
|`enkrypt_api_response.jsonl`|Raw API responses (debug)|
|`enkrypt_api_debug.jsonl`|Debug information|
|`config_errors.log`|Configuration validation errors|

### Log Retention

Logs are automatically rotated after 7 days (configurable via `CREWAI_HOOKS_LOG_RETENTION_DAYS` environment variable). Old logs are archived with `.old` suffix and deleted after 14 days.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENKRYPT_API_KEY` | `""` | Enkrypt API key (overrides config file) |
| `ENKRYPT_API_URL` | `https://api.enkryptai.com/guardrails/policy/detect` | API endpoint URL |
| `CREWAI_HOOKS_LOG_DIR` | `~/crewai/hooks_logs` | Log directory path |
| `CREWAI_HOOKS_LOG_RETENTION_DAYS` | `7` | Days to keep logs before archiving |

### Viewing Logs

```bash
# View latest LLM call blocks
tail -f ~/crewai/hooks_logs/before_llm_call.jsonl

# View security alerts
tail -f ~/crewai/hooks_logs/security_alerts.jsonl

# View all tool calls
tail -f ~/crewai/hooks_logs/before_tool_call.jsonl

# Pretty print last 5 events
tail -5 ~/crewai/hooks_logs/before_llm_call.jsonl | jq .
```

### Metrics

The hooks collect performance metrics that can be accessed programmatically:

```python
from enkrypt_guardrails import get_hook_metrics, reset_metrics

# Get metrics for a specific hook
metrics = get_hook_metrics("before_llm_call")
print(f"Total calls: {metrics['total_calls']}")
print(f"Blocked calls: {metrics['blocked_calls']}")
print(f"Allowed calls: {metrics['allowed_calls']}")
print(f"Errors: {metrics['errors']}")
print(f"Avg latency: {metrics['avg_latency_ms']:.2f}ms")

# Get all hook metrics
all_metrics = get_hook_metrics()

# Reset metrics
reset_metrics("before_llm_call")  # Reset one hook
reset_metrics()  # Reset all
```

---

## 🔒 How It Works

### 1. before_llm_call

```text
Agent prepares LLM call → Hook intercepts → Enkrypt API scans → Block or Allow
```

**What gets checked:**
- Task descriptions
- Agent prompts
- User inputs

**On violation:**
- Raises `ValueError` with detailed violation message
- Hook returns `False` to block the LLM call
- Event logged to `security_alerts.jsonl`

### 2. after_llm_call

```text
LLM responds → Hook intercepts → Enkrypt API scans → Block or Log
```

**What gets checked:**
- LLM response text
- Generated content

**On violation:**
- Can block the response (if configured)
- Logs violations for audit
- Raises `ValueError` if blocking

### 3. before_tool_call

```text
Agent calls tool → Hook intercepts → Enkrypt API scans → Block or Allow
```

**What gets checked:**
- Tool name
- Tool input parameters
- Combined tool context

**On violation:**
- Blocks tool execution
- Returns `False` to prevent tool call

### 4. after_tool_call

```text
Tool completes → Hook intercepts → Enkrypt API scans → Block or Log
```

**What gets checked:**
- Tool output/results
- Returned data

**On violation:**
- Can block the output (if configured)
- Logs violations for compliance

---

## 🛠️ Advanced Usage

### Dynamic Configuration Reload

Reload configuration without restarting:

```python
from enkrypt_guardrails import reload_config

# Make changes to guardrails_config.json
reload_config()
# New config is now active
```

### Manual Guardrails Check

Check text directly without going through hooks:

```python
from enkrypt_guardrails import check_guardrails

try:
    result = check_guardrails(
        text="Check this text for issues",
        hook_name="before_llm_call",
        context={"source": "manual_check"}
    )
    print("Passed guardrails!")
except ValueError as e:
    print(f"Blocked: {e}")
```

### Flush Logs Manually

```python
from enkrypt_guardrails import flush_logs

# Force flush all buffered logs
flush_logs()
```

### Session Cleanup

```python
from enkrypt_guardrails import close_http_session

# Close HTTP session and cleanup
close_http_session()
```

---

## 🧪 Testing

Run the unit tests:

```bash
cd hooks/crewai
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run all tests
cd hooks/tests
python test_enkrypt_guardrails.py

# Run with verbose output
python test_enkrypt_guardrails.py -v

# Run specific test
python -m unittest test_enkrypt_guardrails.TestParseEnkryptResponse
```

All 84 tests should pass:

```
....................................................................................
----------------------------------------------------------------------
Ran 84 tests in 0.007s

OK
```

---

## 🛠️ Troubleshooting

### Guardrails Not Working

1. **Check hook is enabled** in `guardrails_config.json`:
   ```json
   "before_llm_call": {
     "enabled": true
   }
   ```

2. **Verify API key** is set correctly:
   ```bash
   export ENKRYPT_API_KEY="your-key-here"
   ```

3. **Check logs** for errors:
   ```bash
   tail -f ~/crewai/hooks_logs/config_errors.log
   ```

### API Returning 404

The `"Policy not found"` error means:

- The policy name in your config doesn't exist in Enkrypt dashboard
- **Fix:** Create the policy in Enkrypt Dashboard or update `policy_name`

```json
"before_llm_call": {
  "enabled": true,
  "policy_name": "Existing Policy Name"
}
```

### CrewAI Import Errors

If you get `ModuleNotFoundError: No module named 'crewai'`:

```bash
pip install crewai crewai-tools
```

### Hook Not Triggering

The hooks require CrewAI's hook system. Make sure you're using one of the integration methods:

```python
# Option 1: Context Manager
with EnkryptGuardrailsContext():
    result = crew.kickoff()

# Option 2: Decorator
@with_guardrails
def run():
    return crew.kickoff()

# Option 3: Global
enable_guardrails()
result = crew.kickoff()
disable_guardrails()
```

### Test Hook Manually

```python
from enkrypt_guardrails import check_llm_input
from unittest.mock import Mock

# Create mock context
mock_context = Mock()
mock_context.task = Mock()
mock_context.task.description = "Test task"
mock_context.agent_name = "test_agent"

# Test the hook
result = check_llm_input(mock_context)
print(f"Hook result: {result}")
```

---

## 🔐 Security Best Practices

1. **Never commit API keys** - Use environment variables for production
2. **Review logs regularly** - Check `security_alerts.jsonl` for issues
3. **Enable all relevant detectors** - More coverage = better protection
4. **Customize block lists** - Tune which detectors block vs. alert
5. **Use fail_silently wisely** - Set to `false` in production for strict enforcement
6. **Monitor metrics** - Track blocked calls and latency
7. **Test your policies** - Verify blocks work as expected before production

---

## 📈 Performance Considerations

### Connection Pooling

The module uses HTTP connection pooling for 20-30% faster repeated API calls:

```python
from enkrypt_guardrails import get_http_session

# Session is reused across all API calls
session = get_http_session()
```

### Buffered Logging

Logs are buffered in memory and flushed periodically for 40-60% faster I/O:

```python
from enkrypt_guardrails import BufferedLogger

# Buffer size of 10 entries, flush every 5 seconds
logger = BufferedLogger(buffer_size=10, flush_interval=5.0)
```

### Latency Metrics

Average latency per hook:

```python
metrics = get_hook_metrics("before_llm_call")
print(f"Average latency: {metrics['avg_latency_ms']:.2f}ms")
```

Typical latency:
- **before_llm_call**: 50-150ms
- **after_llm_call**: 50-150ms  
- **before_tool_call**: 50-150ms
- **after_tool_call**: 50-150ms

---

## 📚 Resources

- [CrewAI Documentation](https://docs.crewai.com)
- [CrewAI Hooks](https://docs.crewai.com/en/learn/execution-hooks)
- [Enkrypt AI Documentation](https://docs.enkryptai.com)
- [Enkrypt AI Dashboard](https://app.enkryptai.com)

---

## 🤝 Support

- **Enkrypt AI Support:** support@enkryptai.com
- **Documentation:** [docs.enkryptai.com](https://docs.enkryptai.com)
- **Issues:** Report issues in the repository

---

## 📄 License

This integration is provided as-is for use with Enkrypt AI guardrails.

---

## 🎯 Example: Complete Integration

Here's a complete example of integrating Enkrypt Guardrails with a CrewAI crew:

```python
from crewai import Agent, Task, Crew
from enkrypt_guardrails import EnkryptGuardrailsContext

# Define your agents
researcher = Agent(
    role='Researcher',
    goal='Find accurate information',
    backstory='Expert researcher',
    verbose=True
)

writer = Agent(
    role='Writer',
    goal='Write engaging content',
    backstory='Professional writer',
    verbose=True
)

# Define tasks
research_task = Task(
    description='Research {topic}',
    agent=researcher,
    expected_output='Research findings'
)

write_task = Task(
    description='Write article about {topic}',
    agent=writer,
    expected_output='Article text'
)

# Create crew
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    verbose=True
)

# Run with guardrails protection
with EnkryptGuardrailsContext():
    result = crew.kickoff(inputs={'topic': 'AI Safety'})
    print(result)
```

This setup will:
- ✅ Check all LLM calls for violations (before and after)
- ✅ Check all tool calls for violations (before and after)
- ✅ Log all events to `~/crewai/hooks_logs/`
- ✅ Block any violations according to your policy
- ✅ Provide detailed metrics and audit trails

---

## 🔄 Migration from Other Guardrails

If you're migrating from another guardrails solution:

1. **Export your existing policies** to Enkrypt Dashboard
2. **Update configuration** to match new format
3. **Test thoroughly** with your existing crews
4. **Monitor metrics** to ensure proper coverage
5. **Adjust block lists** based on false positive rates

---

## 🎓 Best Practices for CrewAI

1. **Enable before_llm_call** - Catch issues at the source
2. **Use after_llm_call for audit** - Monitor what agents generate
3. **Enable before_tool_call** - Prevent dangerous tool usage
4. **Log after_tool_call** - Track tool outputs for compliance
5. **Set fail_silently=false** in production - Strict enforcement
6. **Review logs daily** - Stay on top of violations
7. **Update policies regularly** - Adapt to new threats

---

Enjoy safe and compliant AI agent operations with Enkrypt Guardrails! 🛡️
