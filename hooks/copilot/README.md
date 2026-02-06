# Enkrypt AI Guardrails for GitHub Copilot Hooks

Protect your GitHub Copilot coding agent sessions with Enkrypt AI guardrails.

## What runs when

| Hook | When it runs | Can Block? | Output Fields |
|------|--------------|------------|---------------|
| `sessionStart` | Session begins | NO (ignored) | *none* |
| `userPromptSubmitted` | After user submits a prompt | NO (audit only) | *none* |
| `preToolUse` | Before a tool executes | **YES** | `permissionDecision`, `permissionDecisionReason` |
| `postToolUse` | After a tool returns | NO (audit only) | *none* |
| `sessionEnd` | Session completes | NO (ignored) | *none* |
| `errorOccurred` | When an error occurs | NO (ignored) | *none* |

> **Important:** Per the [Copilot hooks specification](https://docs.github.com/en/copilot/reference/hooks-configuration), only `preToolUse` can block actions. All other hooks are observational — they log events and detect violations but cannot prevent actions.

### Blocking vs Observational Hooks

**Blocking Hook** — Can prevent tool execution:

- `preToolUse`: Set `"permissionDecision": "deny"` to block the tool call

**Observational Hooks** — Fire-and-forget, audit only:

- `userPromptSubmitted`: Logs prompt violations (cannot block prompts)
- `postToolUse`: Logs tool output violations
- `sessionStart` / `sessionEnd`: Logs session lifecycle
- `errorOccurred`: Logs errors, detects security-related errors

When violations are detected in observational hooks, they are logged to `security_alerts.jsonl` for forensics but the action has already completed.

## Where Hooks Work

> **Important:** Copilot hooks work with specific Copilot environments, not all of them.

| Environment | Hooks Support | Description |
|-------------|---------------|-------------|
| **Copilot Coding Agent** | ✅ YES | Cloud-based agent triggered via GitHub Issues/PRs |
| **Copilot CLI** (`gh copilot`) | ✅ YES | Command-line interface for Copilot |
| **VS Code Copilot Chat** | ❌ NO | The chat sidebar in VS Code does not support hooks |
| **Copilot Inline Suggestions** | ❌ NO | Code completions/suggestions do not trigger hooks |

**Official Documentation:**
- [Copilot Coding Agent Hooks](https://docs.github.com/en/copilot/customizing-copilot/extending-the-capabilities-of-copilot-coding-agent-with-mcp/using-copilot-coding-agent-hooks)
- [Hooks Configuration Reference](https://docs.github.com/en/copilot/reference/hooks-configuration)

## Quick start

### Prerequisites

- GitHub Copilot with coding agent hooks support
- Python 3.8+
- **PowerShell 7+** (required for Windows - see note below)
- An Enkrypt API key

> **Windows Users:** Copilot CLI requires PowerShell 7+ (`pwsh.exe`), not Windows PowerShell 5.x. Install it via:
> ```powershell
> winget install Microsoft.PowerShell
> ```
> After installation, add `C:\Program Files\PowerShell\7` to your system PATH and restart your terminal.

### 1) Create a Python venv and install dependencies

From the repo root:

```bash
cd hooks/copilot
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r hooks/requirements.txt
```

### 2) Configure Enkrypt (guardrails_config_example.json -> guardrails_config.json)

- Copy `hooks/copilot/hooks/guardrails_config_example.json` -> `hooks/copilot/hooks/guardrails_config.json`
- Put your key in one of these ways:
  - Edit `hooks/copilot/hooks/guardrails_config.json`, OR
  - Set `ENKRYPT_API_KEY` in your environment

> `guardrails_config.json` is gitignored on purpose. Keep keys local.

### 3) Configure Copilot Hooks

The location of `hooks.json` depends on which Copilot environment you're using:

| Environment | hooks.json Location | Notes |
|-------------|---------------------|-------|
| **Copilot Coding Agent** | `.github/hooks/hooks.json` | Must be on the repository's default branch |
| **Copilot CLI** | `hooks.json` (project root) | Loaded from current working directory |

**For Copilot Coding Agent:**
```bash
# Copy template to .github/hooks/
mkdir -p .github/hooks
cp hooks/copilot/hooks_example.json .github/hooks/hooks.json
# Commit and push to default branch
git add .github/hooks/hooks.json
git commit -m "Add Copilot hooks configuration"
git push
```

**For Copilot CLI:**
```bash
# Copy template to project root
cp hooks/copilot/hooks_example.json hooks.json
```

- If you're on macOS/Linux, the `bash` commands should work as-is
- On Windows, ensure PowerShell 7+ is installed and in PATH
- Adjust paths if your repo structure differs

### 4) Test

Try running a tool that triggers a guardrail violation. The `preToolUse` hook should block it.

You can also test manually:

```bash
echo '{"timestamp":1704614600000,"cwd":".","toolName":"bash","toolArgs":"ls"}' | python hooks/copilot/hooks/pre_tool_use.py
```

Expected output:

```json
{"permissionDecision": "allow"}
```

## Repo layout

```text
hooks/copilot/
├── hooks_example.json                  # Template for hooks.json
├── .gitignore                          # Ignore venv and local config
└── hooks/
    ├── guardrails_config_example.json  # Template config (commit-safe)
    ├── guardrails_config.json          # Local config (gitignored)
    ├── enkrypt_guardrails.py           # Core module with API integration
    ├── session_start.py                # Session start hook (observational)
    ├── user_prompt_submitted.py        # Prompt audit hook (observational)
    ├── pre_tool_use.py                 # Tool input validation hook (BLOCKING)
    ├── post_tool_use.py                # Tool output audit hook (observational)
    ├── session_end.py                  # Session end hook (observational)
    ├── error_occurred.py               # Error logging hook (observational)
    ├── requirements.txt                # Python dependencies
    └── tests/
        ├── __init__.py
        └── test_enkrypt_guardrails.py  # Unit tests

# After setup, your project will have:
.github/hooks/hooks.json                # For Copilot Coding Agent
hooks.json                              # For Copilot CLI (project root)
```

## Configuration reference

### `.github/hooks/hooks.json`

Use the template at `hooks/copilot/hooks_example.json` as your starting point.

Each hook entry uses:
- `type`: `"command"`
- `bash`: Shell command for Unix/Linux
- `powershell`: Command for Windows PowerShell
- `cwd`: Working directory (default `"."`)
- `timeoutSec`: Maximum execution time in seconds (default `30`)

### `guardrails_config.json`

Start from `guardrails_config_example.json`. Full configuration reference:

#### `enkrypt_api` section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `https://api.enkryptai.com/guardrails/policy/detect` | Enkrypt guardrails API endpoint |
| `api_key` | string | `""` | Your Enkrypt API key (or set `ENKRYPT_API_KEY` env var) |
| `ssl_verify` | boolean | `true` | Enable/disable SSL certificate verification |
| `timeout` | integer | `15` | API request timeout in seconds |
| `fail_silently` | boolean | `true` | If true, allow on API error; if false, block on error |

#### Hook policy sections

Each hook (`userPromptSubmitted`, `preToolUse`, `postToolUse`, `errorOccurred`) has:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable guardrails for this hook |
| `guardrail_name` | string | `""` | Enkrypt guardrail name to use (must exist in Enkrypt dashboard) |
| `block` | array | `[]` | List of detectors that should trigger blocking/alerting |

#### `sensitive_tools` section

Array of tool name prefixes/patterns that require user confirmation before execution.

Example:

```json
"sensitive_tools": ["execute_sql", "delete_", "run_command"]
```

---

## Detector Reference

|Detector|Description|
|---|---|
|`injection_attack`|Detects prompt injection attempts|
|`toxicity`|Detects toxic, harmful, or offensive content|
|`nsfw`|Detects adult/inappropriate content|
|`pii`|Detects personal info & secrets|
|`bias`|Detects biased content|
|`sponge_attack`|Detects resource exhaustion attacks|
|`keyword_detector`|Blocks specific keywords|
|`topic_detector`|Detects off-topic content|
|`policy_violation`|Custom policy enforcement|
|`system_prompt`|System prompt detection|
|`copyright_ip`|Copyright/IP detection|

### PII Entities

Available entities for the `pii` detector:

- `pii` - General PII (names, addresses)
- `secrets` - API keys, passwords, tokens
- `ip_address` - IP addresses
- `url` - URLs

---

## Audit Logs

All hook events are logged to `~/copilot/hooks_logs/`:

|Log File|Contents|
|---|---|
|`sessionStart.jsonl`|Session start events|
|`userPromptSubmitted.jsonl`|Prompt audit events|
|`preToolUse.jsonl`|Tool input validation events|
|`postToolUse.jsonl`|Tool output audit events|
|`sessionEnd.jsonl`|Session end events|
|`errorOccurred.jsonl`|Error events|
|`combined_audit.jsonl`|All events combined|
|`security_alerts.jsonl`|Security-related alerts|
|`session_summaries.jsonl`|Session completion summaries|
|`enkrypt_api_response.jsonl`|Raw API responses (debug)|
|`enkrypt_api_debug.jsonl`|Debug information|
|`config_errors.log`|Configuration validation errors|

### Log Retention

Logs are automatically rotated after 7 days (configurable via `COPILOT_HOOKS_LOG_RETENTION_DAYS` environment variable). Old logs are archived with `.old` suffix and deleted after 14 days.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENKRYPT_API_KEY` | `""` | Enkrypt API key (overrides config file) |
| `ENKRYPT_API_URL` | `https://api.enkryptai.com/guardrails/policy/detect` | API endpoint URL |
| `COPILOT_HOOKS_LOG_DIR` | `~/copilot/hooks_logs` | Log directory path |
| `COPILOT_HOOKS_LOG_RETENTION_DAYS` | `7` | Days to keep logs before archiving |

### Viewing Logs

```bash
# View latest tool blocks
tail -5 ~/copilot/hooks_logs/preToolUse.jsonl

# View security alerts
tail -5 ~/copilot/hooks_logs/security_alerts.jsonl

# View all audit events
tail -10 ~/copilot/hooks_logs/combined_audit.jsonl
```

### Metrics

The hooks collect performance metrics that can be accessed programmatically:

```python
from enkrypt_guardrails import get_hook_metrics, reset_metrics

# Get metrics for a specific hook
metrics = get_hook_metrics("preToolUse")
print(f"Total calls: {metrics['total_calls']}")
print(f"Blocked calls: {metrics['blocked_calls']}")
print(f"Avg latency: {metrics['avg_latency_ms']:.2f}ms")

# Get all hook metrics
all_metrics = get_hook_metrics()

# Reset metrics
reset_metrics("preToolUse")  # Reset one hook
reset_metrics()  # Reset all
```

---

## How It Works

### 1. preToolUse (BLOCKING)

```text
Tool call initiated -> Hook intercepts -> Enkrypt API scans -> Allow or Deny
```

**Input from Copilot:**

```json
{
  "timestamp": 1704614600000,
  "cwd": "/path/to/project",
  "toolName": "bash",
  "toolArgs": "{\"command\": \"rm -rf /\"}"
}
```

**Output to Copilot:**

```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "Blocked by Enkrypt AI Guardrails:\nInjection attack pattern detected"
}
```

### 2. userPromptSubmitted (AUDIT-ONLY)

```text
User submits prompt -> Hook receives prompt -> Scan for violations -> Log alerts (no blocking)
```

This hook cannot block prompts — Copilot ignores its output. Violations are logged to `security_alerts.jsonl`.

### 3. postToolUse (AUDIT-ONLY)

```text
Tool completes -> Hook receives output -> Scan for sensitive data -> Log alerts
```

**Input from Copilot:**

```json
{
  "timestamp": 1704614700000,
  "cwd": "/path/to/project",
  "toolName": "bash",
  "toolArgs": "{\"command\": \"cat .env\"}",
  "toolResult": {
    "resultType": "success",
    "textResultForLlm": "API_KEY=sk-12345..."
  }
}
```

---

## Troubleshooting

### Hooks Not Running

1. Ensure hooks.json is in the correct location:
   - **Coding Agent:** `.github/hooks/hooks.json` on the default branch
   - **Copilot CLI:** `hooks.json` in your current working directory
2. Verify `"version": 1` is set in hooks.json
3. Check that Python is accessible at the configured path
4. Validate JSON syntax of hooks.json

### PowerShell 7 Not Found (Windows)

If you see this error with Copilot CLI:
```
PowerShell 6+ (pwsh) is not available. Please install it from https://aka.ms/powershell
```

**Solution:**
1. Install PowerShell 7+:
   ```powershell
   winget install Microsoft.PowerShell
   ```
2. Add to system PATH:
   - Open System Properties → Environment Variables
   - Edit the `Path` system variable
   - Add: `C:\Program Files\PowerShell\7`
3. Restart your terminal/IDE completely
4. Verify: `pwsh --version` should show `PowerShell 7.x.x`

### API Returning 404

The `"Policy not found"` error means:

- The `policy_violation` detector references a non-existent policy
- **Fix:** Disable `policy_violation` or create the policy in Enkrypt Dashboard

### Python Not Found

Ensure the correct Python path in `.github/hooks/hooks.json`:

```json
// macOS/Linux with venv
"bash": "hooks/copilot/venv/bin/python hooks/copilot/hooks/pre_tool_use.py"

// Windows with venv
"powershell": "hooks\\copilot\\venv\\Scripts\\python.exe hooks\\copilot\\hooks\\pre_tool_use.py"

// System Python
"bash": "python hooks/copilot/hooks/pre_tool_use.py"
```

### Test Hook Manually

```bash
echo '{"timestamp":1704614600000,"cwd":".","toolName":"bash","toolArgs":"ls"}' | python hooks/copilot/hooks/pre_tool_use.py
```

Expected output:

```json
{"permissionDecision": "allow"}
```

---

## Security Best Practices

1. **Never commit API keys** - Use environment variables for production
2. **Review logs regularly** - Check `security_alerts.jsonl` for issues
3. **Enable all relevant detectors** - More coverage = better protection
4. **Customize block lists** - Tune which detectors block vs. alert
5. **Keep hooks.json in your repo** - Share hook configuration; keep secrets in `guardrails_config.json` local-only

---

## Resources

- [GitHub Copilot Hooks Documentation](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
- [Copilot Hooks Configuration Reference](https://docs.github.com/en/copilot/reference/hooks-configuration)
- [Enkrypt AI Documentation](https://docs.enkryptai.com)
- [Enkrypt AI Dashboard](https://app.enkryptai.com)

---

## Support

- **Enkrypt AI Support:** support@enkryptai.com
- **Documentation:** [docs.enkryptai.com](https://docs.enkryptai.com)

---

## License

This integration is provided as-is for use with Enkrypt AI guardrails.
