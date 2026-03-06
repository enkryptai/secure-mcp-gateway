# Hooks CLI Reference

The `hooks` subcommand installs Enkrypt AI guardrail hooks into IDEs and agent frameworks. Hooks intercept prompts, tool calls, and responses at key lifecycle events and run guardrail checks (injection attack detection, PII, toxicity, NSFW, etc.) before allowing execution to continue.

Hooks work **standalone** — they do not require the Enkrypt MCP Gateway to be running.

---

## Prerequisites

Complete all five steps before running any `hooks` command.

### 1. Verify Python 3.10+

```bash
python --version
# Must print Python 3.10.x or later
```

If `python` is not found, try `python3`. Python 3.10, 3.11, 3.12, and 3.13 are all supported.

### 2. Create a virtual environment and install

```bash
# Create a virtual environment
python -m venv .venv

# Activate it
# macOS / Linux
source .venv/bin/activate

# Windows — Command Prompt
.venv\Scripts\activate.bat

# Windows — PowerShell
.venv\Scripts\Activate.ps1

# Install with hooks support
pip install "enkryptai-agent-security[hooks]"
```

> **Why venv?** The installer embeds the exact Python path (`sys.executable`) into every
> hook config file. Installing in a venv ensures hooks always run with the same interpreter
> that has the package installed, regardless of what Python is on the IDE's PATH.
>
> **For globally-scoped hooks** (claude-code, claude with `--scope global`): create the venv
> in a stable location that won't be deleted, e.g. `~/.venvs/enkryptai`, since the embedded
> Python path must remain valid across all projects.

Verify the CLI is available (with the venv active):

```bash
enkryptai-agent-security --help
```

### 3. Create an Enkrypt AI account

Go to <https://app.enkryptai.com> and sign up for a free account.

### 4. Get your API key

1. Log in and navigate to **Settings**: <https://app.enkryptai.com/settings>
2. Copy your `ENKRYPT_API_KEY` value

Set it as an environment variable so you do not have to pass `--api-key` on every command:

```bash
# macOS / Linux
export ENKRYPT_API_KEY=ek_live_abc123

# Windows — Command Prompt
set ENKRYPT_API_KEY=ek_live_abc123

# Windows — PowerShell
$env:ENKRYPT_API_KEY="ek_live_abc123"
```

To persist on Windows, set it via **System Properties → Environment Variables**.

### 5. Create a guardrail policy in the Enkrypt dashboard

> **This is the most common source of silent failures.** If the policy name in the config does not match a policy that exists in the dashboard, all guardrail checks pass silently without blocking anything.

1. Go to <https://app.enkryptai.com/guardrails>
2. Click **Create Policy** and configure the detectors you want (injection attack, PII, toxicity, etc.)
3. Note the exact policy name you used — you will need it in step 4 of the First-Time Setup

The default policy name embedded in generated configs is `"Sample Airline Guardrail"`. You can rename it in the dashboard or update the config after install (see [Updating the policy name](#updating-the-policy-name)).

---

## Quick Start

Minimum commands for a working setup from a fresh environment:

```bash
# Install package (with hooks support)
pip install "enkryptai-agent-security[hooks]"

# Set API key
export ENKRYPT_API_KEY=ek_live_abc123

# Install hooks for your IDE
enkryptai-agent-security hooks install --platform cursor
# or
enkryptai-agent-security hooks install --platform claude-code --scope global

# Restart your IDE

# Verify
enkryptai-agent-security hooks list
```

> `generate-config` is **not required** for a hooks-only setup. `hooks install` creates
> everything hooks need under `~/.enkrypt/hooks/<platform>/guardrails_config.json` directly.
> Only run `generate-config` if you are also setting up the MCP gateway (see
> [First-Time Setup — Path B](#path-b--generate-config---hook-use-when-also-setting-up-the-gateway)).

---

## First-Time Setup

### Path A — `hooks install` (recommended)

One command writes both the IDE hook config and the guardrails config:

```bash
enkryptai-agent-security hooks install --platform cursor --api-key ek_live_abc123
```

After install, **update the `guardrail_name`** in the generated config to match your dashboard policy:

- macOS/Linux: `~/.enkrypt/hooks/cursor/guardrails_config.json`
- Windows: `%USERPROFILE%\.enkrypt\hooks\cursor\guardrails_config.json`

Change the `"guardrail_name"` value in that file to match your policy name exactly, then restart your IDE.

### Path B — `generate-config --hook` (use when also setting up the gateway)

This creates a unified config file at `~/.enkrypt/enkrypt_config.json` with hooks defaults embedded. It does **not** write IDE-specific config files — you must still run `hooks install` afterward.

```bash
# Generate unified config with hooks section for cursor and claude-code
enkryptai-agent-security generate-config --hook cursor --hook claude-code

# Then install into each IDE
enkryptai-agent-security hooks install --platform cursor
enkryptai-agent-security hooks install --platform claude-code

# Or generate everything (gateway + SDK + all 10 hook platforms) at once:
enkryptai-agent-security generate-config --all
enkryptai-agent-security hooks install --all   # installs 5 IDE platforms only; see note below
```

---

## Supported Platforms

| Platform      | Type      | Default Scope | Supported Scopes | Config Path                                                    |
| ------------- | --------- | ------------- | ---------------- | -------------------------------------------------------------- |
| `cursor`      | IDE       | project       | project, global  | `.cursor/hooks.json` or `~/.cursor/hooks.json`                 |
| `claude`      | IDE       | global        | global, project  | `~/.claude/settings.json` or `<project>/.claude/settings.json` |
| `claude_code` | IDE       | global        | global, project  | `~/.claude/settings.json` or `<project>/.claude/settings.json` |
| `copilot`     | IDE       | project       | project only     | `.github/hooks/hooks.json`                                     |
| `kiro`        | IDE       | project       | project only     | `.kiro/hooks/*.kiro.hook`                                      |
| `langchain`   | Framework | global        | global only      | pip extras install                                             |
| `langgraph`   | Framework | global        | global only      | pip extras install                                             |
| `openai`      | Framework | global        | global only      | pip extras install                                             |
| `strands`     | Framework | global        | global only      | pip extras install                                             |
| `crewai`      | Framework | global        | global only      | manual install                                                 |

> **Note on `--all`**: The `--all` flag installs only the **5 IDE platforms** (cursor, claude, claude_code, copilot, kiro). Framework platforms must be installed individually with `--platform <name>`.
>
> **Note on `vercel-ai-sdk`**: TypeScript/npm-based and must be installed manually. See `src/enkryptai_agent_security/hooks/vercel_ai_sdk/README.md`.

### Platform Aliases

These aliases are accepted anywhere a platform name is expected:

- `claude-code`, `claudecode` → `claude_code`
- `openai-agents`, `openai_agents` → `openai`

---

## Commands Reference

### `hooks install`

Install hooks and guardrails config for one or more platforms.

```text
enkryptai-agent-security hooks install [OPTIONS]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform. Repeatable or comma-separated. |
| `--all` | Install hooks for all 5 IDE platforms. Does not include framework platforms. |
| `--api-key KEY` | Enkrypt API key. Falls back to `ENKRYPT_API_KEY` env var, then empty string. |
| `--scope {global,project}` | Install scope. Default depends on platform (see table above). |
| `--project-dir DIR` | Project directory for project-scoped installs. Default: current directory. |
| `--force` | Overwrite existing config files (creates `.bak` backup first). |

Either `--platform` or `--all` is required.

**Examples:**

```bash
# Single platform
enkryptai-agent-security hooks install --platform cursor

# Multiple platforms
enkryptai-agent-security hooks install --platform cursor --platform claude-code
enkryptai-agent-security hooks install --platform cursor,copilot,kiro

# All 5 IDE platforms with API key
enkryptai-agent-security hooks install --all --api-key ek_live_abc123

# Project-scoped Claude Code install in a specific directory
enkryptai-agent-security hooks install --platform claude-code --scope project --project-dir /path/to/project

# Force reinstall (backs up existing files)
enkryptai-agent-security hooks install --platform cursor --force

# Framework install (installs pip extras + guardrails config)
enkryptai-agent-security hooks install --platform langchain --api-key YOUR_KEY
```

### `hooks configure`

Regenerate only the guardrails config file for a platform, without touching hook configs. Use this to update your API key or reset policy defaults without reinstalling hooks.

```text
enkryptai-agent-security hooks configure --platform NAME [OPTIONS]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform (required). |
| `--api-key KEY` | Enkrypt API key. |

**Examples:**

```bash
# Update API key in guardrails config
enkryptai-agent-security hooks configure --platform cursor --api-key ek_live_new_key

# Regenerate config from defaults
enkryptai-agent-security hooks configure --platform claude_code
```

### `hooks list`

List all platforms and their installation status.

```text
enkryptai-agent-security hooks list [--project-dir DIR]
```

| Parameter | Description |
| --- | --- |
| `--project-dir DIR` | Project directory to check for project-scoped installs. Default: current directory. |

**Example output:**

```text
Platform        Type         Hooks      Guardrails   Status
---------------------------------------------------------------
claude          ide          yes        yes          installed
claude_code     ide          yes        yes          installed
copilot         ide          no         no           not_installed
crewai          framework    no         yes          partial
cursor          ide          yes        yes          installed
kiro            ide          no         no           not_installed
langchain       framework    yes        yes          installed
langgraph       framework    no         no           not_installed
openai          framework    no         no           not_installed
strands         framework    no         no           not_installed
```

Status values:

- **installed** — both hooks config and guardrails config present
- **partial** — only one of hooks or guardrails config present
- **not_installed** — neither present

### `hooks status`

Show detailed status for a single platform.

```text
enkryptai-agent-security hooks status --platform NAME [--project-dir DIR]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform (required). |
| `--project-dir DIR` | Project directory. Default: current directory. |

**Example output:**

```text
Platform:         cursor
Type:             ide
Hooks installed:  yes
Guardrails config:yes
Status:           installed
Supported scopes: project, global
Default scope:    project
Guardrails path:  /home/user/.enkrypt/hooks/cursor/guardrails_config.json
Hooks path (project): /home/user/myproject/.cursor/hooks.json (exists)
Hooks path ( global): /home/user/.cursor/hooks.json (not found)
Guardrail policies:
  beforeSubmitPrompt        disabled
  beforeMCPExecution        enabled  [injection_attack, nsfw, toxicity, pii, keyword_detector]
  afterMCPExecution         enabled  [pii, toxicity, nsfw]
  afterAgentResponse        disabled
  stop                      disabled
```

### `hooks uninstall`

Remove hook config files and guardrails config for one or more platforms.

```text
enkryptai-agent-security hooks uninstall [OPTIONS]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform. Repeatable or comma-separated. |
| `--all` | Uninstall hooks for all 5 IDE platforms. |
| `--scope {global,project}` | Scope to uninstall from. Default depends on platform. |
| `--project-dir DIR` | Project directory. Default: current directory. |
| `--keep-guardrails` | Keep guardrails config file (only remove hook config files). |

For Claude and Claude Code, only the Enkrypt hook entries are removed from `settings.json` — all other settings are preserved. For Kiro, only `.kiro.hook` files referencing `enkryptai_agent_security` are deleted. Framework platforms print pip uninstall instructions instead of running the command.

**Examples:**

```bash
# Uninstall cursor hooks from current project
enkryptai-agent-security hooks uninstall --platform cursor

# Uninstall but keep guardrails config
enkryptai-agent-security hooks uninstall --platform cursor --keep-guardrails

# Uninstall all 5 IDE platforms
enkryptai-agent-security hooks uninstall --all

# Uninstall global-scoped Claude Code hooks
enkryptai-agent-security hooks uninstall --platform claude-code --scope global
```

### `hooks disable`

Disable guardrail policies for a platform without removing any files. Sets `"enabled": false` in the guardrails config.

```text
enkryptai-agent-security hooks disable --platform NAME [--hook HOOK_NAME]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform (required). |
| `--hook HOOK_NAME` | Disable only a specific hook. Default: all hooks. |

**Examples:**

```bash
# Disable all guardrail hooks for cursor
enkryptai-agent-security hooks disable --platform cursor

# Disable only the beforeMCPExecution hook
enkryptai-agent-security hooks disable --platform cursor --hook beforeMCPExecution
```

### `hooks enable`

Re-enable guardrail policies for a platform. Sets `"enabled": true` in the guardrails config.

```text
enkryptai-agent-security hooks enable --platform NAME [--hook HOOK_NAME]
```

| Parameter | Description |
| --- | --- |
| `--platform NAME` | Target platform (required). |
| `--hook HOOK_NAME` | Enable only a specific hook. Default: all hooks. |

**Examples:**

```bash
# Enable all guardrail hooks for cursor
enkryptai-agent-security hooks enable --platform cursor

# Enable only the beforeMCPExecution hook
enkryptai-agent-security hooks enable --platform cursor --hook beforeMCPExecution
```

---

## Scope Reference

### Cursor

- **project** (default): `.cursor/hooks.json` inside the project directory
- **global**: `~/.cursor/hooks.json` in the user home directory

### Claude / Claude Code

Both share the same settings file path. The installer merges hooks into an existing `settings.json` if one already exists, preserving all non-hook settings and avoiding duplicate entries.

- **global** (default): `~/.claude/settings.json`
- **project**: `<project-dir>/.claude/settings.json`

### Copilot

- **project** only: `.github/hooks/hooks.json` inside the project directory
- Global scope is not supported.

### Kiro

- **project** only: `.kiro/hooks/` directory, with individual `.kiro.hook` files
- Global scope is not supported.

### Framework Platforms

All framework platforms use global scope only. Installation means:

1. Installing pip extras (e.g., `enkryptai-agent-security[hooks-langchain]`)
2. Writing guardrails config to `~/.enkrypt/hooks/<platform>/guardrails_config.json`

---

## What Gets Installed

### IDE Platforms

For each IDE platform, two things are created:

1. **Hook config file** — platform-specific JSON at the location shown in the scope reference
2. **Guardrails config** — always at:
   - macOS/Linux: `~/.enkrypt/hooks/<platform>/guardrails_config.json`
   - Windows: `%USERPROFILE%\.enkrypt\hooks\<platform>\guardrails_config.json`

#### Cursor

Creates `.cursor/hooks.json` (or `~/.cursor/hooks.json` for global scope) with 5 hooks: `beforeSubmitPrompt`, `beforeMCPExecution`, `afterMCPExecution`, `afterAgentResponse`, `stop`.

#### Claude

Merges into `settings.json` with 4 hooks: `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`.

#### Claude Code

Merges into `settings.json` with 11 hooks: `Setup`, `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `SubagentStop`, `Stop`, `PreCompact`, `Notification`, `SessionEnd`.

#### Copilot

Creates `.github/hooks/hooks.json` with 6 hooks: `sessionStart`, `userPromptSubmitted`, `preToolUse`, `postToolUse`, `sessionEnd`, `errorOccurred`.

#### Kiro

Creates `.kiro/hooks/` directory with 5 individual `.kiro.hook` files:

- `before-prompt-guardrails.kiro.hook`
- `after-agent-guardrails.kiro.hook`
- `file-save-guardrails.kiro.hook`
- `file-create-guardrails.kiro.hook`
- `manual-security-scan.kiro.hook`

### Framework Platforms

| Platform    | pip extras                                        | Integration module                                              |
| ----------- | ------------------------------------------------- | --------------------------------------------------------------- |
| `langchain` | `enkryptai-agent-security[hooks-langchain]`       | `enkryptai_agent_security.hooks.wrappers.langchain_handler`     |
| `langgraph` | `enkryptai-agent-security[hooks-langgraph]`       | `enkryptai_agent_security.hooks.wrappers.langgraph_hook`        |
| `openai`    | `enkryptai-agent-security[hooks-openai-agents]`   | `enkryptai_agent_security.hooks.wrappers.openai_hook`           |
| `strands`   | `enkryptai-agent-security[hooks-strands]`         | `enkryptai_agent_security.hooks.wrappers.strands_hook`          |
| `crewai`    | none (manual)                                     | `enkryptai_agent_security.hooks.providers.crewai`               |

After `hooks install`, the CLI prints an integration snippet for each framework. Add it to your agent code:

**LangChain:**

```python
from enkryptai_agent_security.hooks.wrappers.langchain_handler import EnkryptGuardrailsHandler
handler = EnkryptGuardrailsHandler()
# Pass handler as callback to your LangChain chain/agent
```

**LangGraph:**

```python
from enkryptai_agent_security.hooks.wrappers.langgraph_hook import EnkryptLangGraphHook
hook = EnkryptLangGraphHook()
# Pass hook as callback to your LangGraph agent
```

**OpenAI Agents:**

```python
from enkryptai_agent_security.hooks.wrappers.openai_hook import EnkryptOpenAIHook
hook = EnkryptOpenAIHook()
# Wrap your OpenAI Agents runner with hook
```

**Strands:**

```python
from enkryptai_agent_security.hooks.wrappers.strands_hook import EnkryptStrandsHook
hook = EnkryptStrandsHook()
# Pass hook as callback to your Strands agent
```

**CrewAI:**

```python
from enkryptai_agent_security.hooks.providers.crewai import EnkryptCrewAIProvider
provider = EnkryptCrewAIProvider()
# Integrate provider with your CrewAI crew
```

---

## API Key Resolution

The API key is resolved in this order:

1. `--api-key` CLI flag (highest priority)
2. `ENKRYPT_API_KEY` environment variable
3. Empty string — runtime will check `ENKRYPT_API_KEY` env var again at hook execution time

> **Tip**: Set `ENKRYPT_API_KEY` in your environment and omit `--api-key` entirely.

---

## Guardrails Config Format

The generated `guardrails_config.json` (at `~/.enkrypt/hooks/<platform>/guardrails_config.json`) has this structure:

```json
{
  "enkrypt_api": {
    "url": "https://api.enkryptai.com/guardrails/policy/detect",
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "ssl_verify": true,
    "timeout": 15,
    "fail_silently": true
  },
  "beforeSubmitPrompt": {
    "enabled": false,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["injection_attack", "topic_detector", "nsfw", "toxicity", "pii", "keyword_detector", "bias", "sponge_attack"]
  },
  "beforeMCPExecution": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["injection_attack", "nsfw", "toxicity", "pii", "keyword_detector"]
  },
  "afterMCPExecution": {
    "enabled": true,
    "guardrail_name": "Sample Airline Guardrail",
    "block": ["pii", "toxicity", "nsfw"]
  },
  "sensitive_tools": ["execute_sql", "delete_", "remove_", "drop_", "write_file", "run_command", "shell_", "exec_"]
}
```

> **CRITICAL — Policy name must match the dashboard**: The `"guardrail_name"` value in each hook block must exactly match the name of a policy you created in the Enkrypt AI dashboard at <https://app.enkryptai.com/guardrails>. If there is no match, guardrails pass silently because `"fail_silently": true` by default. There is no error or warning.

The per-hook policies (enabled, block lists) and sensitive tools are generated from platform defaults defined in `src/enkryptai_agent_security/config/hook_defaults.py`.

### Updating the policy name

After install, you can update the policy name in two ways:

**Option 1 — Edit the file directly:**

```bash
# macOS/Linux
nano ~/.enkrypt/hooks/cursor/guardrails_config.json

# Windows PowerShell
notepad $env:USERPROFILE\.enkrypt\hooks\cursor\guardrails_config.json
```

Change every `"guardrail_name": "Sample Airline Guardrail"` to your actual policy name.

**Option 2 — Regenerate with `hooks configure`:**

```bash
enkryptai-agent-security hooks configure --platform cursor --api-key ek_live_abc123
# Then manually update guardrail_name in the regenerated file
```

### Config search order at runtime

The hooks runtime searches for `guardrails_config.json` in this order:

1. `ENKRYPT_GUARDRAILS_CONFIG` environment variable (explicit path)
2. `guardrails_config.json` in the current working directory
3. `~/.enkrypt/hooks/<platform>/guardrails_config.json`
4. Unified config file (`~/.enkrypt/enkrypt_config.json`)

---

## Verifying the Installation

After running `hooks install`, confirm everything is in place before restarting your IDE:

```bash
# 1. Check installation status for all platforms
enkryptai-agent-security hooks list

# 2. Check detailed status for a specific platform
enkryptai-agent-security hooks status --platform cursor

# 3. Confirm guardrails config exists and inspect it
# macOS/Linux:
cat ~/.enkrypt/hooks/cursor/guardrails_config.json

# Windows PowerShell:
Get-Content $env:USERPROFILE\.enkrypt\hooks\cursor\guardrails_config.json
```

Confirm:

- `"api_key"` is set to your actual key (not empty)
- `"guardrail_name"` matches the policy name in your dashboard
- At least one hook has `"enabled": true`

Then restart your IDE. Most IDEs only read hook config files at startup.

---

## Common Workflows

### Set up a new project with Cursor hooks

```bash
cd /path/to/project
enkryptai-agent-security hooks install --platform cursor --api-key ek_live_abc123
# Update guardrail_name in ~/.enkrypt/hooks/cursor/guardrails_config.json
# Restart Cursor
```

### Add hooks to an existing Claude Code setup

The installer merges into your existing `~/.claude/settings.json` without overwriting other settings:

```bash
enkryptai-agent-security hooks install --platform claude-code --api-key ek_live_abc123
# Restart Claude Code
```

### Install hooks for all IDEs at once

```bash
enkryptai-agent-security hooks install --all --api-key ek_live_abc123
# Updates: .cursor/hooks.json, ~/.claude/settings.json,
#          .github/hooks/hooks.json, .kiro/hooks/
# Restart each IDE
```

### Regenerate guardrails config with a new API key

```bash
enkryptai-agent-security hooks configure --platform cursor --api-key ek_live_new_key
```

### Check which platforms are installed

```bash
enkryptai-agent-security hooks list
```

### Force reinstall after upgrading

```bash
enkryptai-agent-security hooks install --platform cursor --force
# Existing hooks.json is backed up to hooks.json.bak
```

### Install framework hooks for LangChain

```bash
enkryptai-agent-security hooks install --platform langchain --api-key YOUR_KEY
# Installs pip extras and prints integration snippet (see above)
```

### Temporarily disable all guardrails

```bash
enkryptai-agent-security hooks disable --platform cursor
# ... do your work ...
enkryptai-agent-security hooks enable --platform cursor
```

### Uninstall hooks from a project

```bash
enkryptai-agent-security hooks uninstall --platform cursor
# Removes .cursor/hooks.json and guardrails config
```

### Uninstall hooks but keep guardrails config

```bash
enkryptai-agent-security hooks uninstall --platform cursor --keep-guardrails
# Removes .cursor/hooks.json only; guardrails config preserved for reinstall
```

---

## Troubleshooting

### Guardrails not triggering — no errors, requests not blocked

The most common cause: the `"guardrail_name"` in `guardrails_config.json` does not match a policy that exists in your Enkrypt dashboard.

1. Open `~/.enkrypt/hooks/<platform>/guardrails_config.json` (Windows: `%USERPROFILE%\.enkrypt\hooks\<platform>\guardrails_config.json`)
2. Check the `"guardrail_name"` value in each hook block
3. Log into <https://app.enkryptai.com/guardrails> and confirm a policy with that exact name exists
4. Fix the name in the config or create the policy in the dashboard

Also verify:

- `"api_key"` is set correctly in the `"enkrypt_api"` block
- At least one hook that covers your scenario has `"enabled": true`
- Set `ENKRYPT_GUARDRAILS_CONFIG` to the full path of your config if the default location is not being picked up

### Hooks fail after venv was moved or deleted

Hook config files embed the absolute path to `sys.executable` at install time. If the venv is later moved, renamed, or deleted, that path no longer exists and hooks fail silently.

Fix: reinstall hooks with `--force` after recreating or moving the venv:

```bash
source /new/path/to/.venv/bin/activate   # or Windows equivalent
enkryptai-agent-security hooks install --platform cursor --force
```

### `python: command not found` (non-venv installs)

If you installed without a venv (e.g., `pip install --user`), hook configs contain the path
to that Python. If the IDE cannot find it, hooks fail silently. Check that the Python from
your install is accessible, or reinstall using a venv (recommended).

### Hooks not activating after install

Restart the IDE after installing hooks. Most IDEs only read hook config files at startup.

For **Claude Code** (global scope), restart means closing all Claude Code sessions and reopening. For **Cursor**, fully quit and relaunch.

### "Config already exists" error

Use `--force` to overwrite. A `.bak` backup of the existing file is created automatically:

```bash
enkryptai-agent-security hooks install --platform cursor --force
```

### Global scope not supported error

Copilot and Kiro only support project scope. Remove `--scope global` or use `--scope project`:

```bash
# Wrong — will error:
enkryptai-agent-security hooks install --platform copilot --scope global

# Correct:
enkryptai-agent-security hooks install --platform copilot
```

### `ImportError: No module named 'requests'` when hooks execute

The `[hooks]` extra was not installed. The base package has no dependencies — `requests`
is only included with the `[hooks]` extra.

Fix (with venv active):

```bash
pip install "enkryptai-agent-security[hooks]"
enkryptai-agent-security hooks install --platform <name> --force
```

### Framework hooks not working

Framework platforms require pip extras. If you ran `hooks install --platform langchain` and it did not install the extras (e.g., pip failed), install them manually:

```bash
pip install "enkryptai-agent-security[hooks-langchain]"
pip install "enkryptai-agent-security[hooks-langgraph]"
pip install "enkryptai-agent-security[hooks-openai-agents]"
pip install "enkryptai-agent-security[hooks-strands]"
```

CrewAI has no pip extras — install the package itself and add the integration code manually.

### Windows: hooks not activating despite correct config

IDEs on Windows may not inherit environment variables set in a terminal session. If you set `ENKRYPT_API_KEY` with `set` or `$env:`, that only applies to the current shell.

Fix: Set `ENKRYPT_API_KEY` as a permanent **system** environment variable:

1. Open **System Properties → Advanced → Environment Variables**
2. Under **System variables**, click **New**
3. Name: `ENKRYPT_API_KEY`, Value: your key
4. Restart the IDE

### Hooks installed but `hooks list` shows `not_installed`

The status check looks for `enkryptai_agent_security` in the hook config file. If the file was manually edited and the reference was removed, status will show `not_installed` even though other hooks exist.

Run `hooks install --force` to regenerate the config with the correct references.
