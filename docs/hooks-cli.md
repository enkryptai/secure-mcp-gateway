# Hooks CLI Reference

The `hooks` subcommand automates the installation and management of Enkrypt guardrail hooks for IDEs and agent frameworks.

## Prerequisites

```bash
pip install enkryptai-agent-security
```

## Quick Start

```bash
# Install hooks for Cursor in the current project
enkryptai-agent-security hooks install --platform cursor [--api-key YOUR_KEY]

# Install hooks for Claude Code globally
enkryptai-agent-security hooks install --platform claude-code --scope global [--api-key YOUR_KEY]

# Install hooks for all IDEs at once
enkryptai-agent-security hooks install --all [--api-key YOUR_KEY]

# Check installation status
enkryptai-agent-security hooks list
enkryptai-agent-security hooks status --platform cursor
```

## Supported Platforms

| Platform | Type | Default Scope | Supported Scopes | Config Path(s) |
|---|---|---|---|---|
| `cursor` | IDE | project | project, global | `.cursor/hooks.json` or `~/.cursor/hooks.json` |
| `claude` | IDE | global | global, project | `~/.claude/settings.json` or `<project>/.claude/settings.json` |
| `claude_code` | IDE | global | global, project | `~/.claude/settings.json` or `<project>/.claude/settings.json` |
| `copilot` | IDE | project | project | `.github/hooks/hooks.json` |
| `kiro` | IDE | project | project | `.kiro/hooks/*.kiro.hook` |
| `langchain` | Framework | global | global | pip extras install |
| `langgraph` | Framework | global | global | pip extras install |
| `openai` | Framework | global | global | pip extras install |
| `strands` | Framework | global | global | pip extras install |
| `crewai` | Framework | global | global | manual install |

> **Note**: `vercel-ai-sdk` is TypeScript/npm-based and must be installed manually. See `src/enkryptai_agent_security/hooks/vercel_ai_sdk/README.md`.

### Platform Aliases

These aliases are accepted anywhere a platform name is expected:

- `claude-code`, `claudecode` → `claude_code`
- `openai-agents`, `openai_agents` → `openai`

## Commands Reference

### `hooks install`

Install hooks and guardrails config for one or more platforms.

```
enkryptai-agent-security hooks install [OPTIONS]
```

| Parameter | Description |
|---|---|
| `--platform NAME` | Target platform. Repeatable or comma-separated. |
| `--all` | Install hooks for all 5 IDE platforms. |
| `--api-key KEY` | Enkrypt API key. Falls back to `ENKRYPT_API_KEY` env var, then placeholder. |
| `--scope {global,project}` | Install scope. Default depends on platform (see table above). |
| `--project-dir DIR` | Project directory for project-scoped installs. Default: current directory. |
| `--force` | Overwrite existing config files (creates `.bak` backup first). |

Either `--platform` or `--all` is required. `--all` installs the 5 IDE platforms only (cursor, claude, claude_code, copilot, kiro).

**Examples:**

```bash
# Single platform
enkryptai-agent-security hooks install --platform cursor

# Multiple platforms
enkryptai-agent-security hooks install --platform cursor --platform claude-code
enkryptai-agent-security hooks install --platform cursor,copilot,kiro

# All IDEs with API key
enkryptai-agent-security hooks install --all --api-key ek_live_abc123

# Project-scoped Claude Code install in a specific directory
enkryptai-agent-security hooks install --platform claude-code --scope project --project-dir /path/to/project

# Force reinstall (backs up existing files)
enkryptai-agent-security hooks install --platform cursor --force

# Framework install (installs pip extras + guardrails config)
enkryptai-agent-security hooks install --platform langchain --api-key YOUR_KEY
```

### `hooks configure`

Regenerate only the guardrails config file for a platform, without touching hook configs.

```
enkryptai-agent-security hooks configure --platform NAME [OPTIONS]
```

| Parameter | Description |
|---|---|
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

```
enkryptai-agent-security hooks list [--project-dir DIR]
```

| Parameter | Description |
|---|---|
| `--project-dir DIR` | Project directory to check for project-scoped installs. Default: current directory. |

**Example output:**

```
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

```
enkryptai-agent-security hooks status --platform NAME [--project-dir DIR]
```

| Parameter | Description |
|---|---|
| `--platform NAME` | Target platform (required). |
| `--project-dir DIR` | Project directory. Default: current directory. |

**Example output:**

```
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

```
enkryptai-agent-security hooks uninstall [OPTIONS]
```

| Parameter | Description |
|---|---|
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

# Uninstall all IDE platforms
enkryptai-agent-security hooks uninstall --all

# Uninstall global-scoped Claude Code hooks
enkryptai-agent-security hooks uninstall --platform claude-code --scope global
```

### `hooks disable`

Disable guardrail policies for a platform without removing any files. Sets `"enabled": false` in the guardrails config.

```
enkryptai-agent-security hooks disable --platform NAME [--hook HOOK_NAME]
```

| Parameter | Description |
|---|---|
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

```
enkryptai-agent-security hooks enable --platform NAME [--hook HOOK_NAME]
```

| Parameter | Description |
|---|---|
| `--platform NAME` | Target platform (required). |
| `--hook HOOK_NAME` | Enable only a specific hook. Default: all hooks. |

**Examples:**

```bash
# Enable all guardrail hooks for cursor
enkryptai-agent-security hooks enable --platform cursor

# Enable only the beforeMCPExecution hook
enkryptai-agent-security hooks enable --platform cursor --hook beforeMCPExecution
```

## Scope Reference

### Cursor

- **project**: `.cursor/hooks.json` inside the project directory
- **global**: `~/.cursor/hooks.json` in the user home directory

### Claude / Claude Code

Both share the same settings file path (`settings.json`). The installer merges hooks into an existing `settings.json` if one already exists, preserving all non-hook settings and avoiding duplicate entries.

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

## What Gets Installed

### IDE Platforms

For each IDE platform, two things are created:

1. **Hook config file** — platform-specific JSON at the location shown in the scope reference
2. **Guardrails config** — always at `~/.enkrypt/hooks/<platform>/guardrails_config.json`

#### Cursor

Creates `.cursor/hooks.json` with 5 hooks: `beforeSubmitPrompt`, `beforeMCPExecution`, `afterMCPExecution`, `afterAgentResponse`, `stop`.

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

| Platform | pip extras | Integration module |
|---|---|---|
| `langchain` | `enkryptai-agent-security[hooks-langchain]` | `enkryptai_agent_security.hooks.wrappers.langchain_handler` |
| `langgraph` | `enkryptai-agent-security[hooks-langgraph]` | `enkryptai_agent_security.hooks.wrappers.langgraph_hook` |
| `openai` | `enkryptai-agent-security[hooks-openai-agents]` | `enkryptai_agent_security.hooks.wrappers.openai_hook` |
| `strands` | `enkryptai-agent-security[hooks-strands]` | `enkryptai_agent_security.hooks.wrappers.strands_hook` |
| `crewai` | none (manual) | `enkryptai_agent_security.hooks.providers.crewai` |

After installing a framework, the CLI prints an integration code snippet. For example:

```python
# LangChain
from enkryptai_agent_security.hooks.wrappers.langchain_handler import EnkryptGuardrailsHandler
handler = EnkryptGuardrailsHandler()
# Pass handler as callback to your LangChain chain/agent
```

## API Key Resolution

The API key is resolved in this order:

1. `--api-key` CLI flag (highest priority)
2. `ENKRYPT_API_KEY` environment variable
3. Empty string — runtime will check `ENKRYPT_API_KEY` env var at execution time

> **Tip**: If `ENKRYPT_API_KEY` is set in your environment, you can omit `--api-key` entirely.

## Guardrails Config Format

The generated `guardrails_config.json` uses the legacy format expected by `HooksCore.from_config_file()`:

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
  "sensitive_tools": ["execute_sql", "delete_", "remove_", "drop_", "write_file", "run_command", "shell_", "exec_"]
}
```

The per-hook policies (enabled, block lists) and sensitive tools are auto-generated from the platform defaults defined in `src/enkryptai_agent_security/config/hook_defaults.py`.

The guardrails config is searched in this order at runtime:
1. `ENKRYPT_GUARDRAILS_CONFIG` environment variable
2. `guardrails_config.json` in the current working directory
3. `~/.enkrypt/hooks/<platform>/guardrails_config.json`
4. Unified config file

## Common Workflows

### Set up a new project with Cursor hooks

```bash
cd /path/to/project
enkryptai-agent-security hooks install --platform cursor --api-key ek_live_abc123
# Restart Cursor
```

### Add hooks to an existing Claude Code setup

The installer merges into your existing `~/.claude/settings.json` without overwriting other settings:

```bash
enkryptai-agent-security hooks install --platform claude-code --api-key ek_live_abc123
# Restart Claude Code
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
# Installs pip extras and prints integration snippet
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

## Troubleshooting

### Hooks not activating

Restart the IDE after installing hooks. Most IDEs only read hook config files at startup.

### Config already exists

Use `--force` to overwrite. A `.bak` backup of the existing file is created automatically.

### Global scope not supported

Copilot and Kiro only support project scope. Passing `--scope global` for these platforms will print an error. Remove the `--scope` flag or use `--scope project`.

### Guardrails not triggering

1. Verify your API key is set correctly in `~/.enkrypt/hooks/<platform>/guardrails_config.json`
2. Check that the hook policies have `"enabled": true` for the hooks you want active
3. Ensure the `guardrail_name` matches an existing guardrail in your Enkrypt dashboard
4. Check the guardrails config search path — set `ENKRYPT_GUARDRAILS_CONFIG` env var to point to your config file explicitly
