"""Hooks CLI installer — install, uninstall, configure, enable, disable, and
check status of hook integrations.

Supports 5 IDE platforms (cursor, claude, claude_code, copilot, kiro) and
5 framework platforms (langchain, langgraph, openai, strands, crewai).

Each IDE platform has a specific JSON template embedded here and a guardrails
config generated from ``hook_defaults.PLATFORM_DEFAULTS``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from enkryptai_agent_security.config.hook_defaults import PLATFORM_DEFAULTS

# =========================================================================
# Constants & Registry
# =========================================================================

IDE_PLATFORMS = {"cursor", "claude", "claude_code", "copilot", "kiro"}
FRAMEWORK_PLATFORMS = {"langchain", "langgraph", "openai", "strands", "crewai"}
ALL_PLATFORMS = IDE_PLATFORMS | FRAMEWORK_PLATFORMS

PLATFORM_REGISTRY: dict[str, dict[str, Any]] = {
    "cursor": {"type": "ide", "default_scope": "project", "scopes": ["project", "global"]},
    "claude": {"type": "ide", "default_scope": "global", "scopes": ["global", "project"]},
    "claude_code": {"type": "ide", "default_scope": "global", "scopes": ["global", "project"]},
    "copilot": {"type": "ide", "default_scope": "project", "scopes": ["project"]},
    "kiro": {"type": "ide", "default_scope": "project", "scopes": ["project"]},
    "langchain": {"type": "framework", "default_scope": "global", "scopes": ["global"]},
    "langgraph": {"type": "framework", "default_scope": "global", "scopes": ["global"]},
    "openai": {"type": "framework", "default_scope": "global", "scopes": ["global"]},
    "strands": {"type": "framework", "default_scope": "global", "scopes": ["global"]},
    "crewai": {"type": "framework", "default_scope": "global", "scopes": ["global"]},
}

FRAMEWORK_EXTRAS: dict[str, str | None] = {
    "langchain": "hooks-langchain",
    "langgraph": "hooks-langgraph",
    "openai": "hooks-openai-agents",
    "strands": "hooks-strands",
    "crewai": None,
}

_PLATFORM_ALIASES: dict[str, str] = {
    "claude-code": "claude_code",
    "claudecode": "claude_code",
    "openai-agents": "openai",
    "openai_agents": "openai",
}

# =========================================================================
# IDE Hook Templates (embedded Python dicts matching *_example.json)
# =========================================================================

_MOD = "enkryptai_agent_security.hooks.scripts"


def _cursor_template() -> dict:
    m = f"{_MOD}.cursor"
    if sys.platform == "win32":
        exe = sys.executable.replace("\\", "\\\\")
        def _cmd(script: str) -> dict:
            return {"command": f'powershell.exe -NoProfile -NonInteractive -Command "& \'{exe}\' -m {m}.{script}"'}
    else:
        def _cmd(script: str) -> dict:
            return {"command": f"{sys.executable} -m {m}.{script}"}
    return {
        "version": 1,
        "hooks": {
            "beforeSubmitPrompt": [_cmd("before_submit_prompt")],
            "beforeMCPExecution": [_cmd("before_mcp_execution")],
            "afterMCPExecution":  [_cmd("after_mcp_execution")],
            "afterAgentResponse": [_cmd("after_agent_response")],
            "stop":               [_cmd("stop")],
        },
    }


def _claude_template() -> dict:
    m = f"{_MOD}.claude"
    cmd = lambda script: {"type": "command", "command": f"{sys.executable} -m {m}.{script}", "timeout": 30}
    return {
        "hooks": {
            "UserPromptSubmit": [cmd("user_prompt_submit")],
            "PreToolUse": [{"matcher": "", "hooks": [cmd("pre_tool_use")]}],
            "PostToolUse": [{"matcher": "", "hooks": [cmd("post_tool_use")]}],
            "Stop": [cmd("stop")],
        }
    }


def _claude_code_template() -> dict:
    m = f"{_MOD}.claude_code"
    cmd = lambda script, timeout=30: {"type": "command", "command": f"{sys.executable} -m {m}.{script}", "timeout": timeout}
    return {
        "hooks": {
            "Setup": [{"matcher": "init|maintenance", "hooks": [cmd("setup", 60)]}],
            "SessionStart": [{"hooks": [cmd("session_start")]}],
            "UserPromptSubmit": [{"hooks": [cmd("user_prompt_submit")]}],
            "PreToolUse": [{"matcher": "", "hooks": [cmd("pre_tool_use")]}],
            "PermissionRequest": [{"matcher": "", "hooks": [cmd("permission_request")]}],
            "PostToolUse": [{"matcher": "", "hooks": [cmd("post_tool_use")]}],
            "SubagentStop": [{"hooks": [cmd("subagent_stop")]}],
            "Stop": [{"hooks": [cmd("stop")]}],
            "PreCompact": [{"matcher": "manual|auto", "hooks": [cmd("pre_compact")]}],
            "Notification": [{"matcher": "permission_prompt|idle_prompt", "hooks": [cmd("notification")]}],
            "SessionEnd": [{"hooks": [cmd("session_end")]}],
        }
    }


def _copilot_template() -> dict:
    m = f"{_MOD}.copilot"

    def entry(script: str, timeout: int = 30) -> dict:
        return {
            "type": "command",
            "bash": f"{sys.executable} -m {m}.{script}",
            "powershell": f"{sys.executable} -m {m}.{script}",
            "cwd": ".",
            "timeoutSec": timeout,
        }

    return {
        "version": 1,
        "hooks": {
            "sessionStart": [entry("session_start", 10)],
            "userPromptSubmitted": [entry("user_prompt_submitted")],
            "preToolUse": [entry("pre_tool_use")],
            "postToolUse": [entry("post_tool_use")],
            "sessionEnd": [entry("session_end", 10)],
            "errorOccurred": [entry("error_occurred", 10)],
        },
    }


def _kiro_hooks_list() -> list[dict]:
    m = f"{_MOD}.kiro"
    return [
        {
            "enabled": True,
            "name": "Enkrypt Prompt Guardrail",
            "description": "Validate user prompts for injection attacks, PII, and policy violations",
            "version": "1",
            "when": {"type": "promptSubmit"},
            "then": {"type": "runCommand", "command": f"{sys.executable} -m {m}.prompt_submit"},
            "shortName": "before-prompt-guardrails",
        },
        {
            "enabled": True,
            "name": "Enkrypt Response Audit",
            "description": "Audit agent responses for security issues after agent execution completes",
            "version": "1",
            "when": {"type": "agentStop"},
            "then": {"type": "runCommand", "command": f"{sys.executable} -m {m}.agent_stop"},
            "shortName": "after-agent-guardrails",
        },
        {
            "enabled": True,
            "name": "Enkrypt File Security Scan",
            "description": "Scan saved files for secrets and sensitive data",
            "version": "1",
            "when": {"type": "fileSave", "pattern": "**/*.{py,js,ts,json,yaml,yml,env*}"},
            "then": {"type": "runCommand", "command": f'FILE_PATH="${{filePath}}" {sys.executable} -m {m}.file_save'},
            "shortName": "file-save-guardrails",
        },
        {
            "enabled": True,
            "name": "Enkrypt New File Validator",
            "description": "Validate new files for security issues",
            "version": "1",
            "when": {"type": "fileCreate", "pattern": "**/*.{py,js,ts,json,yaml,yml,env*}"},
            "then": {"type": "runCommand", "command": f'FILE_PATH="${{filePath}}" {sys.executable} -m {m}.file_create'},
            "shortName": "file-create-guardrails",
        },
        {
            "enabled": True,
            "name": "Enkrypt Security Scanner",
            "description": "On-demand security scanning for files and code",
            "version": "1",
            "when": {"type": "manual"},
            "then": {
                "type": "runCommand",
                "command": f'SCAN_TARGET="${{workspaceFolder}}" SCAN_TYPE=directory {sys.executable} -m {m}.manual_security_scan',
            },
            "shortName": "manual-security-scan",
        },
    ]


# =========================================================================
# Utility functions
# =========================================================================


def normalize_platform(name: str) -> str:
    """Normalize user-supplied platform name to internal key."""
    key = name.strip().lower().replace("-", "_")
    return _PLATFORM_ALIASES.get(key, key)


def resolve_api_key(cli_key: str | None) -> str:
    if cli_key:
        return cli_key
    env_key = os.environ.get("ENKRYPT_API_KEY", "")
    if env_key:
        return env_key
    print("INFO: No API key provided. Set ENKRYPT_API_KEY env var or use --api-key flag.")
    return ""


def validate_scope(platform: str, scope: str) -> None:
    reg = PLATFORM_REGISTRY.get(platform)
    if not reg:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)
    if scope not in reg["scopes"]:
        supported = ", ".join(reg["scopes"])
        print(f"ERROR: Platform '{platform}' does not support scope '{scope}'. Supported: {supported}")
        sys.exit(1)


def get_hooks_config_dest(platform: str, scope: str, project_dir: Path) -> Path:
    if platform == "cursor":
        if scope == "project":
            return project_dir / ".cursor" / "hooks.json"
        return Path.home() / ".cursor" / "hooks.json"
    if platform in ("claude", "claude_code"):
        if scope == "project":
            return project_dir / ".claude" / "settings.json"
        return Path.home() / ".claude" / "settings.json"
    if platform == "copilot":
        return project_dir / ".github" / "hooks" / "hooks.json"
    if platform == "kiro":
        return project_dir / ".kiro" / "hooks"
    raise ValueError(f"No config dest for platform: {platform}")


def _guardrails_config_dir(platform: str) -> Path:
    return Path.home() / ".enkrypt" / "hooks" / platform


# =========================================================================
# Guardrails config generation (legacy format for HooksCore.from_config_file)
# =========================================================================


def generate_guardrails_config(platform: str, api_key: str) -> dict:
    defaults = PLATFORM_DEFAULTS[platform]
    config: dict[str, Any] = {
        "enkrypt_api": {
            "url": "https://api.enkryptai.com/guardrails/policy/detect",
            "api_key": api_key,
            "ssl_verify": True,
            "timeout": 15,
            "fail_silently": True,
        },
        "sensitive_tools": defaults.sensitive_tools,
    }
    if defaults.sensitive_file_patterns:
        config["sensitive_file_patterns"] = defaults.sensitive_file_patterns
    for hook_name, policy in defaults.policies.items():
        config[hook_name] = {
            "enabled": policy.enabled,
            "guardrail_name": policy.guardrail_name,
            "block": policy.block,
        }
    return config


def write_guardrails_config(platform: str, api_key: str) -> Path:
    dest_dir = _guardrails_config_dir(platform)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "guardrails_config.json"
    config = generate_guardrails_config(platform, api_key)
    dest.write_text(json.dumps(config, indent=2) + "\n")
    return dest


# =========================================================================
# Settings merge logic (Claude / Claude Code share settings.json)
# =========================================================================


def _merge_settings_hooks(existing: dict, new_hooks: dict) -> dict:
    """Merge new hooks into existing settings.json, preserving all non-hook keys."""
    result = dict(existing)
    if "hooks" not in result:
        result["hooks"] = {}
    for event_name, entries in new_hooks.items():
        if event_name not in result["hooks"]:
            result["hooks"][event_name] = entries
        else:
            existing_cmds: set[str] = set()
            for e in result["hooks"][event_name]:
                if isinstance(e, dict):
                    cmd = e.get("command", "")
                    if not cmd and "hooks" in e:
                        for h in e["hooks"]:
                            existing_cmds.add(h.get("command", ""))
                    else:
                        existing_cmds.add(cmd)
            for entry in entries:
                cmd = ""
                if isinstance(entry, dict):
                    cmd = entry.get("command", "")
                    if not cmd and "hooks" in entry:
                        cmd = entry["hooks"][0].get("command", "") if entry["hooks"] else ""
                if cmd not in existing_cmds:
                    result["hooks"][event_name].append(entry)
    return result


def _write_json(path: Path, data: dict, backup: bool = False) -> None:
    if backup and path.exists():
        bak = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, bak)
        print(f"INFO: Backed up existing file to {bak}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _check_existing(path: Path, force: bool, label: str) -> bool:
    """Return True if we should proceed. Exit if file exists and no --force."""
    if path.exists() and not force:
        print(f"ERROR: {label} already exists at {path}")
        print("       Use --force to overwrite (a backup will be created).")
        sys.exit(1)
    return True


# =========================================================================
# Per-platform installers
# =========================================================================


def install_cursor(api_key: str, scope: str, project_dir: Path, force: bool) -> None:
    validate_scope("cursor", scope)
    dest = get_hooks_config_dest("cursor", scope, project_dir)
    _check_existing(dest, force, "Cursor hooks config")
    template = _cursor_template()
    _write_json(dest, template, backup=force)
    gc_path = write_guardrails_config("cursor", api_key)
    print(f"INFO: Cursor hooks installed at {dest}")
    print(f"INFO: Guardrails config written to {gc_path}")
    print("INFO: Restart Cursor to activate hooks.")


def install_claude(api_key: str, scope: str, project_dir: Path, force: bool) -> None:
    validate_scope("claude", scope)
    dest = get_hooks_config_dest("claude", scope, project_dir)
    template = _claude_template()
    if dest.exists():
        existing = json.loads(dest.read_text())
        merged = _merge_settings_hooks(existing, template["hooks"])
        _write_json(dest, merged, backup=force)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_json(dest, template)
    gc_path = write_guardrails_config("claude", api_key)
    print(f"INFO: Claude hooks installed at {dest}")
    print(f"INFO: Guardrails config written to {gc_path}")
    print("INFO: Restart Claude Desktop to activate hooks.")


def install_claude_code(api_key: str, scope: str, project_dir: Path, force: bool) -> None:
    validate_scope("claude_code", scope)
    dest = get_hooks_config_dest("claude_code", scope, project_dir)
    template = _claude_code_template()
    if dest.exists():
        existing = json.loads(dest.read_text())
        merged = _merge_settings_hooks(existing, template["hooks"])
        _write_json(dest, merged, backup=force)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_json(dest, template)
    gc_path = write_guardrails_config("claude_code", api_key)
    print(f"INFO: Claude Code hooks installed at {dest}")
    print(f"INFO: Guardrails config written to {gc_path}")
    print("INFO: Restart Claude Code to activate hooks.")


def install_copilot(api_key: str, project_dir: Path, force: bool) -> None:
    dest = get_hooks_config_dest("copilot", "project", project_dir)
    _check_existing(dest, force, "Copilot hooks config")
    template = _copilot_template()
    _write_json(dest, template, backup=force)
    gc_path = write_guardrails_config("copilot", api_key)
    print(f"INFO: Copilot hooks installed at {dest}")
    print(f"INFO: Guardrails config written to {gc_path}")
    print("INFO: Restart VS Code / Copilot to activate hooks.")


def install_kiro(api_key: str, project_dir: Path, force: bool) -> None:
    dest_dir = get_hooks_config_dest("kiro", "project", project_dir)
    hooks = _kiro_hooks_list()
    dest_dir.mkdir(parents=True, exist_ok=True)
    for hook in hooks:
        filename = f"{hook['shortName']}.kiro.hook"
        dest = dest_dir / filename
        if dest.exists() and not force:
            print(f"ERROR: Kiro hook file already exists at {dest}")
            print("       Use --force to overwrite.")
            sys.exit(1)
        _write_json(dest, hook, backup=force)
    gc_path = write_guardrails_config("kiro", api_key)
    print(f"INFO: Kiro hooks installed at {dest_dir}")
    print(f"INFO: {len(hooks)} hook files created.")
    print(f"INFO: Guardrails config written to {gc_path}")
    print("INFO: Restart Kiro to activate hooks.")


def install_framework(platform: str, api_key: str) -> None:
    extras = FRAMEWORK_EXTRAS.get(platform)
    if extras:
        pkg = f"enkryptai-agent-security[{extras}]"
        print(f"INFO: Installing {pkg}...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"ERROR: pip install failed:\n{result.stderr}")
            sys.exit(1)
        print(f"INFO: Successfully installed {pkg}")
    else:
        print(f"INFO: No pip extras available for '{platform}'.")
        print(f"INFO: Install manually: pip install enkryptai-agent-security")

    gc_path = write_guardrails_config(platform, api_key)
    print(f"INFO: Guardrails config written to {gc_path}")
    _print_framework_snippet(platform)


def _print_framework_snippet(platform: str) -> None:
    snippets = {
        "langchain": (
            "from enkryptai_agent_security.hooks.wrappers.langchain_handler import EnkryptGuardrailsHandler\n"
            "handler = EnkryptGuardrailsHandler()\n"
            "# Pass handler as callback to your LangChain chain/agent"
        ),
        "langgraph": (
            "from enkryptai_agent_security.hooks.wrappers.langgraph_hook import EnkryptLangGraphHook\n"
            "hook = EnkryptLangGraphHook()\n"
            "# Pass hook as callback to your LangGraph agent"
        ),
        "openai": (
            "from enkryptai_agent_security.hooks.wrappers.openai_hook import EnkryptOpenAIHook\n"
            "hook = EnkryptOpenAIHook()\n"
            "# Wrap your OpenAI Agents runner with hook"
        ),
        "strands": (
            "from enkryptai_agent_security.hooks.wrappers.strands_hook import EnkryptStrandsHook\n"
            "hook = EnkryptStrandsHook()\n"
            "# Pass hook as callback to your Strands agent"
        ),
        "crewai": (
            "from enkryptai_agent_security.hooks.providers.crewai import EnkryptCrewAIProvider\n"
            "provider = EnkryptCrewAIProvider()\n"
            "# Integrate provider with your CrewAI crew"
        ),
    }
    snippet = snippets.get(platform, "")
    if snippet:
        print(f"\nIntegration code:\n\n{snippet}\n")


# =========================================================================
# Install dispatcher
# =========================================================================


def _install_single(platform: str, api_key: str, scope: str | None,
                    project_dir: Path, force: bool) -> None:
    reg = PLATFORM_REGISTRY.get(platform)
    if not reg:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)

    effective_scope = scope or reg["default_scope"]
    validate_scope(platform, effective_scope)

    if reg["type"] == "framework":
        install_framework(platform, api_key)
        return

    if platform == "cursor":
        install_cursor(api_key, effective_scope, project_dir, force)
    elif platform == "claude":
        install_claude(api_key, effective_scope, project_dir, force)
    elif platform == "claude_code":
        install_claude_code(api_key, effective_scope, project_dir, force)
    elif platform == "copilot":
        install_copilot(api_key, project_dir, force)
    elif platform == "kiro":
        install_kiro(api_key, project_dir, force)


# =========================================================================
# Per-platform uninstallers
# =========================================================================


def _remove_hooks_from_settings(path: Path) -> bool:
    """Remove enkryptai_agent_security hook entries from a settings.json file.

    Handles both flat entries (``{"command": "..."}`` ) and nested entries
    (``{"matcher": "", "hooks": [{"command": "..."}]}``).  Returns True if
    any entries were actually removed.
    """
    if not path.exists():
        return False
    data = json.loads(path.read_text())
    hooks = data.get("hooks")
    if not hooks or not isinstance(hooks, dict):
        return False

    _MARKER = "enkryptai_agent_security"
    changed = False
    events_to_delete: list[str] = []

    for event_name, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        filtered: list[dict] = []
        for entry in entries:
            if not isinstance(entry, dict):
                filtered.append(entry)
                continue
            # Flat format: {"command": "python -m enkryptai_agent_security..."}
            cmd = entry.get("command", "")
            if cmd and _MARKER in cmd:
                changed = True
                continue
            # Nested format: {"matcher": "...", "hooks": [{"command": "..."}]}
            inner_hooks = entry.get("hooks")
            if isinstance(inner_hooks, list):
                kept = [h for h in inner_hooks
                        if not (isinstance(h, dict) and _MARKER in h.get("command", ""))]
                if len(kept) < len(inner_hooks):
                    changed = True
                if kept:
                    entry = dict(entry)
                    entry["hooks"] = kept
                    filtered.append(entry)
                # else: all inner hooks removed — drop the whole entry
                continue
            # Copilot-style: {"bash": "...", "powershell": "..."}
            bash_cmd = entry.get("bash", "")
            if bash_cmd and _MARKER in bash_cmd:
                changed = True
                continue
            filtered.append(entry)
        if not filtered:
            events_to_delete.append(event_name)
        else:
            hooks[event_name] = filtered

    for event_name in events_to_delete:
        del hooks[event_name]
        changed = True

    if not hooks:
        del data["hooks"]

    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n")
    return changed


def _rmdir_if_empty(path: Path) -> None:
    """Remove directory if it exists and is empty."""
    try:
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    except OSError:
        pass


def uninstall_cursor(scope: str, project_dir: Path) -> None:
    dest = get_hooks_config_dest("cursor", scope, project_dir)
    if dest.exists():
        dest.unlink()
        _rmdir_if_empty(dest.parent)
        print(f"INFO: Removed Cursor hooks config at {dest}")
    else:
        print(f"INFO: No Cursor hooks config found at {dest}")


def uninstall_claude(scope: str, project_dir: Path) -> None:
    dest = get_hooks_config_dest("claude", scope, project_dir)
    if dest.exists():
        if _remove_hooks_from_settings(dest):
            print(f"INFO: Removed Claude hook entries from {dest}")
        else:
            print(f"INFO: No Enkrypt hooks found in {dest}")
    else:
        print(f"INFO: No settings file found at {dest}")


def uninstall_claude_code(scope: str, project_dir: Path) -> None:
    dest = get_hooks_config_dest("claude_code", scope, project_dir)
    if dest.exists():
        if _remove_hooks_from_settings(dest):
            print(f"INFO: Removed Claude Code hook entries from {dest}")
        else:
            print(f"INFO: No Enkrypt hooks found in {dest}")
    else:
        print(f"INFO: No settings file found at {dest}")


def uninstall_copilot(project_dir: Path) -> None:
    dest = get_hooks_config_dest("copilot", "project", project_dir)
    if dest.exists():
        dest.unlink()
        _rmdir_if_empty(dest.parent)
        print(f"INFO: Removed Copilot hooks config at {dest}")
    else:
        print(f"INFO: No Copilot hooks config found at {dest}")


def uninstall_kiro(project_dir: Path) -> None:
    dest_dir = get_hooks_config_dest("kiro", "project", project_dir)
    if not dest_dir.is_dir():
        print(f"INFO: No Kiro hooks directory found at {dest_dir}")
        return
    removed = 0
    for f in list(dest_dir.glob("*.kiro.hook")):
        try:
            if "enkryptai_agent_security" in f.read_text():
                f.unlink()
                removed += 1
        except OSError:
            pass
    if removed:
        _rmdir_if_empty(dest_dir)
        print(f"INFO: Removed {removed} Kiro hook file(s) from {dest_dir}")
    else:
        print(f"INFO: No Enkrypt hook files found in {dest_dir}")


def _remove_guardrails_config(platform: str) -> None:
    gc_dir = _guardrails_config_dir(platform)
    gc_path = gc_dir / "guardrails_config.json"
    if gc_path.exists():
        gc_path.unlink()
        _rmdir_if_empty(gc_dir)
        print(f"INFO: Removed guardrails config at {gc_path}")
    else:
        print(f"INFO: No guardrails config found for {platform}")


def _uninstall_single(platform: str, scope: str | None,
                      project_dir: Path, keep_guardrails: bool) -> None:
    reg = PLATFORM_REGISTRY.get(platform)
    if not reg:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)

    effective_scope = scope or reg["default_scope"]
    validate_scope(platform, effective_scope)

    if reg["type"] == "framework":
        print(f"INFO: Framework hooks are installed as pip packages.")
        print(f"      To uninstall: pip uninstall enkryptai-agent-security")
    elif platform == "cursor":
        uninstall_cursor(effective_scope, project_dir)
    elif platform == "claude":
        uninstall_claude(effective_scope, project_dir)
    elif platform == "claude_code":
        uninstall_claude_code(effective_scope, project_dir)
    elif platform == "copilot":
        uninstall_copilot(project_dir)
    elif platform == "kiro":
        uninstall_kiro(project_dir)

    if not keep_guardrails:
        _remove_guardrails_config(platform)


# =========================================================================
# Enable / Disable guardrail policies
# =========================================================================


def _toggle_guardrail_policies(platform: str, enabled: bool,
                               hook_name: str | None) -> None:
    """Toggle ``enabled`` flag in guardrails config for a platform."""
    gc_path = _guardrails_config_dir(platform) / "guardrails_config.json"
    if not gc_path.exists():
        print(f"ERROR: No guardrails config found for '{platform}'.")
        print("       Run `hooks install` or `hooks configure` first.")
        sys.exit(1)

    config = json.loads(gc_path.read_text())

    # Identify policy keys (dicts with an "enabled" field)
    policy_keys = [k for k in config
                   if isinstance(config[k], dict) and "enabled" in config[k]]

    if not policy_keys:
        print(f"INFO: No guardrail policies found in config for '{platform}'.")
        return

    state_word = "enabled" if enabled else "disabled"

    if hook_name:
        if hook_name not in policy_keys:
            print(f"ERROR: Unknown hook '{hook_name}' for platform '{platform}'.")
            print(f"       Valid hooks: {', '.join(policy_keys)}")
            sys.exit(1)
        config[hook_name]["enabled"] = enabled
        print(f"INFO: {hook_name}: {state_word}")
    else:
        for key in policy_keys:
            config[key]["enabled"] = enabled
            print(f"INFO: {key}: {state_word}")

    gc_path.write_text(json.dumps(config, indent=2) + "\n")
    print(f"INFO: Guardrails config updated at {gc_path}")


# =========================================================================
# Status / list
# =========================================================================

_FRAMEWORK_SPEC_MAP = {
    "langchain": "enkryptai_agent_security.hooks.wrappers.langchain_handler",
    "langgraph": "enkryptai_agent_security.hooks.wrappers.langgraph_hook",
    "openai": "enkryptai_agent_security.hooks.wrappers.openai_hook",
    "strands": "enkryptai_agent_security.hooks.wrappers.strands_hook",
    "crewai": "enkryptai_agent_security.hooks.providers.crewai",
}


def _ide_hooks_installed(platform: str, project_dir: Path) -> bool:
    """Check if IDE hook config exists and references our package."""
    reg = PLATFORM_REGISTRY[platform]
    for scope in reg["scopes"]:
        try:
            dest = get_hooks_config_dest(platform, scope, project_dir)
        except ValueError:
            continue
        if platform == "kiro":
            if dest.is_dir() and any(dest.glob("*.kiro.hook")):
                for f in dest.glob("*.kiro.hook"):
                    if "enkryptai_agent_security" in f.read_text():
                        return True
        elif dest.exists():
            if "enkryptai_agent_security" in dest.read_text():
                return True
    return False


def _framework_installed(platform: str) -> bool:
    spec_mod = _FRAMEWORK_SPEC_MAP.get(platform)
    if not spec_mod:
        return False
    return importlib.util.find_spec(spec_mod) is not None


def check_platform_status(platform: str, project_dir: Path) -> dict:
    reg = PLATFORM_REGISTRY.get(platform)
    if not reg:
        return {"platform": platform, "type": "unknown", "status": "unknown"}

    gc_path = _guardrails_config_dir(platform) / "guardrails_config.json"
    has_gc = gc_path.exists()

    if reg["type"] == "ide":
        has_hooks = _ide_hooks_installed(platform, project_dir)
    else:
        has_hooks = _framework_installed(platform)

    if has_hooks and has_gc:
        status = "installed"
    elif has_hooks or has_gc:
        status = "partial"
    else:
        status = "not_installed"

    return {
        "platform": platform,
        "type": reg["type"],
        "hooks_config": has_hooks,
        "guardrails_config": has_gc,
        "status": status,
    }


def list_all_platforms(project_dir: Path) -> list[dict]:
    results = []
    for platform in sorted(ALL_PLATFORMS):
        results.append(check_platform_status(platform, project_dir))
    return results


# =========================================================================
# Command handlers
# =========================================================================


def handle_hooks_command(args: Any) -> None:
    cmd = getattr(args, "hooks_command", None)
    if cmd == "install":
        _handle_install(args)
    elif cmd == "uninstall":
        _handle_uninstall(args)
    elif cmd == "configure":
        _handle_configure(args)
    elif cmd == "enable":
        _handle_enable(args)
    elif cmd == "disable":
        _handle_disable(args)
    elif cmd == "list":
        _handle_list(args)
    elif cmd == "status":
        _handle_status(args)
    else:
        print("ERROR: Please specify a hooks subcommand: install, uninstall, configure, enable, disable, list, status")
        sys.exit(1)


def _handle_install(args: Any) -> None:
    project_dir = Path(getattr(args, "project_dir", None) or os.getcwd()).resolve()
    api_key = resolve_api_key(getattr(args, "api_key", None))
    scope = getattr(args, "scope", None)
    force = getattr(args, "force", False)

    platforms_raw = getattr(args, "platform", None) or []
    install_all = getattr(args, "install_all", False)

    if install_all:
        platforms = sorted(IDE_PLATFORMS)
        print(f"INFO: Installing hooks for all IDE platforms: {', '.join(platforms)}")
    elif platforms_raw:
        platforms = []
        for raw in platforms_raw:
            for p in raw.split(","):
                p = p.strip()
                if p:
                    platforms.append(normalize_platform(p))
    else:
        print("ERROR: Specify --platform <name> or --all")
        sys.exit(1)

    for platform in platforms:
        if platform not in ALL_PLATFORMS:
            print(f"ERROR: Unknown platform: {platform}")
            print(f"       Available: {', '.join(sorted(ALL_PLATFORMS))}")
            sys.exit(1)
        print(f"\n--- Installing hooks for: {platform} ---")
        _install_single(platform, api_key, scope, project_dir, force)


def _handle_uninstall(args: Any) -> None:
    project_dir = Path(getattr(args, "project_dir", None) or os.getcwd()).resolve()
    scope = getattr(args, "scope", None)
    keep_guardrails = getattr(args, "keep_guardrails", False)

    platforms_raw = getattr(args, "platform", None) or []
    uninstall_all = getattr(args, "uninstall_all", False)

    if uninstall_all:
        platforms = sorted(IDE_PLATFORMS)
        print(f"INFO: Uninstalling hooks for all IDE platforms: {', '.join(platforms)}")
    elif platforms_raw:
        platforms = []
        for raw in platforms_raw:
            for p in raw.split(","):
                p = p.strip()
                if p:
                    platforms.append(normalize_platform(p))
    else:
        print("ERROR: Specify --platform <name> or --all")
        sys.exit(1)

    for platform in platforms:
        if platform not in ALL_PLATFORMS:
            print(f"ERROR: Unknown platform: {platform}")
            print(f"       Available: {', '.join(sorted(ALL_PLATFORMS))}")
            sys.exit(1)
        print(f"\n--- Uninstalling hooks for: {platform} ---")
        _uninstall_single(platform, scope, project_dir, keep_guardrails)


def _handle_enable(args: Any) -> None:
    platform_raw = getattr(args, "platform", None)
    if not platform_raw:
        print("ERROR: --platform is required for enable")
        sys.exit(1)
    platform = normalize_platform(platform_raw)
    if platform not in ALL_PLATFORMS:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)
    hook_name = getattr(args, "hook", None)
    _toggle_guardrail_policies(platform, enabled=True, hook_name=hook_name)


def _handle_disable(args: Any) -> None:
    platform_raw = getattr(args, "platform", None)
    if not platform_raw:
        print("ERROR: --platform is required for disable")
        sys.exit(1)
    platform = normalize_platform(platform_raw)
    if platform not in ALL_PLATFORMS:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)
    hook_name = getattr(args, "hook", None)
    _toggle_guardrail_policies(platform, enabled=False, hook_name=hook_name)


def _handle_configure(args: Any) -> None:
    platform_raw = getattr(args, "platform", None)
    if not platform_raw:
        print("ERROR: --platform is required for configure")
        sys.exit(1)
    platform = normalize_platform(platform_raw)
    if platform not in ALL_PLATFORMS:
        print(f"ERROR: Unknown platform: {platform}")
        sys.exit(1)
    api_key = resolve_api_key(getattr(args, "api_key", None))
    gc_path = write_guardrails_config(platform, api_key)
    print(f"INFO: Guardrails config written to {gc_path}")


def _handle_list(args: Any) -> None:
    project_dir = Path(getattr(args, "project_dir", None) or os.getcwd()).resolve()
    results = list_all_platforms(project_dir)

    print(f"\n{'Platform':<15} {'Type':<12} {'Hooks':<10} {'Guardrails':<12} {'Status'}")
    print("-" * 63)
    for r in results:
        hooks_icon = "yes" if r["hooks_config"] else "no"
        gc_icon = "yes" if r["guardrails_config"] else "no"
        print(f"{r['platform']:<15} {r['type']:<12} {hooks_icon:<10} {gc_icon:<12} {r['status']}")
    print()
    note = (
        "Note: vercel-ai-sdk is TypeScript/npm-based and must be installed manually.\n"
        "      See src/enkryptai_agent_security/hooks/vercel_ai_sdk/README.md for instructions."
    )
    print(note)


def _handle_status(args: Any) -> None:
    platform_raw = getattr(args, "platform", None)
    if not platform_raw:
        print("ERROR: --platform is required for status")
        sys.exit(1)
    platform = normalize_platform(platform_raw)
    project_dir = Path(getattr(args, "project_dir", None) or os.getcwd()).resolve()
    result = check_platform_status(platform, project_dir)

    print(f"\nPlatform:         {result['platform']}")
    print(f"Type:             {result['type']}")
    print(f"Hooks installed:  {'yes' if result['hooks_config'] else 'no'}")
    print(f"Guardrails config:{'yes' if result['guardrails_config'] else 'no'}")
    print(f"Status:           {result['status']}")

    reg = PLATFORM_REGISTRY.get(platform, {})
    scopes = reg.get("scopes", [])
    print(f"Supported scopes: {', '.join(scopes)}")
    print(f"Default scope:    {reg.get('default_scope', 'n/a')}")

    gc_path = _guardrails_config_dir(platform) / "guardrails_config.json"
    print(f"Guardrails path:  {gc_path}")

    if reg.get("type") == "ide":
        for scope in scopes:
            try:
                dest = get_hooks_config_dest(platform, scope, project_dir)
                exists = dest.exists() if platform != "kiro" else dest.is_dir()
                print(f"Hooks path ({scope:>7}): {dest} {'(exists)' if exists else '(not found)'}")
            except ValueError:
                pass

    # Show per-hook guardrail policy status
    if gc_path.exists():
        try:
            gc = json.loads(gc_path.read_text())
            policy_keys = [k for k in gc
                           if isinstance(gc[k], dict) and "enabled" in gc[k]]
            if policy_keys:
                print("Guardrail policies:")
                for key in policy_keys:
                    entry = gc[key]
                    state = "enabled" if entry.get("enabled") else "disabled"
                    blocks = entry.get("block", [])
                    block_str = f"  [{', '.join(blocks)}]" if blocks and entry.get("enabled") else ""
                    print(f"  {key:<25} {state}{block_str}")
        except (json.JSONDecodeError, OSError):
            print("WARNING: Could not parse guardrails config")
    print()
