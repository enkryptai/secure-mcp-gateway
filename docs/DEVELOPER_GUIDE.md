# Developer Guide — `enkryptai-agent-security`

This document is a knowledge-transfer reference for developers working on this codebase. It explains what the package contains, why it's structured the way it is, and where to find everything.

> **Not the user docs.** For installation and usage guides see [README.md](../README.md). For the CLI reference see [CLI-Commands-Reference.md](../CLI-Commands-Reference.md).

---

## Background: Three repos, one package

This package was consolidated from three separate codebases:

| Original repo / directory | Now lives at | Purpose |
| --- | --- | --- |
| Root `hooks/` (IDE platform hooks) | `src/enkryptai_agent_security/hooks/` | Guardrails for IDE coding tools |
| `enkrypt-in-agent-sdk` | `src/enkryptai_agent_security/sdk/` | Guardrails + observability for agent code |
| Gateway | `src/enkryptai_agent_security/gateway/` | MCP security proxy server |

The three are now one pip-installable package (`enkryptai-agent-security`) with three independent sub-systems that share a common guardrails client (`guardrails/`).

---

## Sub-system 1: MCP Gateway (`gateway/`)

**What it does:** Sits between an MCP client (Claude Desktop, Cursor, etc.) and real MCP servers. Acts as a transparent proxy that adds authentication, guardrail checks, caching, and telemetry.

**Entry points:**

| Entry point | File | Description |
| --- | --- | --- |
| `secure-mcp-gateway` | `gateway/cli.py` | CLI — config management, server management, hooks install |
| MCP server | `gateway/gateway.py` | FastMCP server on `0.0.0.0:8000/mcp/` |
| REST API | `gateway/api_server.py` | FastAPI management API on port 8001 |

**Key internals:**

```
gateway/
├── gateway.py          # FastMCP server — the actual proxy
├── cli.py              # CLI (36k+ lines, all commands)
├── api_server.py       # FastAPI REST API
├── client.py           # MCP client — forwards calls to real MCP servers
├── hooks_installer.py  # `enkrypt-hooks install <platform>` command
├── plugins/
│   ├── auth/           # Auth provider (local API key or remote Enkrypt)
│   ├── guardrails/     # Guardrail provider (Enkrypt API, OpenAI, keyword)
│   └── telemetry/      # Telemetry provider (OpenTelemetry, stdout)
└── services/
    ├── cache/          # In-memory + Redis caching
    ├── discovery/      # Tool discovery from MCP servers
    ├── execution/      # Secure tool execution (with guardrail checks)
    ├── oauth/          # OAuth 2.0/2.1 token management
    ├── server/         # Server listing and info
    └── timeout/        # Timeout management and metrics
```

**Request flow:** MCP client → Gateway (auth → guardrail check → forward call → guardrail check) → Real MCP server

---

## Sub-system 2: IDE Hooks (`hooks/`)

**What it does:** Adds Enkrypt guardrail checks to IDE coding sessions. These are standalone Python scripts that the IDE invokes before/after certain events (tool use, prompts, etc.).

**Completely separate from the Agent SDK** — different purpose, different integration model.

```
hooks/
├── core.py           # HooksCore — shared: config loading, API calls, metrics, logging
├── providers/        # Thin wrappers, one per IDE platform
│   ├── claude.py         # Claude Desktop
│   ├── claude_code.py    # Claude Code (CLI)
│   ├── copilot.py        # GitHub Copilot
│   ├── cursor.py         # Cursor IDE
│   └── kiro.py           # Kiro IDE
└── scripts/          # Standalone scripts invoked by IDE hook configs
    ├── claude/           # pre_tool_use.py, post_tool_use.py, user_prompt_submit.py, stop.py
    ├── claude_code/      # pre_tool_use.py, post_tool_use.py, session_start.py, ...
    ├── copilot/
    ├── cursor/
    └── kiro/
```

**How it works:** The IDE calls a script in `hooks/scripts/<platform>/` → script calls the platform's `hooks/providers/<platform>.py` → provider calls `HooksCore` → `HooksCore` calls the Enkrypt guardrail API → returns pass/block.

**Installation:** `enkrypt-hooks install claude-code` (or `cursor`, `copilot`, `kiro`). The installer in `gateway/hooks_installer.py` writes the IDE's hooks config pointing to the scripts.

---

## Sub-system 3: In-Agent Security SDK (`sdk/`)

**What it does:** Embeds guardrail enforcement and observability directly inside AI agent code. Works with 15 agent frameworks via auto-patching or manual integration.

This is the most complex sub-system. It has three internal layers:

### Layer 1: Observability adapters (`sdk/adapters/`)

**Passive, non-blocking.** Converts framework-native events into structured `AgentEvent` objects for tracing, logging, and monitoring.

- Pattern: `EnkryptXxxAdapter(FrameworkNativeHookBase)` implements the framework's hook interface and calls `self._observer.emit(AgentEvent(...))` on each event.
- Used automatically when `auto_secure()` is called (via `_patch/` modules below).
- Can also be used manually for pure observability without guardrails.

Example — [sdk/adapters/strands.py](../src/enkryptai_agent_security/sdk/adapters/strands.py):
```python
class EnkryptStrandsAdapter(HookProvider):
    def _on_before_tool_call(self, event):
        self._observer.emit(AgentEvent(name=EventName.TOOL_CALL_START, ...))
```

### Layer 2: Guardrail patches (`sdk/_patch/`)

**Active, blocking.** Monkey-patches the framework's core Agent class at runtime to inject the adapter (observability) and apply guardrail checkpoints (blocking).

- Pattern: Each `_patch/<fw>.py` has `install(observer, guard_engine)` and `uninstall()`.
- `install()` typically wraps `Agent.__init__` (to inject the adapter) and `Agent.__call__` (to call `async_checkpoint()` before/after).
- Called by `auto_secure()` automatically for each detected framework.

Example — [sdk/_patch/strands.py](../src/enkryptai_agent_security/sdk/_patch/strands.py):
```python
def install(observer, guard_engine):
    _orig_call = Agent.__call__
    async def _patched_call(self, prompt, *args, **kwargs):
        await async_checkpoint(guard_engine, "pre_llm", str(prompt), AGENT_ID)
        result = await _orig_call(self, prompt, *args, **kwargs)
        await async_checkpoint(guard_engine, "post_llm", extract_output(result), AGENT_ID)
        return result
    Agent.__call__ = _patched_call
```

### Layer 3: Framework hook classes (`sdk/framework_hooks/`)

**Active, blocking — for manual integration.** Native callback/hook classes you instantiate and pass directly to the framework. No monkey-patching required.

Available for the **5 frameworks with rich native callback systems**:

| Framework | Handler/Hook class | Provider helpers |
| --- | --- | --- |
| LangChain | `langchain_handler.py` → `EnkryptGuardrailsHandler(BaseCallbackHandler)` | `langchain.py` |
| LangGraph | `langgraph_hook.py` → `EnkryptLangGraphHook`, pre/post model hooks | `langgraph.py` |
| OpenAI Agents | `openai_hook.py` → `EnkryptRunHooks`, `EnkryptAgentHooks` | `openai_agents.py` |
| Strands | `strands_hook.py` → `EnkryptGuardrailsHook(HookProvider)` | `strands.py` |
| CrewAI | `crewai.py` → `EnkryptGuardrailsContext`, `check_guardrails()` | (same file) |

The other 10 frameworks (Anthropic, AutoGen, Bedrock, Google ADK, Haystack, LlamaIndex, Phidata, PydanticAI, Semantic Kernel, SmolaAgents) intentionally do **not** have standalone `framework_hooks/` classes — their native APIs don't have callback systems rich enough to warrant it. Use `auto_secure()` for those.

---

## The two SDK integration paths

### Path A: `auto_secure()` — recommended, works for all 15 frameworks

```python
from enkryptai_agent_security.sdk import auto_secure

auto_secure(
    enkrypt_api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack", "pii", "toxicity"],
)
# All agent frameworks in the environment are now automatically protected
```

**What happens internally:**

```
auto_secure()
    │
    ├── _state.initialize(cfg)       ← creates AgentObserver + GuardEngine
    │
    └── for each framework detected:
            _patch/<fw>.install(observer, guard_engine)
                │
                ├── wraps Agent.__init__ → injects adapter (observability)
                └── wraps Agent.__call__ → adds async_checkpoint() (guardrails)
```

Config file: `sdk/auto.py` → `_REGISTRY` dict maps framework name → `(probe_module, patch_module_path)`.

### Path B: Manual `framework_hooks` — for LangChain, LangGraph, OpenAI Agents, Strands, CrewAI

```python
from enkryptai_agent_security.sdk.framework_hooks.langchain_handler import EnkryptGuardrailsHandler

handler = EnkryptGuardrailsHandler()
llm = ChatOpenAI(callbacks=[handler])
```

No `auto_secure()` needed. The handler reads config from environment variables or a config file directly via `HooksCore`.

---

## Framework coverage

| Framework | `sdk/adapters/` | `sdk/_patch/` | `sdk/framework_hooks/` | Unit tests | Examples |
| --- | --- | --- | --- | --- | --- |
| LangChain | ✅ | ✅ | ✅ handler + provider | ✅ | ✅ `langchain/` + `langchain_hooks/` |
| LangGraph | ✅ | ✅ | ✅ hook + provider | ✅ | ✅ `langgraph/` + `langgraph_hooks/` |
| OpenAI Agents | ✅ | ✅ | ✅ hook + provider | ✅ | ✅ `openai_agents/` + `openai_hooks/` |
| Strands | ✅ | ✅ | ✅ hook + provider | ✅ | ✅ `strands/` + `strands_hooks/` |
| CrewAI | ✅ | ✅ | ✅ provider | ✅ | ✅ `crewai/` |
| Anthropic | ✅ | ✅ | — | — | ✅ `anthropic/` |
| AutoGen | ✅ | ✅ | — | — | ✅ `autogen/` |
| Bedrock Agents | ✅ | ✅ | — | — | ✅ `bedrock_agents/` |
| Google ADK | ✅ | ✅ | — | — | ✅ `google_adk/` |
| Haystack | ✅ | ✅ | — | — | ✅ `haystack/` |
| LlamaIndex | ✅ | ✅ | — | — | ✅ `llamaindex/` |
| Phidata | ✅ | ✅ | — | — | ✅ `phidata/` |
| PydanticAI | ✅ | ✅ | — | — | ✅ `pydantic_ai/` |
| Semantic Kernel | ✅ | ✅ | — | — | ✅ `semantic_kernel/` |
| SmolaAgents | ✅ | ✅ | — | — | ✅ `smolagents/` |

**Tests note:** The "✅" unit tests for the first 5 frameworks live in `tests/sdk/framework_hooks/<fw>/`. The other 10 frameworks have no per-framework unit tests — only `tests/sdk/test_auto.py` and `tests/sdk/test_generic_adapter.py` cover the adapter and auto-patch paths generically. Adding per-framework adapter tests is a known gap.

---

## Full annotated directory map

```
src/enkryptai_agent_security/
├── __init__.py                    # Package root — version only
├── version.py                     # Single source of version string
│
├── gateway/                       # ── Sub-system 1: MCP Gateway ──────────────────
│   ├── gateway.py                 # FastMCP server (the proxy)
│   ├── cli.py                     # CLI entry point (all commands)
│   ├── api_server.py              # FastAPI REST API (port 8001)
│   ├── client.py                  # MCP client — forwards calls to real servers
│   ├── hooks_installer.py         # `enkrypt-hooks install` command
│   ├── consts.py                  # Constants and default config values
│   ├── utils.py                   # Logging, masking, config loading
│   ├── plugins/
│   │   ├── auth/                  # Auth plugins (local_apikey, enkrypt)
│   │   ├── guardrails/            # Guardrail plugins (enkrypt, openai, keyword)
│   │   └── telemetry/             # Telemetry plugins (opentelemetry, stdout)
│   └── services/
│       ├── cache/                 # Cache operations (local + Redis)
│       ├── discovery/             # Tool discovery from MCP servers
│       ├── execution/             # Secure tool execution with guardrail checks
│       ├── oauth/                 # OAuth 2.0/2.1 token lifecycle
│       ├── server/                # Server listing and info
│       └── timeout/               # Timeout management and escalation
│
├── hooks/                         # ── Sub-system 2: IDE Platform Hooks ──────────
│   ├── core.py                    # HooksCore — shared: config, API calls, metrics
│   ├── providers/                 # One file per IDE platform
│   │   ├── claude.py              # Claude Desktop
│   │   ├── claude_code.py         # Claude Code (CLI)
│   │   ├── copilot.py             # GitHub Copilot
│   │   ├── cursor.py              # Cursor IDE
│   │   └── kiro.py                # Kiro IDE
│   └── scripts/                   # Entry-point scripts called by IDE hook configs
│       ├── claude/                # pre_tool_use.py, post_tool_use.py, ...
│       ├── claude_code/           # pre_tool_use.py, post_tool_use.py, session_*, ...
│       ├── copilot/
│       ├── cursor/
│       └── kiro/
│
├── sdk/                           # ── Sub-system 3: In-Agent Security SDK ───────
│   ├── __init__.py                # Public API: auto_secure, GuardEngine, AgentObserver, ...
│   ├── auto.py                    # auto_secure() — one-liner; _REGISTRY of all frameworks
│   ├── config.py                  # SDKConfig, GuardrailConfig, AgentSDKConfig
│   ├── guard.py                   # GuardEngine — policy enforcement, guardrail API calls
│   ├── observer.py                # AgentObserver — buffers and exports AgentEvents
│   ├── events.py                  # AgentEvent, EventName, GuardrailVerdict, GuardrailAction
│   ├── otel_setup.py              # OpenTelemetry tracer/meter init, ExporterType
│   ├── redaction.py               # PayloadPolicy — PII scrubbing before export
│   ├── _state.py                  # Global SDK singleton (observer + guard + config)
│   ├── compliance.py              # Compliance mapping helpers
│   ├── encoding.py                # Payload encoding detection (from Sentry)
│   ├── exceptions.py              # SDK exception hierarchy
│   │
│   ├── guardrails/                # Guardrail provider implementations for SDK
│   │   ├── base.py                # GuardrailProvider ABC + GuardrailRegistry
│   │   ├── enkrypt_provider.py    # Production: calls Enkrypt AI guardrail API
│   │   └── keyword_provider.py    # Simple keyword blocklist provider
│   │
│   ├── adapters/                  # 📡 Observability adapters (passive, non-blocking)
│   │   ├── generic.py             # GenericAgentAdapter — framework-agnostic
│   │   ├── langchain.py           # LangChain → AgentEvents
│   │   ├── langgraph.py           # LangGraph → AgentEvents
│   │   ├── openai_agents.py       # OpenAI Agents → AgentEvents
│   │   ├── strands.py             # Strands → AgentEvents
│   │   ├── crewai.py              # CrewAI → AgentEvents
│   │   ├── anthropic.py           # Anthropic SDK → AgentEvents
│   │   ├── autogen.py             # AutoGen → AgentEvents
│   │   ├── bedrock_agents.py      # Bedrock Agents → AgentEvents
│   │   ├── google_adk.py          # Google ADK → AgentEvents
│   │   ├── haystack.py            # Haystack → AgentEvents
│   │   ├── llamaindex.py          # LlamaIndex → AgentEvents
│   │   ├── phidata.py             # Phidata → AgentEvents
│   │   ├── pydantic_ai.py         # PydanticAI → AgentEvents
│   │   ├── semantic_kernel.py     # Semantic Kernel → AgentEvents
│   │   └── smolagents.py          # SmolaAgents → AgentEvents
│   │
│   ├── framework_hooks/           # 🛡️ Guardrail hook classes (active, blocking)
│   │   ├── __init__.py            # Exports all hook classes
│   │   ├── langchain_handler.py   # EnkryptGuardrailsHandler (BaseCallbackHandler)
│   │   ├── langchain.py           # Config/provider helpers for LangChain
│   │   ├── langgraph_hook.py      # EnkryptLangGraphHook, pre/post model hooks
│   │   ├── langgraph.py           # Config/provider helpers for LangGraph
│   │   ├── openai_hook.py         # EnkryptRunHooks, EnkryptAgentHooks
│   │   ├── openai_agents.py       # Config/provider helpers for OpenAI Agents
│   │   ├── strands_hook.py        # EnkryptGuardrailsHook (Strands HookProvider)
│   │   ├── strands.py             # Config/provider helpers for Strands
│   │   └── crewai.py              # EnkryptGuardrailsContext, check_guardrails()
│   │
│   └── _patch/                    # 🔧 Auto-patch modules (used by auto_secure())
│       ├── _checkpoint.py         # async_checkpoint() — shared by all patch modules
│       ├── langchain.py           # install()/uninstall() for LangChain
│       ├── langgraph.py           # install()/uninstall() for LangGraph
│       ├── openai_agents.py       # install()/uninstall() for OpenAI Agents
│       ├── strands.py             # install()/uninstall() for Strands ← canonical example
│       ├── crewai.py              # install()/uninstall() for CrewAI
│       ├── anthropic.py           # install()/uninstall() for Anthropic SDK
│       ├── autogen.py             # install()/uninstall() for AutoGen
│       ├── bedrock_agents.py      # install()/uninstall() for Bedrock Agents
│       ├── google_adk.py          # install()/uninstall() for Google ADK
│       ├── haystack.py            # install()/uninstall() for Haystack
│       ├── llamaindex.py          # install()/uninstall() for LlamaIndex
│       ├── phidata.py             # install()/uninstall() for Phidata
│       ├── pydantic_ai.py         # install()/uninstall() for PydanticAI
│       ├── semantic_kernel.py     # install()/uninstall() for Semantic Kernel
│       └── smolagents.py          # install()/uninstall() for SmolaAgents
│
├── guardrails/                    # 🔑 Core guardrail client (shared by hooks/ and sdk/)
│   ├── client.py                  # EnkryptGuardrailClient — raw HTTP API wrapper
│   ├── parser.py                  # Response parser
│   └── types.py                   # GuardrailResult, Violation, etc.
│
└── config/                        # Package-level config helpers
```

---

## Tests layout

```
tests/
├── gateway/                       # Gateway tests
├── guardrails/                    # Core guardrail client tests
├── hooks/                         # IDE platform hook tests (claude, claude_code, copilot, cursor, kiro)
├── sdk/                           # SDK core tests
│   ├── test_auto.py               # auto_secure() integration
│   ├── test_generic_adapter.py    # GenericAgentAdapter
│   ├── test_guard.py              # GuardEngine
│   ├── test_events.py             # AgentEvent, EventName
│   ├── test_observer.py           # AgentObserver
│   ├── test_redaction.py          # PayloadPolicy
│   ├── test_encoding.py           # Encoding detection
│   ├── test_compliance.py         # Compliance mappings
│   └── framework_hooks/           # Per-framework guardrail hook tests
│       ├── langchain/             # test_enkrypt_guardrails.py, test_handler.py
│       ├── langgraph/             # test_enkrypt_guardrails.py
│       ├── openai/                # test_enkrypt_guardrails.py
│       ├── strands/               # test_enkrypt_guardrails.py
│       └── crewai/                # test_enkrypt_guardrails.py
├── telemetry/                     # OpenTelemetry integration tests
└── config/                        # Config loading/validation tests
```

---

## Examples layout

```
examples/
└── sdk/
    ├── _env_setup.py              # Shared .env loading and test helpers
    ├── demo.py                    # Generic SDK demo
    │
    # auto_secure() + observability examples (one per framework)
    ├── langchain/real_test.py
    ├── langgraph/real_test.py
    ├── openai_agents/real_test.py
    ├── strands/real_test.py       # Shows both auto_secure() and manual setup
    ├── crewai/real_test.py
    ├── anthropic/real_test.py
    ├── autogen/real_test.py
    ├── bedrock_agents/real_test.py
    ├── google_adk/real_test.py
    ├── haystack/real_test.py
    ├── llamaindex/real_test.py
    ├── phidata/real_test.py
    ├── pydantic_ai/real_test.py
    ├── semantic_kernel/real_test.py
    ├── smolagents/real_test.py
    │
    # framework_hooks manual integration examples (4 frameworks)
    ├── langchain_hooks/           # basic_usage.py, demo_injection_attack.py, ...
    ├── langgraph_hooks/           # basic_agent.py, demo_injection_attack.py, ...
    ├── openai_hooks/              # basic_agent.py, demo_injection_attack.py, ...
    └── strands_hooks/             # basic_agent.py, demo_injection_attack.py, ...
```

Note: `<fw>/real_test.py` demos use `auto_secure()`. `<fw>_hooks/` demos use `sdk.framework_hooks` classes directly. The `strands/real_test.py` shows both approaches side by side.

---

## Known gaps

| Gap | Details |
| --- | --- |
| No per-framework adapter unit tests for 10 frameworks | `tests/sdk/` has no dedicated tests for Anthropic, AutoGen, Bedrock, Google ADK, Haystack, LlamaIndex, Phidata, PydanticAI, Semantic Kernel, SmolaAgents adapters. `test_auto.py` and `test_generic_adapter.py` give general coverage. |
| Framework-specific adapters excluded from `adapters/__init__.py` | By design — lazy imports prevent pulling optional framework deps at package import time. Import adapters directly: `from enkryptai_agent_security.sdk.adapters.strands import EnkryptStrandsAdapter`. |

**Design decisions (not gaps):**

- `framework_hooks/` covers only 5 frameworks — intentional. Those 5 (LangChain, LangGraph, OpenAI Agents, Strands, CrewAI) have rich native callback/hook systems that make standalone guardrail hook classes worthwhile. For the other 10, `auto_secure()` is the supported path.

---

## How to add support for a new framework

1. **`sdk/adapters/<fw>.py`** — Create `Enkrypt<Fw>Adapter` implementing the framework's native hook interface. Call `self._observer.emit(AgentEvent(...))` on each significant event. Follow `sdk/adapters/strands.py` as a template.

2. **`sdk/_patch/<fw>.py`** — Create `install(observer, guard_engine, agent_id="")` and `uninstall()`. Monkey-patch the framework's Agent class:
   - In `__init__`: inject the adapter (register its hooks via the framework's hook registry)
   - In `__call__` / `invoke` / `run`: call `await async_checkpoint(guard_engine, "pre_llm", prompt, agent_id)` before, and `await async_checkpoint(guard_engine, "post_llm", output, agent_id)` after. Follow `sdk/_patch/strands.py`.

3. **`sdk/auto.py`** — Add to `_REGISTRY`:
   ```python
   "my_framework": ("my_framework.core", "enkryptai_agent_security.sdk._patch.my_framework"),
   ```
   First element is the import probe (if it imports cleanly, the framework is installed). Second is the patch module path.

4. *(Optional)* **`sdk/framework_hooks/<fw>_hook.py`** — Only if the framework has a rich native callback system. Implement `Enkrypt<Fw>Hook` as a framework callback class that calls `HooksCore.check()` directly.

5. **`tests/sdk/framework_hooks/<fw>/test_enkrypt_guardrails.py`** — Unit tests.

6. **`examples/sdk/<fw>/real_test.py`** — Integration example. See `examples/sdk/strands/real_test.py` for a two-approach (auto + manual) template.

7. **`docs/sdk/frameworks/<fw>.md`** — Framework-specific doc page. Copy structure from `docs/sdk/frameworks/langchain.md`.

---

## Key files to read first

| File | Why |
| --- | --- |
| [`sdk/auto.py`](../src/enkryptai_agent_security/sdk/auto.py) | `_REGISTRY` + `auto_secure()` — the main entry point |
| [`sdk/_patch/_checkpoint.py`](../src/enkryptai_agent_security/sdk/_patch/_checkpoint.py) | `async_checkpoint()` — shared guardrail check used by all patch modules |
| [`sdk/_patch/strands.py`](../src/enkryptai_agent_security/sdk/_patch/strands.py) | Canonical complete patch module |
| [`sdk/adapters/strands.py`](../src/enkryptai_agent_security/sdk/adapters/strands.py) | Canonical observability adapter |
| [`sdk/framework_hooks/strands_hook.py`](../src/enkryptai_agent_security/sdk/framework_hooks/strands_hook.py) | Canonical guardrail hook class |
| [`hooks/core.py`](../src/enkryptai_agent_security/hooks/core.py) | `HooksCore` — shared infra for all IDE hooks |
| [`gateway/hooks_installer.py`](../src/enkryptai_agent_security/gateway/hooks_installer.py) | `enkrypt-hooks install` command |

---

## Quick-start recipes

**MCP Gateway** — protect MCP tool calls from Claude Desktop / Cursor:

```bash
pip install enkryptai-agent-security
secure-mcp-gateway generate-config
secure-mcp-gateway install claude-desktop
```

**IDE Hooks** — protect IDE coding sessions:

```bash
pip install enkryptai-agent-security
enkrypt-hooks install claude-code   # or: cursor, copilot, kiro
```

**In-Agent SDK — auto** (all 15 frameworks, one line):

```python
from enkryptai_agent_security.sdk import auto_secure

auto_secure(
    enkrypt_api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack", "pii", "toxicity"],
)
```

**In-Agent SDK — manual** (LangChain / LangGraph / OpenAI Agents / Strands / CrewAI):

```python
from enkryptai_agent_security.sdk.framework_hooks.langchain_handler import EnkryptGuardrailsHandler

handler = EnkryptGuardrailsHandler()
llm = ChatOpenAI(callbacks=[handler])
```
