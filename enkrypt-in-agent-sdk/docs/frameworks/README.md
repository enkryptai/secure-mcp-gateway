# Framework Integration Guides

Detailed, beginner-friendly guides for using the **Enkrypt In-Agent SDK** with every supported framework.

Each guide walks you through installation, setup, auto-secure (one-liner), manual integration, guardrail configuration, and what to expect.

---

## Beginner Guide: Adding Security to Your AI Agent in 5 Minutes

If you've never used the Enkrypt SDK before, follow these steps:

### 1. Install the SDK

```bash
cd enkrypt-in-agent-sdk
pip install -e .
```

### 2. Get your Enkrypt API key

Sign up at [enkryptai.com](https://enkryptai.com) and create a guardrail policy in the dashboard. You'll get:
- An **API key** (starts with `ek-...`)
- A **policy name** (e.g. "My Safety Policy")

### 3. Add one line to your code

At the very top of your script, **before** any agent code:

```python
from enkrypt_agent_sdk import auto_secure

auto_secure(
    enkrypt_api_key="ek-your-key-here",
    guardrail_policy="My Safety Policy",
    block=["injection_attack", "pii", "toxicity"],
)
```

### 4. Run your agent as usual

That's it. Your existing code works unchanged -- but now:
- Dangerous user inputs are **blocked before reaching the LLM** (pre_llm checkpoint)
- Dangerous tool inputs are **blocked before tools execute** (pre_tool checkpoint)
- A `GuardrailBlockedError` is raised when something is blocked
- Full OpenTelemetry traces are emitted for observability

### 5. Handle blocked inputs (recommended)

Wrap your agent calls in a try/except so users see a friendly message:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    result = agent.run("your user's input here")
    print(result)
except GuardrailBlockedError as e:
    print(f"Sorry, that request was blocked for safety: {e}")
```

### What gets blocked?

| User says... | What happens | Why |
|---|---|---|
| "What is AI?" | Allowed | Safe question |
| "Hack the server and steal passwords" | **Blocked at pre_llm** | Injection attack detected |
| "Run `rm -rf /`" | **Blocked at pre_tool** | Dangerous command detected |
| `"aGFja2luZw=="` (base64 for "hacking") | **Blocked** | Encoded attack decoded and caught |
| "What's the weather in London?" | Allowed | Safe question |

---

## How Guardrail Checkpoints Work

Every auto-patch enforces guardrails at up to **four checkpoints** in the agent pipeline:

```text
User Input
    |
    v
[pre_llm]   <-- Block dangerous input BEFORE it reaches the LLM
    |
    v
  LLM Call   (e.g. ChatOpenAI, Messages.create, Runner.run)
    |
    v
[post_llm]  <-- Block unsafe LLM response BEFORE it reaches the user
    |
    v
  Tool Call  (if the LLM decides to use a tool)
    |
    v
[pre_tool]  <-- Block dangerous tool input BEFORE the tool runs
    |
    v
  Tool Exec  (e.g. BaseTool.invoke, Tool.forward)
    |
    v
[post_tool] <-- Block unsafe tool output BEFORE it's used
```

**Defaults**: `pre_llm` and `pre_tool` are enabled. `post_llm` and `post_tool` are disabled.

You can customize which checkpoints are active:

```python
auto_secure(
    enkrypt_api_key="...",
    guardrail_policy="My Policy",
    block=["injection_attack", "toxicity"],
    checkpoints={
        "pre_llm":   True,   # default: True
        "pre_tool":  True,   # default: True
        "post_tool": True,   # default: False -- enable to check tool outputs
        "post_llm":  True,   # default: False -- enable to check LLM responses
    },
)
```

When a checkpoint blocks, a visible message is printed and `GuardrailBlockedError` is raised:

```text
  >> [ENKRYPT BLOCKED] (PRE-LLM) anthropic-auto: injection_attack
  >> LLM was NOT called. Message never reached the model.
```

---

## Supported Frameworks

| # | Framework | Guide | Checkpoints | Difficulty |
|---|---|---|---|---|
| 1 | [LangChain](langchain.md) | Chains, tools, LLM calls | pre_llm, post_llm, pre_tool, post_tool | Beginner |
| 2 | [LangGraph](langgraph.md) | Stateful graph agents | pre_llm, post_llm (+ LC tools) | Beginner |
| 3 | [OpenAI Agents](openai-agents.md) | OpenAI's agent framework | pre_llm, post_llm | Beginner |
| 4 | [Anthropic](anthropic.md) | Claude API calls | pre_llm, post_llm | Beginner |
| 5 | [CrewAI](crewai.md) | Multi-agent crews | pre_llm, post_llm, pre_tool, post_tool | Beginner |
| 6 | [PydanticAI](pydantic-ai.md) | Type-safe agents | pre_llm, post_llm | Beginner |
| 7 | [LlamaIndex](llamaindex.md) | RAG pipelines | pre_llm, post_llm, pre_tool, post_tool | Beginner |
| 8 | [Google ADK](google-adk.md) | Google's Agent Dev Kit | pre_llm | Intermediate |
| 9 | [Amazon Bedrock](bedrock-agents.md) | AWS Bedrock Agents | adapter-based | Intermediate |
| 10 | [AutoGen](autogen.md) | Microsoft multi-agent chat | pre_llm, post_llm | Intermediate |
| 11 | [Semantic Kernel](semantic-kernel.md) | Microsoft orchestration | pre_llm, post_llm, filter | Intermediate |
| 12 | [Haystack](haystack.md) | Deepset NLP pipelines | pre_llm, post_llm | Beginner |
| 13 | [smolagents](smolagents.md) | HuggingFace code agents | pre_llm, post_llm, pre_tool, post_tool | Beginner |
| 14 | [Phidata / Agno](phidata.md) | Phidata agent platform | pre_llm, post_llm | Beginner |
| 15 | [Generic (Custom)](generic.md) | Any framework or custom agent | manual | Beginner |

---

## Two Ways to Integrate

### Option A: Auto-Secure (Recommended)

One line of code. The SDK auto-detects which frameworks are installed and patches them:

```python
from enkrypt_agent_sdk import auto_secure

results = auto_secure(
    enkrypt_api_key="ek-your-key-here",
    guardrail_policy="My Safety Policy",
    block=["injection_attack", "pii", "toxicity"],
)
print(results)  # {"langchain": True, "anthropic": True, ...}

# Your existing code works unchanged - now with security!
```

### Option B: Manual Integration (Full Control)

Create the guard engine and install patches yourself:

```python
from enkrypt_agent_sdk import GuardEngine, AgentObserver
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter
from enkrypt_agent_sdk._patch import langchain as lc_patch  # or any framework

# 1. Set up guardrails
registry = GuardrailRegistry()
registry.register(KeywordGuardrailProvider())

guard = GuardEngine(registry, input_policy={
    "enabled": True,
    "policy_name": "safety",
    "block": ["keyword_detector"],
    "blocked_keywords": ["hack*", "exploit*"],
})

# 2. Set up observer
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())

# 3. Install the patch
lc_patch.install(observer, guard)

# 4. Use your framework normally -- checkpoints are enforced
```

### Option C: No API Key (Offline Keyword Blocking)

You can use the SDK without an Enkrypt API key for basic keyword blocking:

```python
from enkrypt_agent_sdk import auto_secure

auto_secure(
    guardrail_policy="offline",
    block=["keyword_detector"],
)
```

This uses the local `KeywordGuardrailProvider` to block inputs matching wildcard patterns.

---

## What Happens When You Call `auto_secure()`

1. **Telemetry is initialized** -- OpenTelemetry tracer and meter are created
2. **Guardrails are configured** -- Connection to Enkrypt AI API (or local keyword engine)
3. **Checkpoint configuration is applied** -- Which pipeline stages enforce guardrails
4. **Frameworks are detected** -- SDK checks which packages are installed
5. **Monkey-patches are applied** -- Each framework's key methods are wrapped with checkpoint enforcement
6. **A dict is returned** -- Shows which frameworks were patched: `{"langchain": True, "anthropic": True, ...}`

After this, every call through the patched frameworks automatically:
- Checks user input at the **pre_llm** checkpoint (blocks dangerous prompts)
- Checks tool input at the **pre_tool** checkpoint (blocks dangerous tool calls)
- Optionally checks outputs at **post_llm** and **post_tool** checkpoints
- Emits OpenTelemetry spans for observability
- Raises `GuardrailBlockedError` when a check fails
