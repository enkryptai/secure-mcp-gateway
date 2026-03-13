# Streaming Guardrails Guide

Streaming guardrails check LLM responses in real time, chunk by chunk, while they stream to your client. They work **standalone** — no MCP Gateway, no IDE hooks, no agent framework required.

Use streaming guardrails when you call LLM APIs directly (OpenAI, Anthropic, etc.) and stream responses to end users over WebSockets, SSE, or similar.

---

## Prerequisites

Complete all four steps before using streaming guardrails.

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

# Install the package
pip install enkryptai-agent-security
```

Verify the installation:

```bash
python -c "from enkryptai_agent_security.guardrails.streaming import StreamGuard; print('OK')"
```

### 3. Create an Enkrypt AI account

Go to <https://app.enkryptai.com> and sign up for a free account.

### 4. Get your API key and create a guardrail policy

1. In the Enkrypt AI dashboard, go to **Settings → API Keys** and copy your API key (starts with `ek-` or similar).
2. Go to **Guardrails → Policies** and create a new policy (e.g. "My Streaming Policy"). Enable the detectors you want: injection attack, toxicity, NSFW, PII, etc.
3. Note the exact policy name — you will pass it to `StreamGuard`.

---

## Quick Start

```bash
export ENKRYPT_API_KEY="ek-your-api-key"
export ENKRYPT_GUARDRAIL_NAME="My Streaming Policy"
```

```python
from enkryptai_agent_security.guardrails.streaming import StreamGuard, StreamViolationError

guard = StreamGuard(
    original_input=user_prompt,
    block=["injection_attack", "toxicity"],
)

try:
    async for chunk in guard.shield(your_llm_stream()):
        await send_to_client(chunk)
except StreamViolationError as e:
    await send_block_notice(e.violation)
```

That's it. The `api_key` and `guardrail_policy` are read from environment variables automatically.

---

## Configuration

### Constructor arguments (primary)

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `original_input` | `str` | *(required)* | The user's original prompt. Sent to the guardrail API for context-aware checks (relevancy, adherence). |
| `client` | `EnkryptGuardrailClient` | `None` | Pre-configured client instance. If provided, all `api_key`/`guardrail_policy`/`base_url`/`block` kwargs are ignored. |
| `api_key` | `str` | `""` | Enkrypt API key. Falls back to `ENKRYPT_API_KEY` env var if empty. |
| `guardrail_policy` | `str` | `""` | Guardrail policy name (must match your Enkrypt dashboard). Falls back to `ENKRYPT_GUARDRAIL_NAME` env var if empty. |
| `block` | `list[str]` | `None` | Detector names that should BLOCK the stream. Others trigger WARN (log only). |
| `base_url` | `str` | `"https://api.enkryptai.com"` | Enkrypt API base URL. |
| `check_interval` | `int` | `100` | Run a guardrail check every N characters of new text. |
| `window_size` | `int` | `500` | Maximum characters sent per check (sliding window from the tail of accumulated text). |
| `sentence_boundary` | `bool` | `True` | Align check windows to sentence boundaries (`.` `!` `?` followed by whitespace). |
| `fail_open` | `bool` | `True` | If `True`, API errors are logged and the stream continues. If `False`, API errors raise. |
| `timeout` | `float` | `15.0` | Timeout (seconds) for each guardrail API call. |
| `post_stream_check` | `bool` | `True` | Run a final full-text check after the stream ends. Catches detectors that need complete context (bias, topic drift, hallucination). |

### Environment variables (fallback)

| Variable | Maps to | Default |
| --- | --- | --- |
| `ENKRYPT_API_KEY` | `api_key` | `""` |
| `ENKRYPT_GUARDRAIL_NAME` | `guardrail_policy` | `""` |

Constructor arguments always take precedence over environment variables. Env vars are only read when the corresponding constructor argument is empty.

### Block list — detector names

Pass canonical detector names to the `block` parameter:

| Detector | What it catches |
| --- | --- |
| `injection_attack` | Prompt injection, jailbreak attempts |
| `toxicity` | Toxic, hateful, or threatening content |
| `nsfw` | Sexually explicit content |
| `pii` | Personal identifiable information |
| `policy_violation` | Custom policy rule violations |
| `bias` | Biased content |
| `keyword_detector` | Custom keyword blocklist matches |
| `topic_detector` | Off-topic responses |
| `sponge_attack` | Resource exhaustion attacks |

Detectors **not** in the block list still run but only trigger a WARN (logged, stream continues).

---

## Usage Patterns

### Pattern 1: Async shield (recommended)

Wraps any `AsyncIterable[str]` and yields chunks while running guardrail checks in the background.

**Anthropic SDK:**

```python
from anthropic import AsyncAnthropic
from enkryptai_agent_security.guardrails.streaming import StreamGuard, StreamViolationError

client = AsyncAnthropic(api_key="sk-ant-...")
prompt = "Explain quantum computing in simple terms."

guard = StreamGuard(
    original_input=prompt,
    api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack", "toxicity"],
)

async with client.messages.stream(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": prompt}],
) as stream:

    async def text_chunks():
        async for text in stream.text_stream:
            yield text

    try:
        async for chunk in guard.shield(text_chunks()):
            await websocket.send(chunk)
    except StreamViolationError as e:
        await websocket.send(f"[BLOCKED] {e.violation.result.violations}")
```

**OpenAI SDK:**

```python
from openai import AsyncOpenAI
from enkryptai_agent_security.guardrails.streaming import StreamGuard, StreamViolationError

client = AsyncOpenAI(api_key="sk-...")
prompt = "Write a summary of today's news."

guard = StreamGuard(
    original_input=prompt,
    api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack", "toxicity", "pii"],
)

stream = await client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    stream=True,
)

async def text_chunks():
    async for chunk in stream:
        if chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content

try:
    async for text in guard.shield(text_chunks()):
        await response.write(text)
except StreamViolationError as e:
    await response.write(f"[BLOCKED] Content policy violation")
```

### Pattern 2: Context manager + manual feed (flexible)

For cases where you need explicit control over the feed/check/finish lifecycle.

```python
guard = StreamGuard(
    original_input=prompt,
    api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack"],
)

async with guard:
    async for chunk in llm_stream:
        guard.feed(chunk)
        if guard.violation is not None:
            print(f"BLOCKED: {guard.violation}")
            break
        await client.send(chunk)

    result = await guard.finish()
    if not result.is_safe:
        print(f"Post-stream violation: {result}")
```

### Pattern 3: Sync shield

For synchronous code (Flask, Django, CLI tools).

```python
from anthropic import Anthropic
from enkryptai_agent_security.guardrails.streaming import StreamGuard, StreamViolationError

client = Anthropic(api_key="sk-ant-...")
prompt = "List the planets."

guard = StreamGuard(
    original_input=prompt,
    api_key="ek-...",
    guardrail_policy="My Policy",
    block=["injection_attack"],
)

with client.messages.stream(
    model="claude-sonnet-4-6",
    max_tokens=256,
    messages=[{"role": "user", "content": prompt}],
) as stream:

    def text_chunks():
        for text in stream.text_stream:
            yield text

    try:
        for chunk in guard.shield_sync(text_chunks()):
            print(chunk, end="", flush=True)
    except StreamViolationError as e:
        print(f"\n[BLOCKED] {e}")
```

---

## How It Works

### Sliding window algorithm

```
Stream:  [chunk1][chunk2][chunk3][chunk4][chunk5][chunk6]...
                    ↑ check_interval reached
                    └─ Extract window (last window_size chars)
                       Schedule background check
                       Continue yielding chunks immediately
```

1. **Chunks arrive** from the LLM stream and are immediately forwarded to the client.
2. **Character counter** tracks how many characters have arrived since the last check.
3. When the counter exceeds `check_interval`, a **background `asyncio.Task`** is scheduled with the current sliding window (last `window_size` characters).
4. Only **one check runs at a time** — if a previous check is still in progress, the new check is skipped (the post-stream accumulator will catch it).
5. When a check completes, the result is inspected for violations.

### Three verdicts

| Verdict | Action | Stream behavior |
| --- | --- | --- |
| **PASS** | `GuardrailAction.ALLOW` | Continue streaming normally |
| **FLAG** | `GuardrailAction.WARN` | Continue streaming, log the warning |
| **BLOCK** | `GuardrailAction.BLOCK` | Stop streaming, raise `StreamViolationError` |

A detector triggers BLOCK only if it appears in the `block` list. All other detectors trigger FLAG/WARN.

### Post-stream accumulator

After the LLM stream ends, `finish()` runs one final check on the **complete accumulated text**. This catches detectors that need full context:

- Bias detection
- Topic drift / coherence
- Relevancy (is the response relevant to the input?)
- Adherence (does the response follow instructions?)
- Hallucination detection

The post-stream check can be disabled with `post_stream_check=False`.

---

## Handling Violations

### StreamViolationError

Raised when a BLOCK-listed detector fires during streaming.

```python
try:
    async for chunk in guard.shield(stream):
        await send(chunk)
except StreamViolationError as e:
    v = e.violation
    print(f"Blocked by: {[d.detector for d in v.result.violations]}")
    print(f"Characters already sent: {v.chars_sent}")
    print(f"Chunk index at detection: {v.chunk_index}")
    print(f"Text that triggered: {v.text_checked[:100]}")
```

### Client-side clearing

`e.violation.chars_sent` tells you how many characters were already forwarded to the client before the block. Use this to clear or redact content on the client side:

```python
except StreamViolationError as e:
    # Tell the client to discard the last e.violation.chars_sent characters
    await websocket.send(json.dumps({
        "type": "content_clear",
        "chars_to_remove": e.violation.chars_sent,
        "reason": "Content policy violation detected",
    }))
```

### Checking for violations after stream ends

```python
# After shield() completes without error, check post-stream result:
if guard.violation is not None:
    print(f"Post-stream violation: {guard.violation}")
```

---

## Properties and Inspection

After streaming, you can inspect the guard state:

```python
guard.accumulated_text   # Full text accumulated during streaming
guard.chunk_count        # Number of chunks processed
guard.chars_sent         # Total characters forwarded to client
guard.violation          # StreamViolation if detected, else None
```

---

## Troubleshooting

### "Policy not found" or empty results

The `guardrail_policy` (or `ENKRYPT_GUARDRAIL_NAME` env var) must exactly match the policy name in your Enkrypt AI dashboard. Check for trailing spaces or case mismatches.

### API key not working

Verify your API key is valid:

```python
from enkryptai_agent_security.guardrails.client import EnkryptGuardrailClient

client = EnkryptGuardrailClient(
    api_key="ek-...",
    base_url="https://api.enkryptai.com",
    guardrail_name="My Policy",
    block=["injection_attack"],
)

import asyncio
result = asyncio.run(client.acheck_output("Hello world", "test"))
print(result)  # Should print GuardrailResult with action=ALLOW
```

### `aiohttp` not installed

The guardrail client uses `aiohttp` for async HTTP. If you get an import error:

```bash
pip install aiohttp
```

### `fail_open` behavior

By default, `fail_open=True`: if the Enkrypt API is unreachable or returns an error, the stream continues and the error is logged. Set `fail_open=False` to raise on API errors (stricter but may interrupt streams during API outages).

### Stream hangs or is slow

- **High `check_interval`** means fewer API calls but delayed detection. Start with `100` (default) and adjust.
- **Large `window_size`** sends more text per check, increasing API latency. Start with `500` (default).
- **Network latency** to the Enkrypt API affects background check speed. The stream itself is never blocked — checks run in the background.

### Env vars not being picked up

Environment variables are read at `StreamGuard` construction time. If you set them after creating the guard, they won't take effect. Also, constructor arguments always override env vars:

```python
# This uses the constructor arg, NOT the env var:
guard = StreamGuard(
    original_input=prompt,
    api_key="ek-explicit-key",  # This wins over ENKRYPT_API_KEY
)
```
