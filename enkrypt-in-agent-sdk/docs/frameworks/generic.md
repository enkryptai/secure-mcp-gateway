# Generic Adapter Guide (Custom / Unsupported Frameworks)

## When to Use This

Use the **Generic Adapter** when:
- Your framework **isn't in our supported list** (LangChain, AutoGen, etc.)
- You're building a **custom agent** with no framework
- You need **manual guardrail enforcement** (auto-patch isn't available)
- You want **maximum control** over checkpoint enforcement
- You're **wrapping API calls** that don't fit into other adapters

The Generic Adapter provides **sync and async context managers** that let you manually instrument any code with full Enkrypt security. Unlike framework-specific adapters that auto-patch, you must manually call `guard.check_input()` and `guard.check_output()` at the appropriate checkpoints.

## Step 1: Install the SDK

```bash
cd enkrypt-in-agent-sdk
pip install -e .
```

## Step 2: Set Up the Components

```python
from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

# 1. Create a guardrail registry and register providers
registry = GuardrailRegistry()
registry.register(KeywordGuardrailProvider())

# 2. Create the guard engine with your policies
guard = GuardEngine(registry, input_policy={
    "enabled": True,
    "policy_name": "my-safety-policy",
    "block": ["keyword_detector"],
    "blocked_keywords": ["hack*", "exploit*", "rm -rf", "drop table", "steal*"],
})

# 3. Create the observer (for OTel traces)
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
```

## Step 3: Use Context Managers

The Generic Adapter has a hierarchical structure: **Run > Step > Tool Call / LLM Call**

### Sync Usage

```python
from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter

adapter = GenericAgentAdapter(observer, guard, agent_id="my-custom-agent")

# A "run" represents the entire agent execution
with adapter.run(task="Book a flight from SFO to JFK") as run_ctx:

    # A "step" is a logical phase of reasoning
    with run_ctx.step(reason="Search for available flights") as step_ctx:

        # A "tool_call" wraps an external action
        with step_ctx.tool_call("flight_search", input={"from": "SFO", "to": "JFK"}) as tc:
            # Your actual tool logic here
            results = search_flights("SFO", "JFK")
            tc.set_output(results)

        # An "llm_call" wraps an LLM interaction
        with step_ctx.llm_call(model="gpt-4") as llm:
            response = call_my_llm("Pick the best flight from these results...")
            llm.set_output(response, tokens={"prompt": 150, "completion": 45})

    # You can have multiple steps
    with run_ctx.step(reason="Confirm booking") as step_ctx:
        with step_ctx.tool_call("booking_api", input={"flight_id": "UA123"}) as tc:
            confirmation = book_flight("UA123")
            tc.set_output(confirmation)
```

### Async Usage

Same API, just add `a` prefix and use `async with`:

```python
async with adapter.arun(task="Book a flight") as run_ctx:
    async with run_ctx.astep(reason="Search flights") as step_ctx:
        async with step_ctx.atool_call("flight_search", input="SFO to JFK") as tc:
            results = await async_search_flights("SFO", "JFK")
            tc.set_output(results)
        async with step_ctx.allm_call(model="gpt-4") as llm:
            response = await async_call_llm("Pick the best flight...")
            llm.set_output(response)
```

## Manual Guardrail Enforcement

The Generic Adapter requires **manual guardrail checks** at checkpoints. You must call `guard.check_input()` and `guard.check_output()` explicitly.

### Pre-LLM Checkpoint (Before LLM Calls)

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

# Wrap any LLM call with pre_llm checkpoint
user_input = "What is the weather in Tokyo?"

# Pre-LLM checkpoint: check input before sending to LLM
try:
    input_result = await guard.check_input(user_input, policy=guard._input_policy)
    if input_result.blocked:
        raise GuardrailBlockedError(
            f"Input blocked at pre_llm checkpoint: {input_result.blocked_reasons}",
            blocked_reasons=input_result.blocked_reasons,
            checkpoint="pre_llm",
        )
except GuardrailBlockedError as e:
    print(f"Blocked! {e}")
    # Handle blocked input - return safe response, log, etc.
    return {"error": "Request blocked by security policy"}

# If input passes, proceed with LLM call
llm_response = await call_my_llm(user_input)

# Post-LLM checkpoint: check output after receiving response
output_result = await guard.check_output(user_input, llm_response, policy=guard._output_policy)
if output_result.blocked:
    print(f"Output blocked: {output_result.blocked_reasons}")
    # Handle blocked output - sanitize, log, or reject
    llm_response = "I cannot provide that information due to security policies."
```

### Pre-Tool / Post-Tool Checkpoints (For Tool Calls)

```python
# Wrap any tool call with pre_tool/post_tool checkpoints
tool_input = {"command": "search_flights", "destination": "Tokyo"}

# Pre-tool checkpoint: check input before calling tool
try:
    input_result = await guard.check_input(str(tool_input), policy=guard._input_policy)
    if input_result.blocked:
        raise GuardrailBlockedError(
            f"Input blocked at pre_tool checkpoint: {input_result.blocked_reasons}",
            blocked_reasons=input_result.blocked_reasons,
            checkpoint="pre_tool",
        )
except GuardrailBlockedError as e:
    print(f"Tool input blocked! {e}")
    return {"error": "Tool call blocked"}

# If input passes, execute tool
tool_result = await execute_tool(tool_input)

# Post-tool checkpoint: check output after tool execution
output_result = await guard.check_output(str(tool_input), str(tool_result), policy=guard._output_policy)
if output_result.blocked:
    print(f"Tool output blocked: {output_result.blocked_reasons}")
    # Handle blocked output
    tool_result = {"error": "Tool output blocked by security policy"}
```

### Using with Generic Adapter Context Managers

You can combine manual guardrail checks with the adapter's context managers:

```python
with adapter.run(task="Execute command") as run_ctx:
    with run_ctx.step(reason="Run user command") as step_ctx:
        tool_input = "hacking the server"
        
        # Manual pre-tool checkpoint
        try:
            input_result = await guard.check_input(tool_input, policy=guard._input_policy)
            if input_result.blocked:
                raise GuardrailBlockedError(
                    f"Input blocked: {input_result.blocked_reasons}",
                    blocked_reasons=input_result.blocked_reasons,
                    checkpoint="pre_tool",
                )
        except GuardrailBlockedError as e:
            print(f"Blocked! {e}")
            # GuardrailBlockedError: Input blocked at pre_tool checkpoint: ('keyword_detector',)
            return
        
        # If input passes, record tool call
        with step_ctx.tool_call("shell", input=tool_input) as tc:
            result = execute_shell(tool_input)
            
            # Manual post-tool checkpoint
            output_result = await guard.check_output(tool_input, result, policy=guard._output_policy)
            if output_result.blocked:
                result = "Command output blocked"
            
            tc.set_output(result)
```

## Complete Example: Manual Checkpoint Enforcement

Here's a complete example showing how to manually enforce guardrails at all checkpoints:

```python
"""Complete example with manual guardrail enforcement at all checkpoints."""

from enkrypt_agent_sdk.guardrails.base import GuardrailRegistry
from enkrypt_agent_sdk.guardrails.keyword_provider import KeywordGuardrailProvider
from enkrypt_agent_sdk.guard import GuardEngine
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter
from enkrypt_agent_sdk.adapters.generic import GenericAgentAdapter
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

# Setup
registry = GuardrailRegistry()
registry.register(KeywordGuardrailProvider())
guard = GuardEngine(
    registry,
    input_policy={
        "enabled": True,
        "policy_name": "safety",
        "block": ["keyword_detector"],
        "blocked_keywords": ["hack*", "steal*"],
    },
    output_policy={
        "enabled": True,
        "policy_name": "output-safety",
        "block": ["keyword_detector"],
        "blocked_keywords": ["password*", "credit card*"],
    },
)
observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = GenericAgentAdapter(observer, guard, agent_id="demo-agent")

async def process_user_request(user_input: str):
    """Example showing manual checkpoint enforcement."""
    
    # Pre-LLM checkpoint: check user input before LLM
    try:
        input_result = await guard.check_input(user_input, policy=guard._input_policy)
        if input_result.blocked:
            raise GuardrailBlockedError(
                f"Input blocked at pre_llm: {input_result.blocked_reasons}",
                blocked_reasons=input_result.blocked_reasons,
                checkpoint="pre_llm",
            )
    except GuardrailBlockedError as e:
        return {"error": f"Request blocked: {e.blocked_reasons}"}
    
    # LLM call
    with adapter.run(task="Process request") as run_ctx:
        with run_ctx.step(reason="Generate response") as step_ctx:
            with step_ctx.llm_call(model="gpt-4") as llm:
                llm_response = await call_llm(user_input)
                
                # Post-LLM checkpoint: check LLM output
                output_result = await guard.check_output(
                    user_input, llm_response, policy=guard._output_policy
                )
                if output_result.blocked:
                    llm_response = "I cannot provide that information."
                
                llm.set_output(llm_response, tokens={"prompt": 50, "completion": 10})
                return llm_response
```

## GuardrailBlockedError Handling

Always wrap guardrail checks with proper error handling:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

async def safe_llm_call(user_input: str):
    """Example with proper GuardrailBlockedError handling."""
    try:
        # Pre-LLM checkpoint
        input_result = await guard.check_input(user_input, policy=guard._input_policy)
        if input_result.blocked:
            raise GuardrailBlockedError(
                f"Input blocked: {input_result.blocked_reasons}",
                blocked_reasons=input_result.blocked_reasons,
                checkpoint="pre_llm",
            )
    except GuardrailBlockedError as e:
        # Log the blocked request
        print(f"Request blocked at {e.checkpoint}: {e.blocked_reasons}")
        # Return safe fallback response
        return {
            "error": "Your request was blocked by security policies",
            "blocked_reasons": e.blocked_reasons,
        }
    
    # Proceed with LLM call
    response = await call_llm(user_input)
    
    # Post-LLM checkpoint
    output_result = await guard.check_output(user_input, response, policy=guard._output_policy)
    if output_result.blocked:
        print(f"Output blocked: {output_result.blocked_reasons}")
        response = "I cannot provide that information."
    
    return response
```

## Event Hierarchy with Checkpoints

When using manual guardrail enforcement, events are emitted at checkpoints:

```text
agent.lifecycle.start           (run begins)
  agent.step.start              (step begins)
    agent.guardrail.check       (pre_llm checkpoint - input checked, safe)
    agent.llm.call.start        (LLM begins)
    agent.llm.call.end          (LLM ends)
    agent.guardrail.check       (post_llm checkpoint - output checked, safe)
    agent.tool.call.start       (tool begins)
    agent.guardrail.check       (pre_tool checkpoint - input checked, safe)
    agent.tool.call.end         (tool ends)
    agent.guardrail.check       (post_tool checkpoint - output checked, safe)
  agent.step.end                (step ends)
agent.lifecycle.end             (run ends)
```

If input is blocked at pre_llm checkpoint:
```text
agent.lifecycle.start
  agent.step.start
    agent.guardrail.block       (pre_llm checkpoint - input blocked!)
    GuardrailBlockedError raised
  agent.step.end (ok=False)
agent.lifecycle.end (ok=False)
```

## When to Use Generic vs. Framework-Specific

| Scenario | Use |
|---|---|
| Using LangChain | LangChain adapter (automatic) |
| Using multiple frameworks | `auto_secure()` (patches all) |
| Custom agent with no framework | **Generic adapter** |
| Wrapping raw API calls | **Generic adapter** |
| Need per-tool guardrail control | **Generic adapter** |
| Framework not in supported list | **Generic adapter** |

## Troubleshooting

**Q: My sync context manager hangs?**
If you're inside an async event loop (like Jupyter), the sync `_run_coro` helper might deadlock. Use the async versions (`arun`, `astep`, `atool_call`, `allm_call`) instead.

**Q: Can I nest runs?**
Yes, but each `run` creates a new run_id. If you want nested operations within one run, use `step` inside `run`.

**Q: How do I add custom attributes to events?**
Pass keyword arguments: `step.tool_call("search", input="q", custom_field="value")`. They'll appear in the event's `attributes` dict.

**Q: Do I need to call guard.check_input() and guard.check_output() manually?**
Yes! Unlike framework-specific adapters that auto-patch, the Generic Adapter requires manual checkpoint enforcement. You must call `guard.check_input()` before LLM/tool calls and `guard.check_output()` after receiving responses.

**Q: What checkpoints should I enforce?**
- **pre_llm**: Before sending user input to an LLM
- **post_llm**: After receiving LLM response
- **pre_tool**: Before calling a tool/function
- **post_tool**: After receiving tool output

**Q: Can I use auto_secure() with Generic Adapter?**
`auto_secure()` is for frameworks that support auto-patching. For unsupported frameworks, use the Generic Adapter with manual guardrail enforcement.
