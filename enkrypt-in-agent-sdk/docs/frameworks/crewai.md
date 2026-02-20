# CrewAI Integration Guide

## What is CrewAI?

CrewAI is a framework for building **multi-agent systems** where multiple AI agents work together as a "crew." Each agent has a role (like "Researcher" or "Writer"), and they collaborate on tasks. Think of it like building a team of AI specialists.

Key concepts:
- **Agent** - An AI with a specific role, goal, and backstory
- **Task** - A specific job for an agent to do
- **Crew** - A team of agents working together
- **`kickoff()`** - Starts the crew working

## What the Enkrypt SDK Does for CrewAI

1. **Patches `Crew.kickoff()`** - Intercepts crew execution with **pre_llm** and **post_llm** checkpoints for guardrail enforcement
2. **Patches `BaseTool._run()`** - Intercepts individual tool calls with **pre_tool** and **post_tool** checkpoints
3. **Provides `CrewAIAdapter`** - For fine-grained tracking of individual tasks and tool calls
4. **Wraps async too** - `kickoff_async()` is also patched with checkpoint enforcement

## Step 1: Install Dependencies

```bash
cd enkrypt-in-agent-sdk
pip install -e .
pip install crewai
```

## Step 2: Add Enkrypt Security

```python
from enkrypt_agent_sdk import auto_secure

auto_secure(
    enkrypt_api_key="ek-your-key-here",
    guardrail_policy="My Safety Policy",
    block=["injection_attack", "pii", "toxicity"],
)
```

## Step 3: Use CrewAI Normally

```python
from crewai import Agent, Task, Crew

# Define agents
researcher = Agent(
    role="Researcher",
    goal="Find the latest AI news",
    backstory="You are an expert AI researcher.",
)

writer = Agent(
    role="Writer",
    goal="Write a summary of findings",
    backstory="You are a skilled technical writer.",
)

# Define tasks
research_task = Task(
    description="Research the latest developments in AI agents",
    expected_output="A list of key findings",
    agent=researcher,
)

write_task = Task(
    description="Write a blog post based on the research",
    expected_output="A well-written blog post",
    agent=writer,
)

# Create and run the crew
crew = Crew(agents=[researcher, writer], tasks=[research_task, write_task])
result = crew.kickoff()  # Automatically protected by Enkrypt SDK checkpoints!

# Task descriptions are checked at pre_llm checkpoint before crew execution
# Individual tool calls are checked at pre_tool checkpoint before execution
```

## Manual Adapter for Detailed Tracking

For more granular control, use the `CrewAIAdapter` directly:

```python
from enkrypt_agent_sdk.adapters.crewai import CrewAIAdapter
from enkrypt_agent_sdk.observer import AgentObserver
from enkrypt_agent_sdk.otel_setup import _NoOpTracer, _NoOpMeter

observer = AgentObserver(_NoOpTracer(), _NoOpMeter())
adapter = CrewAIAdapter(observer, agent_id="research-crew")

# Wrap the entire crew execution
with adapter.observe_crew(crew_name="Research Crew") as ctx:
    # Track individual tasks
    step_id = adapter.on_task_start("Research AI news", ctx.run_id)

    # Track tool usage within tasks
    tc_id = adapter.on_tool_use("web_search", ctx.run_id, input_data="AI agents 2025")
    # ... tool executes ...
    adapter.on_tool_result(ctx.run_id, tc_id, "web_search", result="Found 5 articles")

    # Mark task as done
    adapter.on_task_end(ctx.run_id, step_id, output="Research complete")

    # Set the final result
    ctx.set_result("Blog post about AI agents written successfully")
```

## Events Emitted

| What Happens | Enkrypt Event | Details |
|---|---|---|
| `crew.kickoff()` starts | `agent.lifecycle.start` | Crew name captured |
| Task description checked | `pre_llm` checkpoint | Guardrail enforcement |
| LLM response checked | `post_llm` checkpoint | Guardrail enforcement |
| Tool call checked | `pre_tool` checkpoint | Guardrail enforcement |
| Tool result checked | `post_tool` checkpoint | Guardrail enforcement |
| Task begins | `agent.step.start` | Via manual adapter |
| Tool is used | `agent.tool.call.start/end` | Via manual adapter |
| Task completes | `agent.step.end` | Via manual adapter |
| `crew.kickoff()` ends | `agent.lifecycle.end` | Success/failure |

## Guardrail Checkpoints

The Enkrypt SDK enforces guardrails at **4 checkpoints**:

1. **pre_llm** - Task descriptions are checked before crew execution begins
2. **post_llm** - LLM responses are checked after generation
3. **pre_tool** - Individual tool calls are checked before execution
4. **post_tool** - Tool results are checked after execution

All checkpoints are automatically enforced when using `auto_secure()`. If a guardrail violation is detected, a `GuardrailBlockedError` is raised.

## Error Handling

If the crew fails, the SDK captures the error:

```python
try:
    with adapter.observe_crew(crew_name="Failing Crew") as ctx:
        raise RuntimeError("Something went wrong")
except RuntimeError:
    pass  # The SDK recorded ok=False and the error message
```

### GuardrailBlockedError Handling

When guardrails block execution, catch `GuardrailBlockedError`:

```python
from enkrypt_agent_sdk.exceptions import GuardrailBlockedError

try:
    crew = Crew(agents=[researcher], tasks=[research_task])
    result = crew.kickoff()
except GuardrailBlockedError as e:
    print(f"Guardrail violation: {e.violation_type}")
    print(f"Blocked at checkpoint: {e.checkpoint}")
    print(f"Reason: {e.message}")
    # Handle blocked execution appropriately
```

## Troubleshooting

**Q: I get `PermissionError` when importing crewai?**
CrewAI tries to create directories on import. Run outside a restricted sandbox or ensure write permissions to `~/.local/share/crewai/`.

**Q: My crew uses custom tools. Are they tracked?**
The auto-patch tracks the overall `kickoff()` call. For individual tool tracking within tasks, use the manual `CrewAIAdapter` with `on_tool_use()` and `on_tool_result()`.
