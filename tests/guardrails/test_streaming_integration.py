"""Integration tests: StreamGuard with real Anthropic Claude Sonnet 4.6 streaming.

Uses mock guardrail clients (no Enkrypt API key needed) to test the full
streaming pipeline with a real LLM.

Requires:
    ANTHROPIC_API_KEY env var set to run.

Run:
    pytest tests/guardrails/test_streaming_integration.py -v
"""

from __future__ import annotations

import os
import time

import pytest

from enkryptai_agent_security.guardrails.streaming import (
    StreamGuard,
    StreamViolationError,
)
from enkryptai_agent_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)

_ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

try:
    import anthropic as _anthropic  # noqa: F401
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

pytestmark = [
    pytest.mark.skipif(
        not (_ANTHROPIC_KEY and _HAS_ANTHROPIC),
        reason="ANTHROPIC_API_KEY not set or anthropic package not installed",
    ),
    pytest.mark.integration,
]

MODEL = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Mock guardrail clients (no Enkrypt key needed)
# ---------------------------------------------------------------------------

class _PassthroughClient:
    """Always returns ALLOW."""

    def __init__(self):
        self.call_count = 0
        self.checked_texts: list[str] = []

    async def acheck_output(
        self, text: str, original_input: str = "", *, source_event: str = "post-tool"
    ) -> GuardrailResult:
        self.call_count += 1
        self.checked_texts.append(text)
        return GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True)

    async def aredact_pii(self, text: str) -> tuple[str, dict]:
        return text, {}


class _BlockAfterNClient:
    """Returns BLOCK after N calls."""

    def __init__(self, block_after: int = 2):
        self.call_count = 0
        self._block_after = block_after

    async def acheck_output(
        self, text: str, original_input: str = "", *, source_event: str = "post-tool"
    ) -> GuardrailResult:
        self.call_count += 1
        if self.call_count >= self._block_after:
            return GuardrailResult(
                action=GuardrailAction.BLOCK,
                is_safe=False,
                violations=(
                    GuardrailViolation(
                        detector="toxicity",
                        violation_type=ViolationType.TOXICITY,
                        action=GuardrailAction.BLOCK,
                        severity=0.95,
                        message="Simulated block for testing",
                    ),
                ),
            )
        return GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True)

    async def aredact_pii(self, text: str) -> tuple[str, dict]:
        return text, {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def anthropic_async():
    from anthropic import AsyncAnthropic
    return AsyncAnthropic(api_key=_ANTHROPIC_KEY)


@pytest.fixture
def anthropic_sync():
    from anthropic import Anthropic
    return Anthropic(api_key=_ANTHROPIC_KEY)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_streaming_clean(anthropic_async):
    """Real Claude stream through StreamGuard with passthrough guardrail."""
    mock_gr = _PassthroughClient()
    prompt = "What are the three primary colors? Answer in one short sentence."

    guard = StreamGuard(
        original_input=prompt,
        client=mock_gr,
        check_interval=50,
        window_size=200,
    )

    collected: list[str] = []

    async with anthropic_async.messages.stream(
        model=MODEL,
        max_tokens=128,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:

        async def text_chunks():
            async for text in stream.text_stream:
                yield text

        async for chunk in guard.shield(text_chunks()):
            collected.append(chunk)

    assert len(collected) > 0, "Expected at least one chunk"
    assert guard.violation is None, "Expected no violation"
    assert mock_gr.call_count >= 1, "Expected at least 1 guardrail check"


@pytest.mark.asyncio
async def test_async_streaming_block(anthropic_async):
    """Real Claude stream, guardrail blocks after 2nd check."""
    mock_gr = _BlockAfterNClient(block_after=2)
    prompt = "Write a paragraph about the history of the internet."

    guard = StreamGuard(
        original_input=prompt,
        client=mock_gr,
        check_interval=30,
        window_size=100,
    )

    collected: list[str] = []

    async with anthropic_async.messages.stream(
        model=MODEL,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:

        async def text_chunks():
            async for text in stream.text_stream:
                yield text

        with pytest.raises(StreamViolationError) as exc_info:
            async for chunk in guard.shield(text_chunks()):
                collected.append(chunk)

    assert len(collected) > 0, "Expected some chunks before block"
    assert guard.violation is not None, "Expected violation recorded"
    assert exc_info.value.violation.result.violations[0].detector == "toxicity"


def test_sync_streaming_clean(anthropic_sync):
    """Real Claude sync stream through shield_sync with passthrough guardrail."""
    mock_gr = _PassthroughClient()
    prompt = "Name three planets in our solar system. One sentence."

    guard = StreamGuard(
        original_input=prompt,
        client=mock_gr,
        check_interval=50,
        window_size=200,
    )

    collected: list[str] = []

    with anthropic_sync.messages.stream(
        model=MODEL,
        max_tokens=128,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:

        def text_chunks():
            for text in stream.text_stream:
                yield text

        for chunk in guard.shield_sync(text_chunks()):
            collected.append(chunk)

    assert len(collected) > 0, "Expected at least one chunk"
    assert guard.violation is None, "Expected no violation"


@pytest.mark.asyncio
async def test_context_manager_feed(anthropic_async):
    """Real Claude stream using manual feed() + finish() pattern."""
    mock_gr = _PassthroughClient()
    prompt = "What is 2 + 2? Answer with just the number."

    guard = StreamGuard(
        original_input=prompt,
        client=mock_gr,
        check_interval=20,
        window_size=100,
    )

    collected: list[str] = []

    async with guard:
        async with anthropic_async.messages.stream(
            model=MODEL,
            max_tokens=64,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            async for text in stream.text_stream:
                guard.feed(text)
                collected.append(text)

                if guard.violation is not None:
                    break

        result = await guard.finish()

    assert result.is_safe, "Expected safe result"
    assert result.action == GuardrailAction.ALLOW
    assert len(collected) > 0


@pytest.mark.asyncio
async def test_window_text_correctness(anthropic_async):
    """Verify the text sent to guardrail checks matches accumulated stream."""
    mock_gr = _PassthroughClient()
    prompt = "Write a two-sentence fact about dogs."

    guard = StreamGuard(
        original_input=prompt,
        client=mock_gr,
        check_interval=30,
        window_size=100,
    )

    collected: list[str] = []

    async with anthropic_async.messages.stream(
        model=MODEL,
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:

        async def text_chunks():
            async for text in stream.text_stream:
                yield text

        async for chunk in guard.shield(text_chunks()):
            collected.append(chunk)

    full_text = "".join(collected)

    # Every checked text must be a substring of the accumulated text
    for i, checked in enumerate(mock_gr.checked_texts):
        assert checked in full_text or full_text in checked, (
            f"Check {i} text not found in accumulated stream"
        )
        # Non-final checks should respect window_size
        if i < len(mock_gr.checked_texts) - 1:
            assert len(checked) <= 100, (
                f"Window check {i} exceeded window_size (got {len(checked)} chars)"
            )

    # The last check (post-stream accumulator) should be the full text
    if mock_gr.checked_texts:
        last_check = mock_gr.checked_texts[-1]
        assert last_check == full_text, (
            f"Post-stream accumulator should check full text "
            f"(got {len(last_check)} chars, expected {len(full_text)})"
        )
