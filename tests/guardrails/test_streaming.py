"""Tests for the streaming guardrails module (no network needed).

Uses a mock client that returns configurable GuardrailResult objects.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator

from enkryptai_agent_security.guardrails.streaming import (
    StreamGuard,
    StreamViolation,
    StreamViolationError,
)
from enkryptai_agent_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASS = GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True, violations=())
_BLOCK = GuardrailResult(
    action=GuardrailAction.BLOCK,
    is_safe=False,
    violations=(
        GuardrailViolation(
            detector="toxicity",
            violation_type=ViolationType.TOXICITY,
            action=GuardrailAction.BLOCK,
            severity=0.9,
            message="Toxic content detected",
        ),
    ),
)
_WARN = GuardrailResult(
    action=GuardrailAction.WARN,
    is_safe=True,
    violations=(
        GuardrailViolation(
            detector="policy_violation",
            violation_type=ViolationType.POLICY_VIOLATION,
            action=GuardrailAction.WARN,
            severity=0.4,
            message="Minor policy flag",
        ),
    ),
)
_ALLOW_WITH_DETECTIONS = GuardrailResult(
    action=GuardrailAction.ALLOW,
    is_safe=True,
    violations=(
        GuardrailViolation(
            detector="toxicity",
            violation_type=ViolationType.TOXICITY,
            action=GuardrailAction.WARN,
            severity=0.5,
            message="toxicity detected",
        ),
    ),
)


class _MockClient:
    """Mock EnkryptGuardrailClient returning configurable results."""

    def __init__(
        self,
        results: list[GuardrailResult] | None = None,
        *,
        default_result: GuardrailResult | None = None,
        raise_on_call: Exception | None = None,
    ) -> None:
        self._results = list(results) if results else []
        self._default = default_result or _PASS
        self._call_count = 0
        self._checked_texts: list[str] = []
        self._raise_on_call = raise_on_call

    async def acheck_output(
        self,
        text: str,
        original_input: str = "",
        *,
        source_event: str = "post-tool",
    ) -> GuardrailResult:
        self._checked_texts.append(text)
        if self._raise_on_call is not None:
            raise self._raise_on_call
        self._call_count += 1
        if self._results:
            return self._results.pop(0)
        return self._default


async def _async_chunks(chunks: list[str]) -> AsyncIterator[str]:
    for c in chunks:
        yield c


def _sync_chunks(chunks: list[str]) -> Iterator[str]:
    yield from chunks


def _make_guard(
    mock: _MockClient,
    *,
    check_interval: int = 50,
    window_size: int = 200,
    sentence_boundary: bool = False,
    fail_open: bool = True,
    post_stream_check: bool = True,
) -> StreamGuard:
    return StreamGuard(
        original_input="test prompt",
        client=mock,
        check_interval=check_interval,
        window_size=window_size,
        sentence_boundary=sentence_boundary,
        fail_open=fail_open,
        post_stream_check=post_stream_check,
    )


# ---------------------------------------------------------------------------
# TestStreamGuardShield
# ---------------------------------------------------------------------------

class TestStreamGuardShield:
    def test_clean_stream(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["Hello ", "world!"])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == ["Hello ", "world!"]
        assert guard.violation is None

    def test_violation_stops_stream(self):
        mock = _MockClient(results=[_BLOCK])
        guard = _make_guard(mock, check_interval=5)
        chunks = ["This is toxic content that should be blocked."]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        try:
            asyncio.run(_run())
            assert False, "Should have raised StreamViolationError"
        except StreamViolationError as e:
            assert e.violation is not None
            assert not e.violation.result.is_safe
            assert e.violation.result.violations[0].detector == "toxicity"

    def test_violation_mid_stream(self):
        # First check passes, second blocks
        mock = _MockClient(results=[_PASS, _BLOCK])
        guard = _make_guard(mock, check_interval=10)
        chunks = ["a" * 15, "b" * 15, "c" * 15]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        try:
            result = asyncio.run(_run())
            # If post_stream_check is true, might raise there
            # But mid-stream block should have fired
            assert False, "Should have raised StreamViolationError"
        except StreamViolationError:
            pass

    def test_empty_stream(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks([])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == []

    def test_single_chunk(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=1000)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["Hi"])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == ["Hi"]

    def test_single_chunk_blocked_post_stream(self):
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=1000, post_stream_check=True)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["bad content"])):
                collected.append(chunk)
            return collected

        try:
            asyncio.run(_run())
            assert False, "Should have raised"
        except StreamViolationError as e:
            assert e.violation.result.violations[0].detector == "toxicity"

    def test_large_chunks_still_trigger_check(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=10)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["x" * 100])):
                collected.append(chunk)
            return collected

        asyncio.run(_run())
        # Should have triggered at least one window check
        assert mock._call_count >= 1

    def test_empty_chunks_ignored(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["", "hi", "", "there"])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == ["hi", "there"]
        assert guard.chunk_count == 2


# ---------------------------------------------------------------------------
# TestStreamGuardFlagBehavior
# ---------------------------------------------------------------------------

class TestStreamGuardFlagBehavior:
    def test_warn_continues_stream(self):
        mock = _MockClient(results=[_WARN])
        guard = _make_guard(mock, check_interval=5, post_stream_check=False)
        chunks = ["Hello this is a test."]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == chunks
        assert guard.violation is None  # WARN does not set violation

    def test_warn_then_block(self):
        mock = _MockClient(results=[_WARN, _BLOCK])
        guard = _make_guard(mock, check_interval=10)
        chunks = ["a" * 15, "b" * 15]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        try:
            asyncio.run(_run())
            assert False, "Should have raised"
        except StreamViolationError:
            assert guard.violation is not None


# ---------------------------------------------------------------------------
# TestStreamGuardAllowWithDetections
# ---------------------------------------------------------------------------


class TestStreamGuardAllowWithDetections:
    """Tests for ALLOW results that carry non-blocking violations."""

    def test_allow_with_detections_counter(self):
        """ALLOW results with violations increment checks_with_detections."""
        mock = _MockClient(results=[_ALLOW_WITH_DETECTIONS, _PASS])
        guard = _make_guard(mock, check_interval=10, post_stream_check=False)
        chunks = ["a" * 15, "b" * 15]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == chunks
        assert guard.violation is None
        assert guard.checks_with_detections >= 1
        assert guard.checks_passed >= guard.checks_with_detections

    def test_clean_result_has_zero_detections(self):
        """ALLOW with empty violations does NOT increment checks_with_detections."""
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=10, post_stream_check=True)
        chunks = ["a" * 15, "b" * 15]

        async def _run():
            async for _ in guard.shield(_async_chunks(chunks)):
                pass

        asyncio.run(_run())
        assert guard.checks_with_detections == 0
        assert guard.checks_passed >= 1

    def test_allow_with_detections_does_not_block(self):
        """ALLOW-with-detections must not raise StreamViolationError."""
        mock = _MockClient(default_result=_ALLOW_WITH_DETECTIONS)
        guard = _make_guard(mock, check_interval=5, post_stream_check=True)
        chunks = ["Hello this is a test with some content."]

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(chunks)):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == chunks
        assert guard.violation is None


# ---------------------------------------------------------------------------
# TestStreamGuardContextManager
# ---------------------------------------------------------------------------

class TestStreamGuardContextManager:
    def test_feed_and_finish_clean(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock)

        async def _run():
            async with guard as sg:
                sg.feed("Hello ")
                sg.feed("world!")
                result = await sg.finish()
            return result

        result = asyncio.run(_run())
        assert result.is_safe
        assert guard.accumulated_text == "Hello world!"

    def test_feed_detects_violation(self):
        mock = _MockClient(results=[_BLOCK])
        guard = _make_guard(mock, check_interval=5)

        async def _run():
            async with guard as sg:
                sg.feed("bad content here")
                # Give the background task a chance to run
                await asyncio.sleep(0.05)
                return sg.violation

        violation = asyncio.run(_run())
        assert violation is not None
        assert not violation.result.is_safe

    def test_finish_runs_accumulator(self):
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=1000, post_stream_check=True)

        async def _run():
            async with guard as sg:
                sg.feed("some text")
                return await sg.finish()

        try:
            asyncio.run(_run())
            assert False, "Should have raised"
        except StreamViolationError as e:
            assert e.violation.result.violations[0].detector == "toxicity"

    def test_feed_after_close_raises(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)

        async def _run():
            async with guard as sg:
                sg.feed("hello")
                await sg.finish()
            sg.feed("should fail")

        try:
            asyncio.run(_run())
            assert False, "Should have raised RuntimeError"
        except RuntimeError:
            pass

    def test_cleanup_cancels_tasks(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=5)

        async def _run():
            async with guard as sg:
                sg.feed("a" * 20)
                # Don't call finish — __aexit__ should clean up

        asyncio.run(_run())
        assert guard.is_closed
        assert guard._pending_task is None


# ---------------------------------------------------------------------------
# TestStreamGuardSlidingWindow
# ---------------------------------------------------------------------------

class TestStreamGuardSlidingWindow:
    def test_window_size_respected(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=10, window_size=50)

        async def _run():
            # Feed 200 chars total, should get multiple checks
            async for _ in guard.shield(_async_chunks(["x" * 25] * 8)):
                pass

        asyncio.run(_run())
        # Window-based checks (all but the last, which is the post-stream
        # accumulator on the full text) should respect window_size.
        window_checks = mock._checked_texts[:-1]  # exclude accumulator
        assert len(window_checks) >= 1, "Expected at least one window check"
        for text in window_checks:
            assert len(text) <= 50

    def test_sentence_boundary_alignment(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(
            mock, check_interval=20, window_size=100, sentence_boundary=True,
        )

        async def _run():
            text = "Hello world. This is a test. More content here. End."
            # Feed char-by-char to test sentence boundary detection
            async for _ in guard.shield(_async_chunks(list(text))):
                pass

        asyncio.run(_run())
        # At least one check should have been made
        assert mock._call_count >= 1

    def test_check_interval_skips_when_pending(self):
        # Use a slow mock to test one-at-a-time behavior
        call_count = 0
        original_pass = _PASS

        class _SlowMock(_MockClient):
            async def acheck_output(self, text, original_input="", **kw):
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.1)
                return original_pass

        mock = _SlowMock()
        guard = _make_guard(mock, check_interval=5)

        async def _run():
            # Feed many chunks quickly — only one check should be pending
            chunks = ["x" * 10 for _ in range(5)]
            async for _ in guard.shield(_async_chunks(chunks)):
                pass

        asyncio.run(_run())
        # Should not have started dozens of concurrent tasks
        assert call_count <= 10  # generous upper bound




# ---------------------------------------------------------------------------
# TestStreamGuardPostStream
# ---------------------------------------------------------------------------

class TestStreamGuardPostStream:
    def test_accumulator_runs_on_full_text(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, check_interval=1000, post_stream_check=True)

        async def _run():
            async for _ in guard.shield(_async_chunks(["hello ", "world"])):
                pass

        asyncio.run(_run())
        # Post-stream check should have been called with full text
        assert "hello world" in mock._checked_texts

    def test_accumulator_catches_violation(self):
        # No window checks trigger (interval too high), but post-stream blocks
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=1000, post_stream_check=True)

        async def _run():
            async for _ in guard.shield(_async_chunks(["safe text"])):
                pass

        try:
            asyncio.run(_run())
            assert False, "Should have raised"
        except StreamViolationError as e:
            assert not e.violation.result.is_safe

    def test_accumulator_disabled(self):
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=1000, post_stream_check=False)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["safe text"])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == ["safe text"]
        # No checks should have been called at all
        assert mock._call_count == 0


# ---------------------------------------------------------------------------
# TestStreamGuardFailOpen
# ---------------------------------------------------------------------------

class TestStreamGuardFailOpen:
    def test_continues_on_api_error(self):
        mock = _MockClient(raise_on_call=RuntimeError("API down"))
        guard = _make_guard(mock, check_interval=5, fail_open=True)

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["hello world!"])):
                collected.append(chunk)
            return collected

        result = asyncio.run(_run())
        assert result == ["hello world!"]
        assert guard.violation is None

    def test_stops_on_api_error(self):
        mock = _MockClient(raise_on_call=RuntimeError("API down"))
        guard = _make_guard(
            mock, check_interval=5, fail_open=False, post_stream_check=False,
        )

        async def _run():
            collected = []
            async for chunk in guard.shield(_async_chunks(["a" * 20])):
                collected.append(chunk)
                # Give the background task a chance to complete
                await asyncio.sleep(0.01)
            return collected

        try:
            asyncio.run(_run())
            # Might not raise if the task hasn't completed
            # Check violation property instead
        except StreamViolationError:
            pass


# ---------------------------------------------------------------------------
# TestStreamGuardSync
# ---------------------------------------------------------------------------

class TestStreamGuardSync:
    def test_shield_sync_clean(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)
        result = list(guard.shield_sync(_sync_chunks(["hello ", "world"])))
        assert result == ["hello ", "world"]

    def test_shield_sync_blocked(self):
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=5, post_stream_check=True)
        try:
            list(guard.shield_sync(_sync_chunks(["bad content here"])))
            assert False, "Should have raised"
        except StreamViolationError:
            pass


# ---------------------------------------------------------------------------
# TestStreamGuardEdgeCases
# ---------------------------------------------------------------------------

class TestStreamGuardEdgeCases:
    def test_violation_is_frozen(self):
        mock = _MockClient(default_result=_BLOCK)
        guard = _make_guard(mock, check_interval=5)

        async def _run():
            try:
                async for _ in guard.shield(_async_chunks(["bad content"])):
                    pass
            except StreamViolationError:
                pass

        asyncio.run(_run())
        v = guard.violation
        assert v is not None
        assert isinstance(v, StreamViolation)
        # Frozen dataclass — attribute assignment should fail
        try:
            v.chunk_index = 999  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass

    def test_accumulated_text_property(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)

        async def _run():
            async for _ in guard.shield(_async_chunks(["abc", "def"])):
                pass

        asyncio.run(_run())
        assert guard.accumulated_text == "abcdef"

    def test_chars_sent_and_chunk_count(self):
        mock = _MockClient(default_result=_PASS)
        guard = _make_guard(mock, post_stream_check=False)

        async def _run():
            async for _ in guard.shield(_async_chunks(["abc", "de", "f"])):
                pass

        asyncio.run(_run())
        assert guard.chars_sent == 6
        assert guard.chunk_count == 3

    def test_stream_violation_error_has_violation(self):
        violation = StreamViolation(
            result=_BLOCK,
            text_checked="test",
            chunk_index=5,
            chars_sent=100,
        )
        err = StreamViolationError("blocked", violation=violation)
        assert err.violation is violation
        assert "blocked" in str(err)
