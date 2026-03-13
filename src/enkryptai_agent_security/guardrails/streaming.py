"""Real-time streaming guardrails for LLM output streams.

Checks LLM responses chunk-by-chunk using a sliding-window strategy while
forwarding chunks to the client with minimal latency.  Background guardrail
checks run asynchronously on accumulated text windows so the stream is never
blocked by the Enkrypt API.

Architecture (maps to the five conceptual components):

1. **Stream Interceptor** — ``StreamGuard`` wraps ``AsyncIterable[str]`` /
   ``Iterable[str]`` and intercepts each chunk.
2. **Chunk Buffer & Windowing** — Internal buffer with sliding-window and
   optional sentence-boundary alignment for check timing.
3. **GR Engine** — ``EnkryptGuardrailClient.acheck_output()`` runs each
   window check as a background ``asyncio.Task``.
4. **Block & Cancellation Handler** — On BLOCK, raises
   ``StreamViolationError``.  On FLAG (WARN), logs and continues.  Upstream
   cancellation is the caller's responsibility.
5. **Post-Stream Accumulator** — ``finish()`` runs a final full-response
   check after the stream ends for detectors that need complete context
   (bias, coherence, topic drift, relevancy, adherence, hallucination).

Usage (OpenAI example)::

    from enkryptai_agent_security.guardrails.streaming import (
        StreamGuard, StreamViolationError,
    )

    guard = StreamGuard(
        api_key="ek-...",
        guardrail_policy="My Policy",
        block=["injection_attack", "toxicity"],
        original_input=prompt,
    )

    async def text_chunks(openai_stream):
        async for chunk in openai_stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    try:
        async for text in guard.shield(text_chunks(stream)):
            await websocket.send(text)
    except StreamViolationError as e:
        await websocket.send_clear(e.violation)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections.abc import AsyncIterable, AsyncIterator, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from enkryptai_agent_security.guardrails.client import EnkryptGuardrailClient
from enkryptai_agent_security.guardrails.types import (
    GuardrailAction,
    GuardrailResult,
    GuardrailViolation,
    ViolationType,
)

logger = logging.getLogger("enkryptai_agent_security.guardrails.streaming")

# Sentence-boundary regex: period / exclamation / question mark followed by
# whitespace.  Simple heuristic — no NLP dependency required.
_SENTENCE_END_RE = re.compile(r"[.!?]\s")

# Default PASS result returned when no checks ran.
_PASS = GuardrailResult(action=GuardrailAction.ALLOW, is_safe=True, violations=())


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StreamViolation:
    """Immutable record of a guardrail violation detected during streaming.

    Attributes:
        result: The full guardrail result (action, violations, raw response).
        text_checked: The text window that was evaluated when the violation
            was detected.
        chunk_index: How many chunks had been fed at detection time.
        chars_sent: Total characters forwarded to the client before detection.
        timestamp_ns: ``time.time_ns()`` at detection time.
    """

    result: GuardrailResult
    text_checked: str
    chunk_index: int
    chars_sent: int
    timestamp_ns: int = field(default_factory=time.time_ns)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class StreamViolationError(Exception):
    """Raised when a guardrail blocks content during streaming.

    Attributes:
        violation: Full context of the violation including the guardrail
            result, the text window that triggered the block, how many
            characters were already sent, and the chunk index.
    """

    def __init__(self, message: str, *, violation: StreamViolation) -> None:
        super().__init__(message)
        self.violation = violation


# ---------------------------------------------------------------------------
# StreamGuard
# ---------------------------------------------------------------------------

class StreamGuard:
    """Guard LLM output streams with background guardrail checks.

    Sits between the LLM stream and the client.  Captures each chunk,
    buffers it into evaluable windows, and runs guardrail checks in the
    background using the Enkrypt API.  On ``BLOCK``, raises
    :class:`StreamViolationError`.  On ``WARN`` (FLAG), continues streaming
    but logs the event for review.

    Accepts either a pre-configured :class:`EnkryptGuardrailClient` **or**
    convenience keyword arguments (``api_key``, ``guardrail_policy``,
    ``block``) for quick setup.

    Three integration patterns are supported:

    **Pattern 1 — Async generator wrapper** (convenient)::

        try:
            async for chunk in guard.shield(llm_stream):
                await ws.send(chunk)
        except StreamViolationError as e:
            await ws.send_clear(e.violation)

    **Pattern 2 — Context manager with manual feed** (flexible)::

        async with StreamGuard(...) as sg:
            async for chunk in llm_stream:
                sg.feed(chunk)
                if sg.violation:
                    break
                await ws.send(chunk)
            await sg.finish()

    **Pattern 3 — Sync wrapper**::

        for chunk in guard.shield_sync(sync_stream):
            response.write(chunk)
    """

    def __init__(
        self,
        original_input: str,
        *,
        # Client injection (advanced users / testing)
        client: EnkryptGuardrailClient | None = None,
        # Convenience kwargs (creates client internally)
        api_key: str = "",
        guardrail_policy: str = "",
        block: list[str] | None = None,
        base_url: str = "https://api.enkryptai.com",
        # Windowing
        check_interval: int = 100,
        window_size: int = 500,
        sentence_boundary: bool = True,
        # Behaviour
        fail_open: bool = True,
        timeout: float = 15.0,
        # Post-stream accumulator
        post_stream_check: bool = True,
    ) -> None:
        # Env-var fallback (constructor args always take precedence)
        if not api_key:
            api_key = os.environ.get("ENKRYPT_API_KEY", "")
        if not guardrail_policy:
            guardrail_policy = os.environ.get("ENKRYPT_GUARDRAIL_NAME", "")

        if client is not None:
            self._client = client
        else:
            self._client = EnkryptGuardrailClient(
                api_key=api_key,
                base_url=base_url,
                guardrail_name=guardrail_policy,
                block=block or [],
                fail_open=fail_open,
                timeout=timeout,
                source_name="enkrypt-streaming-guard",
            )

        self._original_input = original_input
        self._check_interval = max(check_interval, 1)
        self._window_size = max(window_size, self._check_interval)
        self._sentence_boundary = sentence_boundary
        self._fail_open = fail_open
        self._post_stream_check = post_stream_check

        # Buffer state
        self._buffer: list[str] = []
        self._total_chars: int = 0
        self._chunk_index: int = 0
        self._chars_since_last_check: int = 0

        # Background check state
        self._pending_task: asyncio.Task[GuardrailResult] | None = None
        self._violation: StreamViolation | None = None
        self._closed: bool = False

        # Check counters
        self._checks_completed: int = 0
        self._checks_passed: int = 0
        self._checks_failed: int = 0
        self._checks_with_detections: int = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def accumulated_text(self) -> str:
        """The full text accumulated so far."""
        return "".join(self._buffer)

    @property
    def chars_sent(self) -> int:
        """Total characters fed so far."""
        return self._total_chars

    @property
    def chunk_count(self) -> int:
        """Number of chunks fed."""
        return self._chunk_index

    @property
    def is_closed(self) -> bool:
        """Whether ``finish()`` or ``__aexit__`` has been called."""
        return self._closed

    @property
    def checks_completed(self) -> int:
        """Total guardrail checks that have completed."""
        return self._checks_completed

    @property
    def checks_passed(self) -> int:
        """Guardrail checks that returned ALLOW."""
        return self._checks_passed

    @property
    def checks_failed(self) -> int:
        """Guardrail checks that returned BLOCK or WARN."""
        return self._checks_failed

    @property
    def checks_with_detections(self) -> int:
        """Guardrail checks that returned ALLOW but had non-empty violations."""
        return self._checks_with_detections

    @property
    def violation(self) -> StreamViolation | None:
        """The first detected BLOCK violation, or ``None`` if clean so far.

        Non-blocking.  Polls completed background tasks and caches the
        result.  Once a violation is detected this property returns the
        same :class:`StreamViolation` on every subsequent access.
        """
        self._poll_pending()
        return self._violation

    # ------------------------------------------------------------------
    # Pattern 1: Async generator wrapper
    # ------------------------------------------------------------------

    async def shield(
        self,
        stream: AsyncIterable[str],
    ) -> AsyncIterator[str]:
        """Wrap an async text-chunk stream with guardrail protection.

        Yields chunks while scheduling background guardrail checks on a
        sliding window of accumulated text.  If a check returns ``BLOCK``,
        raises :class:`StreamViolationError`.  If ``WARN`` (FLAG), logs
        and continues streaming.

        At stream exhaustion, waits for any pending check and optionally
        runs a full-response check (post-stream accumulator).

        Raises:
            StreamViolationError: When a guardrail blocks the content.
        """
        try:
            async for chunk in stream:
                if not chunk:
                    continue

                self._ingest(chunk)

                # Check for violation from background tasks
                if self._violation is not None:
                    raise StreamViolationError(
                        f"Stream blocked: "
                        f"{[v.detector for v in self._violation.result.violations]}",
                        violation=self._violation,
                    )

                yield chunk

            # Run post-stream checks
            await self.finish()

        except StreamViolationError:
            raise
        except asyncio.CancelledError:
            self._cancel_pending()
            raise
        finally:
            self._closed = True

    # ------------------------------------------------------------------
    # Pattern 2: Context manager + manual feed
    # ------------------------------------------------------------------

    def feed(self, chunk: str) -> None:
        """Append a chunk to the buffer and schedule a background check
        if the interval threshold is reached.

        Non-blocking.  Must be called from within a running ``asyncio``
        event loop.  After calling, inspect :attr:`violation` to check
        whether a background check completed with a ``BLOCK`` verdict.

        Raises:
            RuntimeError: If called after :meth:`finish` or close.
        """
        if self._closed:
            raise RuntimeError("Cannot feed chunks to a closed StreamGuard")
        if not chunk:
            return
        self._ingest(chunk)

    async def finish(self) -> GuardrailResult:
        """Wait for pending checks and run the post-stream accumulator.

        Must be called when the stream ends.  The async context manager
        calls this automatically via ``__aexit__``.

        Returns:
            The final :class:`GuardrailResult`.

        Raises:
            StreamViolationError: If the final or accumulator check
                detects a ``BLOCK``.
        """
        self._closed = True

        # 1. Await any pending background task
        if self._pending_task is not None and not self._pending_task.done():
            try:
                result = await self._pending_task
                self._process_result(result)
            except Exception as exc:
                logger.warning("Pending guardrail check failed: %s", exc)
                if not self._fail_open:
                    self._record_error_violation(str(exc))
            self._pending_task = None
        elif self._pending_task is not None and self._pending_task.done():
            self._poll_pending()

        # 2. If already violated, raise
        if self._violation is not None:
            raise StreamViolationError(
                f"Stream blocked: "
                f"{[v.detector for v in self._violation.result.violations]}",
                violation=self._violation,
            )

        # 3. Post-stream accumulator — full-response check
        if self._post_stream_check:
            full_text = "".join(self._buffer)
            if full_text:
                try:
                    result = await self._client.acheck_output(
                        full_text,
                        self._original_input,
                        source_event="stream-final",
                    )
                except Exception as exc:
                    logger.warning("Post-stream guardrail check failed: %s", exc)
                    if self._fail_open:
                        return _PASS
                    self._record_error_violation(str(exc))
                    raise StreamViolationError(
                        f"Post-stream check error: {exc}",
                        violation=self._violation,  # type: ignore[arg-type]
                    )

                if not result.is_safe:
                    violation = StreamViolation(
                        result=result,
                        text_checked=full_text,
                        chunk_index=self._chunk_index,
                        chars_sent=self._total_chars,
                    )
                    self._violation = violation
                    raise StreamViolationError(
                        "Post-stream check blocked: "
                        f"{[v.detector for v in result.violations]}",
                        violation=violation,
                    )

                # FLAG (WARN) from post-stream
                if result.action == GuardrailAction.WARN:
                    logger.warning(
                        "Post-stream FLAG: %s",
                        [v.detector for v in result.violations],
                    )
                return result

        return _PASS

    async def __aenter__(self) -> StreamGuard:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        """Cancel pending tasks to prevent leaks.  Does NOT suppress
        exceptions."""
        self._closed = True
        self._cancel_pending()
        return False

    # ------------------------------------------------------------------
    # Pattern 3: Sync wrapper
    # ------------------------------------------------------------------

    def shield_sync(self, stream: Iterable[str]) -> Iterator[str]:
        """Synchronous version of :meth:`shield`.

        Runs the async ``shield()`` in a background thread with its own
        event loop, passing chunks back through a thread-safe queue.

        Raises:
            StreamViolationError: When a guardrail blocks the content.
        """
        import queue
        import threading

        q: queue.Queue[str | BaseException | None] = queue.Queue()

        async def _producer() -> None:
            async def _to_async() -> AsyncIterator[str]:
                for chunk in stream:
                    yield chunk

            try:
                async for chunk in self.shield(_to_async()):
                    q.put(chunk)
                q.put(None)
            except BaseException as exc:
                q.put(exc)

        thread = threading.Thread(
            target=asyncio.run, args=(_producer(),), daemon=True,
        )
        thread.start()

        while True:
            item = q.get()
            if item is None:
                break
            if isinstance(item, BaseException):
                raise item
            yield item

        thread.join()

    # ------------------------------------------------------------------
    # Internal: chunk ingestion
    # ------------------------------------------------------------------

    def _ingest(self, chunk: str) -> None:
        """Append a chunk to the buffer, poll pending tasks, and schedule
        a new background check if the interval threshold is reached."""
        self._buffer.append(chunk)
        self._total_chars += len(chunk)
        self._chunk_index += 1
        self._chars_since_last_check += len(chunk)

        # Poll any completed background task
        self._poll_pending()

        # Schedule a new check if ready
        self._maybe_schedule_check()

    # ------------------------------------------------------------------
    # Internal: background check scheduling
    # ------------------------------------------------------------------

    def _maybe_schedule_check(self) -> None:
        """Schedule a background guardrail check if the interval threshold
        is reached and no check is currently pending."""
        # One-at-a-time: skip if a check is still running
        if self._pending_task is not None and not self._pending_task.done():
            return

        # Clear completed task reference
        if self._pending_task is not None and self._pending_task.done():
            self._poll_pending()

        # Not enough new text yet
        if self._chars_since_last_check < self._check_interval:
            return

        # Sentence boundary alignment
        accumulated = "".join(self._buffer)
        check_pos = len(accumulated)

        if self._sentence_boundary:
            # Search for a sentence boundary in the recent text
            search_start = max(0, check_pos - self._chars_since_last_check)
            match = None
            for m in _SENTENCE_END_RE.finditer(accumulated, search_start):
                match = m
            if match is not None:
                boundary_pos = match.end()
                # Only use boundary if within 1.5x the interval
                if boundary_pos >= check_pos - int(self._check_interval * 1.5):
                    check_pos = boundary_pos

        # Build sliding window
        window_start = max(0, check_pos - self._window_size)
        check_text = accumulated[window_start:check_pos]

        if not check_text:
            return

        # Schedule background task
        self._pending_task = asyncio.create_task(
            self._client.acheck_output(
                check_text,
                self._original_input,
                source_event="stream-window",
            )
        )
        self._chars_since_last_check = 0

    def _poll_pending(self) -> None:
        """Non-blocking poll of a completed background task.  Processes
        the result if ready."""
        if self._pending_task is None or not self._pending_task.done():
            return

        try:
            result = self._pending_task.result()
        except Exception as exc:
            logger.warning("Background guardrail check failed: %s", exc)
            self._pending_task = None
            if not self._fail_open:
                self._record_error_violation(str(exc))
            return

        self._pending_task = None
        self._process_result(result)

    def _process_result(self, result: GuardrailResult) -> None:
        """Handle a completed guardrail result: BLOCK records a violation,
        WARN logs, ALLOW is logged at INFO."""
        self._checks_completed += 1
        if not result.is_safe:
            # BLOCK
            self._checks_failed += 1
            self._violation = StreamViolation(
                result=result,
                text_checked="".join(self._buffer),
                chunk_index=self._chunk_index,
                chars_sent=self._total_chars,
            )
        elif result.action == GuardrailAction.WARN:
            # FLAG — continue but log
            self._checks_failed += 1
            logger.warning(
                "Guardrail FLAG on chunk %d (%d chars sent): %s",
                self._chunk_index,
                self._total_chars,
                [v.detector for v in result.violations],
            )
        else:
            # ALLOW — safe
            self._checks_passed += 1
            if result.violations:
                # Detectors fired but none were in the block list
                self._checks_with_detections += 1
                logger.info(
                    "Guardrail check PASSED with detections on chunk %d "
                    "(%d chars sent): %s",
                    self._chunk_index,
                    self._total_chars,
                    [v.detector for v in result.violations],
                )
            else:
                logger.info(
                    "Guardrail check PASSED on chunk %d (%d chars sent)",
                    self._chunk_index,
                    self._total_chars,
                )

    def _record_error_violation(self, error_msg: str) -> None:
        """Record a synthetic violation when a guardrail API call fails
        and ``fail_open`` is False."""
        error_result = GuardrailResult(
            action=GuardrailAction.BLOCK,
            is_safe=False,
            violations=(
                GuardrailViolation(
                    detector="system",
                    violation_type=ViolationType.CUSTOM,
                    action=GuardrailAction.BLOCK,
                    severity=1.0,
                    message=f"Guardrail check error: {error_msg}",
                ),
            ),
        )
        self._violation = StreamViolation(
            result=error_result,
            text_checked="".join(self._buffer),
            chunk_index=self._chunk_index,
            chars_sent=self._total_chars,
        )

    def _cancel_pending(self) -> None:
        """Cancel any pending background task to prevent leaks."""
        if self._pending_task is not None and not self._pending_task.done():
            self._pending_task.cancel()
        self._pending_task = None

