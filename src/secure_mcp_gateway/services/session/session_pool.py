"""Implicit session pool for reusing live MCP server processes across calls.

Each pooled session runs in its own background asyncio task to avoid
cancel-scope conflicts with anyio's structured concurrency (the MCP SDK's
``ClientSession`` creates internal TaskGroups tied to the creating task).
Callers interact with sessions exclusively through an async request queue.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from secure_mcp_gateway.plugins.sandbox.server_params import build_server_params
from secure_mcp_gateway.utils import logger

_SENTINEL = object()


@dataclass
class _CallRequest:
    tool_name: str
    args: Dict[str, Any]
    future: asyncio.Future


class PooledSession:
    """A live MCP session running in a dedicated background task.

    All ``call_tool`` invocations are serialised through a queue so the
    underlying ``ClientSession`` is only ever accessed from the single task
    that owns its cancel scope.
    """

    def __init__(self, pool_key: str, server_name: str) -> None:
        self.pool_key = pool_key
        self.server_name = server_name
        self.last_used: float = time.monotonic()

        self._server_description: str = ""
        self._server_name: str = "unknown"
        self._server_version: str = "unknown"
        self._server_info: Any = None

        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._ready = asyncio.Event()
        self._closed = False
        self._use_lock = asyncio.Lock()

    @property
    def age_seconds(self) -> float:
        return time.monotonic() - self.last_used

    def touch(self) -> None:
        self.last_used = time.monotonic()

    async def start(
        self,
        server_config: Dict[str, Any],
        server_entry: Dict[str, Any],
    ) -> None:
        """Launch the background worker and wait until the session is ready."""
        self._task = asyncio.create_task(
            self._worker(server_config, server_entry),
            name=f"session-pool-{self.server_name}",
        )
        await self._ready.wait()
        if self._closed:
            raise RuntimeError(
                f"Session for {self.server_name} failed to start"
            )

    async def call_tool(self, tool_name: str, *, arguments: Dict[str, Any]) -> Any:
        """Proxy a tool call to the background worker."""
        if self._closed:
            raise RuntimeError("Session is closed")
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        await self._queue.put(_CallRequest(tool_name, arguments, future))
        return await future

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._queue.put(_SENTINEL)
        if self._task and not self._task.done():
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            except Exception as exc:
                logger.warning(
                    f"[SessionPool] Error closing session "
                    f"{self.pool_key}/{self.server_name}: {exc}"
                )

    async def _worker(
        self,
        server_config: Dict[str, Any],
        server_entry: Dict[str, Any],
    ) -> None:
        """Background task that owns the ClientSession and its cancel scopes."""
        from mcp import ClientSession

        command: str = server_config["command"]
        args: list = server_config.get("args", [])
        env: dict | None = server_config.get("env")

        try:
            async with build_server_params(
                server_entry, command, args, env
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()

                    server_info = getattr(init_result, "serverInfo", {})
                    self._server_description = getattr(server_info, "description", "")
                    self._server_name = getattr(server_info, "name", "unknown")
                    self._server_version = getattr(server_info, "version", "unknown")
                    self._server_info = server_info

                    logger.info(
                        f"[SessionPool] Worker ready for {self.server_name} "
                        f"(server={self._server_name} v={self._server_version})"
                    )
                    self._ready.set()

                    while True:
                        item = await self._queue.get()
                        if item is _SENTINEL:
                            break
                        req: _CallRequest = item
                        try:
                            result = await session.call_tool(
                                req.tool_name, arguments=req.args
                            )
                            if not req.future.done():
                                req.future.set_result(result)
                        except Exception as exc:
                            if not req.future.done():
                                req.future.set_exception(exc)
        except Exception as exc:
            logger.error(
                f"[SessionPool] Worker for {self.server_name} crashed: {exc}"
            )
            self._closed = True
            if not self._ready.is_set():
                self._ready.set()
            self._drain_queue_with_error(exc)

    def _drain_queue_with_error(self, exc: Exception) -> None:
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item is not _SENTINEL and isinstance(item, _CallRequest):
                    if not item.future.done():
                        item.future.set_exception(exc)
            except asyncio.QueueEmpty:
                break


class SessionPool:
    """Process-wide pool of live MCP server sessions.

    *acquire* returns a ``PooledSession`` (duck-typing ``call_tool``).
    *release* returns it to the pool for future reuse.
    Sessions that sit idle longer than *ttl_seconds* are reaped automatically.
    """

    def __init__(self, ttl_seconds: float = 300.0, enabled: bool = True) -> None:
        self._ttl = ttl_seconds
        self._enabled = enabled
        self._pool: Dict[Tuple[str, str], PooledSession] = {}
        self._pool_lock = asyncio.Lock()
        self._reaper_task: Optional[asyncio.Task] = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def ttl(self) -> float:
        return self._ttl

    def start_reaper(self) -> None:
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.ensure_future(self._reaper_loop())

    async def acquire(
        self,
        pool_key: str,
        server_name: str,
        server_config: Dict[str, Any],
        server_entry: Dict[str, Any],
    ) -> Tuple[PooledSession, bool]:
        """Return a ``(PooledSession, reused)`` tuple.

        If pooling is disabled or no cached session exists, a new session
        is created.  *reused* is ``True`` when an existing session was found.
        """
        key = (pool_key, server_name)

        if self._enabled:
            async with self._pool_lock:
                entry = self._pool.get(key)
                if entry is not None and not entry._closed:
                    await entry._use_lock.acquire()
                    entry.touch()
                    logger.info(
                        f"[SessionPool] Reusing session for {server_name} "
                        f"(idle {entry.age_seconds:.1f}s)"
                    )
                    return entry, True

        pooled = PooledSession(pool_key, server_name)
        await pooled.start(server_config, server_entry)
        await pooled._use_lock.acquire()

        if self._enabled:
            async with self._pool_lock:
                old = self._pool.get(key)
                if old is not None and not old._closed:
                    await old.close()
                self._pool[key] = pooled

        return pooled, False

    async def release(self, pool_key: str, server_name: str) -> None:
        """Mark the session as idle and release the per-session lock."""
        key = (pool_key, server_name)
        async with self._pool_lock:
            entry = self._pool.get(key)
        if entry is not None:
            entry.touch()
            try:
                entry._use_lock.release()
            except RuntimeError:
                pass
            logger.info(
                f"[SessionPool] Released session for {server_name} back to pool"
            )

    async def evict(self, pool_key: str, server_name: str) -> None:
        """Immediately close and remove a specific session."""
        key = (pool_key, server_name)
        async with self._pool_lock:
            entry = self._pool.pop(key, None)
        if entry is not None:
            try:
                entry._use_lock.release()
            except RuntimeError:
                pass
            await entry.close()
            logger.info(f"[SessionPool] Evicted session for {server_name}")

    async def close_all(self) -> None:
        """Drain every session in the pool (used on gateway shutdown)."""
        if self._reaper_task and not self._reaper_task.done():
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
        async with self._pool_lock:
            entries = list(self._pool.values())
            self._pool.clear()
        for entry in entries:
            await entry.close()
        logger.info(f"[SessionPool] Closed {len(entries)} pooled session(s)")

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self._enabled,
            "ttl_seconds": self._ttl,
            "active_sessions": len(self._pool),
            "sessions": [
                {
                    "pool_key_hash": hash(e.pool_key) % 10000,
                    "server_name": e.server_name,
                    "idle_seconds": round(e.age_seconds, 1),
                    "locked": e._use_lock.locked(),
                }
                for e in self._pool.values()
            ],
        }

    # -- internal ------------------------------------------------------------

    async def _reaper_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(30)
                await self._reap()
        except asyncio.CancelledError:
            return

    async def _reap(self) -> None:
        now = time.monotonic()
        to_evict: list[Tuple[str, str]] = []
        async with self._pool_lock:
            for key, entry in list(self._pool.items()):
                if entry._use_lock.locked():
                    continue
                if (now - entry.last_used) > self._ttl:
                    to_evict.append(key)
        for key in to_evict:
            async with self._pool_lock:
                entry = self._pool.pop(key, None)
            if entry is not None:
                await entry.close()
                logger.info(
                    f"[SessionPool] Reaped expired session for {entry.server_name} "
                    f"(idle {entry.age_seconds:.0f}s > TTL {self._ttl:.0f}s)"
                )


# -- singleton ---------------------------------------------------------------

_pool: Optional[SessionPool] = None


def initialize_session_pool(common_config: Dict[str, Any]) -> SessionPool:
    global _pool
    ttl = common_config.get("session_pool_ttl", 300)
    enabled = common_config.get("session_pool_enabled", True)
    _pool = SessionPool(ttl_seconds=float(ttl), enabled=enabled)
    _pool.start_reaper()
    return _pool


def get_session_pool() -> SessionPool:
    global _pool
    if _pool is None:
        _pool = SessionPool(ttl_seconds=300.0, enabled=True)
        _pool.start_reaper()
    return _pool
