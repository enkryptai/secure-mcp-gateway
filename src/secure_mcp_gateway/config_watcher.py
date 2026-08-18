"""Background config-file watcher.

Polls the active config file's mtime and calls ``trigger_full_reload()``
when it changes so the running gateway picks up edits without a restart.

Design notes:

- Polling (vs inotify/FSEvents) keeps the implementation cross-platform and
  works inside Docker bind-mounts where some filesystems do not deliver
  inotify events.
- A single daemon thread is enough -- the file is checked every
  ``enkrypt_config_watcher_poll_seconds`` (default 2s) which is well under
  the cost of a config reload.
- If the file is missing or unreadable, we skip the cycle silently. A
  partially-written file (e.g. mid-save) would cause ``json.load`` to fail
  inside ``trigger_full_reload``; we catch that and resume polling rather
  than retry-loop, and on the next poll the file should be valid again.
- ``poll_seconds <= 0`` disables the watcher.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

from secure_mcp_gateway.utils import (
    get_active_config_path,
    get_config_watcher_poll_seconds,
    logger,
)

_watcher_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_started = False
_start_lock = threading.Lock()


def _watch_loop() -> None:
    last_mtime: Optional[float] = None
    # Avoid triggering a reload on the very first tick; just record the
    # current mtime so genuine subsequent changes fire a reload.
    try:
        path = get_active_config_path()
        if os.path.exists(path):
            last_mtime = os.path.getmtime(path)
    except Exception:
        last_mtime = None

    while not _stop_event.is_set():
        poll_seconds = get_config_watcher_poll_seconds()
        if poll_seconds <= 0:
            logger.info(
                "[config_watcher] disabled (poll_seconds<=0); exiting loop"
            )
            return
        try:
            path = get_active_config_path()
            if not os.path.exists(path):
                _stop_event.wait(poll_seconds)
                continue
            mtime = os.path.getmtime(path)
            if last_mtime is None:
                last_mtime = mtime
            elif mtime != last_mtime:
                logger.info(
                    "[config_watcher] config mtime changed; triggering reload",
                    path=path,
                    old_mtime=last_mtime,
                    new_mtime=mtime,
                )
                last_mtime = mtime
                try:
                    from secure_mcp_gateway.reload import trigger_full_reload

                    trigger_full_reload(include_tool_cache=False)
                except Exception as e:
                    logger.warning(
                        f"[config_watcher] trigger_full_reload failed: {e}"
                    )
        except Exception as e:
            logger.warning(f"[config_watcher] poll cycle error: {e}")
        _stop_event.wait(poll_seconds)


def start_config_watcher() -> bool:
    """Spawn the background watcher thread if not already running.

    Returns True if the watcher was started or is already running, False if
    it is disabled by config (poll_seconds <= 0).
    """
    global _watcher_thread, _started

    with _start_lock:
        if _started:
            return True

        poll_seconds = get_config_watcher_poll_seconds()
        if poll_seconds <= 0:
            logger.info(
                "[config_watcher] start skipped: poll_seconds<=0 (disabled)"
            )
            return False

        _stop_event.clear()
        _watcher_thread = threading.Thread(
            target=_watch_loop,
            name="enkrypt-config-watcher",
            daemon=True,
        )
        _watcher_thread.start()
        _started = True
        logger.info(
            f"[config_watcher] started (poll interval = {poll_seconds}s)"
        )
        return True


def stop_config_watcher(timeout: float = 5.0) -> None:
    """Stop the watcher thread. Mostly for tests."""
    global _watcher_thread, _started

    with _start_lock:
        if not _started:
            return
        _stop_event.set()
        if _watcher_thread is not None:
            _watcher_thread.join(timeout=timeout)
        _watcher_thread = None
        _started = False


__all__ = ["start_config_watcher", "stop_config_watcher"]
