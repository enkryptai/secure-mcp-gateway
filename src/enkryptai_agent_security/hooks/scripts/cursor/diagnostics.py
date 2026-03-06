#!/usr/bin/env python
"""Cursor hooks diagnostic — determines how Cursor actually passes event data on Windows."""
import os
import sys
import json
import threading
from pathlib import Path

LOG = Path.home() / "cursor" / "hooks_logs" / "diagnostic.json"
LOG.parent.mkdir(parents=True, exist_ok=True)

out: dict = {
    "sys_argv": sys.argv,
    "env_vars": {k: v for k, v in os.environ.items() if "cursor" in k.lower() or "hook" in k.lower()},
    "stdin_result": None,
    "stdin_empty": None,
}

# Try reading stdin with 3-second timeout
stdin_data: list = []


def _read_stdin() -> None:
    try:
        stdin_data.append(sys.stdin.buffer.read())
    except Exception as exc:
        stdin_data.append(repr(exc).encode())


t = threading.Thread(target=_read_stdin, daemon=True)
t.start()
t.join(timeout=3.0)

if stdin_data:
    raw = stdin_data[0]
    out["stdin_result"] = raw.decode("utf-8", errors="replace")
    out["stdin_empty"] = raw == b""
else:
    out["stdin_result"] = "timeout_no_data"
    out["stdin_empty"] = True

LOG.write_text(json.dumps(out, indent=2, default=str))

# Always allow — this is diagnostic only
print(json.dumps({"continue": True}))
