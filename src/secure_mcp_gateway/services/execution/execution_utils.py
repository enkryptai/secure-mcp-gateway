from __future__ import annotations

import json
from typing import Any


def extract_input_text_from_args(args: Any) -> tuple[str, str]:
    """
    Derive the primary input text from arbitrary tool args, preserving existing behavior.

    Returns a tuple of (input_text_content, input_json_string) where:
    - input_text_content: the best-effort string to use for guardrails
    - input_json_string: JSON dump of args, used as fallback and for logging

    Behavior (matches current inline logic):
    - If args is a dict, try common keys: message, text, content, input, query, prompt
    - If none found, use the first non-empty string value
    - If still none, fallback to JSON string of args
    - If args is not a dict, cast to str
    """
    try:
        input_json_string = json.dumps(args)
    except Exception:
        # In case non-serializable, use str
        input_json_string = str(args)

    if isinstance(args, dict):
        # Common keys in priority order
        for key in [
            "message",
            "text",
            "content",
            "input",
            "query",
            "prompt",
        ]:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value, input_json_string

        # First non-empty string value
        for value in args.values():
            if isinstance(value, str) and value.strip():
                return value, input_json_string

        # Fallback
        return input_json_string, input_json_string

    # Non-dict: best-effort string
    return str(args), input_json_string
