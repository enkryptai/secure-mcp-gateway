from __future__ import annotations

import json
from typing import Any

# ``request_apikey_var`` lives in ``secure_mcp_gateway.request_context`` so
# the guardrail provider can import it without dragging the execution service
# (and its telemetry-at-import-time side effects) into its dependency graph.
# Re-exported here for convenience.
from secure_mcp_gateway.request_context import request_apikey_var


def extract_input_text_from_args(args: Any) -> tuple[str, str]:
    """
    Build the guardrail input text from arbitrary tool args.

    Returns a tuple ``(input_text_content, input_json_string)`` where **both
    elements are the full JSON dump of args**. The tuple shape is preserved
    for backward compatibility with the existing call site in
    ``secure_tool_execution_service``.

    Why send the full JSON?

    The previous implementation tried to pick a "primary" text field by
    checking a hardcoded list of common keys (``message``, ``text``,
    ``content``, ``input``, ``query``, ``prompt``) and fell back to the
    first non-empty string value. That created a **silent guardrail
    bypass** for tools whose primary user-controlled field has a different
    name (e.g. DeepWiki's ``ask_question(repoName, question)`` — ``question``
    was never scanned, ``repoName`` was sent instead). Direct Enkrypt API
    comparison showed the same prompt scored 0.999 attack on the actual
    content but 0.679 on ``repoName`` alone, with ``most_unsafe_content``
    pointing at the wrong field.

    Sending the full JSON guarantees:

    - Content in **any** arg key is scanned, not just six hardcoded ones
    - **Nested** objects (filters, options, metadata) are included
    - **No hardcoded list** of "primary text fields" to maintain
    - New tools work out of the box without code changes

    Trade-off: the payload is larger (especially for tools with big args),
    but Enkrypt accepts large text inputs and the security win is worth it.

    The JSON is dumped with ``sort_keys=True`` so two callers with the
    same args produce the same string regardless of dict insertion order.
    ``ensure_ascii=False`` is used so non-ASCII characters reach the
    guardrail in their natural form (important for non-English content).

    Falls back to ``str(args)`` if ``args`` is not JSON-serializable.
    """
    try:
        input_json_string = json.dumps(args, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        input_json_string = str(args)

    return input_json_string, input_json_string
