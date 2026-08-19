"""Fire PII + toxicity tool calls at the dev gateway so the Guardrails
Deep Dive dashboard's new per-detector panels populate.

What this exercises
-------------------
Each call goes through ``enkrypt_secure_call_tools`` (input guardrails
will fire) and we expect a BLOCK with violation_type=pii / toxicity.

When the patched v2.2.0-guardraildetail image is running, blocks at
those sites also fire the two new metric helpers
(record_pii_entities, record_toxicity_subtypes) and emit a structured
``guardrail.detector_detail`` log line with per-entity / per-subtype
fields.

After running this script, in OSD:

  - Guardrails Deep Dive -> "PII Entities by Direction" / "Top PII
    Entity Types" should populate (new metric enkrypt.guardrail.
    pii_entity bucketed by entity_type).
  - Guardrails Deep Dive -> "Toxicity Subtypes" / "Top Toxicity
    Subtypes by Score Bucket" should populate (new metric enkrypt.
    guardrail.toxicity_subtype bucketed by subtype + score_bucket).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


# These prompts are crafted to trip specific Enkrypt detectors so the
# upstream API returns details with the entity_types / subtype scores
# we want the dashboard to surface.  Keep them obvious-but-mild so we
# don't dump genuinely harmful content into logs.
PII_PROMPTS = [
    # Email + phone (US format) + SSN-shaped sequence; Enkrypt PII
    # detector should flag at least EMAIL + PHONE.
    "Please email alice@example.com or call 555-867-5309 to confirm.",
    # Multiple PII types in one message: email, credit card, address.
    "Send the refund to jane.doe@company.org or charge 4111-1111-1111-1111 "
    "billed to 1600 Pennsylvania Ave NW, Washington DC 20500.",
    # IP + URL + email (covers pii_ip_count / pii_url_count side fields
    # too).
    "Server 192.168.1.42 (admin: ops@corp.io) is reachable at "
    "https://internal.corp.io/admin -- please verify uptime.",
]

TOXICITY_PROMPTS = [
    # Mild insult variants -- enough to trip "insult" / "toxicity"
    # subtypes without using slurs.
    "You're an idiot if you can't figure out this trivial bug.",
    "This codebase is garbage and whoever wrote it was incompetent.",
    "Stop asking dumb questions and read the manual yourself, moron.",
]


async def _fire_one(session: ClientSession, server: str, prompt: str, label: str) -> str:
    """Returns a one-word verdict: success | blocked | other | exc."""
    try:
        res = await session.call_tool(
            "enkrypt_secure_call_tools",
            arguments={
                "server_name": server,
                "tool_calls": [
                    {
                        "name": "ask_question",
                        "args": {
                            "repoName": "enkryptai/secure-mcp-gateway",
                            "question": prompt,
                        },
                    }
                ],
            },
        )
        text = "".join(getattr(b, "text", "") for b in (res.content or []))
        if "blocked_calls\": 1" in text or "blocked_input" in text:
            return "blocked"
        if "successful_calls\": 1" in text:
            return "success"
        return f"other ({text[:80]})"
    except Exception as exc:  # noqa: BLE001
        return f"exc:{type(exc).__name__}:{exc}"


async def main(url: str, apikey: str, server: str) -> int:
    headers = {"apikey": apikey, "X-Enkrypt-MCP-Gateway": "demo_mcp_gateway"}
    print(f"[SETUP] {url} as ****{apikey[-4:]}  server={server}")

    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[SETUP] handshake OK\n")

            for i, q in enumerate(PII_PROMPTS, 1):
                print(f"[PII {i}/{len(PII_PROMPTS)}] {q[:60]}...")
                verdict = await _fire_one(session, server, q, "pii")
                print(f"  -> {verdict}")

            for i, q in enumerate(TOXICITY_PROMPTS, 1):
                print(f"[TOX {i}/{len(TOXICITY_PROMPTS)}] {q[:60]}...")
                verdict = await _fire_one(session, server, q, "toxicity")
                print(f"  -> {verdict}")

    print("\n[DONE]")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="https://mcp.dev.enkryptai.com/mcp")
    p.add_argument("--apikey", required=True)
    p.add_argument("--server", default="test-deepwiki-hosted-public")
    a = p.parse_args()
    try:
        sys.exit(asyncio.run(main(a.url, a.apikey, a.server)))
    except KeyboardInterrupt:
        sys.exit(130)
