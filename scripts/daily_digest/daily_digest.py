"""Daily MCP Gateway digest -> Slack.

Posts a single Block Kit message to Slack with multiple sections:

  1. Signups   (Supabase, via PostgREST view public.recent_signups)
  2. Top users (OpenSearch ss4o_metrics-gateway*, top 10 by enkrypt.tool.calls)

Each section is independent. If one section's backend is unreachable or
misconfigured, that section is rendered as an error block and the rest of
the digest still posts. The script only exits non-zero if Slack itself
fails (i.e. nothing made it into the channel).

Required env vars:
    SLACK_WEBHOOK_URL            incoming webhook for the target channel

Optional env vars (per section):
    SUPABASE_URL                 e.g. https://auth.app.dev.enkryptai.com
    SUPABASE_SERVICE_ROLE_KEY    service-role key
    OPENSEARCH_URL               e.g. https://opensearch.dev.enkryptai.com
                                 (Dashboards host; we use its console proxy)
    OPENSEARCH_AUTH              "user:password" basic-auth pair

Usage:
    python daily_digest.py                # last 24h, post to Slack
    python daily_digest.py --hours 168    # last 7 days
    python daily_digest.py --dry-run      # print payload, don't post
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

IST = timezone(timedelta(hours=5, minutes=30))


def _env(name: str, required: bool = True) -> str | None:
    val = os.environ.get(name)
    if not val and required:
        print(f"ERROR: missing required env var {name}", file=sys.stderr)
        sys.exit(2)
    return val or None


# ---------------------------------------------------------------------------
# Section 1: Signups (Supabase)
# ---------------------------------------------------------------------------

def fetch_signups(hours: int) -> list[dict[str, Any]]:
    """Fetch signups created in the last `hours` hours."""
    base = _env("SUPABASE_URL", required=False)
    key = _env("SUPABASE_SERVICE_ROLE_KEY", required=False)
    if not base or not key:
        raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set")
    base = base.rstrip("/")
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    url = f"{base}/rest/v1/recent_signups"
    params = {
        "select": "id,email,created_at,email_confirmed_at,full_name,signup_provider",
        "created_at": f"gte.{since_iso}",
        "order": "created_at.desc",
    }
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}
    r = httpx.get(url, params=params, headers=headers, timeout=30.0)
    r.raise_for_status()
    return r.json()


def render_signups_blocks(signups: list[dict[str, Any]], hours: int) -> list[dict[str, Any]]:
    n = len(signups)
    if n == 0:
        return [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*:inbox_tray: Signups (last {hours}h)*\n_No new signups in the window._"},
            }
        ]
    confirmed = sum(1 for s in signups if s.get("email_confirmed_at"))
    summary = f"*:inbox_tray: Signups (last {hours}h)* — *{n}* total ({confirmed} confirmed, {n - confirmed} unconfirmed)"
    lines: list[str] = []
    for s in signups[:25]:
        email = s.get("email") or "—"
        name = s.get("full_name") or "—"
        provider = s.get("signup_provider") or "email"
        status = "✓" if s.get("email_confirmed_at") else "·"
        ts = (s.get("created_at") or "")[:19].replace("T", " ")
        lines.append(f"{status} `{email}` — {name} _(via {provider}, {ts} UTC)_")
    body = "\n".join(lines)
    if n > 25:
        body += f"\n…and {n - 25} more."
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
    ]


# ---------------------------------------------------------------------------
# Section 2: Top users (OpenSearch via Dashboards console proxy)
# ---------------------------------------------------------------------------

# The OpenSearch API is not directly exposed on the Dashboards host; we go
# through the Dashboards console proxy which forwards arbitrary OpenSearch
# requests after authenticating the caller. Requires `osd-xsrf: true`.

def _opensearch_search(path: str, body: dict[str, Any]) -> dict[str, Any]:
    base = _env("OPENSEARCH_URL", required=False)
    auth_pair = _env("OPENSEARCH_AUTH", required=False)
    if not base or not auth_pair or ":" not in auth_pair:
        raise RuntimeError("OPENSEARCH_URL / OPENSEARCH_AUTH not set (auth must be user:password)")
    base = base.rstrip("/")
    user, _, password = auth_pair.partition(":")
    proxy_url = f"{base}/api/console/proxy"
    params = {"path": path, "method": "POST"}
    headers = {"osd-xsrf": "true", "Content-Type": "application/json"}
    r = httpx.post(
        proxy_url,
        params=params,
        headers=headers,
        auth=(user, password),
        json=body,
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()


def fetch_top_users(hours: int, size: int = 10) -> list[dict[str, Any]]:
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"name": "enkrypt.tool.calls"}},
                    {"term": {"aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA"}},
                    {"range": {"time": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "aggs": {
            "top_users": {
                "terms": {
                    "field": "metric.attributes.user_email",
                    "size": size,
                    "order": {"calls": "desc"},
                    "missing": "(no user)",
                },
                "aggs": {"calls": {"sum": {"field": "value"}}},
            }
        },
    }
    resp = _opensearch_search("ss4o_metrics-gateway*/_search", query)
    buckets = (resp.get("aggregations") or {}).get("top_users", {}).get("buckets", [])
    return [{"email": b["key"], "calls": int(b["calls"]["value"])} for b in buckets]


def render_top_users_blocks(users: list[dict[str, Any]], hours: int) -> list[dict[str, Any]]:
    header = f"*:bar_chart: Top users — tool calls (last {hours}h)*"
    if not users:
        return [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"{header}\n_No tool calls in the window._"},
            }
        ]
    rows = []
    for i, u in enumerate(users, start=1):
        rows.append(f"{i:>2}.  `{u['email']}`  —  *{u['calls']}* calls")
    body = "\n".join(rows)
    return [{"type": "section", "text": {"type": "mrkdwn", "text": f"{header}\n{body}"}}]


# ---------------------------------------------------------------------------
# Section error block (used when a section's backend fails)
# ---------------------------------------------------------------------------

def render_error_block(section: str, err: Exception) -> list[dict[str, Any]]:
    msg = str(err)
    if len(msg) > 300:
        msg = msg[:297] + "…"
    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f":warning: *{section} unavailable* — `{msg}`"},
        }
    ]


# ---------------------------------------------------------------------------
# Slack post
# ---------------------------------------------------------------------------

def build_payload(hours: int) -> dict[str, Any]:
    today_ist = datetime.now(IST).strftime("%Y-%m-%d")
    header_text = f":wave: MCP Gateway Daily Digest — {today_ist} (last {hours}h)"

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": header_text}},
        {"type": "divider"},
    ]

    try:
        signups = fetch_signups(hours)
        blocks += render_signups_blocks(signups, hours)
    except Exception as e:
        blocks += render_error_block("Signups", e)

    blocks.append({"type": "divider"})

    try:
        users = fetch_top_users(hours)
        blocks += render_top_users_blocks(users, hours)
    except Exception as e:
        blocks += render_error_block("Top users", e)

    return {"text": header_text, "blocks": blocks}


def post_to_slack(payload: dict[str, Any]) -> None:
    url = _env("SLACK_WEBHOOK_URL")
    r = httpx.post(url, json=payload, timeout=15.0)
    if r.status_code >= 300:
        print(f"ERROR: Slack returned {r.status_code}: {r.text}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=int, default=24, help="lookback window (default 24)")
    ap.add_argument("--dry-run", action="store_true", help="print payload, don't POST")
    args = ap.parse_args()

    payload = build_payload(args.hours)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return

    post_to_slack(payload)
    print(f"OK: posted digest with {len(payload['blocks'])} blocks to Slack.")


if __name__ == "__main__":
    main()
