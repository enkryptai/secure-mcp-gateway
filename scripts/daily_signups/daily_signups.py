"""Daily signups -> Slack digest.

Reads new signups from Supabase (via the public.recent_signups view) and
posts a single Block Kit message to a Slack incoming webhook.

Required env vars:
    SUPABASE_URL                 e.g. https://abcdef.supabase.co
    SUPABASE_SERVICE_ROLE_KEY    service-role key (NOT the anon key)
    SLACK_WEBHOOK_URL            incoming webhook for the target channel

Usage:
    python daily_signups.py                # last 24h, post to Slack
    python daily_signups.py --hours 168    # last 7 days
    python daily_signups.py --dry-run      # print payload, don't post

Exits non-zero on failure so GitHub Actions marks the run red.
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


def _env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(f"ERROR: missing env var {name}", file=sys.stderr)
        sys.exit(2)
    return val


def fetch_signups(since: datetime) -> list[dict[str, Any]]:
    """Fetch signups created at or after `since` from public.recent_signups."""
    base = _env("SUPABASE_URL").rstrip("/")
    key = _env("SUPABASE_SERVICE_ROLE_KEY")
    since_iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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


def build_slack_payload(signups: list[dict[str, Any]], hours: int) -> dict[str, Any]:
    """Render a Slack Block Kit payload for the given signups."""
    today_ist = datetime.now(IST).strftime("%Y-%m-%d")
    n = len(signups)
    header = f":wave: Daily signups — {today_ist} (last {hours}h)"

    if n == 0:
        return {
            "text": f"{header}\n0 signups",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": header}},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "_No new signups in the window._"},
                },
            ],
        }

    confirmed = sum(1 for s in signups if s.get("email_confirmed_at"))
    summary = f"*{n} new signup{'s' if n != 1 else ''}*  ({confirmed} confirmed, {n - confirmed} unconfirmed)"

    lines: list[str] = []
    for s in signups[:50]:
        email = s.get("email") or "—"
        name = s.get("full_name") or "—"
        provider = s.get("signup_provider") or "email"
        status = "✓" if s.get("email_confirmed_at") else "·"
        ts = (s.get("created_at") or "")[:19].replace("T", " ")
        lines.append(f"{status} `{email}` — {name} _(via {provider}, {ts} UTC)_")
    body = "\n".join(lines)
    if n > 50:
        body += f"\n…and {n - 50} more."

    return {
        "text": f"{header} — {n} new signups",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": body}},
        ],
    }


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

    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    signups = fetch_signups(since)
    payload = build_slack_payload(signups, args.hours)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return

    post_to_slack(payload)
    print(f"OK: posted {len(signups)} signup(s) to Slack.")


if __name__ == "__main__":
    main()
