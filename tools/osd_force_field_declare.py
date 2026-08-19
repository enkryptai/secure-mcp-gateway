"""Force-declare a list of fields in an OSD index pattern's field cache.

Why this exists
---------------
OpenSearch Dashboards builds its per-pattern "field list" via the
``_fields_for_wildcard`` endpoint, which only returns fields that have
at least one document with a value (this is correct in principle --
the cache mirrors what's actually queryable).

But when a dashboard panel reads ``metric.attributes.foo`` and the
backing helper hasn't fired yet (because the upstream API hasn't
emitted the precondition that triggers it), the field is missing from
the cache and OSD renders the ugly "Could not locate that
index-pattern-field (id: metric.attributes.foo)" error banner on
every refresh.

This script lets an operator pre-declare those fields so the panel
renders an honest "No results found" empty state instead.  Once real
documents start arriving with values for the field, OSD's normal
refresh will keep the entry (existing `count` is preserved).

When to use
-----------
- After deploying new metric instruments whose attributes don't yet
  have data flowing (e.g. ``enkrypt.guardrail.pii_entity`` waiting on
  Enkrypt cloud-policy detail mode being enabled).
- When debugging "Could not locate" errors that are caused by missing
  field-cache entries rather than missing index mappings.

Usage
-----
Edit FORCED_PATTERNS_AND_FIELDS to declare which fields belong to
which patterns.  Then run with a port-forward to OSD:

    kubectl port-forward -n dev svc/<osd-svc> 15601:5601
    OSD_URL=http://localhost:15601 python tools/osd_force_field_declare.py

The script is idempotent: fields already present in the cache are
left untouched.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import urllib.request


OSD = os.environ.get("OSD_URL", "http://localhost:15601")
# OSD admin credentials are typically in a k8s secret; override via env
# if running against a non-default cluster setup.
CRED_SECRET = os.environ.get(
    "OSD_CRED_SECRET",
    "enkryptai-opensearch-admin-password",
)
CRED_NAMESPACE = os.environ.get("OSD_CRED_NAMESPACE", "dev")


# (pattern_id, [(field_name, type, searchable, aggregatable), ...])
FORCED_PATTERNS_AND_FIELDS: list[tuple[str, list[tuple[str, str, bool, bool]]]] = [
    (
        "gateway-metrics",
        [
            # Emitted by record_pii_entities / record_toxicity_subtypes when
            # Enkrypt returns a non-empty metadata.details payload.  Until
            # then OSD's field discovery doesn't see them.
            ("metric.attributes.entity_type",  "string", True, True),
            ("metric.attributes.subtype",      "string", True, True),
            ("metric.attributes.score_bucket", "string", True, True),
        ],
    ),
]


def _cred() -> str:
    user = subprocess.check_output(
        f"kubectl get secret {CRED_SECRET} -n {CRED_NAMESPACE} "
        f"-o jsonpath={{.data.username}}",
        shell=True,
    ).decode()
    pw = subprocess.check_output(
        f"kubectl get secret {CRED_SECRET} -n {CRED_NAMESPACE} "
        f"-o jsonpath={{.data.password}}",
        shell=True,
    ).decode()
    user = base64.b64decode(user).decode()
    pw = base64.b64decode(pw).decode()
    return base64.b64encode(f"{user}:{pw}".encode()).decode()


def _req(path: str, method: str = "GET", body: bytes | None = None):
    url = OSD + path
    req = urllib.request.Request(url, method=method, data=body)
    req.add_header("Authorization", f"Basic {_cred()}")
    req.add_header("osd-xsrf", "true")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def main() -> int:
    total_added = 0
    for pattern_id, forced_fields in FORCED_PATTERNS_AND_FIELDS:
        try:
            pat = _req(f"/api/saved_objects/index-pattern/{pattern_id}")
        except Exception as exc:
            print(f"[{pattern_id}] FAILED to fetch: {exc}")
            continue
        fields = json.loads(pat["attributes"]["fields"])
        existing_names = {f["name"] for f in fields}
        added: list[str] = []
        for name, ftype, searchable, aggregatable in forced_fields:
            if name in existing_names:
                continue
            fields.append({
                "name": name,
                "type": ftype,
                "esTypes": ["keyword"],
                "searchable": searchable,
                "aggregatable": aggregatable,
                "readFromDocValues": True,
                "count": 0,
            })
            added.append(name)
        if not added:
            print(f"[{pattern_id}] all {len(forced_fields)} fields already present")
            continue
        payload = json.dumps({
            "attributes": {
                "title":         pat["attributes"]["title"],
                "timeFieldName": pat["attributes"].get("timeFieldName") or "time",
                "fields":        json.dumps(fields),
            },
        }).encode()
        resp = _req(
            f"/api/saved_objects/index-pattern/{pattern_id}",
            method="PUT",
            body=payload,
        )
        print(f"[{pattern_id}] added {len(added)} fields: {added}")
        print(f"[{pattern_id}] updated_at={resp.get('updated_at')}")
        total_added += len(added)

    print(f"\nDONE -- {total_added} field(s) added across "
          f"{len(FORCED_PATTERNS_AND_FIELDS)} pattern(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
