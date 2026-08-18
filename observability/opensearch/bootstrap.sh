#!/usr/bin/env bash
# ============================================================================
#  Secure MCP Gateway -- OpenSearch bootstrap
# ============================================================================
#  Idempotent. Applies in this order:
#    1. Health check (waits up to OS_WAIT_SECONDS for cluster to be reachable)
#    2. ISM policies (policies/*.json)
#    3. Index templates (templates/*.json) -- each template's `aliases` block
#       sets the human-friendly aliases (gateway-metrics, gateway-traces,
#       gateway-logs) on every new data-stream backing index automatically.
#       OpenSearch 2.x rejects the standard /_aliases API for data-stream
#       backing indices, so template-level aliases are the only mechanism.
#    4. Notification channels (notification_channels/*.json)
#       -- ${SLACK_WEBHOOK_URL} env var substituted at runtime
#    5. Alerting monitors (monitors/*.json)
#       -- ${SLACK_CHANNEL_ID} substituted with the channel created in (4)
#       so each monitor's action targets the right destination.
#
#  Idempotency:
#    - ISM policy: GET first; POST if missing, PUT (with seq_no/primary_term)
#      if exists. Either path updates the policy in place.
#    - Index template: PUT is upsert-safe.
#    - Notification channel: PUT to /configs/<id> upserts. We use a
#      deterministic id (basename of the JSON file) so re-runs update in
#      place instead of creating duplicates.
#    - Monitor: lookup by name first; PUT to /_alerting/monitors/<id> if
#      exists, POST if new. Either path leaves exactly one monitor with
#      that name.
#
#  Env vars (with defaults):
#    OPENSEARCH_ENDPOINT  -- e.g. https://opensearch:9200  (no trailing /)
#    OPENSEARCH_USERNAME  -- defaults to admin
#    OPENSEARCH_PASSWORD  -- required
#    OPENSEARCH_CACERT    -- path to CA cert; falls back to -k if unset/missing
#    OS_WAIT_SECONDS      -- defaults to 120
#    SLACK_WEBHOOK_URL    -- substituted into notification channel JSONs at
#                            runtime. Default is an obviously-fake URL so the
#                            channel is created (preserving its config_id for
#                            monitor wiring) but Slack POSTs will silently
#                            fail until the operator sets a real value.
#    SKIP_MONITORS        -- "1" disables steps 4+5 (channel + monitors). Use
#                            this if you only need templates + ISM (e.g. a
#                            staging cluster that doesn't page operators yet).
#    BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER -- "1" creates the
#                            `mcp_gateway_telemetry_plugin` user + `mcp_gateway_telemetry_writer`
#                            role + role-mapping via the Security plugin REST
#                            API (Step 0). Used by the LOCAL docker-compose
#                            stack so Data Prepper can write as the
#                            least-privilege user instead of admin -- mirrors
#                            what k8s gets from apps/opensearch/dev/security-config.yaml.
#                            Requires MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD. NOT set in
#                            k8s (k8s creates the user via securityadmin.sh).
#    MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD -- plaintext for the local-only user
#                            created above. Required when
#                            BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER=1; ignored
#                            otherwise.
#    OSD_ENDPOINT         -- if set, Step 6 imports the Dashboards saved-objects
#                            NDJSON from DASHBOARDS_NDJSON. Skipped if unset
#                            (the local docker-compose runs this step in a
#                            separate container so opensearch-bootstrap doesn't
#                            have to wait for dashboards readiness).
#    DASHBOARDS_NDJSON    -- path to the saved-objects NDJSON to import. May
#                            be either a single file (legacy behaviour) or a
#                            directory; if a directory, every `*.ndjson` under
#                            it is imported in lexical order. Index-pattern
#                            files (e.g. `saved-objects.ndjson`) must sort
#                            before files referencing them (e.g.
#                            `gateway-dashboards.ndjson`), which the default
#                            naming already does. Defaults to
#                            ${SCRIPT_DIR}/saved-objects.ndjson; apiaas
#                            operators typically pass the directory path
#                            code/docker/config/opensearch/gateway/.
#    SCRIPT_DIR_OVERRIDE  -- override the directory the script reads from
#                            (used by the apiaas mirror so a single binary can
#                            point at either tree)
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Path resolution -- prefer override, else dir-of-script
# ---------------------------------------------------------------------------
SCRIPT_DIR="${SCRIPT_DIR_OVERRIDE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TEMPLATES_DIR="${SCRIPT_DIR}/templates"
POLICIES_DIR="${SCRIPT_DIR}/policies"
CHANNELS_DIR="${SCRIPT_DIR}/notification_channels"
MONITORS_DIR="${SCRIPT_DIR}/monitors"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OPENSEARCH_ENDPOINT="${OPENSEARCH_ENDPOINT:-https://opensearch:9200}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:-}"
OPENSEARCH_CACERT="${OPENSEARCH_CACERT:-}"
OS_WAIT_SECONDS="${OS_WAIT_SECONDS:-120}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-https://hooks.slack.com/services/REPLACE/WITH/YOUR_WEBHOOK}"
SKIP_MONITORS="${SKIP_MONITORS:-0}"
BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER="${BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER:-0}"
MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD="${MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD:-}"
OSD_ENDPOINT="${OSD_ENDPOINT:-}"
DASHBOARDS_NDJSON="${DASHBOARDS_NDJSON:-${SCRIPT_DIR}/saved-objects.ndjson}"

OPENSEARCH_ENDPOINT="${OPENSEARCH_ENDPOINT%/}"   # strip trailing slash

if [[ -z "$OPENSEARCH_PASSWORD" ]]; then
  echo "ERROR: OPENSEARCH_PASSWORD env var must be set" >&2
  exit 1
fi

if [[ -n "$OPENSEARCH_CACERT" && -f "$OPENSEARCH_CACERT" ]]; then
  CURL_TLS=(--cacert "$OPENSEARCH_CACERT")
else
  CURL_TLS=(-k)
fi

curl_cmd() {
  curl -sS "${CURL_TLS[@]}" -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" "$@"
}

log()  { printf '%s  %s\n' "$(date -u +%FT%TZ)" "$*"; }
fail() { printf '%s  ERROR: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Step 1: wait for cluster
#
# Must wait for status >= yellow, not just "reachable". On a warm restart the
# health endpoint answers RED for ~30s while shards recover, and during that
# window updates to the alerting plugin's system index (.opendistro-alerting-config)
# fail with "all shards failed". `wait_for_status=yellow` lets the server
# block server-side, so we poll cheaply with a short timeout per request.
# ---------------------------------------------------------------------------
log "Waiting up to ${OS_WAIT_SECONDS}s for ${OPENSEARCH_ENDPOINT} (status >= yellow) ..."
deadline=$(( $(date +%s) + OS_WAIT_SECONDS ))
status=""
while (( $(date +%s) < deadline )); do
  body="$(curl_cmd "${OPENSEARCH_ENDPOINT}/_cluster/health?wait_for_status=yellow&timeout=10s" 2>/dev/null || true)"
  if echo "$body" | grep -q '"status"'; then
    status="$(echo "$body" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
    if [[ "$status" == "yellow" || "$status" == "green" ]]; then
      log "Cluster ready, status=${status}"
      break
    fi
    log "Cluster reachable but status=${status}; waiting for yellow..."
  fi
  sleep 2
done
if [[ "$status" != "yellow" && "$status" != "green" ]]; then
  fail "OpenSearch at ${OPENSEARCH_ENDPOINT} did not reach yellow within ${OS_WAIT_SECONDS}s (last status=${status:-unreachable})"
fi

# ---------------------------------------------------------------------------
# Step 1b (local-only): create mcp_gateway_telemetry_plugin user + writer role +
#                       role-mapping via the Security plugin REST API.
#
# Gated on BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER=1. In k8s the same user/role
# trio is provisioned via apps/opensearch/dev/security-config.yaml +
# securityadmin.sh; bypassing this step there avoids two sources of truth.
# In the local docker-compose stack, where there's no security-config
# pipeline, this REST API path keeps the dev environment behaviourally
# identical to prod (Data Prepper writes as a least-privilege user, NOT
# admin).
#
# Role permissions mirror security-config.yaml:roles.yml:mcp_gateway_telemetry_writer
# exactly: crud + create_index + manage on ss4o_*-gateway*, otel-v1-apm-*,
# and .ds-ss4o_*-gateway-*; plus cluster_monitor + cluster_composite_ops +
# cluster_manage_index_templates at cluster scope. Drifting either side is
# a finding (sync-check.sh covers the file pair; this comment is the
# soft-warning for the runtime side).
#
# PUTs are idempotent (upsert) so re-runs on a configured cluster are safe.
# ---------------------------------------------------------------------------
apply_gateway_telemetry_user() {
  if [[ -z "$MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD" ]]; then
    fail "BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER=1 requires MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD to be set"
  fi
  log "=== Creating mcp_gateway_telemetry_writer role + mcp_gateway_telemetry_plugin user ==="

  # 1. role
  log "Role: mcp_gateway_telemetry_writer"
  resp="$(curl_cmd -X PUT \
    "${OPENSEARCH_ENDPOINT}/_plugins/_security/api/roles/mcp_gateway_telemetry_writer" \
    -H 'Content-Type: application/json' \
    -d '{
          "cluster_permissions": [
            "cluster_monitor",
            "cluster_composite_ops",
            "cluster_manage_index_templates"
          ],
          "index_permissions": [
            {
              "index_patterns": [
                "ss4o_metrics-gateway*",
                "ss4o_traces-gateway*",
                "ss4o_logs-gateway*",
                "otel-v1-apm-*",
                ".ds-ss4o_*-gateway-*"
              ],
              "allowed_actions": ["crud", "create_index", "manage"]
            },
            {
              "index_patterns": ["*"],
              "allowed_actions": [
                "indices_monitor",
                "indices:admin/aliases/get",
                "indices:admin/mappings/get"
              ]
            }
          ]
        }')"
  if echo "$resp" | grep -qE '"status":"(OK|CREATED)"'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi

  # 2. user. The Security plugin auto-bcrypts the password server-side
  # (we never store plaintext on disk).
  log "User: mcp_gateway_telemetry_plugin"
  # Escape only the JSON-special characters we care about; the rest of
  # the password (|, &, $, \, etc.) is JSON-safe inside a string already.
  # Replace \ first to avoid double-escaping.
  esc="${MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD//\\/\\\\}"
  esc="${esc//\"/\\\"}"
  resp="$(curl_cmd -X PUT \
    "${OPENSEARCH_ENDPOINT}/_plugins/_security/api/internalusers/mcp_gateway_telemetry_plugin" \
    -H 'Content-Type: application/json' \
    -d "{
          \"password\": \"${esc}\",
          \"backend_roles\": [\"mcp_gateway_telemetry_writer\"],
          \"description\": \"Secure MCP Gateway -- Data Prepper writes telemetry to ss4o_*-gateway (local stack only)\"
        }")"
  if echo "$resp" | grep -qE '"status":"(OK|CREATED)"'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi

  # 3. role-mapping
  log "Role-mapping: mcp_gateway_telemetry_writer"
  resp="$(curl_cmd -X PUT \
    "${OPENSEARCH_ENDPOINT}/_plugins/_security/api/rolesmapping/mcp_gateway_telemetry_writer" \
    -H 'Content-Type: application/json' \
    -d '{"backend_roles": ["mcp_gateway_telemetry_writer"]}')"
  if echo "$resp" | grep -qE '"status":"(OK|CREATED)"'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi
}

if [[ "$BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER" == "1" ]]; then
  apply_gateway_telemetry_user
else
  log "Skipping local mcp_gateway_telemetry_plugin user creation (BOOTSTRAP_MCP_GATEWAY_TELEMETRY_USER!=1)"
fi

# ---------------------------------------------------------------------------
# Step 2: ISM policies
# ---------------------------------------------------------------------------
apply_ism_policy() {
  local file="$1"
  local name
  name="$(basename "$file" .json)"
  log "ISM policy: ${name}"

  local existing
  existing="$(curl_cmd "${OPENSEARCH_ENDPOINT}/_plugins/_ism/policies/${name}" || true)"

  if echo "$existing" | grep -q '"_id"'; then
    # Update via PUT with seq_no/primary_term for optimistic concurrency
    local seq_no primary_term
    seq_no="$(echo "$existing" | sed -n 's/.*"_seq_no":\([0-9]*\).*/\1/p')"
    primary_term="$(echo "$existing" | sed -n 's/.*"_primary_term":\([0-9]*\).*/\1/p')"
    log "  exists (seq_no=${seq_no}, primary_term=${primary_term}); updating..."
    resp="$(curl_cmd -X PUT \
      "${OPENSEARCH_ENDPOINT}/_plugins/_ism/policies/${name}?if_seq_no=${seq_no}&if_primary_term=${primary_term}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${file}")"
  else
    log "  creating..."
    resp="$(curl_cmd -X PUT \
      "${OPENSEARCH_ENDPOINT}/_plugins/_ism/policies/${name}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${file}")"
  fi

  if echo "$resp" | grep -q '"_id"'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi
}

if [[ -d "$POLICIES_DIR" ]]; then
  log "=== Applying ISM policies from ${POLICIES_DIR} ==="
  shopt -s nullglob
  for f in "${POLICIES_DIR}"/*.json; do
    apply_ism_policy "$f"
  done
  shopt -u nullglob
else
  log "No policies/ directory; skipping ISM step"
fi

# ---------------------------------------------------------------------------
# Step 3: index templates
# ---------------------------------------------------------------------------
apply_index_template() {
  local file="$1"
  local name
  name="$(basename "$file" .json | sed 's/-elastic-template$//')"
  log "Index template: ${name}"

  resp="$(curl_cmd -X PUT \
    "${OPENSEARCH_ENDPOINT}/_index_template/${name}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${file}")"

  if echo "$resp" | grep -q '"acknowledged":true'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi
}

if [[ -d "$TEMPLATES_DIR" ]]; then
  log "=== Applying index templates from ${TEMPLATES_DIR} ==="
  shopt -s nullglob
  for f in "${TEMPLATES_DIR}"/*.json; do
    apply_index_template "$f"
  done
  shopt -u nullglob
else
  log "No templates/ directory; skipping templates step"
fi

# ---------------------------------------------------------------------------
# Step 3b: pre-create gateway data streams
#
# Why: each template's `aliases` block (gateway-metrics/traces/logs) only
# attaches on first backing-index creation. Without pre-creating, opening
# Dashboards Discover on `gateway-metrics` shows "no data" until ingest.
# Worse, monitors that referenced the alias by name (legacy) would fail
# with IndexNotFoundException on a fresh cluster.
#
# Creating an empty data stream is cheap and idempotent (PUT returns
# {"acknowledged":true} on a fresh cluster and 400 with "already exists"
# afterward -- we treat both as success).
# ---------------------------------------------------------------------------
ensure_data_stream() {
  local name="$1"
  log "Data stream: ${name}"
  resp="$(curl_cmd -X PUT "${OPENSEARCH_ENDPOINT}/_data_stream/${name}" \
    -H 'Content-Type: application/json')"
  if echo "$resp" | grep -q '"acknowledged":true'; then
    log "  created"
  elif echo "$resp" | grep -qE 'resource_already_exists_exception|already exists'; then
    log "  exists"
  else
    fail "  failed: ${resp}"
  fi
}

log "=== Ensuring gateway data streams exist ==="
ensure_data_stream ss4o_metrics-gateway
ensure_data_stream ss4o_traces-gateway
ensure_data_stream ss4o_logs-gateway

# ---------------------------------------------------------------------------
# Step 4: notification channels (Slack)
#
# OpenSearch Notifications plugin accepts a deterministic config_id which we
# set in the channel JSON. PUT to /configs/<id> upserts cleanly on re-runs.
# ---------------------------------------------------------------------------
apply_notification_channel() {
  local file="$1"
  local config_id
  config_id="$(python3 -c "import json,sys; print(json.load(open('${file}'))['config_id'])" 2>/dev/null || \
                grep -o '"config_id"[[:space:]]*:[[:space:]]*"[^"]*"' "${file}" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  if [[ -z "$config_id" ]]; then
    log "  ERROR: no config_id found in ${file}"
    return 1
  fi
  log "Notification channel: ${config_id}"

  # Render ${SLACK_WEBHOOK_URL} substitution into a tempfile
  local rendered
  rendered="$(mktemp)"
  sed "s|\${SLACK_WEBHOOK_URL}|${SLACK_WEBHOOK_URL}|g" "${file}" > "${rendered}"

  # Check if it already exists
  local existing
  existing="$(curl_cmd "${OPENSEARCH_ENDPOINT}/_plugins/_notifications/configs/${config_id}" 2>/dev/null || true)"

  if echo "$existing" | grep -q "\"config_id\":\"${config_id}\""; then
    log "  exists; updating..."
    resp="$(curl_cmd -X PUT \
      "${OPENSEARCH_ENDPOINT}/_plugins/_notifications/configs/${config_id}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${rendered}")"
  else
    log "  creating..."
    resp="$(curl_cmd -X POST \
      "${OPENSEARCH_ENDPOINT}/_plugins/_notifications/configs" \
      -H 'Content-Type: application/json' \
      --data-binary "@${rendered}")"
  fi
  rm -f "${rendered}"

  if echo "$resp" | grep -q "\"config_id\":\"${config_id}\""; then
    log "  ok"
    NOTIFICATION_CHANNEL_ID="${config_id}"   # exported for monitor step
  else
    fail "  failed: ${resp}"
  fi
}

NOTIFICATION_CHANNEL_ID=""

if [[ "$SKIP_MONITORS" != "1" && -d "$CHANNELS_DIR" ]]; then
  log "=== Applying notification channels from ${CHANNELS_DIR} ==="
  shopt -s nullglob
  for f in "${CHANNELS_DIR}"/*.json; do
    apply_notification_channel "$f"
  done
  shopt -u nullglob
else
  log "Skipping notification channels (SKIP_MONITORS=${SKIP_MONITORS} or no channels/ directory)"
fi

# ---------------------------------------------------------------------------
# Step 5: alerting monitors
#
# Substitute ${SLACK_CHANNEL_ID} with NOTIFICATION_CHANNEL_ID, look up the
# monitor by name (the alerting plugin's POST creates a fresh _id every
# time, so name lookup is the only stable handle), then PUT-upsert or POST.
# ---------------------------------------------------------------------------
apply_monitor() {
  local file="$1"
  local monitor_name
  monitor_name="$(python3 -c "import json; print(json.load(open('${file}'))['name'])" 2>/dev/null || \
                  grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "${file}" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  if [[ -z "$monitor_name" ]]; then
    log "  ERROR: no name found in ${file}"
    return 1
  fi
  log "Monitor: ${monitor_name}"

  local rendered
  rendered="$(mktemp)"
  sed "s|\${SLACK_CHANNEL_ID}|${NOTIFICATION_CHANNEL_ID}|g" "${file}" > "${rendered}"

  # Look up existing monitor by exact name
  local existing_id
  existing_id="$(curl_cmd -X POST \
    "${OPENSEARCH_ENDPOINT}/_plugins/_alerting/monitors/_search" \
    -H 'Content-Type: application/json' \
    -d "{\"size\":1,\"query\":{\"term\":{\"monitor.name.keyword\":\"${monitor_name}\"}}}" 2>/dev/null \
    | python3 -c 'import json,sys; r=json.load(sys.stdin).get("hits",{}).get("hits",[]); print(r[0]["_id"] if r else "")' 2>/dev/null || true)"

  if [[ -n "$existing_id" ]]; then
    log "  exists (id=${existing_id}); updating..."
    resp="$(curl_cmd -X PUT \
      "${OPENSEARCH_ENDPOINT}/_plugins/_alerting/monitors/${existing_id}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${rendered}")"
  else
    log "  creating..."
    resp="$(curl_cmd -X POST \
      "${OPENSEARCH_ENDPOINT}/_plugins/_alerting/monitors" \
      -H 'Content-Type: application/json' \
      --data-binary "@${rendered}")"
  fi
  rm -f "${rendered}"

  if echo "$resp" | grep -q '"_id"'; then
    log "  ok"
  else
    fail "  failed: ${resp}"
  fi
}

if [[ "$SKIP_MONITORS" != "1" && -d "$MONITORS_DIR" ]]; then
  if [[ -z "$NOTIFICATION_CHANNEL_ID" ]]; then
    log "WARNING: no notification channel was applied; monitors will reference an empty channel id and Slack actions won't fire"
  fi
  log "=== Applying alerting monitors from ${MONITORS_DIR} ==="
  shopt -s nullglob
  for f in "${MONITORS_DIR}"/*.json; do
    apply_monitor "$f"
  done
  shopt -u nullglob
else
  log "Skipping monitors (SKIP_MONITORS=${SKIP_MONITORS} or no monitors/ directory)"
fi

# ---------------------------------------------------------------------------
# Step 6 (optional): import Dashboards saved-objects
#
# Skipped if OSD_ENDPOINT is unset OR the NDJSON file doesn't exist. The
# local docker-compose stack runs this step in a separate container (so
# opensearch-bootstrap can run as soon as OpenSearch is healthy, without
# waiting for Dashboards startup). The apiaas / kubectl path sets
# OSD_ENDPOINT and runs everything in one script.
# ---------------------------------------------------------------------------
import_dashboards_file() {
  local file="$1"
  log "  importing ${file}"
  local resp
  # Drop -f so 4xx responses come back with their JSON body (otherwise
  # we silently warn-and-move-on, masking schema/extension/missing-ref
  # failures). The grep below is the authoritative success check.
  resp="$(curl -ks -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" \
            -H 'osd-xsrf: true' \
            -X POST "${OSD_ENDPOINT}/api/saved_objects/_import?overwrite=true" \
            --form "file=@${file}")" || true

  if echo "$resp" | grep -q '"success":true'; then
    log "    ok"
  else
    log "    warn: import response: ${resp}"
  fi
}

if [[ -n "$OSD_ENDPOINT" ]] && { [[ -f "$DASHBOARDS_NDJSON" ]] || [[ -d "$DASHBOARDS_NDJSON" ]]; }; then
  log "=== Importing Dashboards saved-objects from ${DASHBOARDS_NDJSON} ==="

  # Strip trailing slash to keep URL construction predictable
  OSD_ENDPOINT="${OSD_ENDPOINT%/}"

  # Wait briefly for Dashboards to be reachable (it boots slower than OS)
  deadline=$(( $(date +%s) + 60 ))
  while (( $(date +%s) < deadline )); do
    # Hit / instead of /api/status since /api/status requires auth and
    # returns 401 anonymously; / returns 302 to login (curl -f accepts).
    if curl -ksf -o /dev/null "${OSD_ENDPOINT}/"; then
      break
    fi
    sleep 2
  done

  if [[ -d "$DASHBOARDS_NDJSON" ]]; then
    shopt -s nullglob
    files=( "$DASHBOARDS_NDJSON"/*.ndjson )
    shopt -u nullglob
    if (( ${#files[@]} == 0 )); then
      log "  no *.ndjson under ${DASHBOARDS_NDJSON}; skipping"
    else
      # OpenSearch Dashboards 2.19.1's `_import` enforces reference
      # resolution at import time: visualizations whose index-pattern
      # refs don't already exist get rejected with `missing_references`,
      # even with `overwrite=true`. So we can't trust file-by-file
      # iteration order -- if `gateway-dashboards.ndjson` (visualizations)
      # sorts before `saved-objects.ndjson` (index-patterns), every
      # visualization import fails on a fresh cluster.
      #
      # Fix: concatenate every *.ndjson under DASHBOARDS_NDJSON into a
      # single payload and import in ONE call. _import resolves
      # references within a single payload by saved-object type
      # (index-patterns processed before visualizations before
      # dashboards), so the whole set lands atomically regardless of
      # filename ordering.
      IFS=$'\n' files_sorted=( $(printf '%s\n' "${files[@]}" | LC_ALL=C sort) )
      unset IFS
      # `mktemp` gives a random extension; OSD's `_import` rejects
      # anything not ending in .ndjson with `Invalid file extension`.
      # Build a fixed-name file under TMPDIR (or /tmp) so the upload's
      # filename satisfies the extension check.
      combined="${TMPDIR:-/tmp}/gateway-dashboards-combined.$$.ndjson"
      : > "$combined"
      for f in "${files_sorted[@]}"; do
        cat "$f" >> "$combined"
        echo >> "$combined"
      done
      log "  concatenated $(wc -l < "$combined") NDJSON lines from ${#files_sorted[@]} files"
      import_dashboards_file "$combined"
      rm -f "$combined"
    fi
  else
    import_dashboards_file "$DASHBOARDS_NDJSON"
  fi
else
  if [[ -z "$OSD_ENDPOINT" ]]; then
    log "Skipping Dashboards saved-objects import (OSD_ENDPOINT not set)"
  else
    log "Skipping Dashboards saved-objects import (path not found: ${DASHBOARDS_NDJSON})"
  fi
fi

log "Bootstrap complete."
