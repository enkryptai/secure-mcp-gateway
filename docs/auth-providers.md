# Auth providers

The gateway selects an auth provider via `plugins.auth.provider` in the
config file. Two are shipped today:

| `provider` | Class | Source of truth | Use when |
| --- | --- | --- | --- |
| `local_apikey` (default) | `LocalApiKeyProvider` | `~/.enkrypt/enkrypt_mcp_config.json` (`apikeys` / `projects` / `users` / `mcp_configs` blocks) | self-hosted, single-tenant, configs edited by hand or via `secure-mcp-gateway config ...` CLI |
| `enkrypt` | `EnkryptAuthProvider` | `GET {base_url}/mcp-gateway/get-gateway-config` (Enkrypt cloud) | multi-tenant, configs managed in the Enkrypt dashboard, per-request apikeys from many clients |

Whichever provider is registered, `AuthConfigManager.extract_credentials()`
reads the calling MCP client's `apikey` header and forwards it as the
`gateway_key` on every authenticate call. So both providers are inherently
per-request — the boot-time `apikey` in `auth.config` is only a fallback for
clients that don't supply their own.

## `enkrypt` provider — required config shape

```json
{
  "plugins": {
    "auth": {
      "provider": "enkrypt",
      "config": {
        "apikey": "<fallback enkrypt apikey>",
        "gateway_name": "<saved_name from /mcp-gateway/add-gateway>",
        "gateway_version": "v1",
        "project_name": "default",
        "base_url": "https://api.enkryptai.com",
        "cache_ttl_seconds": 600
      }
    }
  }
}
```

| Key | Required | Default | Notes |
| --- | --- | --- | --- |
| `gateway_name` | yes, unless clients send the header | — | Matches the `saved_name` field on the cloud's `add-gateway` response. Sent as the `X-Enkrypt-MCP-Gateway` request header on the outbound cloud call. May be omitted here and supplied per request by the MCP client's own `X-Enkrypt-MCP-Gateway` header; when both are present this config value wins and the header is ignored (logged at INFO). |
| `gateway_version` | no | the request's `X-Enkrypt-MCP-Gateway-Version` header, else `"v1"` | Sent as `X-Enkrypt-MCP-Gateway-Version` on the outbound cloud call. Setting it here pins the version process-wide and overrides the client header (logged at INFO); omit it so header-routed deployments can serve gateways registered under different versions. |
| `project_name` | no | inferred from apikey ownership; defaults to `"default"` if the apikey isn't a project apikey | Sent as `X-Enkrypt-Project`. |
| `apikey` | no | — | Boot-time fallback used when an MCP client connects without its own apikey header. |
| `base_url` | no | `https://api.enkryptai.com` | Trailing slash stripped. |
| `cache_ttl_seconds` | no | 600 | In-process cache TTL for cloud responses. |

### Gateway identity resolution (name + version)

The cloud looks a gateway up by the pair `(gateway_saved_name,
gateway_version)`. Both halves resolve with the same precedence, first
match wins:

1. `auth.config.<gateway_name|gateway_version>` — pinned by the operator,
   always beats a client header (a differing header is logged at INFO and
   dropped).
2. The request header (`X-Enkrypt-MCP-Gateway` /
   `X-Enkrypt-MCP-Gateway-Version`).
3. Default — none for the name (auth fails with
   `AuthStatus.INVALID_CREDENTIALS`), `"v1"` for the version.

Pinning the version is only right when the process serves a single cloud
gateway. A header-routed deployment (`gateway_name` unset, several tenants
on one process) must leave `gateway_version` unset, because the version is
part of the lookup key: with a pinned `v1`, any gateway registered as `1`
or `v2` returns

```json
{"code": 404, "error": "Resource not found", "message": "MCP gateway not found"}
```

which surfaces to the MCP client as `AuthStatus.ERROR` on every call. The
in-process cache keys on the resolved version too, so two versions of the
same gateway never share an entry.

### Removed keys (hard fail)

The pre-rewrite `enkrypt` provider accepted `api_key`, `use_remote_config`
and `timeout`. Those are gone — booting with any of them raises
`ValueError` so operators see the rename instead of silently picking up
old behaviour. Replace with the keys above; the auth timeout is now read
from the global `timeout_settings.auth_timeout`.

## How the cloud response is mapped

The cloud returns an `ExpandedGatewayConfig` (see
`enkryptai-apiaas/docs/mcp-gateway/mcp-gateway-api-spec.yaml`). The
provider maps it to the internal gateway-config dict every other service
expects. The interesting bits:

- `request_context.user_id` populates the metric `user_id` label
  (apikey owner today; an end-user UUID once the calling app forwards
  one through the cloud).
- `request_context.user_email` populates the dashboard `var-email`
  template variable.
- `project_id` is mirrored from `project_name` until the cloud surfaces
  a stable UUID.
- Unmapped `request_context` fields (`org_id`, `actioner`,
  `registry_name`, etc.) are kept under `AuthResult.metadata` for log
  enrichment but are NOT promoted to metric labels (cardinality).

### `request_context` — fields the deployed cloud returns today (May 2026)

```json
"request_context": {
    "gateway_version": "v1",
    "user_id": "28cbcf05-653c-46fb-971c-2db57f4106ab",
    "registry_name": "default",
    "project_name": "test",
    "gateway_saved_name": "my-dev-gateway"
}
```

Fields the mapper already consumes when present, but the cloud has not
shipped yet (May 2026):

- `org_id` — already shipped on dev as of 2026-05-05. May arrive as `null`
  when the gateway isn't bound to an organisation; null entries are
  filtered out before being surfaced as `AuthResult.metadata` so they
  don't pollute OTel attributes.
- `actioner` — pending on the cloud side. Same null-filter treatment will
  apply automatically once returned.
- `user_email` — shipped on dev as of 2026-05-20; when the calling app
  doesn't forward an end-user, `email` is `not_provided`.
- `project_id` (UUID) — pending; until the cloud returns it, `project_id`
  in the gateway equals `project_name`.

### Nullable fields

The cloud may return `null` (not just absent) for any of:
`org_id`, `actioner`, `project_name`, `project_id`, `user_id`,
`user_email`. The mapper treats `null` and "absent" identically:

- For promoted fields (`project_name`, `project_id`, `user_id`, `email`),
  null falls through the normal fallback chain
  (`request_context` → top-level response → `auth.config` → hard default).
- For pass-through fields kept under `_request_context_extra`, null entries
  are dropped entirely so they never reach metric labels or OTel attribute
  setters.

The regression tests `test_map_response_filters_null_values_from_request_context_extra`,
`test_map_response_falls_back_when_project_name_is_null`, and
`test_map_response_handles_real_cloud_shape` lock in this behaviour;
update them if the cloud team changes the contract.

## Override resolution

For each of the three guardrail-style fields — `input_guardrails_config`,
`output_guardrails_config`, `server_tools_guardrails_config` — the mapper
picks the effective value per server using this precedence (first match
wins). `server_tools_guardrails_config` is **common-only** (never read
from per-server overrides or base config):

1. **`response.common_overrides.<key>`** — gateway-wide override. **Always
   wins** when set. The cloud already strips the same key from each
   server's `mcp_config` for us, but it still echoes any per-server
   value in `gateway_overrides` for visibility; the mapper ignores that
   echo when common is set so the runtime matches the cloud's
   "common always wins" contract.
2. **`expanded_servers[].gateway_overrides.<key>`** — per-server override,
   effective only when `common_overrides` doesn't also set this key.
3. **`expanded_servers[].mcp_config.<key>`** — registry server base value.

Empty `{}` is treated as "not set" and falls through to the next layer,
matching the existing per-server convention.

`oauth_config` is **not** part of the four common-override fields — it
lives only on `mcp_config` / per-server `gateway_overrides`, and is
layered on top of the local `oauth_config` fallback if present.

## `local_server_overrides`

`sandbox`, `denied_tools` and the legacy `oauth_config` field aren't yet
part of the cloud spec but are first-class in the gateway. To layer them
onto cloud-fetched servers, add a top-level `local_server_overrides`
block to the local config file:

```json
{
  "local_server_overrides": {
    "echo_server": {
      "sandbox": { "enabled": true, "image": "python:3.11-slim" },
      "denied_tools": [{ "pattern": "delete_*", "reason": "no destructive ops" }]
    }
  }
}
```

Keys are server `saved_name`s. Cloud values win for any field present on
both sides — local entries only fill gaps.

## Failure handling

The provider hard-fails any cloud transport / 5xx / non-JSON error and
surfaces it as `AuthStatus.ERROR` with the upstream message attached.
No local-file fallback, no stale-cache serving. Watch the
`auth_failure_counter` metric (label `failure_reason`) and the gateway
logs (`[EnkryptAuthProvider] fetching gateway config: ...`) to alert on
upstream outages.

## Migrating MCP client config

The `apikey` header contract is provider-specific. If an MCP client
sends headers that match the *other* provider's contract, the gateway
will silently fail authentication — `local_apikey` will reject the
request as "no matching key", `enkrypt` will forward the value to the
cloud and get a 401 back.

### Header contract per provider

| Provider | Required headers | Optional headers |
| --- | --- | --- |
| `local_apikey` | `ENKRYPT_GATEWAY_KEY` | `project_id`, `user_id` |
| `enkrypt` | `apikey` | `X-Enkrypt-MCP-Gateway` — required only when `auth.config.gateway_name` is unset; ignored when it is set. `X-Enkrypt-MCP-Gateway-Version` — used when `auth.config.gateway_version` is unset (defaults to `v1`); ignored when it is set |

When a request arrives, `AuthConfigManager.extract_credentials()` reads
both shapes (this is for backwards compatibility); the active provider
then picks what it needs from the resulting credential bag. Cloud auth
forwards `gateway_key` (which prefers `ENKRYPT_GATEWAY_KEY` over
`apikey` for historical reasons) as the outbound `apikey` to the cloud,
so a stale `ENKRYPT_GATEWAY_KEY` from an old local-mode `mcp.json` will
override the correct `apikey` and produce 401s. Send only the headers
your active provider needs.

### Diagnosing the wrong key

The gateway logs every cloud auth call masked-but-traceable:

```
[EnkryptAuthProvider] fetching gateway config: gateway=my-dev-gateway/v1 project=test apikey=****05yg
```

Match the last 4 characters against the apikey you expect. Mismatch =
the client is sending the wrong header.

### Migrating with the CLI

`secure-mcp-gateway install <client>` is provider-aware: it reads the
local config's `plugins.auth.provider` and writes the matching header /
env-var shape into the client's MCP config.

```bash
# Cloud auth, streamable-HTTP gateway already running on localhost:8000
secure-mcp-gateway install cursor \
  --transport http \
  --apikey <YOUR_ENKRYPT_CLOUD_APIKEY> \
  --url http://localhost:8000/mcp/

# Cloud auth, stdio (gateway spawned by the client as a subprocess)
secure-mcp-gateway install claude-desktop \
  --apikey <YOUR_ENKRYPT_CLOUD_APIKEY>

# Local apikey mode — --apikey is ignored; uses the apikeys block
secure-mcp-gateway install cursor
```

Generated config shapes:

| Mode | Transport | Generated entry |
| --- | --- | --- |
| `enkrypt` | `http` | `{ "url": ..., "headers": { "apikey": "<key>" } }` |
| `enkrypt` | `stdio` | `{ "command": ..., "args": ..., "env": { "ENKRYPT_APIKEY": "<key>" } }` |
| `local_apikey` | `http` | `{ "url": ..., "headers": { "ENKRYPT_GATEWAY_KEY": ..., "project_id": ..., "user_id": ... } }` |
| `local_apikey` | `stdio` | `{ "command": ..., "args": ..., "env": { "ENKRYPT_GATEWAY_KEY": ..., "ENKRYPT_PROJECT_ID": ..., "ENKRYPT_USER_ID": ... } }` |

Stdio installs read the env vars via the gateway's
`extract_credentials()` env-var fallback chain. The cloud-mode
`ENKRYPT_APIKEY` env var takes priority over the legacy
`ENKRYPT_GATEWAY_KEY` so that a leftover legacy var in a shared shell
session doesn't override a fresh cloud install.

### Manually editing `mcp.json`

If you're editing a Cursor / Claude Desktop config by hand, the
streamable-HTTP entry for cloud-auth gateways is exactly:

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "url": "http://localhost:8000/mcp/",
      "headers": { "apikey": "<YOUR_ENKRYPT_CLOUD_APIKEY>" }
    }
  }
}
```

Notably absent: `ENKRYPT_GATEWAY_KEY`, `project_id`, `user_id`. Those
were the local-mode shape; cloud auth derives identity from the apikey
itself.

## Cache

In-process `apikey -> mapped_config` cache, default TTL 600 s. Apikey is
SHA-256 hashed before use as a cache key (never plain text in memory).
Cleared via:

```python
from secure_mcp_gateway.plugins.auth.config_manager import auth_manager
auth_manager.get_provider().invalidate_cache()
```

A future CLI / API endpoint will expose this; for now it's a Python-API
hook used by tests.
