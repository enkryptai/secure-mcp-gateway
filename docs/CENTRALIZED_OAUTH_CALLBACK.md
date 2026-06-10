# Remote OAuth Callback (Gateway-Hosted)

**Feature:** Gateway-managed OAuth 2.1 Authorization-Code + PKCE flow with a
configurable **public** redirect, so a remotely deployed gateway (e.g.
`https://mcp.dev.enkryptai.com`) can complete the browser sign-in instead of
being limited to `http://localhost`.

**Status:** Implemented. Verified locally.
**Last Updated:** 2026-06-10

> ⚠️ **This supersedes the old "centralized relay" design.** Earlier drafts of
> this doc described a single `https://app.enkryptai.com/oauth/callback` relay
> that POSTed codes back to each gateway (via a `centralized_callback.py`
> module). **That was never implemented and does not exist.** The real design
> is simpler: **each gateway hosts its own callback** on its own public URL.
> There is no relay service and no shared callback host.

---

## How it actually works

The gateway already runs a Starlette/uvicorn app on port **8000** (the same one
serving `/mcp/`). The OAuth endpoints ride on that app — no extra port, no
separate callback server. The callback is protected not by the gateway apikey
(the IdP redirect can't send it) but by a one-time, short-lived `state` (CSRF)
that must match a flow this gateway started, plus PKCE.

```
                         ┌──────────────────────────────────────┐
  (1) authorize          │  MCP client / LLM  OR  REST caller    │
  ───────────────────────▶  enkrypt_oauth_authorize (MCP tool)   │
                         │  POST /api/v1/oauth/authorize         │
                         └───────────────────┬───────────────────┘
                                             │ returns auth_url + state
                                             ▼
                         ┌──────────────────────────────────────┐
  (2) user approves      │  User's browser → IdP (e.g. Google)   │
                         └───────────────────┬───────────────────┘
                                             │ 302 to redirect_uri?code&state
                                             ▼
                         ┌──────────────────────────────────────┐
  (3) callback lands on  │  GET <PUBLIC_URL>/oauth2callback      │
      THIS gateway       │  on the gateway itself (port 8000)    │
                         └───────────────────┬───────────────────┘
                                             │ validate state + PKCE,
                                             │ exchange code → token
                                             ▼
                         ┌──────────────────────────────────────┐
  (4) deliver token      │  write credentials file the server    │
                         │  reads on startup (file-mode servers) │
                         │  + cache token in TokenManager        │
                         └──────────────────────────────────────┘
```

The whole point of the `<PUBLIC_URL>` in step (3) is what this feature adds: on
a remote deployment the redirect must come back to the gateway's **public**
host, not `localhost`.

### Endpoints (served on the gateway, port 8000)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/oauth/authorize` | gateway apikey | Start a flow → `{ auth_url, state, redirect_uri, credentials_file, expires_in }` |
| `GET  /oauth2callback` (+ aliases, see below) | `state` + PKCE | IdP redirects here; exchanges code, delivers token |
| `GET  /` | `state` + PKCE | Default loopback callback (for Google **Desktop** clients that match on `/`); also a neutral landing page |
| `GET  /api/v1/oauth/status?server_name=…` | gateway apikey | `{ credentials_present, flow_pending, last_result }` |

There is also an MCP **tool**, `enkrypt_oauth_authorize(server_name)`, that an
LLM/client can call directly to begin the flow (it returns the same `auth_url`).

Code: [`gateway_oauth_routes.py`](../src/secure_mcp_gateway/gateway_oauth_routes.py),
[`gateway.py`](../src/secure_mcp_gateway/gateway.py) (tool + route registration),
[`services/oauth/`](../src/secure_mcp_gateway/services/oauth/).

> **Scope note.** Today this gateway-managed *browser* flow targets stdio
> servers whose token is delivered via a **credentials file** (e.g.
> `mkummer225/google-sheets-mcp`, `OAUTH_TOKEN_DELIVERY=google_credentials_file`).
> Server-to-server OAuth (`client_credentials`) and env-injection
> `authorization_code` are handled by the existing
> [`oauth_service`](../src/secure_mcp_gateway/services/oauth/oauth_service.py)
> paths and do not require this browser callback. The public-URL work below
> applies to the browser flow.

---

## Configuration

Set the gateway's **public, externally-reachable base URL**. Everything else is
derived from it.

### Option A — environment variable (recommended for containers/k8s)

```bash
export ENKRYPT_GATEWAY_BASE_URL=https://mcp.dev.enkryptai.com
```

### Option B — config file (`enkrypt_mcp_config.json`)

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_gateway_base_url": "https://mcp.dev.enkryptai.com"
  }
}
```

The gateway then advertises **`https://mcp.dev.enkryptai.com/oauth2callback`**
as the OAuth `redirect_uri`.

**Optional** — pin the full redirect URI when the callback path differs from the
default `/oauth2callback`:

```bash
export ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI=https://mcp.dev.enkryptai.com/some/other/callback
# or  common_mcp_gateway_config.enkrypt_oauth_redirect_uri
```

Accessors: [`utils.get_gateway_base_url()`](../src/secure_mcp_gateway/utils.py),
[`utils.get_gateway_oauth_redirect_uri()`](../src/secure_mcp_gateway/utils.py).

### Redirect-URI resolution priority

When a flow starts, the redirect is resolved highest-priority-first:

1. **Explicit** `OAUTH_REDIRECT_URI` in the server's `oauth_config` or the
   `/authorize` request body (`redirect_uri` / `oauth_config.OAUTH_REDIRECT_URI`).
2. **Configured public URL** — `ENKRYPT_GATEWAY_BASE_URL` (or
   `enkrypt_gateway_base_url`) → `<base>/oauth2callback`. *Set this on remote
   deploys.*
3. **Keyfile loopback** — `redirect_uris[0]` from the mounted
   `gcp-oauth.keys.json`. *This is the unchanged local-install default.*
4. **Request-derived** — built from `X-Forwarded-Proto`/`X-Forwarded-Host` (or
   `Host`) of the inbound `/authorize` request. Last resort; depends on proxy
   header hygiene, so prefer #2.

> Whatever is chosen **must be registered with the IdP** (see below). If it
> isn't, the IdP returns `redirect_uri_mismatch`.

### Supported callback paths

OAuth 2.0/2.1 do **not** standardize a callback path — `redirect_uri` is opaque
to the spec, and the only rule is **exact-match registration** at the IdP. To
reduce setup friction the gateway **accepts the callback on several well-known
paths** (all behave identically — same handler, same `state`+PKCE protection):

```text
/oauth2callback     ← advertised default (Google @google-cloud/local-auth convention)
/oauth/callback
/oauth2/callback
/callback
/auth/callback
/                   ← also the loopback redirect for Google Desktop clients
```

You only need to register the **one** you actually use with your IdP — pick
whichever your IdP/convention prefers; it will work without changing the gateway.

The gateway also **auto-serves the path of a configured redirect**: if you set
`ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI` (or a server's `OAUTH_REDIRECT_URI`) to a
custom path (e.g. `…/sso/return`), that exact path is registered too — so what
the gateway advertises is always what it serves. (Routes bind once at startup,
so switching to a *brand-new* custom path requires a gateway restart; the
well-known paths above are always available.)

---

## Local install (unchanged)

No `ENKRYPT_GATEWAY_BASE_URL` set → the gateway uses the loopback redirect
registered in `gcp-oauth.keys.json` (e.g. `http://localhost:3000/oauth2callback`),
and auto-opens the browser when not running in a container. Nothing about the
local flow changes. See
[GOOGLE_SHEETS_MCP_GATEWAY.md](GOOGLE_SHEETS_MCP_GATEWAY.md) for the full local
walkthrough.

---

## Remote deployment checklist

To make the callback work at `https://mcp.dev.enkryptai.com`:

1. **Set the public URL.** `ENKRYPT_GATEWAY_BASE_URL=https://mcp.dev.enkryptai.com`
   on the gateway container.

2. **Register the redirect with the IdP** *(manual step — only you can do this)*.
   For Google: **Cloud Console → APIs & Services → Credentials → your OAuth 2.0
   Client (type: Web application) → Authorized redirect URIs →** add
   `https://mcp.dev.enkryptai.com/oauth2callback`. Google requires **HTTPS** for
   non-localhost redirects. Add the same URI to the `redirect_uris` array of the
   `gcp-oauth.keys.json` mounted in the pod (a Web client may list both the
   localhost and the public URI).

3. **Route the callback through the ingress.** The ingress/LB in front of the
   gateway must forward **`GET /oauth2callback`** (and ideally `GET /`) to the
   gateway Service on port 8000 — not just `/mcp/`. It should also pass
   `X-Forwarded-Proto: https` and `X-Forwarded-Host` (most ingress controllers
   do by default).

4. **Single replica or sticky sessions.** Pending flows are held **in memory**
   per process (keyed by `state`, TTL 600s — see `_pending_flows` in
   `gateway_oauth_routes.py`). The browser's callback request **must hit the
   same pod** that started the flow. So either run **`replicas: 1`** (the dev
   manifest already does) **or** enable **session affinity / sticky sessions** on
   the ingress for these paths. With multiple replicas and no affinity you'll see
   *"Invalid or Expired State"* intermittently. *(A shared/Redis-backed flow
   store would lift this restriction — not yet implemented.)*

5. **(File-mode servers only, e.g. Google Sheets.)** The downstream server's
   files **and** its `gcp-oauth.keys.json` must be mounted in the gateway pod,
   and the credentials-file path must be **writable**, because the callback
   writes the credentials file the server reads. The current dev k8s manifest
   does **not** mount the Google Sheets server — that is a separate task.

6. **HTTPS.** The gateway must be reachable over HTTPS at the public URL (TLS is
   normally terminated at the ingress). OAuth 2.1 + Google both require it.

---

## Walkthrough — Google Sheets on a remote gateway

```bash
# On the gateway (container env)
ENKRYPT_GATEWAY_BASE_URL=https://mcp.dev.enkryptai.com
```

```jsonc
// Google Cloud Console → OAuth Web client → Authorized redirect URIs:
//   https://mcp.dev.enkryptai.com/oauth2callback
// gcp-oauth.keys.json (mounted in the pod) "web" block:
{
  "web": {
    "client_id": "…apps.googleusercontent.com",
    "client_secret": "GOCSPX-…",
    "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "redirect_uris": ["https://mcp.dev.enkryptai.com/oauth2callback"]
  }
}
```

Start the flow (either path):

```bash
# REST
curl -sX POST https://mcp.dev.enkryptai.com/api/v1/oauth/authorize \
  -H "apikey: <GATEWAY_KEY>" -H "content-type: application/json" \
  -d '{"server_name": "google_sheets"}'
# → { "auth_url": "...", "redirect_uri": "https://mcp.dev.enkryptai.com/oauth2callback", ... }
```

…or have the LLM call the `enkrypt_oauth_authorize` MCP tool. Open `auth_url`,
approve, and the IdP redirects to `…/oauth2callback`, where the gateway exchanges
the code, writes the credentials file, and the server's tools work. The gateway
owns token refresh thereafter (it holds the refresh_token + client creds), so no
re-auth until the refresh token is revoked. Check state any time:

```bash
curl -s "https://mcp.dev.enkryptai.com/api/v1/oauth/status?server_name=google_sheets" \
  -H "apikey: <GATEWAY_KEY>"
```

---

## Security notes

- **CSRF:** one-time `state` per flow; the callback drops the flow on use and
  rejects unknown/expired state (TTL 600s).
- **PKCE:** S256 verifier/challenge enforced for OAuth 2.1 authorization-code.
- **Offline access:** Google flows force `access_type=offline&prompt=consent` so
  a `refresh_token` is returned (the gateway needs it to refresh file-mode creds).
- **No apikey on the callback:** the `GET /oauth2callback` endpoint can't require
  the gateway apikey (the IdP redirect won't carry it); `state`+PKCE is the
  protection. The `authorize`/`status` endpoints **do** require the apikey.
- **Secrets:** `client_secret` comes from the mounted keyfile, never from the
  cloud registry; tokens are written atomically and masked in logs.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| IdP error `redirect_uri_mismatch` | The advertised redirect isn't registered | Register the **exact** `redirect_uri` from the `/authorize` response in the IdP (and the keyfile) |
| Callback page: *"Invalid or Expired State"* | Took >600s, **or** the callback hit a different replica | Restart the flow; run `replicas: 1` or enable sticky sessions |
| Callback never reaches the gateway (404/timeout) | Ingress only routes `/mcp/` | Route `GET /oauth2callback` (and `/`) to the gateway Service:8000 |
| Redirect comes back as `http://<pod-ip>:8000/…` | No public URL configured; relied on request-derived | Set `ENKRYPT_GATEWAY_BASE_URL` |
| `Token Exchange Failed` | Bad client creds / scope / expired code | Verify keyfile creds; complete approval promptly |
| `Could Not Save Credentials` | Creds-file path not mounted/writable in the pod | Mount the server dir; ensure the creds path is writable |

---

## Quick reference

```text
ENKRYPT_GATEWAY_BASE_URL              # public base URL → <base>/oauth2callback
ENKRYPT_GATEWAY_OAUTH_REDIRECT_URI    # optional: pin the full redirect URI
common_mcp_gateway_config.enkrypt_gateway_base_url
common_mcp_gateway_config.enkrypt_oauth_redirect_uri
```

- Routes/flow: [`gateway_oauth_routes.py`](../src/secure_mcp_gateway/gateway_oauth_routes.py)
- Accessors: [`utils.py`](../src/secure_mcp_gateway/utils.py) → `get_gateway_base_url`, `get_gateway_oauth_redirect_uri`
- File-mode creds: [`services/oauth/local_credentials.py`](../src/secure_mcp_gateway/services/oauth/local_credentials.py)
- Tests: [`tests/test_gateway_oauth_remote_redirect.py`](../tests/test_gateway_oauth_remote_redirect.py)
- Local Google Sheets setup: [GOOGLE_SHEETS_MCP_GATEWAY.md](GOOGLE_SHEETS_MCP_GATEWAY.md)
