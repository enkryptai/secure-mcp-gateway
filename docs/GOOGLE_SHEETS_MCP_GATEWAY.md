# Google Sheets MCP via the Secure MCP Gateway (gateway-managed OAuth)

This guide shows how to run a **local Google Sheets MCP server**
([`mkummer225/google-sheets-mcp`](https://github.com/mkummer225/google-sheets-mcp))
behind the Enkrypt Secure MCP Gateway, with the **gateway driving the Google
OAuth flow** (browser sign-in + token refresh) instead of the server doing it
itself. It works with the gateway running in Docker.

Requires gateway image **`enkryptai/secure-mcp-gateway:v2.2.1-beta`** or later.

---

## 1. Why this is set up the way it is (read this first)

The Google Sheets MCP normally runs its **own** Google OAuth at startup (opens a
browser, binds an ephemeral `localhost` port, saves a credentials file). That is
impossible inside Docker (no browser, unreachable port), and the server ignores
any injected `Authorization`/access-token env var. So:

- The **gateway** runs the OAuth authorization-code + PKCE flow itself and
  **writes the exact credentials file** the server reads on startup
  (`.gsheets-server-credentials.json`). The server then runs headless.
- The gateway **owns the token lifecycle**: it holds the refresh token + client
  secret and **auto-refreshes** the access token before each spawn, so you do
  **not** re-authorize every hour.
- The OAuth **callback is served by the gateway itself** at `/oauth2callback`
  (no external relay).

Two non-obvious operational requirements fall out of this — see
[§6 What to look out for](#6-what-to-look-out-for). **Read them**; they are the
two things most likely to trip you up (the redirect-URI/port match and the
Docker volume for `node_modules`).

---

## 2. Prerequisites

### 2.1 Google Cloud
In the Google Cloud project that owns the OAuth client:
1. **Enable the Google Sheets API** (APIs & Services → Library → "Google Sheets API" → Enable).
2. **OAuth consent screen**: if it's in *Testing*, add every Google account that
   will authorize as a **Test user** (otherwise Google blocks them).
3. **OAuth client** (APIs & Services → Credentials → Create credentials → OAuth client ID):
   - Type: **Web application** (recommended — lets you register an exact redirect URI).
   - Authorized redirect URI: **`http://localhost:3000/oauth2callback`**
     (this exact string — see §6.1 if you change the port).
   - Download the JSON and save it as **`gcp-oauth.keys.json`**.

> A **Desktop app** client also works (it registers `http://localhost` and Google
> allows any loopback port with path `/`), but the **Web** client + exact URI is
> less surprising. The gateway reads `client_id`/`client_secret`/redirect straight
> from this keyfile — you never paste secrets into the gateway config.

### 2.2 Tooling on the host
- Docker (Desktop on Windows/Mac is fine), Node 18+, npm, git.
- A gateway **apikey** + **gateway name** (the cloud `enkrypt` provider). In the
  reference setup these are `demo_mcp_gateway` + your project apikey. Substitute
  `<APIKEY>` / `<GATEWAY_NAME>` below.

---

## 3. One-time setup

### 3.1 Build the server into a Docker **named volume** (not a bind mount)

> **Why a named volume and not `-v <hostdir>:...`?** The `googleapis` npm package
> is thousands of files; reading them over a Docker **bind mount** on Windows/Mac
> takes ~2 minutes per process start and breaks session startup. A **named
> volume** lives on the Docker VM's native fs and loads in ~1s. This is the single
> biggest gotcha. (On native Linux a bind mount is fine.)

```bat
:: 1) clone + build the server on the host
git clone https://github.com/mkummer225/google-sheets-mcp %USERPROFILE%\.enkrypt\mcp-servers\google-sheets-mcp
cd %USERPROFILE%\.enkrypt\mcp-servers\google-sheets-mcp
npm install
npm run build

:: 2) put your OAuth keyfile next to the built server
copy "%USERPROFILE%\Downloads\gcp-oauth.keys.json" dist\gcp-oauth.keys.json

:: 3) create + populate a named volume (deps installed on the fast fs)
docker volume create gsheets_mcp
docker run --rm --entrypoint bash -v gsheets_mcp:/dest -v "%USERPROFILE%\.enkrypt\mcp-servers\google-sheets-mcp:/src:ro" enkryptai/secure-mcp-gateway:v2.2.1-beta -lc "set -e; mkdir -p /dest/dist; cp /src/package.json /src/package-lock.json /dest/; cp -a /src/dist/. /dest/dist/; cd /dest && npm install --omit=dev --no-audit --no-fund; echo POPULATED"
```

The volume now holds `dist/index.js`, `node_modules`, `dist/gcp-oauth.keys.json`,
and (after §4) the materialized `dist/.gsheets-server-credentials.json`.

### 3.2 Register the server in the gateway (cloud APIs)

The server is registered once in the MCP registry and attached to your gateway.
Auth header for all these calls: `apikey: <APIKEY>`. Base URL = your Enkrypt env
(e.g. `https://api.dev.enkryptai.com`).

**a) Create the registry server** — `POST /mcp-registry/add-server`:

```json
{
  "saved_name": "google_sheets",
  "server_version": "v1",
  "server_name": "google-sheets-mcp",
  "description": "Google Sheets MCP (mkummer225) - gateway-managed Google OAuth via credentials file",
  "mcp_config": {
    "config": {
      "command": "node",
      "args": ["/app/mcp-servers/google-sheets-mcp/dist/index.js"],
      "env": {
        "GSHEETS_OAUTH_PATH": "/app/mcp-servers/google-sheets-mcp/dist/gcp-oauth.keys.json",
        "GSHEETS_CREDENTIALS_PATH": "/app/mcp-servers/google-sheets-mcp/dist/.gsheets-server-credentials.json"
      }
    },
    "oauth_config": {
      "enabled": true,
      "OAUTH_VERSION": "2.1",
      "OAUTH_GRANT_TYPE": "authorization_code",
      "OAUTH_TOKEN_DELIVERY": "google_credentials_file",
      "OAUTH_CREDENTIALS_FILE": "/app/mcp-servers/google-sheets-mcp/dist/.gsheets-server-credentials.json",
      "OAUTH_SCOPE": "https://www.googleapis.com/auth/spreadsheets",
      "OAUTH_USE_PKCE": true,
      "OAUTH_AUTHORIZATION_URL": "https://accounts.google.com/o/oauth2/v2/auth",
      "OAUTH_TOKEN_URL": "https://oauth2.googleapis.com/token",
      "OAUTH_ADDITIONAL_PARAMS": { "access_type": "offline", "prompt": "consent" }
    },
    "tools": {},
    "denied_tools": []
  }
}
```

Notes:
- **No `client_id`/`client_secret` here** — the cloud doesn't store secrets, and
  the gateway reads them from the mounted `gcp-oauth.keys.json` at authorize time.
- The runtime server name your MCP client uses is the **`saved_name`**
  (`google_sheets`), not `server_name`.
- `OAUTH_TOKEN_DELIVERY: google_credentials_file` tells the gateway to materialize
  a credentials file (and skip env-token injection). If your registry strips that
  custom key, the gateway still auto-detects it (stdio + Google token URL).

**b) Attach it to the gateway** — `PATCH /mcp-gateway/modify-gateway`
(header `X-Enkrypt-MCP-Gateway: <GATEWAY_NAME>`):

```json
{ "servers_config": { "servers": [ { "saved_name": "google_sheets", "server_version": "v1" } ] } }
```

This deep-merges (other servers untouched). Verify with
`GET /mcp-gateway/get-gateway` (header `X-Enkrypt-MCP-Gateway: <GATEWAY_NAME>`).

### 3.3 Run the gateway

```bat
docker run -d --name enkrypt-gw -p 8000:8000 -p 3000:8000 -v "%USERPROFILE%\.enkrypt\docker\enkrypt_mcp_config.json:/app/.enkrypt/docker/enkrypt_mcp_config.json" -v "gsheets_mcp:/app/mcp-servers/google-sheets-mcp" enkryptai/secure-mcp-gateway:v2.2.1-beta
```

- `-p 8000:8000` → MCP endpoint (`/mcp/`) + APIs.
- `-p 3000:8000` → makes the OAuth redirect `http://localhost:3000/oauth2callback`
  reach the gateway. **Both map to the container's 8000** (the gateway has one
  port; 3000 is just so the registered redirect URL resolves). If you registered a
  different redirect port, publish that instead.
- The `enkrypt_mcp_config.json` is the gateway's provider config (cloud `enkrypt`
  auth/guardrails). Keep telemetry disabled unless you run the observability stack.

---

## 4. Authorize (one-time browser sign-in)

You only do this once per Google account; the gateway refreshes the token
afterwards. Two ways:

**a) From an MCP client / LLM** — call the gateway tool:
`enkrypt_oauth_authorize` with `{ "server_name": "google_sheets" }`. It returns an
`auth_url`. Open it, approve. (If the gateway runs on a host with a browser, it
auto-opens it.)

**b) From the CLI** — `POST http://localhost:8000/api/v1/oauth/authorize`
(headers `apikey: <APIKEY>`, `X-Enkrypt-MCP-Gateway: <GATEWAY_NAME>`, body
`{"server_name":"google_sheets"}`). Open the returned `auth_url`, approve.

After approval the browser is redirected to
`http://localhost:3000/oauth2callback`, the gateway exchanges the code, and you
see **"Authorization Successful"**. Check status anytime:
`GET http://localhost:8000/api/v1/oauth/status?server_name=google_sheets`.

---

## 5. Use it

Point any MCP client at the gateway:

```json
{
  "mcpServers": {
    "Enkrypt Gateway HTTP": {
      "url": "http://localhost:8000/mcp/",
      "headers": { "apikey": "<APIKEY>", "X-Enkrypt-MCP-Gateway": "<GATEWAY_NAME>" }
    }
  }
}
```

Then: `enkrypt_list_all_servers` → see `google_sheets`; `enkrypt_discover_all_tools`
(`server_name: google_sheets`) → 16 tools (`create_spreadsheet`, `edit_cell`,
`read_all_from_sheet`, …); `enkrypt_secure_call_tools` to run them (guardrails
applied).

**No MCP client? Use the bundled test client** (`tools/gsheets_e2e_test.py`):

```bat
set ENKRYPT_GW_APIKEY=<APIKEY>
uv run --with mcp python tools\gsheets_e2e_test.py list
uv run --with mcp python tools\gsheets_e2e_test.py discover --server google_sheets
uv run --with mcp python tools\gsheets_e2e_test.py call --server google_sheets --tool create_spreadsheet --args "{\"title\":\"Hello\"}"
uv run --with mcp python tools\gsheets_e2e_test.py gcall --tool enkrypt_oauth_authorize --args "{\"server_name\":\"google_sheets\"}"
```

---

## 6. What to look out for

### 6.1 Redirect URI must match exactly (Web client)
Google rejects the flow (`redirect_uri_mismatch`) unless the redirect the gateway
sends matches a **registered** one. The gateway reads the redirect from your
`gcp-oauth.keys.json`. So the registered URI, the keyfile, and the published port
must agree. Reference setup: keyfile registers `http://localhost:3000/oauth2callback`
→ run with `-p 3000:8000`. Change the port everywhere if you change it.
(Desktop-app clients are lenient on loopback port but match the path `/`.)

### 6.2 Never bind-mount `node_modules` on Windows/Mac Docker
Use the named volume (§3.1). A bind mount makes `require('googleapis')` take
~120s and the session times out. Native Linux Docker is fine either way.

### 6.3 Token refresh & re-auth
The gateway auto-refreshes the access token (using the stored refresh token) — no
hourly re-auth. You only re-run §4 if the **refresh token** is revoked (you remove
the app's access in your Google account, change scopes, or Google expires it for a
*Testing* app after ~7 days). Symptom: tool returns `Error: invalid_request` and
`/api/v1/oauth/status` shows the last refresh failed → re-authorize.

### 6.4 First call after a cold start
The first tool call after the container starts spawns Node (loads `googleapis`,
~1-2s from the volume). The session is pooled afterwards. If you see
"Could not establish MCP session within Ns", raise
`common_mcp_gateway_config.session_pool_connect_timeout` (default 60s).

### 6.5 Scope
Configured scope is `spreadsheets` (create/read/edit sheets you own or are shared
by ID). It cannot browse arbitrary Drive files. Add Drive scopes to
`OAUTH_SCOPE` + the consent screen if you need that.

### 6.6 Updating the keyfile or server code
The named volume is a *copy*. If you rotate `gcp-oauth.keys.json` or rebuild the
server, re-run the populate step (§3.1) or `docker cp` the new file into the
volume, then restart the container and re-authorize.

### 6.7 Where things live
- Server + deps + creds: Docker volume `gsheets_mcp` →
  `/app/mcp-servers/google-sheets-mcp/...` in the container.
- Materialized token: `dist/.gsheets-server-credentials.json` (in the volume).
- Gateway OAuth endpoints: `POST /api/v1/oauth/authorize`, `GET /oauth2callback`,
  `GET /api/v1/oauth/status` (all on port 8000).

---

## 7. Quick troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `redirect_uri_mismatch` in browser | Registered URI ≠ what the gateway sent. Align keyfile redirect, the GCP console URI, and the published port (§6.1). |
| "Access blocked / app not verified" | Your Google account isn't a Test user on the consent screen (§2.1). |
| `Could not establish MCP session within Ns` | Cold `googleapis` load; ensure you used the **named volume**, not a bind mount (§6.2); raise `session_pool_connect_timeout`. |
| Tool returns `Error: invalid_request` | Token expired and refresh failed → re-run authorize (§6.3). |
| "OAuth not ready … credentials file not found" | You haven't authorized yet → run §4. |
| `enkrypt_oauth_authorize` returns "No OAuth client_id" | `gcp-oauth.keys.json` missing from the volume's `dist/`, or has no `web`/`installed` block. |
