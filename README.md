# Enkrypt AI Secure MCP Gateway

![enkrypt-secure-mcp-gateway-hld](./docs/images/enkrypt-secure-mcp-gateway-hld.png)

> **📖 Featured Blog Post:** Learn how the Secure MCP Gateway prevents top attacks and vulnerabilities in our latest blog:
>
> **[How Enkrypt's Secure MCP Gateway and MCP Scanner Prevent Top Attacks](https://www.enkryptai.com/blog/how-enkrypts-secure-mcp-gateway-and-mcp-scanner-prevent-top-attacks)**
>
> Discover real-world attack scenarios, security best practices, and how our gateway protects your AI applications.

## Overview

This Secure MCP Gateway is built with authentication, automatic tool discovery, caching, and guardrail enforcement.

It sits between your MCP client and MCP servers. So, by it's nature it itself also acts as an MCP server as well as an MCP client :)

When your MCP client connects to the Gateway, it acts as an MCP server. When the Gateway connects to the actual MCP server, it acts as an MCP client.

- [Pypi Package](https://pypi.org/project/secure-mcp-gateway/)

- [Docker Image](https://hub.docker.com/r/enkryptai/secure-mcp-gateway)

- Also see:
  - [CLI-Commands-Reference.md](./CLI-Commands-Reference.md) for the list of commands and their usage
  - [API-Reference.md](./API-Reference.md) for the list of API endpoints and their usage
  - [MCP Gateway Setup Notebook](./mcp_gateway_setup.ipynb) for a complete walkthrough of all the essential commands

## Table of Contents

- [1. Features 🚀](#1-features)
- [2. High level steps of how the MCP Gateway works 🪜](#2-high-level-steps-of-how-the-mcp-gateway-works)
- [3. Prerequisites 🧩](#3-prerequisites)
- [4. Gateway Setup 👨‍💻](#4-gateway-setup)
- [5. (Optional) OpenTelemetry Setup 📊](#5-optional-opentelemetry-setup)
- [6. Verify Installation and check the files generated ✅](#6-verify-installation-and-check-the-files-generated)
- [7. Edit the Gateway config as needed ✏️](#7-edit-the-gateway-config-as-needed)
- [8. CLI Quick Start Guide 🖥️](#8-cli-quick-start-guide)
- [9. (Optional) Add GitHub MCP Server to the Gateway 🤖](#9-optional-add-github-mcp-server-to-the-gateway)
- [9.1 (Optional) Connect to MCP Servers with OAuth 🔐](#91-optional-connect-to-mcp-servers-with-oauth)
- [10. (Optional) Protect GitHub MCP Server and Test Echo Server 🔒](#10-optional-protect-github-mcp-server-and-test-echo-server)
- [11. Recommendations for using Guardrails 💡](#11-recommendations-for-using-guardrails)
- [12. Other tools available 🔧](#12-other-tools-available)
- [13. (Optional) Sandbox Isolation 🛡️](#13-optional-sandbox-isolation)
- [14. Deployment Patterns 🪂](#14-deployment-patterns)
- [15. Uninstall the Gateway 🗑️](#15-uninstall-the-gateway)
- [16. Troubleshooting 🕵](#16-troubleshooting)
- [17. Known Issues being worked on 🏗️](#17-known-issues-being-worked-on)
- [18. Known Limitations ⚠️](#18-known-limitations)
- [19. Contribute 🤝](#19-contribute)
- [20. Testing 🧪](#20-testing)
- [21. License](#21-license)

## 1. Features

![enkrypt-secure-mcp-gateway-features](./docs/images/enkrypt-secure-mcp-gateway-features.png)

Below are the list of features Enkrypt AI Secure MCP Gateway provides:

1. **Authentication**: We use Unique Key to authenticate with the Gateway. We also use Enkrypt API Key if you want to protect your MCPs with Enkrypt Guardrails. Additionally, a secure `admin_apikey` (256-character random string) is automatically generated at the **root** of the config for administrative REST API operations. (When `plugins.auth.provider` is `enkrypt`, `admin_apikey` is **optional** — the Enkrypt cloud `api_key` doubles as the admin credential for most REST endpoints. The cache-flush endpoint specifically uses a stricter org-id-gated policy under cloud auth — see [Hot-Reload Auth Policy](#cache-flush-authorization-policy).)

2. **Ease of use**: You can configure all your MCP servers either locally in `enkrypt_mcp_config.json` or — better yet for teams and production — in **Enkrypt cloud** (run `secure-mcp-gateway generate-config --provider enkrypt`). The cloud owns the server list, guardrail policies, and `common_overrides`, and the gateway pulls them at request time with a 5-minute TTL.

3. **Dynamic Tool Discovery**: The Gateway discovers tools from the MCP servers dynamically and makes them available to the MCP client

4. **Restrict Tool Invocation**: If you don't want all tools to be accessible of a an MCP server, you can restrict them by explicitly mentioning the tools in the Gateway config so that only the allowed tools are accessible to the MCP client

5. **Caching**: We cache the user gateway config and tools discovered from various MCP servers locally or in an external cache server like KeyDB if configured to improve performance

6. **Guardrails**: You can configure guardrails for each MCP server in Enkrypt both on input side (before sending the request to the MCP server) and output side (after receiving the response from the MCP server)

7. **Logging**: We log every request and response from the Gateway locally in your MCP logs and also forward them to Enkrypt *(Coming soon)* for monitoring. This enables you to see all the calls made in your account, servers used, tools invoked, requests blocked, etc.

8. **Sandbox Isolation**: MCP servers can be launched inside isolated sandbox environments (Docker, Podman, or microVMs) so that a compromised or malicious server cannot access the host filesystem, network, or other resources. Each sandbox is ephemeral — created per session and destroyed when done.

### 1.1 Guardrails

![enkrypt-secure-mcp-gateway-guardrails](./docs/images/enkrypt-secure-mcp-gateway-guardrails.png)

**Input Protection:** Topic detection, NSFW filtering, toxicity detection, injection attack prevention, keyword detection, policy violation detection, bias detection, and PII redaction (More coming soon like system prompt protection, copyright protection, etc.)

**Output Protection:** All input protections plus adherence checking and relevancy validation (More coming soon like hallucination detection, etc.) We also auto unredact the response if it was redacted on input.

### 1.2 Concepts

- MCP Config is an array of MCP servers like `mcp_server_1`, `mcp_server_2`, `mcp_server_3` etc.
  - Each config has a unique ID

- User is a user of the gateway with unique email and ID

- A project is a collection of users that share an MCP Config
  - Project has a name and unique ID
  - The MCP Config can be updated or can be pointed to a different config by the Admin
  - Users can be added to multiple projects

- An API Key is created for a user and project combination
  - A user can have different API Keys for different projects
  - This API Key is used to authenticate the user and identify the right project and MCP Config

- *See [6.5 Example config file generated](#65-example-config-file-generated) and [7. Edit the Gateway config as needed](#7-edit-the-gateway-config-as-needed) for schema reference*

## 2. High level steps of how the MCP Gateway works

![Local Gateway with Remote Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local.drawio.png)

<br>
<details>
<summary><strong>🪜 Steps </strong></summary>
<br>

1. Your MCP client connects to the Secure MCP Gateway server with API Key (handled by `src/secure_mcp_gateway/gateway.py`).

2. Gateway server fetches the gateway config from either the local `enkrypt_mcp_config.json` file (`plugins.auth.provider = "local_apikey"`) or the **remote Enkrypt cloud** at `https://api.enkryptai.com/mcp-gateway/get-gateway-config` (`plugins.auth.provider = "enkrypt"`). See [§14.5 Gateway Config Schema](#145-gateway-config-schema) for both shapes.

    - It caches the config locally or in an external cache server like KeyDB if configured to improve performance.

3. If input guardrails are enabled, request is validated before the tool call (handled by `src/secure_mcp_gateway/guardrail.py`).
   - Request is blocked if it violates any of the configured guardrails and the specific detector is configured to block.

4. Requests are forwarded to the Gateway Client (handled by `src/secure_mcp_gateway/client.py`).

5. The Gateway client forwards the request to the appropriate MCP server (handled by `src/secure_mcp_gateway/client.py`).

6. The MCP server processes the request and returns the response to the Gateway client.

7. If it was a discover tools call, the Gateway client caches the tools locally or in an external cache server like KeyDB if configured. It then forwards the response to the Gateway server.

8. The Gateway server receives the response from the Gateway client and if output guardrails are enabled, it validates the response against the configured guardrails (handled by `src/secure_mcp_gateway/guardrail.py`).

    - Response is blocked if it violates any of the configured guardrails and the specific detector is configured to block.

9. The Gateway server forwards the response back to the MCP client if everything is fine.

</details>

## 3. Prerequisites

<details>
<summary><strong>🔗 Dependencies </strong></summary>

- `Git 2.43` or higher

- `Python 3.11` or higher installed on your system and is accessible from the command line using either `python` or `python3` command

- `pip 25.0.1` or higher is installed on your system and is accessible from the command line using either `pip` or `python -m pip` command

- `uv 0.7.9` or higher is installed on your system and is accessible from the command line using either `uv` or `python -m uv` command

<br>
<details>
<summary><strong>🔍 Check versions </strong></summary>

- Check if Python, pip and uv are installed

- If any of the below commands fail, please refer the respective documentation to install them properly

```bash

# ------------------

# Python

# ------------------

python --version

# Example output
Python 3.13.3

# If not, install python from their website and run the version check again

# ------------------

# pip

# ------------------
pip --version

# Example output
pip 25.0.1 from C:\Users\PC\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\pip (python 3.13)

# If not, try the following and run the version check again
python -m ensurepip

# ------------------

# uv

# ------------------

uv --version

# Or run with "python -m" if uv is not found directly

# If this works, use "python -m" before all uv commands from now on
python -m uv --version

# Example output
uv 0.7.9 (13a86a23b 2025-05-30)

# If not, try the following and run the version check again
python -m pip install uv

```

</details>
</details>

<!-- - Set `PYTHONPATH` in your system environment variables

  - For reference, see [How to Add Python to PATH on Windows, Linux, and macOS](https://phoenixnap.com/kb/add-python-to-path)

    - In Windows, if you can't find python in the folder mentioned in the article, try `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps` -->

- Install **Claude Desktop** as the MCP Client from [their website](https://claude.ai/download) if you haven't already and login to it

  - *If you are using Linux and cannot run any [unofficial version](https://www.greghilston.com/post/claude-desktop-on-linux/) of Claude Desktop, you can use [any supported MCP Client](https://modelcontextprotocol.io/quickstart/server#testing-your-server-with-claude-for-desktop) to test the Gateway. If it does not support mcp cli `mcp install` command, then go through the scripts code and run the commands supported manually.*

- Any other dependencies required for the MCP servers we want to proxy requests to

  - Follow the instructions of the respective MCP server to install its dependencies

  - Like `Node.js`, `npx`, `docker`, etc.

- (Optional) A cache server like KeyDB installed and running (If you want to cache externally and not locally)

<br>
<details>
<summary><strong>🔒 Optional Protection with Enkrypt Guardrails </strong></summary>
<br>

If you want to protect your MCPs with Enkrypt Guardrails, you need to do the following:

- Create a new account if you don't have one. It's free! 🆓 No credit card required 💳🚫

- An `ENKRYPT_API_KEY` which you can get from [Enkrypt Dashboard Settings](https://app.enkryptai.com/settings)

- To protect your MCPs with Guardrails, you can use the default sample Guardrail `Sample Airline Guardrail` to get started or you can create your own custom Guardrail

- To configure custom Guardrails, you need to either login to Enkrypt AI App or use the APIs/SDK

  - [Create Guardrails in Enkrypt AI App Dashboard ✅](https://app.enkryptai.com/guardrails)

  - [Create Guardrails using APIs](https://docs.enkryptai.com/guardrails-api-reference/endpoint/add-policy)

  - [Create Guardrails using SDK](https://docs.enkryptai.com/libraries/python/introduction#guardrails-policy-management)

  - [You can also use Enkrypt MCP Server 🤯 to create Guardrails and use them in the Gateway](https://github.com/enkryptai/enkryptai-mcp-server)

</details>

## 4. Gateway Setup

### 4.1 Local Installation with pip

<details>
<summary><strong>📦 Pip Installation Steps </strong></summary>

#### 4.1.1 Download and Install the Package

- Activate a virtual environment

  ```bash
  python -m venv .secure-mcp-gateway-venv

  # Activate the virtual environment
  # On Windows
  .secure-mcp-gateway-venv\Scripts\activate

  # On Linux/macOS
  source .secure-mcp-gateway-venv/bin/activate

  # Run the below to exit the virtual environment later if needed
  deactivate
  ```

- Install the package. For more info see [https://pypi.org/project/secure-mcp-gateway/](https://pypi.org/project/secure-mcp-gateway/)

  ```bash
  pip install secure-mcp-gateway
  ```

#### 4.1.2 Run the Generate Command

- **This generates the config file at `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json` on Windows**

  ```bash
  secure-mcp-gateway generate-config
  ```

> **⚠️ Re-running on an existing config?** `generate-config` refuses to clobber an existing file by default — it exits with `INFO: Config file already exists at <path>. ... use --overwrite flag.` Add `--overwrite` to regenerate (a timestamped `.bkp.<YYYYMMDD_HHMMSS>` backup is written next to the original first). The flag also works with `--provider enkrypt` below.
>
> ```bash
> secure-mcp-gateway generate-config --overwrite
> ```

##### Choosing an auth provider at generation time

The default command emits the full **local-apikey** schema — a sample echo server, a default project, a user, and an auto-generated gateway API key — everything you need to boot offline. If you instead want the gateway to source its servers/projects/users from **Enkrypt cloud**, generate the minimal cloud-backed config:

```bash
secure-mcp-gateway generate-config --provider enkrypt
```

This writes a much shorter file containing only:

- `enkrypt_config.api_key` and `base_url` (you fill in the apikey)
- `plugins.auth.provider = "enkrypt"` with a `gateway_name` placeholder
- `plugins.guardrails.provider = "enkrypt"`
- `plugins.telemetry.provider = "opentelemetry"` (OTLP gRPC to `localhost:4317`, matching the local-apikey default and the bundled Prometheus/Grafana/Jaeger/Loki stack — set `config.enabled: false` if you don't have a collector running)
- Two commonly-tweaked entries under `common_mcp_gateway_config` (`enkrypt_log_level`, `enkrypt_gateway_cache_expiration_minutes`)

No local `mcp_configs` / `projects` / `users` / `apikeys` blocks — the cloud owns those. After generation, edit the file and set:

1. `enkrypt_config.api_key` → your Enkrypt cloud apikey
2. `plugins.auth.config.gateway_name` → the `saved_name` of the gateway you created in the Enkrypt console

> `gateway_name` is the one value that can also arrive per request, as the `X-Enkrypt-MCP-Gateway` header from the MCP client, so that a single gateway process can serve several cloud gateways. When it is set in the config the config wins. Full config-key and header reference: [§7.1 Enkrypt cloud auth provider and gateway headers](#71-enkrypt-cloud-auth-provider-and-gateway-headers).

The shipped reference file is `src/secure_mcp_gateway/example_enkrypt_cloud_config.json` — same shape the CLI generates. Use it as a template for hand-written configs.

Supported flag values:

| `--provider` | Behavior |
|---|---|
| `local_apikey` (default) | Full local schema with sample echo server, project, user, API key, and a root-level `admin_apikey` for the REST admin API. Backward-compatible with all pre-2.2 setups. |
| `enkrypt` | Minimal cloud-backed schema. No `admin_apikey` baked in — the cloud `enkrypt_config.api_key` doubles as the admin credential (see [Admin API Key Authentication](#admin-api-key-authentication)). |

<details>
<summary><strong>🖨️ Example output — <code>--provider local_apikey</code> (default)</strong></summary>
<br>

```bash
Initializing Enkrypt Secure MCP Gateway
Initializing Enkrypt Secure MCP Gateway Common Utilities Module
Initializing Enkrypt Secure MCP Gateway Module
--------------------------------
SYSTEM INFO:
Using Python interpreter: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Scripts\python.exe
Python version: 3.13.3 (tags/v3.13.3:6280bb5, Apr  8 2025, 14:47:33) [MSC v.1943 64 bit (AMD64)]
Current working directory: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway
PYTHONPATH: Not set
--------------------------------
Installing dependencies...
All dependencies installed successfully.
Initializing Enkrypt Secure MCP Gateway Client Module
Initializing Enkrypt Secure MCP Gateway Guardrail Module
Error: Gateway key is required. Please update your mcp client config and try again.
Getting Enkrypt Common Configuration
config_path: C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
example_config_path: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\example_enkrypt_mcp_config.json
No enkrypt_mcp_config.json file found. Defaulting to example_enkrypt_mcp_config.json
--------------------------------
ENKRYPT_GATEWAY_KEY: ****NULL
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_api_key: ****_KEY
enkrypt_tool_cache_expiration: 4
enkrypt_gateway_cache_expiration: 24
enkrypt_mcp_use_external_cache: False
enkrypt_async_input_guardrails_enabled: False
--------------------------------
External Cache is not enabled. Using local cache only.
Initializing Enkrypt Secure MCP Gateway CLI Module
Generated default config at C:\Users\PC\.enkrypt\enkrypt_mcp_config.json

```

</details>

<details>
<summary><strong>🖨️ Example output — <code>--provider enkrypt</code> (cloud)</strong></summary>
<br>

```bash
INFO: Initializing Enkrypt Secure MCP Gateway CLI Module v2.2.0
INFO: HOME_DIR: C:\Users\PC
INFO: GATEWAY_PY_PATH:  C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\gateway.py
INFO: ECHO_SERVER_PATH:  C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\bad_mcps\echo_oauth_mcp.py
INFO: PICKED_CONFIG_PATH:  C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
INFO: Generating minimal Enkrypt-cloud configuration (plugins.auth.provider=enkrypt)...
SUCCESS: Generated config at C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
INFO: Before starting the gateway, edit the file and set:
  * enkrypt_config.api_key            (replace 'YOUR_ENKRYPT_API_KEY' with your Enkrypt cloud apikey)
  * plugins.auth.config.gateway_name  (replace 'your-gateway-saved-name' with the saved_name of the gateway you created in Enkrypt cloud)
```

> Notice the cloud variant skips the long boot/dependency banner — it's a fast, focused command. The two `INFO: Before starting…` lines are the operator-must-edit checklist; the gateway will fail with a 401 from Enkrypt cloud on first boot if you skip them.

</details>

#### 4.1.3 Example of the generated config file

> **Note:** The examples below show the **full** schema emitted by `secure-mcp-gateway generate-config` (default `--provider local_apikey`). Every field is included so you can compare your generated file 1:1. The `oauth_config` block ships disabled (`"enabled": false`) — its keys are placeholders you only need to fill in if a server uses OAuth. The `timeout_settings` block holds the per-operation timeouts the gateway uses internally; defaults are sane and rarely need editing.

<details>
<summary><strong>🍎 Example file in macOS</strong></summary>
<br>

- This is an example of the default configuration file generated by the CLI on macOS:

```json
{
  "admin_apikey": "AUTO_GENERATED_256_CHAR_KEY",
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com"
  },
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_mcp_use_external_cache": false,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": null,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_gateway_cache_expiration_minutes": 5,
    "enkrypt_config_watcher_poll_seconds": 2.0,
    "enkrypt_async_input_guardrails_enabled": false,
    "enkrypt_async_output_guardrails_enabled": false,
    "timeout_settings": {
      "default_timeout": 90,
      "guardrail_timeout": 390,
      "auth_timeout": 30,
      "tool_execution_timeout": 360,
      "discovery_timeout": 540,
      "cache_timeout": 15,
      "connectivity_timeout": 6,
      "escalation_policies": {
        "warn_threshold": 0.8,
        "timeout_threshold": 1.0,
        "fail_threshold": 1.2
      }
    }
  },
  "plugins": {
    "auth": { "provider": "local_apikey", "config": {} },
    "guardrails": { "provider": "enkrypt", "config": {} },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "enabled": true,
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "mcp_configs": {
    "fcbd4508-1432-4f13-abb9-c495c946f638": {
      "mcp_config_name": "default_config",
      "common_overrides": {
        "server_tools_guardrails_config": {
          "enabled": false,
          "guardrail_name": "Sample Airline Guardrail",
          "block": [
            "policy_violation",
            "injection_attack",
            "topic_detector",
            "nsfw",
            "toxicity",
            "pii",
            "keyword_detector",
            "bias",
            "sponge_attack"
          ]
        }
      },
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Simple Echo Server",
          "config": {
            "command": "python",
            "args": [
              "/Users/user/enkryptai/secure-mcp-gateway/venv/lib/python3.13/site-packages/secure_mcp_gateway/bad_mcps/echo_mcp.py"
            ]
          },
          "oauth_config": {
            "enabled": false,
            "is_remote": false,
            "OAUTH_VERSION": "2.1",
            "OAUTH_GRANT_TYPE": "client_credentials",
            "OAUTH_CLIENT_ID": "your-client-id",
            "OAUTH_CLIENT_SECRET": "your-client-secret",
            "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
            "OAUTH_AUDIENCE": "https://api.example.com",
            "OAUTH_ORGANIZATION": "your-org-id",
            "OAUTH_SCOPE": "read write",
            "OAUTH_RESOURCE": "https://resource.example.com",
            "OAUTH_TOKEN_EXPIRY_BUFFER": 300,
            "OAUTH_USE_BASIC_AUTH": true,
            "OAUTH_ENFORCE_HTTPS": true,
            "OAUTH_TOKEN_IN_HEADER_ONLY": true,
            "OAUTH_VALIDATE_SCOPES": true,
            "OAUTH_USE_MTLS": false,
            "OAUTH_CLIENT_CERT_PATH": null,
            "OAUTH_CLIENT_KEY_PATH": null,
            "OAUTH_CA_BUNDLE_PATH": null,
            "OAUTH_REVOCATION_URL": null,
            "OAUTH_ADDITIONAL_PARAMS": {},
            "OAUTH_CUSTOM_HEADERS": {}
          },
          "tools": {},
          "denied_tools": [],
          "input_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          },
          "output_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "relevancy": false,
              "hallucination": false,
              "adherence": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          }
        }
      ]
    }
  },
  "projects": {
    "3c09f06c-1f0d-4153-9ac5-366397937641": {
      "project_name": "default_project",
      "mcp_config_id": "fcbd4508-1432-4f13-abb9-c495c946f638",
      "users": [
        "6469a670-1d64-4da5-b2b3-790de21ac726"
      ],
      "created_at": "2025-07-16T17:02:00.406877"
    }
  },
  "users": {
    "6469a670-1d64-4da5-b2b3-790de21ac726": {
      "email": "default@example.com",
      "created_at": "2025-07-16T17:02:00.406902"
    }
  },
  "apikeys": {
    "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat": {
      "project_id": "3c09f06c-1f0d-4153-9ac5-366397937641",
      "user_id": "6469a670-1d64-4da5-b2b3-790de21ac726",
      "created_at": "2025-07-16T17:02:00.406905"
    }
  }
}

```

</details>
<details>
<summary><strong>🪟 Example file in Windows</strong></summary>
<br>

- This is an example of the default configuration file generated by the CLI on Windows:

```json
{
  "admin_apikey": "AUTO_GENERATED_256_CHAR_KEY",
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com"
  },
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_mcp_use_external_cache": false,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": null,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_gateway_cache_expiration_minutes": 5,
    "enkrypt_config_watcher_poll_seconds": 2.0,
    "enkrypt_async_input_guardrails_enabled": false,
    "enkrypt_async_output_guardrails_enabled": false,
    "timeout_settings": {
      "default_timeout": 90,
      "guardrail_timeout": 390,
      "auth_timeout": 30,
      "tool_execution_timeout": 360,
      "discovery_timeout": 540,
      "cache_timeout": 15,
      "connectivity_timeout": 6,
      "escalation_policies": {
        "warn_threshold": 0.8,
        "timeout_threshold": 1.0,
        "fail_threshold": 1.2
      }
    }
  },
  "plugins": {
    "auth": { "provider": "local_apikey", "config": {} },
    "guardrails": { "provider": "enkrypt", "config": {} },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "enabled": true,
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "mcp_configs": {
    "fcbd4508-1432-4f13-abb9-c495c946f638": {
      "mcp_config_name": "default_config",
      "common_overrides": {
        "server_tools_guardrails_config": {
          "enabled": false,
          "guardrail_name": "Sample Airline Guardrail",
          "block": [
            "policy_violation",
            "injection_attack",
            "topic_detector",
            "nsfw",
            "toxicity",
            "pii",
            "keyword_detector",
            "bias",
            "sponge_attack"
          ]
        }
      },
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Simple Echo Server",
          "config": {
            "command": "python",
            "args": [
              "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\bad_mcps\\echo_mcp.py"
            ]
          },
          "oauth_config": {
            "enabled": false,
            "is_remote": false,
            "OAUTH_VERSION": "2.1",
            "OAUTH_GRANT_TYPE": "client_credentials",
            "OAUTH_CLIENT_ID": "your-client-id",
            "OAUTH_CLIENT_SECRET": "your-client-secret",
            "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
            "OAUTH_AUDIENCE": "https://api.example.com",
            "OAUTH_ORGANIZATION": "your-org-id",
            "OAUTH_SCOPE": "read write",
            "OAUTH_RESOURCE": "https://resource.example.com",
            "OAUTH_TOKEN_EXPIRY_BUFFER": 300,
            "OAUTH_USE_BASIC_AUTH": true,
            "OAUTH_ENFORCE_HTTPS": true,
            "OAUTH_TOKEN_IN_HEADER_ONLY": true,
            "OAUTH_VALIDATE_SCOPES": true,
            "OAUTH_USE_MTLS": false,
            "OAUTH_CLIENT_CERT_PATH": null,
            "OAUTH_CLIENT_KEY_PATH": null,
            "OAUTH_CA_BUNDLE_PATH": null,
            "OAUTH_REVOCATION_URL": null,
            "OAUTH_ADDITIONAL_PARAMS": {},
            "OAUTH_CUSTOM_HEADERS": {}
          },
          "tools": {},
          "denied_tools": [],
          "input_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          },
          "output_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "relevancy": false,
              "hallucination": false,
              "adherence": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          }
        }
      ]
    }
  },
  "projects": {
    "3c09f06c-1f0d-4153-9ac5-366397937641": {
      "project_name": "default_project",
      "mcp_config_id": "fcbd4508-1432-4f13-abb9-c495c946f638",
      "users": [
        "6469a670-1d64-4da5-b2b3-790de21ac726"
      ],
      "created_at": "2025-07-16T17:02:00.406877"
    }
  },
  "users": {
    "6469a670-1d64-4da5-b2b3-790de21ac726": {
      "email": "default@example.com",
      "created_at": "2025-07-16T17:02:00.406902"
    }
  },
  "apikeys": {
    "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat": {
      "project_id": "3c09f06c-1f0d-4153-9ac5-366397937641",
      "user_id": "6469a670-1d64-4da5-b2b3-790de21ac726",
      "created_at": "2025-07-16T17:02:00.406905"
    }
  }
}

```

</details>

<details>
<summary><strong>☁️ Example file with <code>--provider enkrypt</code> (cloud-backed, all platforms)</strong></summary>
<br>

- This is the **complete** file emitted by `secure-mcp-gateway generate-config --provider enkrypt`. Same shape on macOS, Linux, and Windows — only the on-disk path differs (`~/.enkrypt/...` vs `%USERPROFILE%\.enkrypt\...`).

```json
{
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com",
    "org_id": "YOUR_ENKRYPT_ORG_ID"
  },
  "plugins": {
    "auth": {
      "provider": "enkrypt",
      "config": {
        "gateway_name": "your-gateway-saved-name",
        "gateway_version": "v1",
        "cache_ttl_seconds": 300
      }
    },
    "guardrails": {
      "provider": "enkrypt",
      "config": {}
    },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "enabled": true,
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_gateway_cache_expiration_minutes": 5
  }
}

```

**What's intentionally NOT here (cloud owns these):**

- No `mcp_configs` / `projects` / `users` / `apikeys` blocks — the gateway resolves them from Enkrypt cloud via `/mcp-gateway/get-gateway-config` on every authenticated request.
- No root-level `admin_apikey` — the cloud `enkrypt_config.api_key` doubles as the admin credential for most REST endpoints (see [Admin API Key Authentication](#admin-api-key-authentication)). The cache-flush endpoint specifically requires `enkrypt_config.org_id` to be set and validates incoming apikeys against `GET /consumer-info.org_id` — see [Cache-flush authorization policy](#cache-flush-authorization-policy). If you want a separate admin secret for non-flush endpoints, add `"admin_apikey": "<256-char-key>"` at the root.
- No legacy `enkrypt_use_remote_mcp_config` / `enkrypt_remote_mcp_gateway_*` flags — those only drive the deprecated `local_apikey` remote-fetch fallback. The `enkrypt` provider has its own cleaner cloud-config flow in `EnkryptAuthProvider`.

**Two operator-must-edit values before first boot:**

1. `enkrypt_config.api_key` → your real Enkrypt cloud apikey
2. `plugins.auth.config.gateway_name` → the `saved_name` of the gateway you created in the Enkrypt console

The shipped reference file at `src/secure_mcp_gateway/example_enkrypt_cloud_config.json` is byte-for-byte identical to this example.

</details>

#### 4.1.4 Install the Gateway for Claude Desktop

- Run the following command to install the gateway for Claude:

  ```bash
  secure-mcp-gateway install --client claude-desktop
  ```

- This will register Enkrypt Secure MCP Gateway with Claude Desktop.

- **NOTE: Please restart Claude Desktop after installation**

<details>
<summary><strong>🖨️ Example output</strong></summary>
<br>

```bash
Initializing Enkrypt Secure MCP Gateway
Initializing Enkrypt Secure MCP Gateway Common Utilities Module
Initializing Enkrypt Secure MCP Gateway Module
--------------------------------
SYSTEM INFO:
Using Python interpreter: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Scripts\python.exe
Python version: 3.13.3 (tags/v3.13.3:6280bb5, Apr  8 2025, 14:47:33) [MSC v.1943 64 bit (AMD64)]
Current working directory: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway
PYTHONPATH: Not set
--------------------------------
Installing dependencies...
All dependencies installed successfully.
Initializing Enkrypt Secure MCP Gateway Client Module
Initializing Enkrypt Secure MCP Gateway Guardrail Module
Error: Gateway key is required. Please update your mcp client config and try again.
Getting Enkrypt Common Configuration
config_path: C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
example_config_path: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\example_enkrypt_mcp_config.json
Loading enkrypt_mcp_config.json file...
--------------------------------
ENKRYPT_GATEWAY_KEY: ****NULL
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_api_key: ****_KEY
enkrypt_tool_cache_expiration: 4
enkrypt_gateway_cache_expiration: 24
enkrypt_mcp_use_external_cache: False
enkrypt_async_input_guardrails_enabled: False
--------------------------------
External Cache is not enabled. Using local cache only.
Initializing Enkrypt Secure MCP Gateway CLI Module
CONFIG_PATH:  C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
GATEWAY_PY_PATH:  C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\gateway.py
client name from args:  claude-desktop
Successfully installed gateway for claude-desktop
Path to gateway is incorrect. Modifying the path to gateway in claude_desktop_config.json file...
Path to gateway modified in claude_desktop_config.json file
Please restart Claude Desktop to use the gateway.

```

</details>

#### 4.1.5 Example of the Claude Desktop Config after installation

> **The env-var shape depends on your gateway's `plugins.auth.provider`.** Same dichotomy as the Cursor section [below](#416-install-the-gateway-for-cursor):
>
> - **`local_apikey` provider** (default) → three env vars: `ENKRYPT_GATEWAY_KEY` + `ENKRYPT_PROJECT_ID` + `ENKRYPT_USER_ID`
> - **`enkrypt` cloud provider** → single env var: `ENKRYPT_APIKEY`

<details>
<summary><strong>🍎 Example file in macOS</strong></summary>
<br>

- `~/Library/Application Support/Claude/claude_desktop_config.json` — **local_apikey provider** (default)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "/Users/user/enkryptai/secure-mcp-gateway/venv/lib/python3.13/site-packages/secure_mcp_gateway/gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

- `~/Library/Application Support/Claude/claude_desktop_config.json` — **enkrypt cloud provider** (when generated with `--provider enkrypt`)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "/Users/user/enkryptai/secure-mcp-gateway/venv/lib/python3.13/site-packages/secure_mcp_gateway/gateway.py"
        ],
        "env": {
          "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
        }
      }
    }
  }
  ```

</details>
<details>
<summary><strong>🪟 Example file in Windows</strong></summary>
<br>

- `%USERPROFILE%\AppData\Roaming\Claude\claude_desktop_config.json` — **local_apikey provider** (default)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

- `%USERPROFILE%\AppData\Roaming\Claude\claude_desktop_config.json` — **enkrypt cloud provider** (when generated with `--provider enkrypt`)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
        }
      }
    }
  }
  ```

</details>

#### 4.1.6 Install the Gateway for Cursor

- Run the CLI Install Command for Cursor

  ```bash
  secure-mcp-gateway install --client cursor
  ```

- This automatically updates your ~/.cursor/mcp.json (on Windows it is at: %USERPROFILE%\.cursor\mcp.json) with the correct entry.

- *Although it is not usually required to restart, if you see it in loading state for a long time, please restart Cursor*

> **The env-var shape depends on your gateway's `plugins.auth.provider`.** The install command writes whichever shape matches:
>
> | Provider | Env vars written | Used for |
> |---|---|---|
> | `local_apikey` (default) | `ENKRYPT_GATEWAY_KEY` + `ENKRYPT_PROJECT_ID` + `ENKRYPT_USER_ID` | Looking up the local apikey + project + user in your local config |
> | `enkrypt` (cloud) | `ENKRYPT_APIKEY` | Single cloud apikey; project/user come from Enkrypt cloud |
>
> Both `mcp.json` shapes below are valid — pick the one matching how you generated your config. See [Section 4.1.2](#412-run-the-generate-command) for the `--provider enkrypt` flag.

<details>
<summary><strong>🍎 Example file in macOS</strong></summary>
<br>

- `~/.cursor/mcp.json` — **local_apikey provider** (default)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "/Users/user/enkryptai/secure-mcp-gateway/venv/lib/python3.13/site-packages/secure_mcp_gateway/gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

- `~/.cursor/mcp.json` — **enkrypt cloud provider** (when generated with `--provider enkrypt`)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "/Users/user/enkryptai/secure-mcp-gateway/venv/lib/python3.13/site-packages/secure_mcp_gateway/gateway.py"
        ],
        "env": {
          "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
        }
      }
    }
  }
  ```

</details>
<details>
<summary><strong>🪟 Example file in Windows</strong></summary>
<br>

- `%USERPROFILE%\.cursor\mcp.json` — **local_apikey provider** (default)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

  > If `mcp` is not on your PATH (e.g. you didn't activate the venv), you can wrap it through `uv` instead:
  >
  > ```json
  > "command": "uv",
  > "args": ["run", "--with", "mcp[cli]", "mcp", "run", "<full path to gateway.py>"]
  > ```
  >
  > The `secure-mcp-gateway install --client cursor` command always emits the bare `"mcp"` form above — switch to the `uv` wrapper only if you hit a `mcp: command not found` error.

- `%USERPROFILE%\.cursor\mcp.json` — **enkrypt cloud provider** (when generated with `--provider enkrypt`)

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
        }
      }
    }
  }
  ```

</details>

#### 4.1.7 Install the Gateway for Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) is Anthropic's CLI-based coding agent. It uses `claude mcp add` commands to configure MCP servers. Unlike Claude Desktop and Cursor which use JSON config files, Claude Code manages MCP servers through its own CLI.

> **Prerequisite:** The `claude` CLI must be installed on your system. See [Claude Code docs](https://docs.anthropic.com/en/docs/claude-code) for installation.

**Step 1: Install the gateway**

```bash
secure-mcp-gateway install --client claude-code
```

This automatically:
- Reads the gateway credentials from your generated config (provider-aware):
  - **`local_apikey` provider** (default) → emits three `--env` flags: `ENKRYPT_GATEWAY_KEY`, `ENKRYPT_PROJECT_ID`, `ENKRYPT_USER_ID`
  - **`enkrypt` cloud provider** → emits a single `--env` flag: `ENKRYPT_APIKEY` (sourced from `enkrypt_config.api_key`, or `--apikey <key>` if you pass it on the CLI)
- Runs `claude mcp add` with `--transport stdio` and the correct credentials and gateway path
- Registers the server as `Enkrypt-Secure-MCP-Gateway` with `--scope user` (available across all Claude Code projects)

**Step 2: Verify the server was added**

```bash
claude mcp list
```

You should see `Enkrypt-Secure-MCP-Gateway` in the list.

**Step 3: Use the gateway in Claude Code**

Launch Claude Code and try:

```
list all servers, get all tools available
```

<details>
<summary><strong>Manual alternative (if you prefer to run claude mcp add directly)</strong></summary>
<br>

Get your credentials from the generated `enkrypt_mcp_config.json` and the gateway path:

```bash
python -c "import secure_mcp_gateway.gateway; print(secure_mcp_gateway.gateway.__file__)"
```

Then add the gateway manually. The exact command depends on your gateway's `plugins.auth.provider` (see [§4.1.2](#412-run-the-generate-command)):

**For `local_apikey` provider** (default):

```bash
claude mcp add --transport stdio --env ENKRYPT_GATEWAY_KEY=YOUR_GATEWAY_KEY --env ENKRYPT_PROJECT_ID=YOUR_PROJECT_ID --env ENKRYPT_USER_ID=YOUR_USER_ID --scope user Enkrypt-Secure-MCP-Gateway -- mcp run /path/to/secure_mcp_gateway/gateway.py
```

**For `enkrypt` cloud provider** (when generated with `--provider enkrypt`):

```bash
claude mcp add --transport stdio --env ENKRYPT_APIKEY=YOUR_ENKRYPT_CLOUD_APIKEY --scope user Enkrypt-Secure-MCP-Gateway -- mcp run /path/to/secure_mcp_gateway/gateway.py
```

> **Note:** The server name must use hyphens or underscores — Claude Code does not allow spaces in names.

</details>

</details>

### 4.2 Local Installation with git clone

<details>
<summary><strong>🗂️ Git Clone Installation Steps </strong></summary>

#### 4.2.1 Clone the repo, setup virtual environment and install dependencies

- Clone the repository:

```bash
git clone https://github.com/enkryptai/secure-mcp-gateway

cd secure-mcp-gateway

```

<br>
<details>
<summary><strong>⚡ Activate a virtual environment </strong></summary>
<br>

```bash

# ------------------

# Create a virtual environment

# ------------------

uv venv

# Example output
Using CPython 3.13.3 interpreter at: C:\Users\PC\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\python.exe
Creating virtual environment at: .venv
Activate with: .venv\Scripts\activate

# ------------------

# Activate the virtual environment

# ------------------

# For 🍎 Linux/macOS, run the following
source ./.venv/Scripts/activate

# For 🪟 Windows, run the following
.\.venv\Scripts\activate

# After activating, you should see (enkrypt-secure-mcp-gateway) before the file path in the terminal

# Example:

# (enkrypt-secure-mcp-gateway) %USERPROFILE%\Documents\GitHub\EnkryptAI\secure-mcp-gateway>

# ------------------

# Install pip in the virtual environment

# ------------------

python -m ensurepip

# ------------------

# Install uv in the virtual environment

# ------------------

python -m pip install uv

```

- Install Python dependencies:

```bash
uv pip install -r requirements.txt

```

- Verify mcp cli got installed successfully:

```bash
mcp version

# Example output
MCP version 1.9.2

```

</details>

#### 4.2.2 Run the setup script

<!-- - The `setup` script checks versions of Python, pip, uv and makes sure they are installed and accessible -->

<!-- - It then installs the dependencies -->

- This script creates the config file at `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json` on Windows based on `src/secure_mcp_gateway/example_enkrypt_mcp_config.json` file

- It replaces `UNIQUE_GATEWAY_KEY` and other `UUIDs` with auto generated values and also replaces `DUMMY_MCP_FILE_PATH` with the actual path to the test MCP file `bad_mcps/echo_mcp.py`

- It also installs the MCP client in Claude Desktop

- *NOTE: Please restart Claude Desktop after running the setup script to see the Gateway running in Claude Desktop*

```bash

# On 🍎 Linux/macOS run the below
cd scripts
chmod +x *.sh
./setup.sh

# On 🪟 Windows run the below
cd scripts
setup.bat

# Now restart Claude Desktop to see the Gateway running

```

<br>
<details>
<summary><strong>🖨️ Example output</strong></summary>
<br>

```bash
-------------------------------
Setting up Enkrypt Secure MCP Gateway enkrypt_mcp_config.json config file
-------------------------------
        1 file(s) copied.
Generated unique gateway key: WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_
Generated unique uuid: 7920749a-228e-47fe-a6a9-cd2d64a2283b
DUMMY_MCP_FILE_PATH: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\src\secure_mcp_gateway\bad_mcps\echo_mcp.py
-------------------------------
Setup complete. Please check the enkrypt_mcp_config.json file in the ~\.enkrypt directory and update with your MCP server configs as needed.
-------------------------------
-------------------------------
Installing Enkrypt Secure MCP Gateway with gateway key and dependencies
-------------------------------
mcp is installed. Proceeding with installation...
ENKRYPT_GATEWAY_KEY: WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_
The system cannot find the path specified.
Package names only:
Dependencies string for the cli install command:
Running the cli install command: mcp install gateway.py --env-var ENKRYPT_GATEWAY_KEY=WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_
Initializing Enkrypt Secure MCP Gateway
Initializing Enkrypt Secure MCP Gateway Common Utilities Module
Initializing Enkrypt Secure MCP Gateway Module
--------------------------------
SYSTEM INFO:
Using Python interpreter: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Scripts\python.exe
Python version: 3.13.3 (tags/v3.13.3:6280bb5, Apr  8 2025, 14:47:33) [MSC v.1943 64 bit (AMD64)]
Current working directory: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\src\secure_mcp_gateway
PYTHONPATH: Not set
--------------------------------
Installing dependencies...
All dependencies installed successfully.
Initializing Enkrypt Secure MCP Gateway Client Module
Initializing Enkrypt Secure MCP Gateway Guardrail Module
Getting Enkrypt Common Configuration
config_path: C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
example_config_path: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\example_enkrypt_mcp_config.json
Loading enkrypt_mcp_config.json file...
--------------------------------
ENKRYPT_GATEWAY_KEY: ****BN8_
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_api_key: ****_KEY
enkrypt_tool_cache_expiration: 4
enkrypt_gateway_cache_expiration: 24
enkrypt_mcp_use_external_cache: False
enkrypt_async_input_guardrails_enabled: False
--------------------------------
External Cache is not enabled. Using local cache only.
Initializing Enkrypt Secure MCP Gateway Module
--------------------------------
SYSTEM INFO:
Using Python interpreter: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Scripts\python.exe
Python version: 3.13.3 (tags/v3.13.3:6280bb5, Apr  8 2025, 14:47:33) [MSC v.1943 64 bit (AMD64)]
Current working directory: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\src\secure_mcp_gateway
PYTHONPATH: Not set
--------------------------------
Installing dependencies...
All dependencies installed successfully.
Getting Enkrypt Common Configuration
config_path: C:\Users\PC\.enkrypt\enkrypt_mcp_config.json
example_config_path: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\.secure-mcp-gateway-venv\Lib\site-packages\secure_mcp_gateway\example_enkrypt_mcp_config.json
Loading enkrypt_mcp_config.json file...
--------------------------------
ENKRYPT_GATEWAY_KEY: ****BN8_
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_api_key: ****_KEY
enkrypt_tool_cache_expiration: 4
enkrypt_gateway_cache_expiration: 24
enkrypt_mcp_use_external_cache: False
enkrypt_async_input_guardrails_enabled: False
--------------------------------
External Cache is not enabled. Using local cache only.
[06/15/25 13:14:10] INFO     Added server 'Enkrypt Secure MCP Gateway' to Claude config                                                                                                             claude.py:137
                    INFO     Successfully installed Enkrypt Secure MCP Gateway in Claude app                                                                                                           cli.py:486
-------------------------------
Installation complete. Check the claude_desktop_config.json file as per the readme instructions and restart Claude Desktop.
-------------------------------

```

</details>

#### 4.2.3 Setup Other MCP Clients

<details>
<summary><strong>⬡ Cursor </strong></summary>
<br>

- You can navigate to cursor's **Global MCP** file at `~/.cursor/mcp.json` on Linux/macOS or `%USERPROFILE%\.cursor\mcp.json` on Windows

  - If you would like to use at a **Project level** place it inside your project. For details see [Cursor's docs](https://docs.cursor.com/context/model-context-protocol#configuration-locations)

- You can also navigate to the file Via cursor's UI by clicking on `settings` gear icon on the top right

  ![cursor-settings-icon](./docs/images/cursor-settings-icon.png)

- Click on `MCP` and then click on `Add new global MCP server` which takes you to the `mcp.json` file

  ![cursor-settings-mcp](./docs/images/cursor-settings-mcp.png)

- Example `mcp.json` file opened in the editor

  ![cursor-mcp-file](./docs/images/cursor-mcp-file.png)

- Once the file is opened at Global or Project level, you can copy paste the same config we used in `Claude Desktop`. For reference, you can refer to [Installation - 6.2 Example MCP config file generated 📄](#62-example-mcp-config-file-generated)

  - *Be sure to use your own file that was generated by the `setup` script in [Installation - 4.2.2 Run the setup script 📥](#422-run-the-setup-script). Please do not copy paste the example config file in this repo.*

- See [Verify Cursor](#66-verify-cursor) section to verify the MCP server is running in Cursor

</details>
<details>
<summary><strong>⬡ Claude Code </strong></summary>
<br>

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) uses its own CLI to manage MCP servers instead of JSON config files

- Get your credentials from the generated `enkrypt_mcp_config.json` (gateway key, project ID, user ID)

- Find the gateway.py path:

  ```bash
  python -c "import secure_mcp_gateway.gateway; print(secure_mcp_gateway.gateway.__file__)"
  ```

- Add the gateway to Claude Code. The env vars differ by auth provider:

  ```bash
  # For local_apikey provider (default)
  claude mcp add --transport stdio --env ENKRYPT_GATEWAY_KEY=YOUR_GATEWAY_KEY --env ENKRYPT_PROJECT_ID=YOUR_PROJECT_ID --env ENKRYPT_USER_ID=YOUR_USER_ID --scope user Enkrypt-Secure-MCP-Gateway -- mcp run /path/to/secure_mcp_gateway/gateway.py

  # For enkrypt cloud provider (generated with --provider enkrypt)
  claude mcp add --transport stdio --env ENKRYPT_APIKEY=YOUR_ENKRYPT_CLOUD_APIKEY --scope user Enkrypt-Secure-MCP-Gateway -- mcp run /path/to/secure_mcp_gateway/gateway.py
  ```

- Verify: `claude mcp list`

- For detailed setup, see [4.1.7 Install the Gateway for Claude Code](#417-install-the-gateway-for-claude-code)

</details>
</details>

### 4.3 Docker Installation

<details>
<summary><strong>🐳 Docker Installation Steps </strong></summary>

#### 4.3.1 Build the Docker Image

```bash
docker build -t secure-mcp-gateway .

```

> **Tag your build so the `--docker` wrapper finds it.** Starting in v2.2.0 the `secure-mcp-gateway --docker ...` wrapper pulls `enkryptai/secure-mcp-gateway:<your-host-CLI-version>` by default (e.g. `enkryptai/secure-mcp-gateway:2.2.0`). Until that exact tag is published on Docker Hub, every `--docker` command fails with `Unable to find image ... not found`. Fix it once by tagging your local build to match (find your version with `secure-mcp-gateway --version`):
>
> ```bash
> # Replace 2.2.0 with the output of `secure-mcp-gateway --version`
> docker tag secure-mcp-gateway:latest enkryptai/secure-mcp-gateway:2.2.0
> ```
>
> After this one command, every `secure-mcp-gateway --docker generate-config`, `--docker install --client X`, `--docker config list`, etc. in the rest of §4.3 works without needing `--docker-image` overrides.

<details>
<summary><strong>🖨️ Example output</strong></summary>
<br>

> Truncated for readability — actual output includes a long pip dependency dump under step `[18/18] RUN pip3 install --break-system-packages .`. First-time builds typically take **3–5 minutes** depending on network/CPU; subsequent rebuilds are mostly cached and complete in under 30s.

```bash
[+] Building 72.9s (20/20) FINISHED                                                                                                                                          docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                   0.1s
 => => transferring dockerfile: 724B                                                                                                                                                   0.1s
 => [internal] load metadata for docker.io/library/python:3.11-alpine                                                                                                                  1.0s
 => [internal] load .dockerignore                                                                                                                                                      0.1s
 => => transferring context: 456B                                                                                                                                                      0.1s
 => [ 1/15] FROM docker.io/library/python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3                                                          0.0s
 => => resolve docker.io/library/python:3.11-alpine@sha256:8068890a42d68ece5b62455ef327253249b5f094dcdee57f492635a40217f6a3                                                            0.0s
 => [internal] load build context                                                                                                                                                      1.5s
 => => transferring context: 82.25kB                                                                                                                                                   1.4s
 => CACHED [ 2/15] WORKDIR /app                                                                                                                                                        0.0s
 => CACHED [ 3/15] COPY requirements.txt .                                                                                                                                             0.0s
 => [ 4/15] COPY requirements-dev.txt .                                                                                                                                                0.0s
 => [ 5/15] RUN pip install --upgrade pip && pip install -r requirements.txt && pip install -r requirements-dev.txt                                                                   38.7s
 => [ 6/15] COPY src src                                                                                                                                                               0.2s
 => [ 7/15] COPY setup.py setup.py                                                                                                                                                     0.1s
 => [ 8/15] COPY MANIFEST.in MANIFEST.in                                                                                                                                               0.1s
 => [ 9/15] COPY pyproject.toml pyproject.toml                                                                                                                                         0.1s
 => [10/15] COPY CHANGELOG.md CHANGELOG.md                                                                                                                                             0.1s
 => [11/15] COPY LICENSE.txt LICENSE.txt                                                                                                                                               0.1s
 => [12/15] COPY README.md README.md                                                                                                                                                   0.1s
 => [13/15] COPY README_PYPI.md README_PYPI.md                                                                                                                                         0.1s
 => [14/15] RUN python -m build                                                                                                                                                        8.5s
 => [15/15] RUN pip install .                                                                                                                                                          5.5s
 => exporting to image                                                                                                                                                                16.6s
 => => exporting layers                                                                                                                                                               11.8s
 => => exporting manifest sha256:47bd860c903fdefeda59364f577c487f96e1482b0e8eadef8292df86922641dc                                                                                      0.0s
 => => exporting config sha256:9d211386091dfc08fcfe80f1efb399d4a1ab80484f850476c328614ecaaefbae                                                                                        0.1s
 => => exporting attestation manifest sha256:bc85b5aaf4035e6f449d9b94567135a28a61c594fa2a507ca7fea889efbf2952                                                                          0.0s
 => => exporting manifest list sha256:7cd30cbf456ba3105d4bef7c28ea8402ec5476e4da3cd8c16b752f3214f8b3b1                                                                                 0.0s
 => => naming to docker.io/library/secure-mcp-gateway:latest                                                                                                                           0.0s
 => => unpacking to docker.io/library/secure-mcp-gateway:latest


Verify the image landed:

```bash
docker images secure-mcp-gateway

# REPOSITORY            TAG       IMAGE ID       CREATED          SIZE
# secure-mcp-gateway    latest    92d8c6b5714d   2 seconds ago    1.81GB
```

</details>

#### 4.3.2 Generate the config file

- This creates a config file in the `~/.enkrypt/docker/enkrypt_mcp_config.json` file on macOS/Linux and `%USERPROFILE%\.enkrypt\docker\enkrypt_mcp_config.json` file on Windows.

> **Quick shorthand** — If you have the CLI installed locally via pip, you can use the `--docker` flag on any command and skip the verbose Docker syntax:
> ```bash
> secure-mcp-gateway --docker generate-config
> ```

##### Choosing an auth provider at generation time

Identical to the local install — see [§4.1.2 → "Choosing an auth provider at generation time"](#412-run-the-generate-command) for the full explanation. In short:

- **Default (omit `--provider`)** → full **`local_apikey`** schema with a sample echo server, project, user, gateway API key, and root-level `admin_apikey`. Boots offline, no cloud dependency.
- **`--provider enkrypt`** → minimal cloud-backed schema. After generating, edit the file and set `enkrypt_config.api_key` (your Enkrypt cloud apikey) and `plugins.auth.config.gateway_name` (the saved name of the gateway you created in the Enkrypt console). The cloud owns servers/projects/users/apikeys, so those blocks are absent.

**Copy-paste commands** (all OSes, using the `--docker` shorthand — works in bash, zsh, CMD, and PowerShell since the wrapper handles per-OS quoting internally):

```bash
# 1. Default — local_apikey (offline, no cloud dependency)
secure-mcp-gateway --docker generate-config

# 2. Cloud-backed — enkrypt provider (requires container CLI >= v2.2.0; see warning below)
secure-mcp-gateway --docker generate-config --provider enkrypt

# 3. Re-generate over an existing file (adds timestamped .bkp.YYYYMMDD_HHMMSS next to the original)
secure-mcp-gateway --docker generate-config --overwrite
secure-mcp-gateway --docker generate-config --provider enkrypt --overwrite

# 4. If the default image tag isn't on Docker Hub yet, point at a locally-built image:
#    docker build -t secure-mcp-gateway .   # one-time, from this repo root
secure-mcp-gateway --docker --docker-image secure-mcp-gateway generate-config --provider enkrypt --overwrite
```

After the command succeeds, the file lands at:
- macOS/Linux: `~/.enkrypt/docker/enkrypt_mcp_config.json`
- Windows: `%USERPROFILE%\.enkrypt\docker\enkrypt_mcp_config.json`

If you don't have the CLI installed locally via pip, the equivalent raw `docker run ...` invocations for each OS shell are in the **"Verbose Docker run commands"** details block below.

> **⚠️ Re-running on an existing config?** `generate-config` refuses to clobber an existing file by default — it exits with `INFO: Config file already exists at <path>. ... use --overwrite flag.` Add `--overwrite` at the end of the command to regenerate (a timestamped `.bkp.<YYYYMMDD_HHMMSS>` backup is written next to the original first). The flag works the same for `--provider enkrypt` and the `--docker` shorthand.

> **⚠️ "unrecognized arguments: --provider enkrypt" when using `--docker`?** This means the in-container CLI is older than your host CLI (`--provider` was added in v2.2.0). The `--docker` wrapper now defaults to `enkryptai/secure-mcp-gateway:<host-version>`, but if that tag isn't on Docker Hub yet you'll see `Unable to find image ... not found`. Build the image from source: `docker build -t secure-mcp-gateway . && secure-mcp-gateway --docker --docker-image secure-mcp-gateway generate-config --provider enkrypt --overwrite`. See [Docker command pattern → Image tag is pinned to your host CLI version](#docker-command-pattern) for the full workaround table.

<details>
<summary><strong>Verbose Docker run commands (if CLI is not installed locally)</strong></summary>

**Default — `local_apikey` provider:**

```bash

# On 🍎 Linux/macOS run the below
docker run --rm -e HOST_OS=macos -e HOST_ENKRYPT_HOME=$HOME/.enkrypt -v ~/.enkrypt/docker:/app/.enkrypt/docker --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config

# On 🪟 Windows (CMD) run the below
docker run --rm -e HOST_OS=windows -e HOST_ENKRYPT_HOME=%USERPROFILE%\.enkrypt -v %USERPROFILE%\.enkrypt\docker:/app/.enkrypt/docker --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config

# On 🪟 Windows (📟 PowerShell) run the below
docker run --rm -e HOST_OS=windows -e "HOST_ENKRYPT_HOME=$env:USERPROFILE\.enkrypt" -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config
```

**Cloud-backed — `--provider enkrypt`:**

```bash
# On 🍎 Linux/macOS
docker run --rm -e HOST_OS=macos -e HOST_ENKRYPT_HOME=$HOME/.enkrypt -v ~/.enkrypt/docker:/app/.enkrypt/docker --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config --provider enkrypt

# On 🪟 Windows (CMD)
docker run --rm -e HOST_OS=windows -e HOST_ENKRYPT_HOME=%USERPROFILE%\.enkrypt -v %USERPROFILE%\.enkrypt\docker:/app/.enkrypt/docker --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config --provider enkrypt

# On 🪟 Windows (📟 PowerShell)
docker run --rm -e HOST_OS=windows -e "HOST_ENKRYPT_HOME=$env:USERPROFILE\.enkrypt" -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config --provider enkrypt
```

**Re-generate over an existing file** — append `--overwrite` to either command above. Example (PowerShell):

```bash
docker run --rm -e HOST_OS=windows -e "HOST_ENKRYPT_HOME=$env:USERPROFILE\.enkrypt" -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli generate-config --overwrite
```

</details>

<details>
<summary><strong>🐳 Example Docker config file (default <code>local_apikey</code> provider)</strong></summary>
<br>

> Identical schema to the local-install config in [§4.1.3](#413-example-of-the-generated-config-file). The only material differences from a local-install file are:
> - **Path** of `mcp_configs.<id>.mcp_config[0].config.args[0]` points at the container's site-packages: `/usr/local/lib/python3.12/dist-packages/secure_mcp_gateway/bad_mcps/echo_oauth_mcp.py` (vs. the host's venv path locally).
> - **`PICKED_CONFIG_PATH`** the gateway reads is `/app/.enkrypt/docker/enkrypt_mcp_config.json` (mounted from `~/.enkrypt/docker/` on the host), not `/app/.enkrypt/enkrypt_mcp_config.json`.
>
> Everything else (admin_apikey, common_mcp_gateway_config including `timeout_settings`, plugins, mcp_configs.common_overrides, oauth_config, denied_tools, full block lists for input/output guardrails) is byte-for-byte the same shape — the same `generate_default_config()` code path produces both.

```json
{
  "admin_apikey": "AUTO_GENERATED_256_CHAR_KEY",
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com"
  },
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_mcp_use_external_cache": false,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": null,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_gateway_cache_expiration_minutes": 5,
    "enkrypt_config_watcher_poll_seconds": 2.0,
    "enkrypt_async_input_guardrails_enabled": false,
    "enkrypt_async_output_guardrails_enabled": false,
    "timeout_settings": {
      "default_timeout": 90,
      "guardrail_timeout": 390,
      "auth_timeout": 30,
      "tool_execution_timeout": 360,
      "discovery_timeout": 540,
      "cache_timeout": 15,
      "connectivity_timeout": 6,
      "escalation_policies": {
        "warn_threshold": 0.8,
        "timeout_threshold": 1.0,
        "fail_threshold": 1.2
      }
    }
  },
  "plugins": {
    "auth": { "provider": "local_apikey", "config": {} },
    "guardrails": { "provider": "enkrypt", "config": {} },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "enabled": true,
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "mcp_configs": {
    "31491c1c-7258-4617-93aa-0bd81800d318": {
      "mcp_config_name": "default_config",
      "common_overrides": {
        "server_tools_guardrails_config": {
          "enabled": false,
          "guardrail_name": "Sample Airline Guardrail",
          "block": [
            "policy_violation",
            "injection_attack",
            "topic_detector",
            "nsfw",
            "toxicity",
            "pii",
            "keyword_detector",
            "bias",
            "sponge_attack"
          ]
        }
      },
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Simple Echo Server",
          "config": {
            "command": "python",
            "args": [
              "/usr/local/lib/python3.12/dist-packages/secure_mcp_gateway/bad_mcps/echo_oauth_mcp.py"
            ]
          },
          "oauth_config": {
            "enabled": false,
            "is_remote": false,
            "OAUTH_VERSION": "2.1",
            "OAUTH_GRANT_TYPE": "client_credentials",
            "OAUTH_CLIENT_ID": "your-client-id",
            "OAUTH_CLIENT_SECRET": "your-client-secret",
            "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
            "OAUTH_AUDIENCE": "https://api.example.com",
            "OAUTH_ORGANIZATION": "your-org-id",
            "OAUTH_SCOPE": "read write",
            "OAUTH_RESOURCE": "https://resource.example.com",
            "OAUTH_TOKEN_EXPIRY_BUFFER": 300,
            "OAUTH_USE_BASIC_AUTH": true,
            "OAUTH_ENFORCE_HTTPS": true,
            "OAUTH_TOKEN_IN_HEADER_ONLY": true,
            "OAUTH_VALIDATE_SCOPES": true,
            "OAUTH_USE_MTLS": false,
            "OAUTH_CLIENT_CERT_PATH": null,
            "OAUTH_CLIENT_KEY_PATH": null,
            "OAUTH_CA_BUNDLE_PATH": null,
            "OAUTH_REVOCATION_URL": null,
            "OAUTH_ADDITIONAL_PARAMS": {},
            "OAUTH_CUSTOM_HEADERS": {}
          },
          "tools": {},
          "denied_tools": [],
          "input_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          },
          "output_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "relevancy": false,
              "hallucination": false,
              "adherence": false
            },
            "block": [
              "policy_violation",
              "injection_attack",
              "topic_detector",
              "nsfw",
              "toxicity",
              "pii",
              "keyword_detector",
              "bias",
              "sponge_attack"
            ]
          }
        }
      ]
    }
  },
  "projects": {
    "48a1e676-5b4b-41a9-8c50-ef04be4c9173": {
      "project_name": "default_project",
      "mcp_config_id": "31491c1c-7258-4617-93aa-0bd81800d318",
      "users": [
        "dbaf0d74-a312-4469-bb92-ba4f8af7eb18"
      ],
      "created_at": "2026-01-01T00:00:00.000000"
    }
  },
  "users": {
    "dbaf0d74-a312-4469-bb92-ba4f8af7eb18": {
      "email": "default@example.com",
      "created_at": "2026-01-01T00:00:00.000000"
    }
  },
  "apikeys": {
    "Xy2RXGMu_2ZmLP9d7heVb5cj4WYeosldWvDd6hi9opW7ekRL": {
      "project_id": "48a1e676-5b4b-41a9-8c50-ef04be4c9173",
      "user_id": "dbaf0d74-a312-4469-bb92-ba4f8af7eb18",
      "created_at": "2026-01-01T00:00:00.000000"
    }
  }
}
```

</details>

<details>
<summary><strong>🐳 Example Docker config file (<code>--provider enkrypt</code> cloud-mode variant)</strong></summary>
<br>

> **Identical to the local-install cloud config** in [§4.1.3](#413-example-of-the-generated-config-file) (specifically the "☁️ Example file with `--provider enkrypt`" block) — same `generate_default_enkrypt_cloud_config()` code path runs in both modes, so the on-disk JSON is byte-for-byte the same. Only the file path differs (`/app/.enkrypt/docker/...` inside the container, mounted from `~/.enkrypt/docker/` on the host).

Run the appropriate `--provider enkrypt` command from the **"Verbose Docker run commands"** block above (Linux/macOS, Windows CMD, or Windows PowerShell). The exact file written:

```json
{
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com",
    "org_id": "YOUR_ENKRYPT_ORG_ID"
  },
  "plugins": {
    "auth": {
      "provider": "enkrypt",
      "config": {
        "gateway_name": "your-gateway-saved-name",
        "gateway_version": "v1",
        "cache_ttl_seconds": 300
      }
    },
    "guardrails": {
      "provider": "enkrypt",
      "config": {}
    },
    "telemetry": {
      "provider": "opentelemetry",
      "config": {
        "enabled": true,
        "url": "http://localhost:4317",
        "insecure": true
      }
    }
  },
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_gateway_cache_expiration_minutes": 5
  }
}
```

**What's intentionally NOT here** (see [§4.1.3 cloud-variant block](#413-example-of-the-generated-config-file) for the full rationale):

- No `mcp_configs` / `projects` / `users` / `apikeys` — the cloud owns those and the gateway resolves them per-request via `/mcp-gateway/get-gateway-config`.
- No root-level `admin_apikey` — `enkrypt_config.api_key` doubles as the admin credential for most REST endpoints. Cache-flush requires `enkrypt_config.org_id` to be set (cloud-org-gated; see [Cache-flush authorization policy](#cache-flush-authorization-policy)).
- No verbose `common_mcp_gateway_config` block (cache hosts/ports, async guardrails, timeout_settings, etc.) — the cloud variant ships a deliberately minimal common block; the two values you see (`enkrypt_log_level`, `enkrypt_gateway_cache_expiration_minutes`) are the only ones operators commonly tweak. Add any other `common_mcp_gateway_config` keys by hand if you need them.

**Two operator-must-edit values before first boot:**

1. `enkrypt_config.api_key` → your real Enkrypt cloud apikey
2. `plugins.auth.config.gateway_name` → the `saved_name` of the gateway you created in the Enkrypt console

The shipped reference file at `src/secure_mcp_gateway/example_enkrypt_cloud_config.json` is byte-for-byte identical to this example.

</details>

#### 4.3.3 Install the Gateway in Claude Desktop

- You can find the Claude config location at the below locations in your system. [For reference see Claude docs.](https://modelcontextprotocol.io/quickstart/user#:~:text=This%20will%20create%20a%20configuration%20file%20at%3A)
  - macOS: `~/Library/Application Support/Claude`
  - Windows: `%APPDATA%\Claude`

> **Note:** The generated config includes `MCP_TRANSPORT=stdio` for stdio mode communication with Claude Desktop. The command is **provider-aware** — it reads `plugins.auth.provider` from your gateway config and emits the correct `env`/`-e` shape (`ENKRYPT_GATEWAY_KEY`/`ENKRYPT_PROJECT_ID`/`ENKRYPT_USER_ID` for `local_apikey`, single `ENKRYPT_APIKEY` for `enkrypt`).

**Copy-paste command** (all OSes — the `--docker` wrapper auto-mounts your Claude config directory):

```bash
secure-mcp-gateway --docker install --client claude-desktop
```

> Hit `Unable to find image 'enkryptai/secure-mcp-gateway:<version>' ... not found`? You skipped the one-time `docker tag` step at the end of [§4.3.1](#431-build-the-docker-image). Run it once and re-try.

After it runs, **restart Claude Desktop** to pick up the new config.

<details>
<summary><strong>Verbose Docker run commands (if CLI is not installed locally)</strong></summary>

```bash
# On 🍎 Linux/macOS run the below
docker run --rm -i -e HOST_OS=macos -e HOST_ENKRYPT_HOME=$HOME/.enkrypt -v ~/.enkrypt/docker:/app/.enkrypt/docker -v ~/Library/Application\ Support/Claude:/app/.claude --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client claude-desktop

# On 🪟 Windows (CMD) run the below
docker run --rm -i -e HOST_OS=windows -e HOST_ENKRYPT_HOME=%USERPROFILE%\.enkrypt -v %USERPROFILE%\.enkrypt\docker:/app/.enkrypt/docker -v %APPDATA%\Claude:/app/.claude --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client claude-desktop

# On 🪟 Windows (📟 PowerShell) run the below
docker run --rm -i -e HOST_OS=windows -e "HOST_ENKRYPT_HOME=$env:USERPROFILE\.enkrypt" -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" -v "$env:APPDATA\Claude:/app/.claude" --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client claude-desktop
```

</details>

#### 4.3.4 Example Claude Desktop config file

> The `env` block depends on your gateway's `plugins.auth.provider` (see [§4.1.2](#412-run-the-generate-command)). Both shapes are shown below.

<details>
<summary><strong>🪟 Example Windows claude_desktop_config.json — local_apikey provider</strong></summary>
<br>

> **Why one `-e` per env var?** MCP clients set the `env` block on the spawned `docker` process, but Docker only forwards env vars across the container boundary if you list them with `-e VAR_NAME` in the args. Each key in `env` needs a matching `-e` flag — the install command (`secure-mcp-gateway install --client claude-desktop`) generates this pairing for you. Hand-rolled JSON should mirror the pattern exactly or the gateway inside the container will see `os.environ[VAR]` as unset.

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "C:\\Users\\<user>\\.enkrypt\\docker:/app/.enkrypt/docker",
        "-e",
        "ENKRYPT_GATEWAY_KEY",
        "-e",
        "ENKRYPT_PROJECT_ID",
        "-e",
        "ENKRYPT_USER_ID",
        "secure-mcp-gateway"
      ],
      "env": {
        "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
        "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
        "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
      }
    }
  }
}
```

</details>
<details>
<summary><strong>🪟 Example Windows claude_desktop_config.json — enkrypt cloud provider</strong></summary>
<br>

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "C:\\Users\\<user>\\.enkrypt\\docker:/app/.enkrypt/docker",
        "-e",
        "ENKRYPT_APIKEY",
        "secure-mcp-gateway"
      ],
      "env": {
        "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
      }
    }
  }
}
```

</details>

#### 4.3.5 Install the Gateway in Cursor

- You can find the Cursor config location at the below locations. [For reference see Cursor docs.](https://docs.cursor.com/context/model-context-protocol#configuration-locations)
  - macOS: `~/.cursor`
  - Windows: `%USERPROFILE%\.cursor`

> **Note:** The generated config includes `MCP_TRANSPORT=stdio` for stdio mode communication with Cursor. The command is **provider-aware** — it reads `plugins.auth.provider` from your gateway config and emits the correct `env`/`-e` shape (`ENKRYPT_GATEWAY_KEY`/`ENKRYPT_PROJECT_ID`/`ENKRYPT_USER_ID` for `local_apikey`, single `ENKRYPT_APIKEY` for `enkrypt`).

**Copy-paste command** (all OSes — the `--docker` wrapper auto-mounts `~/.cursor` so the in-container `install` can write back to it):

```bash
secure-mcp-gateway --docker install --client cursor
```

> Hit `Unable to find image 'enkryptai/secure-mcp-gateway:<version>' ... not found`? You skipped the one-time `docker tag` step at the end of [§4.3.1](#431-build-the-docker-image). Run it once and re-try.

After it runs, **restart Cursor** to pick up the new server. The entry lands at `~/.cursor/mcp.json` on macOS/Linux or `%USERPROFILE%\.cursor\mcp.json` on Windows.

<details>
<summary><strong>Verbose Docker run commands (if CLI is not installed locally)</strong></summary>

```bash
# On 🍎 Linux/macOS run the below
docker run --rm -i -e HOST_OS=macos -e HOST_ENKRYPT_HOME=$HOME/.enkrypt -v ~/.enkrypt/docker:/app/.enkrypt/docker -v ~/.cursor:/app/.cursor --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client cursor

# On 🪟 Windows (CMD) run the below
docker run --rm -i -e HOST_OS=windows -e HOST_ENKRYPT_HOME=%USERPROFILE%\.enkrypt -v %USERPROFILE%\.enkrypt\docker:/app/.enkrypt/docker -v %USERPROFILE%\.cursor:/app/.cursor --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client cursor

# On 🪟 Windows (📟 PowerShell) run the below
docker run --rm -i -e HOST_OS=windows -e "HOST_ENKRYPT_HOME=$env:USERPROFILE\.enkrypt" -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" -v "$env:USERPROFILE\.cursor:/app/.cursor" --entrypoint python secure-mcp-gateway -m secure_mcp_gateway.cli install --client cursor
```

</details>

#### 4.3.6 Install the Gateway in Claude Code

Claude Code uses its own CLI (`claude mcp add`) to manage MCP servers. When running the gateway in Docker, Claude Code connects via `npx mcp-remote` to the gateway's Streamable HTTP endpoint.

> **Prerequisites:** Node.js and npm must be installed on your machine (`node -v` and `npm -v` to verify).

**Step 1: Run the gateway container**

Start the gateway as a background Docker container with the Streamable HTTP endpoint exposed:

```bash
# On 🍎 Linux/macOS
docker run -d --name enkrypt-gateway -p 8000:8000 -v ~/.enkrypt/docker:/app/.enkrypt/docker secure-mcp-gateway

# On 🪟 Windows (PowerShell)
docker run -d --name enkrypt-gateway -p 8000:8000 -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" secure-mcp-gateway
```

**Step 2: Add the gateway to Claude Code**

The HTTP headers differ by auth provider:

```bash
# For local_apikey provider (default)
claude mcp add --transport http --header "apikey:YOUR_GATEWAY_KEY" --header "project_id:YOUR_PROJECT_ID" --header "user_id:YOUR_USER_ID" --scope user Enkrypt-Secure-MCP-Gateway http://localhost:8000/mcp/

# For enkrypt cloud provider (generated with --provider enkrypt)
claude mcp add --transport http --header "apikey:YOUR_ENKRYPT_CLOUD_APIKEY" --scope user Enkrypt-Secure-MCP-Gateway http://localhost:8000/mcp/
```

Replace the placeholders with the values from your `enkrypt_mcp_config.json` (`apikeys.<key>` and the matching project/user IDs for local_apikey, or `enkrypt_config.api_key` for enkrypt cloud).

<details>
<summary><strong>Alternative: stdio mode via Docker</strong></summary>
<br>

If you prefer stdio mode (no persistent container), the simplest path is to let the CLI generate Claude Code's stdio JSON for you. The command is **provider-aware** — it reads `plugins.auth.provider` from your gateway config and emits the correct `env`/`-e` shape (`ENKRYPT_GATEWAY_KEY`/`ENKRYPT_PROJECT_ID`/`ENKRYPT_USER_ID` for `local_apikey`, single `ENKRYPT_APIKEY` for `enkrypt`).

**Copy-paste command** (all OSes):

```bash
secure-mcp-gateway --docker install --client claude-code
```

> Hit `Unable to find image 'enkryptai/secure-mcp-gateway:<version>' ... not found`? You skipped the one-time `docker tag` step at the end of [§4.3.1](#431-build-the-docker-image). Run it once and re-try.

This writes the server entry under `mcpServers` in `~/.claude.json` with the correct `docker run` args and matching `env` block (handling the `-e VAR_NAME` Docker boundary-forwarding pairing for you). Skip the rest of this details block unless you want to hand-roll the JSON.

---

**Hand-roll alternative** — create or edit `~/.claude.json` and add the server under `mcpServers`. The `env` block depends on your auth provider.

> **Important:** Each key in `env` needs a matching `-e VAR_NAME` flag in `args` so Docker forwards it across the container boundary. Without the flag, the gateway inside the container will see `os.environ[VAR]` as unset. The install command (`secure-mcp-gateway install --client claude-code`) generates this pairing automatically; if you hand-roll the JSON, mirror it exactly.

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "/Users/<user>/.enkrypt/docker:/app/.enkrypt/docker",
        "-e",
        "ENKRYPT_GATEWAY_KEY",
        "-e",
        "ENKRYPT_PROJECT_ID",
        "-e",
        "ENKRYPT_USER_ID",
        "secure-mcp-gateway"
      ],
      "env": {
        "ENKRYPT_GATEWAY_KEY": "YOUR_GATEWAY_KEY",
        "ENKRYPT_PROJECT_ID": "YOUR_PROJECT_ID",
        "ENKRYPT_USER_ID": "YOUR_USER_ID"
      }
    }
  }
}
```

For the `enkrypt` cloud provider, the args list collapses to a single `-e ENKRYPT_APIKEY` and the env block matches:

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "MCP_TRANSPORT=stdio",
        "-v",
        "/Users/<user>/.enkrypt/docker:/app/.enkrypt/docker",
        "-e",
        "ENKRYPT_APIKEY",
        "secure-mcp-gateway"
      ],
      "env": {
        "ENKRYPT_APIKEY": "YOUR_ENKRYPT_CLOUD_APIKEY"
      }
    }
  }
}
```

Or use the Claude Code CLI:

```bash
# For local_apikey provider (default)
claude mcp add-json Enkrypt-Secure-MCP-Gateway '{
  "type": "stdio",
  "command": "docker",
  "args": ["run", "--rm", "-i", "-e", "MCP_TRANSPORT=stdio", "-v", "/Users/<user>/.enkrypt/docker:/app/.enkrypt/docker", "-e", "ENKRYPT_GATEWAY_KEY", "-e", "ENKRYPT_PROJECT_ID", "-e", "ENKRYPT_USER_ID", "secure-mcp-gateway"],
  "env": {
    "ENKRYPT_GATEWAY_KEY": "YOUR_GATEWAY_KEY",
    "ENKRYPT_PROJECT_ID": "YOUR_PROJECT_ID",
    "ENKRYPT_USER_ID": "YOUR_USER_ID"
  }
}'

# For enkrypt cloud provider (generated with --provider enkrypt)
claude mcp add-json Enkrypt-Secure-MCP-Gateway '{
  "type": "stdio",
  "command": "docker",
  "args": ["run", "--rm", "-i", "-e", "MCP_TRANSPORT=stdio", "-v", "/Users/<user>/.enkrypt/docker:/app/.enkrypt/docker", "-e", "ENKRYPT_APIKEY", "secure-mcp-gateway"],
  "env": {
    "ENKRYPT_APIKEY": "YOUR_ENKRYPT_CLOUD_APIKEY"
  }
}'
```

> **Note on Windows (PowerShell):** Replace `/Users/<user>/.enkrypt/docker` with your Windows path (e.g., `C:\Users\<user>\.enkrypt\docker`) and adjust the volume mount syntax accordingly.

</details>

**Step 3: Verify**

```bash
claude mcp list
```

**Step 4: Use in Claude Code**

Launch Claude Code and try prompts like `list all servers, get all tools available`.

#### 4.3.7 Running Gateway with Docker Run (Advanced)

For advanced Docker deployments, you can run the gateway container directly with custom configurations. The auth env vars depend on your gateway's `plugins.auth.provider` (see [§4.1.2](#412-run-the-generate-command)):

```bash
# Basic Docker run command — local_apikey provider (default)
docker run -d --name enkrypt-gateway -p 8000:8000 -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_GATEWAY_KEY="your-gateway-key" -e ENKRYPT_PROJECT_ID="your-project-id" -e ENKRYPT_USER_ID="your-user-id" secure-mcp-gateway:latest

# Basic Docker run command — enkrypt cloud provider (generated with --provider enkrypt)
docker run -d --name enkrypt-gateway -p 8000:8000 -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_APIKEY="your-enkrypt-cloud-apikey" secure-mcp-gateway:latest
```

**Windows PowerShell:**

```powershell
# local_apikey provider (default)
docker run -d `
  --name enkrypt-gateway `
  -p 8000:8000 `
  -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" `
  -e ENKRYPT_GATEWAY_KEY="your-gateway-key" `
  -e ENKRYPT_PROJECT_ID="your-project-id" `
  -e ENKRYPT_USER_ID="your-user-id" `
  secure-mcp-gateway:latest

# enkrypt cloud provider
docker run -d `
  --name enkrypt-gateway `
  -p 8000:8000 `
  -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" `
  -e ENKRYPT_APIKEY="your-enkrypt-cloud-apikey" `
  secure-mcp-gateway:latest
```

##### Environment Variables

Auth env vars are **provider-dependent** — exactly one of the two shapes below is required:

| Variable | Description | Default | Required (provider) |
|----------|-------------|---------|---------|
| `ENKRYPT_GATEWAY_KEY` | API key for authentication | - | Yes (`local_apikey`) |
| `ENKRYPT_PROJECT_ID` | Project ID from config | - | Yes (`local_apikey`) |
| `ENKRYPT_USER_ID` | User ID from config | - | Yes (`local_apikey`) |
| `ENKRYPT_APIKEY` | Enkrypt cloud API key (project/user resolved by Enkrypt) | - | Yes (`enkrypt`) |
| `MCP_TRANSPORT` | Transport mode: `streamable-http` or `stdio` | `streamable-http` | No |
| `SKIP_DEPENDENCY_INSTALL` | Skip runtime dependency installation | `true` (Docker), `false` (other) | No |
| `HOST` | Gateway bind address | `0.0.0.0` | No |
| `FASTAPI_HOST` | FastAPI server bind address | `0.0.0.0` | No |

##### MCP_TRANSPORT

The `MCP_TRANSPORT` environment variable controls the transport mode for the gateway.

**Transport modes:**

- **`streamable-http`** (default): HTTP server mode on port 8000. Use with `-p 8000:8000` for port mapping.
- **`stdio`**: Standard input/output mode for MCP clients that communicate via stdin/stdout. Use with `-i` flag.

**Example for stdio mode (Claude Desktop, Cursor):**

```bash
# local_apikey provider (default) — pass all 3 env vars
docker run --rm -i -e MCP_TRANSPORT=stdio -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_GATEWAY_KEY="your-gateway-key" -e ENKRYPT_PROJECT_ID="your-project-id" -e ENKRYPT_USER_ID="your-user-id" secure-mcp-gateway

# enkrypt cloud provider — pass a single env var
docker run --rm -i -e MCP_TRANSPORT=stdio -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_APIKEY="your-enkrypt-cloud-apikey" secure-mcp-gateway
```

##### SKIP_DEPENDENCY_INSTALL

The `SKIP_DEPENDENCY_INSTALL` environment variable controls whether the gateway reinstalls Python dependencies at runtime.

**Default behavior:**

- **Docker environments**: Defaults to `true` (auto-detected). Dependencies are pre-installed in the Docker image, so runtime installation is skipped automatically.
- **Non-Docker environments**: Defaults to `false`. Dependencies are installed at startup to ensure compatibility.

**When to explicitly set `SKIP_DEPENDENCY_INSTALL=false` in Docker:**

- Development environments where you're testing new dependencies
- When mounting source code volumes for live development
- If you're unsure whether all dependencies are properly installed

**When to explicitly set `SKIP_DEPENDENCY_INSTALL=true` outside Docker:**

- Production deployments where dependencies are pre-installed
- To reduce startup time (faster cold starts)
- In environments where you've already run `pip install`

**Example with docker-compose integration:**

```bash
# Connect to observability stack network — local_apikey provider (default)
# Note: SKIP_DEPENDENCY_INSTALL defaults to true in Docker, so it's optional
docker run -d --name enkrypt-gateway --network secure-mcp-gateway-observability_default -p 8000:8000 -p 8080:8080 -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_GATEWAY_KEY="your-gateway-key" -e ENKRYPT_PROJECT_ID="your-project-id" -e ENKRYPT_USER_ID="your-user-id" secure-mcp-gateway:latest

# Same, but for the enkrypt cloud provider
docker run -d --name enkrypt-gateway --network secure-mcp-gateway-observability_default -p 8000:8000 -p 8080:8080 -v ~/.enkrypt/docker:/app/.enkrypt/docker -e ENKRYPT_APIKEY="your-enkrypt-cloud-apikey" secure-mcp-gateway:latest
```

**Windows PowerShell:**

```powershell
# Note: SKIP_DEPENDENCY_INSTALL defaults to true in Docker, so it's optional
# local_apikey provider (default)
docker run -d `
  --name enkrypt-gateway `
  --network secure-mcp-gateway-observability_default `
  -p 8000:8000 `
  -p 8080:8080 `
  -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" `
  -e ENKRYPT_GATEWAY_KEY="your-gateway-key" `
  -e ENKRYPT_PROJECT_ID="your-project-id" `
  -e ENKRYPT_USER_ID="your-user-id" `
  secure-mcp-gateway:latest

# enkrypt cloud provider
docker run -d `
  --name enkrypt-gateway `
  --network secure-mcp-gateway-observability_default `
  -p 8000:8000 `
  -p 8080:8080 `
  -v "$env:USERPROFILE\.enkrypt\docker:/app/.enkrypt/docker" `
  -e ENKRYPT_APIKEY="your-enkrypt-cloud-apikey" `
  secure-mcp-gateway:latest
```

**Note:** The `--network` flag connects the gateway to the observability stack (Grafana, Prometheus, Loki, Jaeger, plus the 9 Slack alert rules) if you're running the monitoring services from [section 5](#5-optional-observability-stack--logs-metrics-traces--slack-alerts). The network name (`secure-mcp-gateway-observability_default`) is derived from the compose project name set at the top of [`observability/docker-compose.grafana.yml`](./observability/docker-compose.grafana.yml) (the `name:` field is unchanged by the file rename, so the network name is stable).

##### Port Mapping

- `8000`: Gateway MCP server (required) — bound by the default `ENTRYPOINT ["python3", "src/secure_mcp_gateway/gateway.py"]`.
- `8080`: OAuth callback server (optional, only needed for Authorization Code flow). Also bound by the gateway entrypoint when OAuth is configured.
- `8001`: REST admin API server. **Not started by the default entrypoint.** Mapping `-p 8001:8001` alone does nothing — there's no listener on 8001 inside the container unless you also start `python -m secure_mcp_gateway.api_server` (e.g. via a sidecar `docker exec`, a custom `--entrypoint`, or your own image that runs both processes). Built-in cache-flush + last-reload routes are also exposed directly on the gateway (port 8000) at `POST /api/v1/cache/flush-gateway-config` and `GET /api/v1/cache/last-reload`, so most operators don't need to expose 8001 at all.

##### Volume Mounts

- `~/.enkrypt/docker:/app/.enkrypt/docker` - Config file location (required)
- Additional mounts may be needed if your MCP servers require access to local files

> **⚠️ Important:** MCP clients (Claude Desktop, Cursor, Claude Code) spawn Docker directly without a shell, so `~` (tilde) will **not** be expanded. Always use **absolute paths** in your MCP client config JSON files (e.g. `/Users/yourname/.enkrypt/docker:/app/.enkrypt/docker` on macOS/Linux or `C:\\Users\\yourname\\.enkrypt\\docker:/app/.enkrypt/docker` on Windows).

#### ⚠️ Important: Configuring MCP Servers When Gateway Runs in Docker

When running the Enkrypt Gateway in Docker, **DO NOT configure your MCP servers to also run in Docker mode**. This causes Docker-in-Docker issues, networking problems, and volume mount complications.

**❌ Avoid (Docker-based MCP servers):**

```json
{
  "server_name": "github_server",
  "config": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "-e",
      "GITHUB_PERSONAL_ACCESS_TOKEN",
      "ghcr.io/github/github-mcp-server"
    ],
    "env": {
      "GITHUB_PERSONAL_ACCESS_TOKEN": "your-token"
    }
  }
}
```

**✅ Use instead (npx/npm/Python-based servers):**

```json
{
  "server_name": "github_server",
  "config": {
    "command": "npx",
    "args": [
      "-y",
      "@modelcontextprotocol/server-github"
    ],
    "env": {
      "GITHUB_PERSONAL_ACCESS_TOKEN": "your-token"
    }
  }
}
```

**Why?**

- Docker-in-Docker requires privileged mode and special socket mounting
- Network isolation prevents containers from communicating properly
- Volume mounts don't work as expected across container boundaries
- Performance overhead and security concerns
- Increased complexity and debugging difficulty

**Recommended MCP Server Formats When Gateway is in Docker:**

- ✅ **npx-based servers**: `npx -y @modelcontextprotocol/server-*`
- ✅ **npm-based servers**: `npm exec -y server-name`
- ✅ **Python-based servers**: `python /path/to/server.py` or `uv run server.py`
- ✅ **Node.js-based servers**: `node /path/to/server.js`
- ✅ **Remote MCP servers**: `npx mcp-remote https://api.example.com/mcp/`

**Exception:**

If you absolutely must use Docker-based MCP servers, consider:

1. Running the gateway outside of Docker (local installation), OR
2. Setting up proper Docker networking with `--network host` or custom bridge networks, OR
3. Using Docker-in-Docker with proper configuration (requires `--privileged` flag and `/var/run/docker.sock` mount - **not recommended for production**)

</details>

### 4.4 Remote Installation

<details>
<summary><strong>🌐 Remote Installation Steps </strong></summary>

#### 4.4.1 Run the Gateway in a remote server

```bash
python gateway.py

```

- Or run in k8s using our docker image `enkryptai/secure-mcp-gateway:vx.x.x`

- Example: `enkryptai/secure-mcp-gateway:v2.1.2`

- Use the latest version from Docker Hub: <https://hub.docker.com/r/enkryptai/secure-mcp-gateway/tags>

- You can either mount the config file locally or download the json file from a remote place like `S3` using an `initContainer` and mount the volume

- See `docs/secure-mcp-gateway-manifest-example.yaml` for the complete manifest file reference

#### 4.4.2 Modify your MCP Client config to use the Gateway

- You can find the Claude Desktop config location at the below locations in your system. [For reference see Claude docs.](https://modelcontextprotocol.io/quickstart/user#:~:text=This%20will%20create%20a%20configuration%20file%20at%3A)
  - macOS: `~/Library/Application Support/Claude`
  - Windows: `%APPDATA%\Claude`

- You can find the Cursor config location at the below locations. [For reference see Cursor docs.](https://docs.cursor.com/context/model-context-protocol#configuration-locations)
  - macOS: `~/.cursor`
  - Windows: `%USERPROFILE%\.cursor`

- Replace the credentials with values from your `enkrypt_mcp_config.json`. The credential shape depends on your gateway's `plugins.auth.provider`:
  - **`local_apikey`** (default) — `apikey` + `project_id` + `user_id` headers, sourced from `apikeys.<key>` and the matching project/user IDs
  - **`enkrypt` cloud** — single `apikey` header, sourced from `enkrypt_config.api_key`. Add an `X-Enkrypt-MCP-Gateway` header **only** if the gateway config leaves `plugins.auth.config.gateway_name` unset — see [§7.1](#71-enkrypt-cloud-auth-provider-and-gateway-headers)

- Replace the `http://0.0.0.0:8000/mcp/` with the `http(s)://<remote_server_ip>:<port>/mcp/`

- If you are running this locally, you can use `http://0.0.0.0:8000/mcp/`

- You can setup ingress to route the traffic to the MCP Gateway over `https`

- Example: `https://mcp.enkryptai.com/mcp/`

- **NOTE: Please make sure node and npm are installed on the client machine**
  - To verify, run `node -v` and `npm -v`

- **NOTE: Make sure to use the trailing slash `/` in the MCP URL like `/mcp/`**

**For Claude Desktop and Cursor** — add the following to your `claude_desktop_config.json` or `mcp.json`.

`local_apikey` provider (default) — three headers:

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://0.0.0.0:8000/mcp/",
        "--allow-http",
        "--header",
        "apikey:${ENKRYPT_GATEWAY_KEY}",
        "--header",
        "project_id:${ENKRYPT_PROJECT_ID}",
        "--header",
        "user_id:${ENKRYPT_USER_ID}"
      ],
      "env": {
        "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
        "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
        "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
      }
    }
  }
}

```

`enkrypt` cloud provider (generated with `--provider enkrypt`) — single header:

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://0.0.0.0:8000/mcp/",
        "--allow-http",
        "--header",
        "apikey:${ENKRYPT_APIKEY}"
      ],
      "env": {
        "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey"
      }
    }
  }
}

```

> **Optional — routing one gateway process to several cloud gateways.** If the gateway is running **without** `plugins.auth.config.gateway_name`, each client must also send `X-Enkrypt-MCP-Gateway` naming the cloud gateway's `saved_name`; the gateway forwards it to Enkrypt cloud to pick the config. When `gateway_name` *is* set in the gateway config, that value wins and this header is ignored — see [§7.1](#71-enkrypt-cloud-auth-provider-and-gateway-headers).
>
> ```json
> {
>   "mcpServers": {
>     "Enkrypt Secure MCP Gateway": {
>       "command": "npx",
>       "args": [
>         "mcp-remote",
>         "http://0.0.0.0:8000/mcp/",
>         "--allow-http",
>         "--header",
>         "apikey:${ENKRYPT_APIKEY}",
>         "--header",
>         "X-Enkrypt-MCP-Gateway:${ENKRYPT_MCP_GATEWAY}"
>       ],
>       "env": {
>         "ENKRYPT_APIKEY": "your-enkrypt-cloud-apikey",
>         "ENKRYPT_MCP_GATEWAY": "your-gateway-saved-name"
>       }
>     }
>   }
> }
> ```
>
> The env-var names here are arbitrary — `mcp-remote` just substitutes them into the header values. The gateway itself reads no env var for the gateway name, so this routing works on the streamable-HTTP transport only.

**For Claude Code** — use the `claude mcp add` command:

```bash
# local_apikey provider (default)
claude mcp add --transport http --header "apikey:YOUR_GATEWAY_KEY" --header "project_id:YOUR_PROJECT_ID" --header "user_id:YOUR_USER_ID" --scope user Enkrypt-Secure-MCP-Gateway https://mcp.your-domain.com/mcp/

# enkrypt cloud provider (generated with --provider enkrypt)
claude mcp add --transport http --header "apikey:YOUR_ENKRYPT_CLOUD_APIKEY" --scope user Enkrypt-Secure-MCP-Gateway https://mcp.your-domain.com/mcp/

# enkrypt cloud provider, gateway chosen per-request (only when the gateway config leaves plugins.auth.config.gateway_name unset)
claude mcp add --transport http --header "apikey:YOUR_ENKRYPT_CLOUD_APIKEY" --header "X-Enkrypt-MCP-Gateway:your-gateway-saved-name" --scope user Enkrypt-Secure-MCP-Gateway https://mcp.your-domain.com/mcp/
```

> **Note:** For local testing with HTTP (not HTTPS), add `--allow-http` if required, or use `http://0.0.0.0:8000/mcp/` as the URL.

</details>

## 5. (Optional) Observability Stack — Logs, Metrics, Traces & Slack Alerts

<details>
<summary><strong>📊 Observability Stack Setup and Usage </strong></summary>
<br>

This section explains how to set up and use the bundled observability stack with the Enkrypt Secure MCP Gateway. Everything is templated as code in [`observability/`](./observability/): clone, copy `.env.grafana.example`, run one `docker compose -f docker-compose.grafana.yml`, get a working dashboard with Slack alerts.

> **Two backends, pick one.** The repo ships two parallel observability stacks: the **OpenSearch** stack (primary; OTel default ports `4317/4318`) and this legacy **Grafana** stack (`4327/4328`). Each has its own compose + env files (`docker-compose.grafana.yml` + `.env.grafana` vs `docker-compose.opensearch.yml` + `.env.opensearch`) and must be invoked with explicit `-f`/`--env-file` flags. See [`observability/README.opensearch.md`](./observability/README.opensearch.md) for the OpenSearch path; the rest of this section covers the Grafana stack.
>
> For the deep dive — every alert rule, dashboard, and customisation point — see [`observability/README.md`](./observability/README.md). This section is the quick-start.

### 5.1 Architecture

```text
┌─────────────────────┐   logs (OTLP)         ┌────────────┐    LogQL    ┌─────────┐
│ secure-mcp-gateway  │──────────────────────▶│            │────────────▶│         │
│ (host process       │   metrics (OTLP)      │   OTel     │             │ Grafana │
│  on :8000)          │──────────────────────▶│ Collector  │   PromQL    │ (:3001) │
│                     │   traces  (OTLP)      │ (:4317)    │────────────▶│         │
└─────────────────────┘                       └────────────┘             └─────────┘
                                              │     │     │                  ▲
                                              ▼     ▼     ▼                  │
                                          ┌──────┐ ┌────┐ ┌────────┐         │
                                          │ Loki │ │Prom│ │ Jaeger │─────────┘
                                          └──────┘ └────┘ └────────┘   dashboards
                                                          (:16686)      & alerts
```

**Components shipped in [`observability/docker-compose.grafana.yml`](./observability/docker-compose.grafana.yml):**

| Component | Endpoint | What it does |
|---|---|---|
| **OTel Collector** | `:4327` (gRPC), `:4328` (HTTP) | Single entry point for logs / metrics / traces from the gateway. Point `plugins.telemetry.config.url` at `http://localhost:4327` (the default `4317` now routes to the OpenSearch stack) |
| **Prometheus** | `http://localhost:9090` | Scrapes the OTel Collector at `:8889` every 15s |
| **Loki** | `http://localhost:3100` | Log aggregation, receives logs from OTel Collector |
| **Jaeger UI** | `http://localhost:16686` | Trace visualization |
| **Grafana** | `http://localhost:3001` (configurable via `GRAFANA_HOST_PORT`) | Unified dashboards + 9 provisioned alert rules → Slack |

> **Grafana port note:** the compose file publishes Grafana on host port **3001** by default (container still listens on 3000) to avoid clashing with a native Grafana service or Docker WSL relay that often binds 3000 on Windows. Set `GRAFANA_HOST_PORT=3030` (or any free port) in `observability/.env.grafana` to override.

### 5.2 Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine + compose plugin (Linux)

- Gateway installed and running (follow [section 4](#4-gateway-setup))

- (Optional) A Slack incoming-webhook URL if you want the bundled alert rules to post to Slack

### 5.3 Setup Steps

1. **Copy the env template**

   ```bash
   cd observability
   cp .env.grafana.example .env.grafana
   # edit observability/.env.grafana and replace SLACK_WEBHOOK_URL with your
   # real https://hooks.slack.com/services/... URL (leave the placeholder if
   # you don't want Slack — Grafana provisioning will still succeed, the
   # Slack POST will just silently fail).
   ```

2. **Start the Observability Stack**

   ```bash
   docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d
   ```

   This brings up the OTel Collector, Prometheus, Loki, Jaeger, Promtail, and Grafana — with all dashboards, alert rules, and the Slack contact point pre-provisioned. Anonymous admin auth is enabled by default (no login screen). See [`observability/README.md` → Customising](./observability/README.md#customising) to set a real admin password.

3. **To stop the Observability Stack**

   ```bash
   docker compose down
   ```

### 5.4 Configuration

- Edit the `enkrypt_mcp_config.json` file to enable telemetry. The current shape uses the `plugins.telemetry` plugin block (provider `opentelemetry`, the default emitted by `secure-mcp-gateway generate-config`):

  ```json
  {
    "plugins": {
      "telemetry": {
        "provider": "opentelemetry",
        "config": {
          "enabled": true,
          "url": "http://localhost:4317",
          "insecure": true
        }
      }
    }
  }
  ```

### 5.5 Verification Steps

1. **Verify Services are Running**

   ```bash
   # On Windows
   docker ps | findstr "loki grafana jaeger otel prometheus"

   # On Linux/macOS
   docker ps | grep -E "loki|grafana|jaeger|otel|prometheus"
   ```

2. **Access Service UIs**

   - Grafana: <http://localhost:3001> (anonymous admin enabled by default — no login screen; override host port via `GRAFANA_HOST_PORT` in `observability/.env.grafana`)

   - Jaeger: <http://localhost:16686>

   - Prometheus: <http://localhost:9090>

   - Loki: Access through Grafana

      1. Open Grafana (<http://localhost:3001>)
      2. Go to Explore (left sidebar)
      3. Select "Loki" from the data source dropdown

3. **Verify Gateway Telemetry**
   - Make test requests through the Gateway like `List all servers and tools` and `echo test`

   - Check traces in Jaeger:
      - Add optional tags like `enkrypt_email=default@example.com` or `enkrypt_project_name=default_project` or `enkrypt_mcp_config_id=fcbd4508-1432-4f13-abb9-c495c946f638` to see the traces for a specific user, project or MCP config etc.
      - We can also combine tags by separating them with spaces like `enkrypt_email=default@example.com enkrypt_project_name=default_project`
      - Look for `enkrypt_discover_all_tools` spans
      - Examine child spans for cache, tool discovery, etc.

        ![jaeger-1](./docs/images/jaeger-1.png)

   - Check metrics in Grafana:
     - Navigate to `Drilldown` -> `metrics`
     - We can filter on various labels like `email`, `user_id`, `mcp_config_id`, `project_id`, `project_name` etc.

        ![grafana-metrics-1](./docs/images/grafana-metrics-1.png)

   - Check logs in Grafana
     - Navigate to `Drilldown` -> `Logs`
     - Select label as `service_name=secure-mcp-gateway` and click `Show logs`
     - Now we can filter by various labels like `attributes_project_name`, `attributes_project_id`, `attributes_email`, `attributes_user_id`, `attributes_mcp_config_id`, `attributes_tool_name` etc.

        ![grafana-logs-1](./docs/images/grafana-logs-1.png)

   - Check Dashboards in Grafana by navigating to `Dashboards` -> `OpenTelemetry Gateway Metrics`
      - **Due to issues in Grafana, you may need to edit each tile and click `Run queries` to see the data**

### 5.6 Available Telemetry (Not exhaustive)

1. **Traces**
   - Request processing pipeline
   - Tool invocations with duration tracking
   - Cache operations (hits/misses)
   - Guardrail checks
   - Error tracking and status monitoring
   - Detailed attributes for debugging

2. **Metrics**
   - `enkrypt_list_all_servers_calls`: API endpoint usage
   - `mcp_cache_misses_total`: Cache efficiency tracking
   - `enkrypt_servers_discovered`: Server discovery monitoring
   - `mcp_tool_calls_total`: Tool invocation tracking
   - `mcp_tool_call_duration_seconds`: Performance monitoring (histogram)

3. **Logs**
   - Structured JSON format for better querying
   - Gateway operations with context
   - Error conditions with stack traces
   - Security events and guardrail checks
   - Performance data with timing information

> The complete metric → Prometheus series → alert-rule mapping lives in [`docs/metric_reference.md`](./docs/metric_reference.md), and the metric/span/attribute name constants are in [`src/secure_mcp_gateway/plugins/telemetry/conventions.py`](./src/secure_mcp_gateway/plugins/telemetry/conventions.py).

### 5.7 Pre-Provisioned Alert Rules (Slack)

The stack ships **9 Grafana alert rules** wired to a Slack contact point — drop your webhook URL into `observability/.env.grafana` (`SLACK_WEBHOOK_URL=...`) and you start receiving guardrail/security/health alerts immediately.

| Rule | Severity | Trigger (5–10 min window) |
|---|---|---|
| `mcpgw-policy-violation-burst` | critical | > 5 `policy_violation` blocks |
| `mcpgw-injection-attack-burst` | critical | > 3 `injection_attack` input blocks |
| `mcpgw-pii-found` | critical | any PII redaction event |
| `mcpgw-toxicity-nsfw-surge` | warning | > 5 `toxicity` or `nsfw` blocks |
| `mcpgw-output-quality-failure` | warning | > 3 relevancy + adherence + hallucination blocks |
| `mcpgw-tool-deny-list-burst` | warning | > 5 deny-list-block tool calls |
| `mcpgw-user-targeting-guardrails` | critical | single `user_id` triggers > 10 guardrail blocks |
| `mcpgw-guardrail-api-latency` | warning | p95 guardrail HTTP > 2s |
| `mcpgw-auth-failure-burst` | critical | > 10 auth failures |

Burst rules use `sum by (server_name, tool_name)` (or `user_id`, `failure_reason`) so each distinct offender produces a separate Slack message rather than one aggregate alert. To tweak thresholds, edit [`observability/grafana/provisioning/alerting/rules.yaml`](./observability/grafana/provisioning/alerting/rules.yaml) and `docker compose restart grafana` — the rules reload from disk on every start. See [`observability/README.md` → Customising](./observability/README.md#customising) for adding new rules or swapping Slack for PagerDuty / Opsgenie / generic webhook / email.

</details>

## 6. Verify Installation and check the files generated

<details>
<summary><strong>✅ Verification steps and files generated</strong></summary>

### 6.1 Verify Claude Desktop

- To verify Claude installation, navigate to `claude_desktop_config.json` file by [following these instructions](https://modelcontextprotocol.io/quickstart/user#2-add-the-filesystem-mcp-server)

  - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

  - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### 6.2 Example MCP config file generated

> Examples below use the **`local_apikey` provider** (default) shape. If you generated with `--provider enkrypt`, the `env` block has a single `ENKRYPT_APIKEY` entry instead — see [§4.1.5](#415-example-of-the-claude-desktop-config-after-installation) for the enkrypt cloud variant.

<details>
<summary><strong>🍎 Example file in macOS</strong></summary>
<br>

- `~/Library/Application Support/Claude/claude_desktop_config.json`

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "/Users/user/enkryptai/secure-mcp-gateway/src/secure_mcp_gateway/gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

</details>
<details>
<summary><strong>🪟 Example file in Windows</strong></summary>
<br>

- `%USERPROFILE%\AppData\Roaming\Claude\claude_desktop_config.json`

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "mcp",
        "args": [
          "run",
          "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat",
          "ENKRYPT_PROJECT_ID": "3c09f06c-1f0d-4153-9ac5-366397937641",
          "ENKRYPT_USER_ID": "6469a670-1d64-4da5-b2b3-790de21ac726"
        }
      }
    }
  }
  ```

</details>

### 6.3 Restart Claude Desktop to run the Gateway

- After restarting, navigate to Claude Desktop `Settings`

  ![Claude Desktop Settings](./docs/images/claude-desktop-settings.png)

- Click on `Developer` -> `Enkrypt Secure MCP Gateway`

  ![Claude Desktop MCP Gateway Running](./docs/images/claude-desktop-mcp-running.png)

<br>
<details>
<summary><strong>🧰 Check tools and logs </strong></summary>
<br>

- You can also click on the settings icon below the search bar to see the Gateway in available

  ![Claude Desktop Gateway in Search](./docs/images/claude-desktop-gateway-in-search.png)

- Click on `Enkrypt Secure MCP Gateway` to see the list of tools available

  ![Claude Desktop MCP Gateway Tools](./docs/images/claude-desktop-gateway-tools-in-search.png)

- You can check Claude logs while asking Claude to do something to see the Gateway in action

  - Example 🍎 Linux/macOS log path: `~/Library/Application Support/Claude/logs/mcp-server-Enkrypt Secure MCP Gateway.log`

  - Example 🪟 Windows log path: `%USERPROFILE%\AppData\Roaming\Claude\logs\mcp-server-Enkrypt Secure MCP Gateway.log`

</details>

### 6.4 Example prompts

- `list all servers, get all tools available and echo test`
  - This uses a test MCP server `echo_server` which is in `bad_mcps/echo_mcp.py`

![claude-mcp-chat-1](./docs/images/claude-mcp-chat-1.png)

<br>
<details>
<summary><strong>💡 Other examples</strong></summary>
<br>

- We can also combine multiple prompts into one that trigger multiple tool calls at once

- Example: `echo test and also echo best`

![claude-mcp-chat-multiple](./docs/images/claude-mcp-chat-multiple.png)

- **Example: `echo "hello; ls -la; whoami"`**

- This could be a malicious prompt but because no guardrails are enabled, it will not be blocked

![claude-mcp-chat-echo-not-blocked](./docs/images/claude-mcp-chat-echo-not-blocked.png)

</details>

### 6.5 Example config file generated

- Example `enkrypt_mcp_config.json` generated by the `setup` script in `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json` on Windows

- *If you ran docker command to install the Gateway, the config file will be in `~/.enkrypt/docker/enkrypt_mcp_config.json` on macOS and `%USERPROFILE%\.enkrypt\docker\enkrypt_mcp_config.json` on Windows*

  ```json
  {
    "admin_apikey": "AUTO_GENERATED_256_CHAR_ADMIN_API_KEY_FOR_ADMINISTRATIVE_OPERATIONS",
    "enkrypt_config": {
      "api_key": "YOUR_ENKRYPT_API_KEY",
      "base_url": "https://api.enkryptai.com"
    },
    "common_mcp_gateway_config": {
      "enkrypt_log_level": "INFO",
      "enkrypt_mcp_use_external_cache": false,
      "enkrypt_cache_host": "localhost",
      "enkrypt_cache_port": 6379,
      "enkrypt_cache_db": 0,
      "enkrypt_cache_password": null,
      "enkrypt_tool_cache_expiration": 4,
      "enkrypt_gateway_cache_expiration": 24,
      "enkrypt_gateway_cache_expiration_minutes": 5,
      "enkrypt_config_watcher_poll_seconds": 2.0,
      "enkrypt_async_input_guardrails_enabled": false,
      "enkrypt_async_output_guardrails_enabled": false
    },
    "plugins": {
      "auth": { "provider": "local_apikey", "config": {} },
      "guardrails": { "provider": "enkrypt", "config": {} },
      "telemetry": {
        "provider": "opentelemetry",
        "config": {
          "enabled": true,
          "url": "http://localhost:4317",
          "insecure": true
        }
      }
    },
    "mcp_configs": {
      "fcbd4508-1432-4f13-abb9-c495c946f638": {
        "mcp_config_name": "default_config",
        "common_overrides": {
          "server_tools_guardrails_config": { "enabled": false }
        },
        "mcp_config": [
          {
            "server_name": "echo_server",
            "description": "Simple Echo Server",
            "config": {
              "command": "python",
              "args": [
                "C:\\Users\\<User>\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\bad_mcps\\echo_mcp.py"
              ]
            },
            "tools": {},
            "input_guardrails_config": {
              "enabled": false,
              "guardrail_name": "Sample Airline Guardrail",
              "additional_config": {
                "pii_redaction": false
              },
              "block": [
                "policy_violation"
              ]
            },
            "output_guardrails_config": {
              "enabled": false,
              "guardrail_name": "Sample Airline Guardrail",
              "additional_config": {
                "relevancy": false,
                "hallucination": false,
                "adherence": false
              },
              "block": [
                "policy_violation"
              ]
            }
          }
        ]
      }
    },
    "projects": {
      "3c09f06c-1f0d-4153-9ac5-366397937641": {
        "project_name": "default_project",
        "mcp_config_id": "fcbd4508-1432-4f13-abb9-c495c946f638",
        "users": [
          "6469a670-1d64-4da5-b2b3-790de21ac726"
        ],
        "created_at": "2025-07-16T17:02:00.406877"
      }
    },
    "users": {
      "6469a670-1d64-4da5-b2b3-790de21ac726": {
        "email": "default@example.com",
        "created_at": "2025-07-16T17:02:00.406902"
      }
    },
    "apikeys": {
      "2W8UupCkazk4SsOcSu_1hAbiOgPdv0g-nN9NtfZyg-rvYGat": {
        "project_id": "3c09f06c-1f0d-4153-9ac5-366397937641",
        "user_id": "6469a670-1d64-4da5-b2b3-790de21ac726",
        "created_at": "2025-07-16T17:02:00.406905"
      }
    }
  }
  ```

### 6.6 Verify Cursor

- You can see the MCP server in the list of MCP servers in Cursor by navigating to `~/.cursor/mcp.json` and also by clicking on the settings icon on the top right and then clicking on `Tools & Integrations` or on the `MCP` tab

- *Generally restarting is not needed but if it is in loading state for a long time, please restart Cursor*

  ![cursor-mcp-running](./docs/images/cursor-mcp-running.png)

- Now you can chat with the MCP server.

  - **Example prompts:**

    - *(Click `Run Tool` when Cursor asks you to)*

    - `list all servers, get all tools available and echo test`
      - This uses a test MCP server `echo_server` which is in `bad_mcps/echo_mcp.py`

    ![cursor-mcp-chat](./docs/images/cursor-mcp-chat.png)

### 6.7 Verify Claude Code

- Run `claude mcp list` to see the gateway in the list of configured MCP servers

- Launch Claude Code and run `/mcp` to check server status

- Try `list all servers, get all tools available and echo test` as a prompt to verify the gateway is working

</details>

## 7. Edit the Gateway config as needed

### 7.0 Hot-Reload (Zero-Restart Config Updates)

Edits to `enkrypt_mcp_config.json` take effect on the **next request** without restarting the gateway process or reconnecting the MCP client.

**How it works (automatic):**

- A background watcher polls the config file mtime every `enkrypt_config_watcher_poll_seconds` (default `2.0`).
- When a change is detected, the gateway:
  1. Clears the file-level config cache so the next read sees the new contents
  2. Rebuilds the auth / guardrails / telemetry providers with the new credentials
  3. Resets the timeout manager and session pool
  4. Flushes the per-gateway config cache so the next request re-fetches via the (now reloaded) auth provider
- Sessions older than `enkrypt_gateway_cache_expiration_minutes` (default `5`) are evicted on next access so previously-authenticated clients see the new config too.

**How to force a flush immediately (manual):**

The flush endpoint is mounted on **both** processes — the REST admin API (port 8001) **and** the MCP gateway (port 8000). They are separate Python processes with separate in-memory caches, so to refresh both you must call both:

```bash
# 1. Refresh the REST admin API process
curl -X POST http://localhost:8001/api/v1/cache/flush-gateway-config \
  -H "apikey: <flush_apikey>" \
  -H "Content-Type: application/json" \
  -d '{"include_tool_cache": false}'

# 2. Refresh the MCP gateway process (same payload, same auth)
curl -X POST http://localhost:8000/api/v1/cache/flush-gateway-config \
  -H "apikey: <flush_apikey>" \
  -H "Content-Type: application/json" \
  -d '{"include_tool_cache": false}'

# Returns on each:
# {
#   "status": "ok",
#   "summary": { "auth_reloaded": true, "guardrails_reloaded": true, ... },
#   "authorized_via": "org_match" | "static_admin_key",
#   "principal": "alice@example.com" | null
# }
```

**What this clears (per process):**

- The file-level `get_common_config()` cache
- The auth provider — including `EnkryptAuthProvider._cache` (the cloud-config TTL cache), so the next request triggers a fresh fetch from the Enkrypt cloud API
- The guardrail provider (re-reads guardrail credentials)
- The telemetry provider, timeout manager, and session pool
- The per-gateway config cache (`flush_all_gateway_config_cache`)

The flush endpoint also accepts `"include_tool_cache": true` to additionally drop per-server tool caches (forces re-discovery on next call). Use this when you've added new tools to a server.

**Inspecting the last flush:**

```bash
curl -H "apikey: <flush_apikey>" http://localhost:8000/api/v1/cache/last-reload
curl -H "apikey: <flush_apikey>" http://localhost:8001/api/v1/cache/last-reload
# Returns: {"last_reload_ts": <epoch>, "last_reload_summary": {...}}
```

#### Cache-flush authorization policy

The `apikey` header is validated by `auth_policy.authorize_apikey_for_cache_flush`, which has two completely different paths depending on which auth provider is active. The policy is intentionally **strict under `plugins.auth.provider == "enkrypt"`**: every flush rounds-trips Enkrypt cloud's `/consumer-info` so the request's principal (email) is recorded and the cloud's `org_id` is verified against the gateway's configured `org_id`.

| Provider | Accepted apikey | What gets recorded as `principal` |
|---|---|---|
| `plugins.auth.provider == "enkrypt"` | **Any** cloud apikey whose `/consumer-info.org_id` matches an entry in `enkrypt_config.org_id` in the gateway config (single string OR list of strings — see below). No static break-glass — root `admin_apikey` is **NOT** accepted under cloud auth. | The cloud user's `email` (or `user_id` if email is missing). |
| `plugins.auth.provider == "local_apikey"` (and other non-enkrypt providers) | Root `admin_apikey`, or the deprecated `enkrypt_config.admin_apikey`. No cloud roundtrip. | `null` (static-admin path doesn't carry identity). |

Response field `authorized_via` tells you which path matched: `"org_match"` (cloud) or `"static_admin_key"` (local).

**Required config under provider=enkrypt:**

```jsonc
{
  "enkrypt_config": {
    "api_key": "<your operator cloud apikey>",
    "base_url": "https://api.enkryptai.com",

    // Single-org gateway: one string.
    "org_id":   "<your Enkrypt org_id — see GET /consumer-info.org_id>"

    // Multi-org gateway: a list of allowed org_ids. Cache flushes
    // are accepted from any apikey whose /consumer-info.org_id matches
    // any entry. Useful when one gateway fronts multiple Enkrypt orgs
    // (e.g. operator + customer org both flushing the same shared
    // gateway). Blank / placeholder / non-string entries are silently
    // dropped during normalization; an empty effective list is treated
    // the same as the field being absent (500 no_org_gating_configured).
    // "org_id": ["<org-a-uuid>", "<org-b-uuid>"]
  },
  "plugins": { "auth": { "provider": "enkrypt", "config": {} } }
}
```

`enkrypt_config.org_id` is **mandatory** for cache flush to work under cloud auth — without it every flush request returns `500 no_org_gating_configured`. The placeholder `"YOUR_ENKRYPT_ORG_ID"` (which `secure-mcp-gateway generate-config --provider enkrypt` emits) is also treated as not-configured.

`org_id` accepts **either** a single string (the common one-org-per-gateway case) **or** a JSON list of strings (multi-org allow-list — one gateway can authorize flushes from several distinct orgs without having to flip the auth provider). A single-entry list like `["org-uuid-X"]` behaves identically to the bare string form `"org-uuid-X"` (the error message even renders without brackets in that case, so single-org alerting stays unchanged).

**Failure-mode reference:**

| HTTP | `reason` | When |
|---|---|---|
| 200 | `ok_org_match` / `ok_static_admin_key` | flush succeeded; check `authorized_via` to know which path |
| 401 | `missing_apikey` | no `apikey` header |
| 401 | `invalid_apikey` | local-provider apikey didn't match `admin_apikey` / cloud `/consumer-info` rejected the apikey |
| 403 | `org_mismatch` | cloud apikey is valid but its org_id is not in `enkrypt_config.org_id` (single value or allow-list) |
| 409 | (no `reason`) | another reload is already in progress |
| 500 | `no_admin_configured` | local provider, no `admin_apikey` set |
| 500 | `no_org_gating_configured` | enkrypt provider, `enkrypt_config.org_id` missing or still the placeholder |
| 502 | `cloud_unavailable` | cloud `/consumer-info` timed out or returned 5xx |

**Operator implications:**

- Under `provider=enkrypt`, the operator's own `enkrypt_config.api_key` still works because it survives `/consumer-info` and its `org_id` matches by construction — but the request goes through the cloud (cached 5 min after first hit per apikey).
- The Enkrypt cloud must be reachable to flush under `provider=enkrypt`. If you need an emergency local flush during a cloud outage, temporarily switch `plugins.auth.provider` to `local_apikey` (file-watcher applies the change in ~2 s; the next flush then accepts `admin_apikey`).
- Every successful flush leaves a structured log line: `[gateway_cache_routes] cache flushed via=<org_match|static_admin_key> principal=<email|null> include_tool_cache=<bool>` — searchable in OpenSearch via `log.attributes.principal` / `log.attributes.via`.

**Relevant config keys:**

| Key | Default | Meaning |
|-----|---------|---------|
| `enkrypt_gateway_cache_expiration_minutes` | `5` | TTL for cached per-gateway configs and authenticated sessions. Shorter = config edits take effect faster, longer = fewer auth round-trips. |
| `enkrypt_gateway_cache_expiration` | `24` | Legacy hours-based TTL. Kept for backward compatibility; minutes field wins when both are set. |
| `enkrypt_config_watcher_poll_seconds` | `2.0` | How often the watcher re-checks the file mtime. Set to `0` to disable automatic hot-reload (manual flush API still works). |

**Settings that still require restart:**

| Setting | Reason |
|---------|--------|
| Listen port `0.0.0.0:8000` | Socket bind happens once at FastMCP startup |
| `enkrypt_mcp_use_external_cache` toggle | In-memory ↔ Redis swap would lose in-flight operations |
| `enkrypt_cache_host` / `enkrypt_cache_port` | Redis connection pool rebuild risks dropping in-flight pipelines |
| `plugins.telemetry.config.url` / `enabled` | OpenTelemetry's global TracerProvider / MeterProvider can only be set once per process (SDK constraint) |

<details>
<summary><strong>✂️ Edit Gateway Config </strong></summary>

- **Important:**

  - With hot-reload (see Section 7.0), restarting the MCP client is **no longer required** for most config edits. Restart is only needed for the three settings listed in the table above.
  - **To make all new tools accessible, please use prompt "`list all servers, get all tools available`" for the MCP Client to discover all new tools. After this the MCP Client should be able to use all tools of the servers configured in the Gateway config file**

- You can add many MCP servers inside the `mcp_config` array of this gateway config

  - You can [look here for example servers](https://github.com/modelcontextprotocol/servers)

  - You can also try the [Enkrypt MCP Server](https://github.com/enkryptai/enkryptai-mcp-server)

  - Example:

      ```json
      {
        "common_mcp_gateway_config": {...},
        "mcp_configs": {
          "UNIQUE_MCP_CONFIG_ID": {
            "mcp_config_name": "default_config",
            "mcp_config": [
              {
                "server_name": "MCP_SERVER_NAME_1",
                "description": "MCP_SERVER_DESCRIPTION_1",
                "config": {
                  "command": "python/npx/etc.",
                  "args": [
                    "arg1", "arg2", ...
                  ],
                  "env": { "key": "value" }
                },
                // Set explicit tools to restrict access to only the allowed tools
                // Example: "tools": { "tool_name": "tool_description" }
                // Example: "tools": { "echo": "Echo a message" }
                // Or leave the tools empty {} to discover all tools dynamically
                "tools": {},
                "server_tools_guardrails_config": {"enabled": false},
                "input_guardrails_config": {...},
                "output_guardrails_config": {...}
              },
              {
                "server_name": "MCP_SERVER_NAME_2",
                "description": "MCP_SERVER_DESCRIPTION_2",
                "config": {...},
                "tools": {},
                "server_tools_guardrails_config": {"enabled": false},
                "input_guardrails_config": {...},
                "output_guardrails_config": {...}
              }
            ]
          },
          "UNIQUE_MCP_CONFIG_ID_2": {...}
        },
        "projects": {
          "UNIQUE_PROJECT_ID": {
            "project_name": "default_project",
            "mcp_config_id": "UNIQUE_MCP_CONFIG_ID",
            "users": [
              "UNIQUE_USER_ID"
            ],
            "created_at": "2025-01-01T00:00:00.000000"
          },
          "UNIQUE_PROJECT_ID_2": {...}
        },
        "users": {
          "UNIQUE_USER_ID": {
            "email": "default@example.com",
            "created_at": "2025-01-01T00:00:00.000000"
          },
          "UNIQUE_USER_ID_2": {...}
        },
        "apikeys": {
          "UNIQUE_GATEWAY_KEY": {
            "project_id": "UNIQUE_PROJECT_ID",
            "user_id": "UNIQUE_USER_ID",
            "created_at": "2025-01-01T00:00:00.000000"
          },
          "UNIQUE_GATEWAY_KEY_2": {...}
        }
      }
      ```

<br>
<details>
<summary><strong>⛩️ Gateway Config Schema</strong></summary>

- **`enkrypt_config`** (root-level): One centralized object that holds the Enkrypt cloud credentials shared across the auth and guardrails providers and (optionally) the admin REST API. Use this instead of duplicating `api_key` / `base_url` under every plugin block:

  ```json
  {
    "enkrypt_config": {
      "api_key": "YOUR_ENKRYPT_API_KEY",
      "base_url": "https://api.enkryptai.com"
    }
  }
  ```

  Resolution chain (see `src/secure_mcp_gateway/plugins/plugin_loader.py:_resolve_enkrypt_credentials`):

  1. `plugins.<auth|guardrails>.config.api_key` / `apikey` — per-plugin override, if set.
  2. `enkrypt_config.api_key` — the centralized root value.
  3. Default (empty for `api_key`, `https://api.enkryptai.com` for `base_url`).

  So you can set one `enkrypt_config.api_key` at the root and both plugins pick it up automatically. Override per-plugin only when you genuinely need different keys for auth vs guardrails (uncommon).

- **`admin_apikey`** (root-level): A 256-character random string used for authenticating REST API administrative operations (user management, project management, configuration management, API key management). Automatically generated by `secure-mcp-gateway generate-config` when the auth provider is `local_apikey`.

  - **Important**: Keep this key secure! It provides full administrative access to the gateway.
  - Used with `Authorization: Bearer <admin_apikey>` header for REST API calls.
  - Different from regular API keys used by MCP clients to connect to the gateway.
  - **With `plugins.auth.provider = "enkrypt"`** the `admin_apikey` field is **optional**: the cloud `enkrypt_config.api_key` is also accepted as an admin credential, so a separate admin secret is not required. Set `admin_apikey` only if you want a dedicated admin credential rotated independently of the cloud apikey.
  - **Legacy**: `enkrypt_config.admin_apikey` (the pre-2.2 nested location) is still honored as a deprecated fallback so existing configs keep working. New configs use the root-level placement.
  - See [Section 12: REST API for Administrative Operations](#12-other-tools-available) for details.

- If you want a different set of MCP servers for a separate client/user, you can add a new `mcp_config` section to the config file. Also, you can run cli commands. See [CLI-Commands-Reference.md](./CLI-Commands-Reference.md) section `2. CONFIGURATION MANAGEMENT` for details

- Set `enkrypt_log_level` to `DEBUG` to get more detailed logs inside `common_mcp_gateway_config` part of the config file

  - This defaults to `INFO`

- Now, inside `mcp_configs` array, for each individual MCP config, you can set the following:

  - `server_name`: A name of the MCP server which we connect to

  - `description` (optional): A description of the MCP server

  - `config`: The config for the MCP server as instructed by the MCP server's documentation

    - Generally you have the below keys in the config:

      - `command`: The command to run the MCP server

      - `args`: The arguments to pass to the command

      - `env`: The environment variables to set for the command

  - `tools`: The tools exposed by the MCP server

    - Either set explicit tools to restrict access to only the allowed tools or **leave it empty `tools": {}` for the Gateway to discover all tools dynamically**

    - Tools need to be given a name and a description like `"tools": { "dummy_echo": "Echo a message" }`

</details>
<details>
<summary><strong>🔒 Optional Guardrails Schema</strong></summary>

- Get your API key from [Enkrypt Dashboard](https://app.enkryptai.com/settings) and add it to the `enkrypt_config.api_key` field in the config file

- **Cloud-managed gateway config**: set `plugins.auth.provider` to `"enkrypt"` (see `example_enkrypt_cloud_config.json` or run `secure-mcp-gateway generate-config --provider enkrypt`). The gateway then fetches its server list, guardrail policies, and `common_overrides` from Enkrypt cloud via `/mcp-gateway/get-gateway-config`. No local `mcp_configs`/`projects`/`users`/`apikeys` blocks needed.

  - The pre-2.2 flag `enkrypt_use_remote_mcp_config` (plus `enkrypt_remote_mcp_gateway_name` / `enkrypt_remote_mcp_gateway_version`) is **deprecated**. It only drove the legacy "local_apikey provider falls back to Enkrypt cloud" path. New configs should switch to `plugins.auth.provider = "enkrypt"` instead. Existing configs that still set these flags keep working without changes.

- If you have any external cache server like KeyDB running, you can set `enkrypt_mcp_use_external_cache` to `true` in your `common_mcp_gateway_config`

  - Set other relevant keys related to cache in your `common_mcp_gateway_config`

- `enkrypt_tool_cache_expiration` (in hours) decides how long the tools discovered from the MCP servers are cached locally or in the external cache server

- `enkrypt_gateway_cache_expiration` (in hours) is the **legacy** TTL knob for cached gateway configs (kept for backward compatibility). Prefer `enkrypt_gateway_cache_expiration_minutes` (default `5`), which controls how long both the in-memory gateway-config cache and the per-`(gateway_name, version)` cloud-fetch cache (used when `plugins.auth.provider = "enkrypt"`) live before the next request triggers a refresh. See [§14.6 Zero-Restart Hot-Reload](#146-zero-restart-hot-reload).

- `enkrypt_async_input_guardrails_enabled`

  - `false` by default

  - **Async mode is not recommended for tools that perform actions which cannot be undone**

  - Because the tool call is made parallel to guardrails call, it can't be blocked if input guardrails violations are detected

  - Useful for servers that return just info without performing actions i.e., only read operations

- `enkrypt_async_output_guardrails_enabled` *(Coming soon)*

  - This makes output side guardrails calls asynchronously to save time

  - i.e., Guardrails detect call, relevancy check, adherence check, PII unredaction, etc. are made in parallel after getting the response from the MCP server

- **Inside each MCP server config, you can set the following:**

  - `input_guardrails_config`: Use this if we plan to use Enkrypt Guardrails on input side

  - `guardrail_name`: Name of the guardrails policy that you have created in the Enkrypt App or using the API/SDK

  - `enabled`: Whether to enable guardrails on the input side or not. This is `false` in the example config file

  - `additional_config`: Additional config for the guardrails policy

    - `pii_redaction`: Whether to redact PII in the request sent to the MCP server or not

      - If `true`, this also auto unredacts the PII in the response from the MCP server

  - `block`: List of guardrails to block

    - Possible values in the array are:

      - `topic_detector, nsfw, toxicity, pii, injection_attack, keyword_detector, policy_violation, bias, sponge_attack`

      - `system_prompt_protection, copyright_protection` *(Coming soon)*

      - This is similar to our AI Proxy deployments config. [Refer to our docs](https://docs.enkryptai.com/deployments-api-reference/endpoint/add-deployment#body-input-guardrails-policy-block)

- `output_guardrails_config`: Use this if we plan to use Enkrypt Guardrails on output side

  - `guardrail_name`: Name of the guardrails policy that you have created in the Enkrypt App or using the API/SDK

  - `enabled`: Whether to enable guardrails on the output side or not. This is `false` in the example config file

  - `additional_config`: Additional config for the guardrails policy

    - `relevancy`: Whether to check for relevancy of the response from the MCP server

    - `adherence`: Whether to check for adherence of the response from the MCP server

    - `hallucination`: Whether to check for hallucination in the response from the MCP server *(Coming soon)*

  - `block`: List of guardrails to block

    - Possible values in the array are:

      - All possible values in input block array plus `adherence, relevancy`

      - `system_prompt_protection, copyright_protection, hallucination` *(Coming soon)*

      - This is similar to our AI Proxy deployments config. [Refer to our docs](https://docs.enkryptai.com/deployments-api-reference/endpoint/add-deployment#body-output-guardrails-policy-block)

</details>

</details>

### 7.1 Enkrypt cloud auth provider and gateway headers

Setting `plugins.auth.provider` to `"enkrypt"` switches the gateway from local `apikeys` / `projects` / `users` / `mcp_configs` lookups to Enkrypt cloud: on every authenticated request the gateway calls `GET {base_url}/mcp-gateway/get-gateway-config` and maps the response into the internal config shape. **Which** cloud gateway config comes back is decided by the apikey plus the gateway headers described below.

<details>
<summary><strong>🔑 Config block, header contract and multi-gateway routing</strong></summary>
<br>

#### 7.1.1 `plugins.auth.config` keys

```json
{
  "plugins": {
    "auth": {
      "provider": "enkrypt",
      "config": {
        "apikey": "<boot-time fallback enkrypt apikey>",
        "gateway_name": "your-gateway-saved-name",
        "gateway_version": "v1",
        "project_name": "default",
        "base_url": "https://api.enkryptai.com",
        "cache_ttl_seconds": 600
      }
    }
  }
}
```

| Key | Required | Default | What it does |
|---|---|---|---|
| `gateway_name` | yes, unless clients send the `X-Enkrypt-MCP-Gateway` header | — | The `saved_name` of the gateway you created in the Enkrypt console (the `saved_name` field returned by `/mcp-gateway/add-gateway`). Sent to the cloud as `X-Enkrypt-MCP-Gateway`. |
| `gateway_version` | no | the `X-Enkrypt-MCP-Gateway-Version` header, else `"v1"` | Sent as `X-Enkrypt-MCP-Gateway-Version`. Setting it here **pins** the version for every request on this process and overrides the client header; leave it out to let each client pick its own. |
| `project_name` | no | inferred by the cloud from the apikey; `"default"` when the apikey isn't a project apikey | Sent as `X-Enkrypt-Project`, and **only when set** — leave it out to let the cloud infer. Config-only. |
| `apikey` | no | `enkrypt_config.api_key` | Boot-time fallback used only when an MCP client connects without its own `apikey` header. Note the spelling: under `plugins.auth.config` the key is `apikey`, not `api_key`. |
| `base_url` | no | `enkrypt_config.base_url`, else `https://api.enkryptai.com` | Trailing slash is stripped. |
| `cache_ttl_seconds` | no | `600` | TTL of the provider's in-process cloud-response cache (the shipped `--provider enkrypt` template sets `300`). |

`apikey` and `base_url` are filled in from the centralized root-level `enkrypt_config` block when absent here, so most configs only set `gateway_name` (and optionally `gateway_version` / `cache_ttl_seconds`) under `plugins.auth.config`.

> **⚠️ Removed keys fail at boot.** The pre-2.2 provider accepted `api_key`, `use_remote_config` and `timeout` under `plugins.auth.config`. Those now raise a `ValueError` on startup instead of being silently ignored — use `apikey` / `gateway_name` / `gateway_version` / `project_name` / `base_url` instead, and set the auth timeout via `common_mcp_gateway_config.timeout_settings.auth_timeout`.

#### 7.1.2 Headers your MCP client sends to the gateway

| Header | Required | Notes |
|---|---|---|
| `apikey` | yes | Your Enkrypt cloud apikey. It is read per request and forwarded as the outbound `apikey` to Enkrypt cloud, so each connected client can carry its own key and get its own config. |
| `X-Enkrypt-MCP-Gateway` | only when `plugins.auth.config.gateway_name` is **not** set | Selects which cloud gateway config to fetch, per request. If `gateway_name` **is** set in the config, the config value wins and a differing header is ignored (an `INFO` line records the override). |
| `X-Enkrypt-MCP-Gateway-Version` | no | The gateway's registered version. Cloud lookup is keyed on `(saved_name, version)`, so a gateway registered as e.g. `1` rather than `v1` is only reachable when the client sends this. Same precedence as above: a `gateway_version` pinned in `plugins.auth.config` wins and the header is ignored (logged); otherwise the header is used; otherwise `v1`. |

If neither the config nor the header supplies a gateway name, authentication fails with `Missing X-Enkrypt-MCP-Gateway header and no gateway_name in auth.config`.

`project_name` has no per-request equivalent — it comes from the config only.

> **⚠️ Don't send `ENKRYPT_GATEWAY_KEY` in cloud mode.** For backward compatibility the gateway prefers an `ENKRYPT_GATEWAY_KEY` header over `apikey` when both are present, then forwards it to the cloud. A leftover `ENKRYPT_GATEWAY_KEY` from an old `local_apikey` client config will therefore shadow your correct cloud apikey and produce 401s. Send only the headers your active provider needs (see the per-provider header table in [docs/auth-providers.md](./docs/auth-providers.md#header-contract-per-provider)).

> **Note on stdio installs.** Headers only exist on the streamable-HTTP transport. When the MCP client spawns the gateway over stdio, credentials come from env vars (`ENKRYPT_APIKEY` for the cloud provider) and there is **no** env-var equivalent for the gateway name or version — so stdio deployments must set `plugins.auth.config.gateway_name` (and `gateway_version`, if the gateway isn't `v1`) in the config file.

#### 7.1.3 Headers the gateway sends to Enkrypt cloud

`GET {base_url}/mcp-gateway/get-gateway-config` is called with:

| Header | Value |
|---|---|
| `apikey` | The calling client's apikey, falling back to `plugins.auth.config.apikey` / `enkrypt_config.api_key` |
| `X-Enkrypt-MCP-Gateway` | `plugins.auth.config.gateway_name`, falling back to the inbound `X-Enkrypt-MCP-Gateway` header |
| `X-Enkrypt-MCP-Gateway-Version` | `plugins.auth.config.gateway_version` if pinned, else the inbound `X-Enkrypt-MCP-Gateway-Version` header, else `v1` |
| `X-Enkrypt-Project` | `plugins.auth.config.project_name` — omitted entirely when unset |

Every call is logged with the apikey masked, so you can confirm which gateway/project/key a request actually used:

```text
[EnkryptAuthProvider] fetching gateway config: gateway=my-dev-gateway/v1 project=test apikey=****05yg
```

Match the last 4 characters against the key you expect — a mismatch means the client is sending the wrong header.

#### 7.1.4 One gateway process, several cloud gateways

Because `gateway_name` may arrive per request, a single gateway deployment can front more than one cloud gateway config: leave `plugins.auth.config.gateway_name` **unset** and have each MCP client send its own `X-Enkrypt-MCP-Gateway` header alongside its `apikey`. Clients whose gateway is registered under a version other than `v1` send `X-Enkrypt-MCP-Gateway-Version` alongside it. Cloud responses are cached in-process under a SHA-256 hash of `apikey | gateway_name | gateway_version | project_name`, so tenants — and two versions of the same gateway — never cross-contaminate each other's config. See [§4.4.2](#442-modify-your-mcp-client-config-to-use-the-gateway) for the client-side JSON.

Note the trade-off: `project_name` stays process-wide, so all clients on that process share it. Pin `gateway_name` (and `gateway_version`) in the config instead whenever one deployment serves exactly one cloud gateway — it is the safer default, since the effective gateway is then fixed server-side and client-supplied headers can no longer steer it. (Enkrypt cloud still authorizes every apikey against the gateway it names, so the header is not an authorization bypass either way.)

#### 7.1.5 Failure handling

Cloud transport errors, 5xx responses and non-JSON bodies hard-fail the request (`AuthStatus.ERROR` with the upstream message attached) — there is no local-file fallback and no stale-cache serving. Watch the `enkrypt.auth.failure` counter (attributes `provider` / `failure_reason`) and the `[EnkryptAuthProvider] fetching gateway config: ...` log lines to alert on upstream outages.

Full provider reference — cloud response mapping, override precedence, `local_server_overrides`, and cache invalidation — lives in [docs/auth-providers.md](./docs/auth-providers.md).

</details>

## 8. CLI Quick Start Guide

<details>
<summary><strong>🖥️ CLI Quick Start Guide </strong></summary>

This section walks you through managing the gateway entirely via the CLI — from first setup to adding servers, managing projects, and day-to-day operations.

> **Tip:** All commands below show the **local (pip)** version. For Docker, just add `--docker` to any command — see the [Docker command pattern](#docker-command-pattern) at the bottom of this section.
>
> For the complete CLI reference, see [CLI-Commands-Reference.md](./CLI-Commands-Reference.md).

---

### Step 1: Generate your config

If you haven't already, generate the default config file. This creates everything you need to get started — a config with a sample echo server, a default project, user, and API key.

```bash
secure-mcp-gateway generate-config

# To overwrite an existing config and start fresh
secure-mcp-gateway generate-config --overwrite

# Or, for the Enkrypt-cloud-backed variant (no local servers/projects/users;
# the cloud owns those). After running this, edit the file and set
# enkrypt_config.api_key and plugins.auth.config.gateway_name.
secure-mcp-gateway generate-config --provider enkrypt
```

**What this creates:**

| Item | Details |
|---|---|
| Config file | `~/.enkrypt/enkrypt_mcp_config.json` (macOS/Linux) or `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json` (Windows) |
| Default config | `default_config` with one `echo_server` |
| Default project | `default_project` linked to that config |
| Default user | `default@example.com` |
| Gateway API key | Auto-generated key for authentication |

Now that your config is ready, the next step is to tell your MCP client (Claude Desktop, Cursor, or Claude Code) about the gateway. This is a one-time setup — the install command writes the connection details into your client's config so it knows how to talk to the gateway.

---

### Step 2: Install the gateway for your MCP client

Pick the client you use and run the matching command:

```bash
# For Claude Desktop
secure-mcp-gateway install --client claude-desktop

# For Cursor
secure-mcp-gateway install --client cursor

# For Claude Code (requires the `claude` CLI — see https://docs.anthropic.com/en/docs/claude-code)
secure-mcp-gateway install --client claude-code
```

What this does behind the scenes: the install command reads the auth credentials from your generated config and writes them into your MCP client's config file. The exact `env` keys depend on your gateway's `plugins.auth.provider`:

- **`local_apikey`** (default) — install reads `apikeys.<key>` plus the matching project/user IDs and writes `ENKRYPT_GATEWAY_KEY` + `ENKRYPT_PROJECT_ID` + `ENKRYPT_USER_ID`
- **`enkrypt` cloud** (when generated with `--provider enkrypt`) — install reads `enkrypt_config.api_key` and writes a single `ENKRYPT_APIKEY`

For **Cursor** and **Claude Desktop**, you'll see output like:

```
INFO:  Updated 'Enkrypt Secure MCP Gateway' in C:\Users\<user>\.cursor\mcp.json
INFO: Successfully configured Cursor.
```

And your client's config file (e.g. `~/.cursor/mcp.json` or `~/Library/Application Support/Claude/claude_desktop_config.json`) will now contain one of these two shapes.

`local_apikey` provider (default):

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "mcp",
      "args": [
        "run",
        "<path-to-your-install>/secure_mcp_gateway/gateway.py"
      ],
      "env": {
        "ENKRYPT_GATEWAY_KEY": "<your-auto-generated-gateway-key>",
        "ENKRYPT_PROJECT_ID": "<your-project-id>",
        "ENKRYPT_USER_ID": "<your-user-id>"
      }
    }
  }
}
```

`enkrypt` cloud provider (generated with `--provider enkrypt`):

```json
{
  "mcpServers": {
    "Enkrypt Secure MCP Gateway": {
      "command": "mcp",
      "args": [
        "run",
        "<path-to-your-install>/secure_mcp_gateway/gateway.py"
      ],
      "env": {
        "ENKRYPT_APIKEY": "<your-enkrypt-cloud-apikey>"
      }
    }
  }
}
```

For **Claude Code**, the install command runs `claude mcp add` behind the scenes and you'll see:

```
INFO: Successfully installed gateway for Claude Code
INFO: Server name: Enkrypt-Secure-MCP-Gateway
INFO: Scope: user (available across all Claude Code projects)
INFO: Verify with: claude mcp list
```

Once the install finishes, **restart your MCP client** so it picks up the new configuration. After the restart, the gateway will appear as a connected MCP server and you're ready to go.

At this point your setup looks like this:

```
default_project
 └── default_config
      └── echo_server  (a simple test server that echoes back your input)

 default@example.com  ← default user
 oQrnCFS43o-...rDjX   ← auto-generated gateway API key
```

You have one **project** (`default_project`) that points to one **config** (`default_config`), and that config has one **server** (`echo_server`). A default user and gateway API key were also created so everything works out of the box.

---

### Step 3: Check what you have

You can verify this setup at any time:

```bash
# List all configs
secure-mcp-gateway config list

# List servers in a config
secure-mcp-gateway config list-servers --config-name "default_config"

# List projects linked to a config
secure-mcp-gateway config list-projects --config-name "default_config"
```

---

### What can you do from here?

You have three paths depending on what you need. Pick the one that fits and follow the steps underneath it.

> **Rule of thumb:** If you only add or remove servers within your current config, just restart your MCP client. If you switch to a different config or create a new project, you need to reinstall.

---

<details>
<summary><strong>Path A — Add a server to your existing config (simplest, no reinstall needed)</strong></summary>
<br>

This is the most common path. You already have `default_config` — just add more servers to it.

```
  default_project
   └── default_config
        ├── echo_server       (already there)
        └── github_server     ← you are adding this
```

**1. Add the server:**

```bash
secure-mcp-gateway config add-server --config-name "default_config" --server-name "github_server" --server-command "npx" --args="-y,@modelcontextprotocol/server-github" --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_YOUR_TOKEN"}' --description "GitHub MCP Server"
```

**2. Verify it was added:**

```bash
secure-mcp-gateway config list-servers --config-name "default_config"
```

You should see:

```
Servers in config "default_config":
  1. echo_server - Simple Echo Server
  2. github_server - GitHub MCP Server
```

**3. Restart your MCP client** — no reinstall needed, just restart:

| Client | How to Restart |
|---|---|
| **Cursor** | `Ctrl+Shift+P` (or `Cmd+Shift+P`) then "Developer: Reload Window" |
| **Claude Desktop** | Quit the app completely, then reopen it |
| **Claude Code** | Exit and relaunch with `claude` |

**4. Update or remove a server later:**

```bash
# Update a server's description or settings
secure-mcp-gateway config update-server --config-name "default_config" --server-name "github_server" --description "Updated GitHub Server"

# Remove a server you no longer need
secure-mcp-gateway config remove-server --config-name "default_config" --server-name "github_server"
```

</details>

<details>
<summary><strong>Path B — Create a new config under the existing project</strong></summary>
<br>

Useful when you want separate configs for different environments (e.g. dev vs. production) under the same project.

```
  default_project
   ├── default_config         (original, untouched)
   │    └── echo_server
   └── production_config      ← new config you are creating
        └── github_server
```

**1. Create the new config** — pick one of these two options:

```bash
# Option A: Create an empty config and add servers manually (Step 2 below)
secure-mcp-gateway config add --config-name "production_config"

# Option B: Copy an existing config (including all its servers) — skip Step 2
secure-mcp-gateway config copy --source-config "default_config" --target-config "production_config"
```

> You cannot do both — `config copy` creates the target config for you. If you already ran `config add`, use Option A and add servers in Step 2.

**2. Add servers to it** (skip this if you used Option B above):



```bash
secure-mcp-gateway config add-server --config-name "production_config" --server-name "github_server" --server-command "npx" --args="-y,@modelcontextprotocol/server-github" --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_YOUR_TOKEN"}' --description "GitHub MCP Server"
```

**3. Point your project to the new config:**

```bash
secure-mcp-gateway project assign-config --project-name "default_project" --config-name "production_config"
```

**4. Reinstall the gateway for your MCP client** — this is required because the project now points to a different config:

```bash
secure-mcp-gateway install --client cursor
# or: secure-mcp-gateway install --client claude-desktop
# or: secure-mcp-gateway install --client claude-code
```

**5. Restart your MCP client** to pick up the changes.

**Other config management commands:**

```bash
# Rename a config
secure-mcp-gateway config rename --config-name "production_config" --new-name "staging_config"

# Get full details of a config
secure-mcp-gateway config get --config-name "production_config"

# Delete a config you no longer need
secure-mcp-gateway config remove --config-name "production_config"
```

</details>

<details>
<summary><strong>Path C — Create an entirely new project with its own config</strong></summary>
<br>

Creates a completely fresh project. Since a new project gets its own API key, your MCP client must be updated to use it.

```
  default_project              (original, untouched)
   └── default_config
        └── echo_server

  my_new_project               ← new project you are creating
   └── my_new_config           ← new config
        └── github_server
```

**1. Create the new config:**

```bash
secure-mcp-gateway config add --config-name "my_new_config"
```

**2. Add servers to it:**

```bash
secure-mcp-gateway config add-server --config-name "my_new_config" --server-name "github_server" --server-command "npx" --args="-y,@modelcontextprotocol/server-github" --env '{"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_YOUR_TOKEN"}' --description "GitHub MCP Server"
```

**3. Create the new project and link it to the config:**

```bash
# Create the project
secure-mcp-gateway project create --project-name "my_new_project"

# Link the config to the project
secure-mcp-gateway project assign-config --project-name "my_new_project" --config-name "my_new_config"
```

**4. Add a user to the project** (or use the existing default user):

```bash
# Use existing user
secure-mcp-gateway project add-user --project-name "my_new_project" --email "default@example.com"

# Or create a new user first, then add them
secure-mcp-gateway user create --email "alice@company.com"
secure-mcp-gateway project add-user --project-name "my_new_project" --email "alice@company.com"
```

**5. Generate an API key for the user in this project:**

```bash
secure-mcp-gateway user generate-api-key --project-name "my_new_project" --email "alice@company.com"
```

**6. Reinstall the gateway for your MCP client** — this is **required** because the new project has a different API key. Without reinstalling, your client will still use the old project's key and won't see the new project's servers:

```bash
secure-mcp-gateway install --client cursor
# or: secure-mcp-gateway install --client claude-desktop
# or: secure-mcp-gateway install --client claude-code
```

**7. Restart your MCP client** to pick up the new configuration.

</details>

---

### Step 4: Set your Enkrypt API key (for guardrails)

If you want to use Enkrypt AI guardrails (input/output protection, PII redaction, toxicity filtering, etc.), you need to set your Enkrypt API key. You can get one from the [Enkrypt AI dashboard](https://app.enkryptai.com).

```bash
# Set the Enkrypt API key
secure-mcp-gateway config set-enkrypt-api-key --api-key "YOUR_ENKRYPT_API_KEY"

# Verify it was set
secure-mcp-gateway config get-enkrypt-api-key
```

> Without this key, guardrails features won't work — but the gateway itself will still route tools normally.

---

### Step 5: Turn telemetry on or off

The gateway ships with OpenTelemetry support for logging, tracing, and metrics. By default it's enabled but will silently skip if the collector endpoint isn't reachable. You can explicitly enable or disable it:

```bash
# Disable telemetry
secure-mcp-gateway config configure-telemetry --enabled false

# Enable telemetry with a custom collector URL
secure-mcp-gateway config configure-telemetry --enabled true --url "http://localhost:4317"

# Allow insecure (non-TLS) connections to the collector
secure-mcp-gateway config configure-telemetry --insecure true
```

**Starting the telemetry stack:** The gateway sends telemetry data to an OpenTelemetry collector — it doesn't run one itself. The repo ships two ready-made backends in [`observability/`](./observability/): the **OpenSearch** stack (primary, OTel default ports `4317/4318` — see [`observability/README.opensearch.md`](./observability/README.opensearch.md)) and the legacy **Grafana** stack (collector, Prometheus, Grafana, Jaeger, Loki + 9 Slack alert rules, on `4327/4328`). Run one. For the Grafana stack:

```bash
cd observability
cp .env.grafana.example .env.grafana    # (edit SLACK_WEBHOOK_URL if you want Slack alerts)
docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d
# then point plugins.telemetry.config.url at http://localhost:4327
```

| Service | URL |
|---|---|
| Grafana dashboards | http://localhost:3001 (anonymous admin; override via `GRAFANA_HOST_PORT`) |
| Jaeger trace viewer | http://localhost:16686 |
| Prometheus metrics | http://localhost:9090 |
| OTLP gRPC endpoint | http://localhost:4317 |

Once the stack is running, the gateway will automatically start sending traces, logs, and metrics to the collector. See [§5](#5-optional-observability-stack--logs-metrics-traces--slack-alerts) for full details and [`observability/README.md`](./observability/README.md) for the deep dive on alert customisation.

---

### Step 6: System operations

```bash
# Check gateway health
secure-mcp-gateway system health-check

# Backup your entire config
secure-mcp-gateway system backup

# Restore from a backup
secure-mcp-gateway system restore --file <backup_file>

# Reset to defaults (⚠️ destructive)
secure-mcp-gateway system reset
```

---

### Docker command pattern

Add `--docker` to **any** CLI command to run it inside the Docker container automatically.
The flag auto-detects your OS, sets `HOST_OS` and `HOST_ENKRYPT_HOME`, and mounts the
`~/.enkrypt/docker` volume — no long `docker run` incantation needed.

```bash
# Quick (recommended) — works on macOS, Linux, and Windows (all shells)
secure-mcp-gateway --docker <COMMAND_HERE>

# Use a custom Docker image
secure-mcp-gateway --docker --docker-image my-registry/secure-mcp-gateway:v2.1.2 <COMMAND_HERE>
```

#### Image tag is pinned to your host CLI version

Starting in **v2.2.0**, the wrapper defaults to `enkryptai/secure-mcp-gateway:<your-host-CLI-version>` (e.g. `enkryptai/secure-mcp-gateway:2.2.0`) instead of `:latest`. This prevents flag-skew bugs where a newer host CLI passes flags the older in-container CLI doesn't recognise — e.g.

```text
secure-mcp-gateway: error: unrecognized arguments: --provider enkrypt
```

(`generate-config --provider enkrypt` was added in v2.2.0; if your host CLI is v2.2.0 but the container is v2.1.6, that flag silently disappears in transit.)

If `--docker-image` is overridden and the override doesn't contain the host CLI version string, the wrapper logs a `WARN:` line so the cause of any "unrecognized arguments" error is obvious.

**If your default tag isn't on Docker Hub yet** (typical right after a host pip upgrade, before the matching image has been published), Docker exits with `not found`:

```text
Unable to find image 'enkryptai/secure-mcp-gateway:2.2.0' locally
docker: Error response from daemon: failed to resolve reference "docker.io/enkryptai/secure-mcp-gateway:2.2.0": ... not found.
```

You have three workarounds:

| Workaround | Command | Trade-off |
|---|---|---|
| **Build the image locally from this repo (recommended)** | `docker build -t secure-mcp-gateway . && secure-mcp-gateway --docker --docker-image secure-mcp-gateway <CMD>` | Always matches your host CLI; one-time `docker build` cost. |
| **Pin to a known-good published tag** | `secure-mcp-gateway --docker --docker-image enkryptai/secure-mcp-gateway:<X.Y.Z> <CMD>` | Stable; you only see flags supported by `<X.Y.Z>`. |
| **Use `:latest` and accept skew** | `secure-mcp-gateway --docker --docker-image enkryptai/secure-mcp-gateway:latest <CMD>` | Wrapper emits a `WARN:` line; new flags may fail with `unrecognized arguments`. |

**Examples:**

```bash
# List configs
secure-mcp-gateway --docker config list

# Add a server
secure-mcp-gateway --docker config add-server --config-name "default_config" --server-name "my_server" --server-command "npx" --args="-y,@example/mcp-server" --description "My Server"

# Generate config (local_apikey, default)
secure-mcp-gateway --docker generate-config

# Generate config (enkrypt cloud) — requires container CLI >= v2.2.0
secure-mcp-gateway --docker generate-config --provider enkrypt --overwrite

# Health check
secure-mcp-gateway --docker system health-check
```

---

<details>
<summary><strong>🔧 Troubleshooting — Server not showing up?</strong></summary>
<br>

```
┌──────────────────────────────────────────────────────────────────┐
│  ❓ DIAGNOSTIC FLOWCHART                                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Server not showing up after restart?                            │
│       │                                                          │
│       ▼                                                          │
│  Did you verify with "config list-servers"?                      │
│       │                                                          │
│       ├── NO → Run it. Is server listed?                         │
│       │          │                                               │
│       │          ├── NO → Wrong --config-name. Go to Step 3.     │
│       │          │                                               │
│       │          └── YES → Continue below ▼                      │
│       │                                                          │
│       └── YES, server IS in list-servers                         │
│              │                                                   │
│              ▼                                                   │
│  Did you restart the MCP client?                                 │
│       │                                                          │
│       ├── NO → Restart it (Step 5)                               │
│       │                                                          │
│       └── YES, I restarted                                       │
│              │                                                   │
│              ▼                                                   │
│  Check: does your ENKRYPT_PROJECT_ID in the                      │
│  MCP client config match a project that uses                     │
│  this config name?                                               │
│       │                                                          │
│       ├── NO → Your gateway key points to a                      │
│       │        different config. Either:                          │
│       │        a) Add server to the correct config, OR           │
│       │        b) Change the project's config assignment          │
│       │                                                          │
│       └── YES → Check if the server's command is                 │
│                 available in the gateway environment              │
│                 (e.g., npx requires Node.js)                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

</details>

</details>

## 9. (Optional) Add GitHub MCP Server to the Gateway

<details>
<summary><strong>👨🏻‍💻 Configure GitHub </strong></summary>

> **⚠️ Important Note for Docker Users:**
>
> If you're running the Enkrypt Gateway in Docker, **use the npx version** of the GitHub MCP server instead of the Docker version shown below. See the [npx-based configuration example](#github-server-configuration-npx-version) at the end of this section.
>
> For details on why, see [Section 4.3.7: Configuring MCP Servers When Gateway Runs in Docker](#-important-configuring-mcp-servers-when-gateway-runs-in-docker).

- `GitHub MCP Server` can be run with `docker` or `npx`. The Docker version requires Docker to be installed and running on your machine.

  - You can [download docker desktop from here](https://www.docker.com/products/docker-desktop/). Install and run it if you don't have it already

- [Create a personal access token from GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

  - Create a token that has access to only public repos and set expiry very low initially for testing

  - Add the below GitHub server block to `enkrypt_mcp_config.json` inside `"mcp_config": []` array. It should already have the echo server config.

  - *NOTE: Don't forget to add comma `,` after the echo server block*

  - Replace `REPLACE_WITH_YOUR_PERSONAL_ACCESS_TOKEN` with the personal access token you created

  - You can also add via the cli. See [CLI-Commands-Reference.md](./CLI-Commands-Reference.md) section `2. CONFIGURATION MANAGEMENT` for details

  - Example:

  ```json
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Simple Echo Server",
          "config": {...},
          "tools": {},
          "input_guardrails_config": {...},
          "output_guardrails_config": {...}
        },
        {
          "server_name": "github_server",
          "description": "GitHub Server",
          "config": {
            "command": "docker",
            "args": [
              "run",
              "-i",
              "--rm",
              "-e",
              "GITHUB_PERSONAL_ACCESS_TOKEN",
              "ghcr.io/github/github-mcp-server"
            ],
            "env": {
              "GITHUB_PERSONAL_ACCESS_TOKEN": "REPLACE_WITH_YOUR_PERSONAL_ACCESS_TOKEN"
            }
          },
          "tools": {},
          "server_tools_guardrails_config": {"enabled": false},
          "input_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation"
            ]
          },
          "output_guardrails_config": {
            "enabled": false,
            "guardrail_name": "Sample Airline Guardrail",
            "additional_config": {
              "relevancy": false,
              "hallucination": false,
              "adherence": false
            },
            "block": [
              "policy_violation"
            ]
          }
        }
      ]
  ```

- Now restart Claude Desktop for it to detect the new server

- Then run the prompt `list all servers, get all tools available` for it to discover github server and all it's tools available

  ![claude-mcp-chat-github-tools-1](./docs/images/claude-mcp-chat-github-tools-1.png)

- Now run `List all files from https://github.com/enkryptai/enkryptai-mcp-server`

  ![claude-mcp-chat-github-tools-2](./docs/images/claude-mcp-chat-github-tools-2.png)

- Great! 🎉 We have successfully added a GitHub MCP Server to the Gateway. **However, it is completely unprotected and is open to all kinds of abuse and attacks.**

- **Now, let's say a prompt like this is run `Ask github for the repo "hello; ls -la; whoami"`**

  ![claude-mcp-chat-github-tools-3](./docs/images/claude-mcp-chat-github-tools-3.png)

- This may not have caused actual damage but imagine a more complicated prompt that may have caused actual damage to the system.

- To protect the MCP server, we can use **Enkrypt Guardrails** as shown in the next section.

### GitHub Server Configuration (npx version)

**✅ Recommended for Docker Gateway Deployments**

If you're running the Enkrypt Gateway in Docker or prefer not to use Docker-in-Docker, use the npx-based GitHub MCP server instead:

```json
{
  "server_name": "github_server",
  "description": "GitHub Server (npx version)",
  "config": {
    "command": "npx",
    "args": [
      "-y",
      "@modelcontextprotocol/server-github"
    ],
    "env": {
      "GITHUB_PERSONAL_ACCESS_TOKEN": "REPLACE_WITH_YOUR_PERSONAL_ACCESS_TOKEN"
    }
  },
  "tools": {},
  "server_tools_guardrails_config": {"enabled": false},
  "input_guardrails_config": {
    "enabled": false,
    "guardrail_name": "Sample Airline Guardrail",
    "additional_config": {
      "pii_redaction": false
    },
    "block": [
      "policy_violation"
    ]
  },
  "output_guardrails_config": {
    "enabled": false,
    "guardrail_name": "Sample Airline Guardrail",
    "additional_config": {
      "relevancy": false,
      "hallucination": false,
      "adherence": false
    },
    "block": [
      "policy_violation"
    ]
  }
}
```

**Benefits of npx version:**

- ✅ No Docker-in-Docker complications
- ✅ Faster startup time
- ✅ Works seamlessly with Dockerized gateway
- ✅ Simpler networking and volume management
- ✅ Lower resource overhead

**Prerequisites:**

- Node.js and npm must be installed in the gateway container or on the host machine
- The default Dockerfile already includes Node.js 22.x LTS

</details>

## 9.1 (Optional) Connect to MCP Servers with OAuth

<details>
<summary><strong>🔐 Configure OAuth for Remote MCP Servers </strong></summary>

Many MCP servers require OAuth authentication to access protected resources. The Secure MCP Gateway supports OAuth 2.0/2.1 with both **Client Credentials** and **Authorization Code + PKCE** flows for seamless integration with OAuth-enabled servers.

### Overview

The Gateway handles OAuth token acquisition, caching, and automatic refresh so you don't have to manage tokens manually. Tokens are automatically injected into requests when connecting to remote MCP servers.

**Supported Grant Types:**

- **Client Credentials** - For server-to-server authentication (machine-to-machine)
- **Authorization Code + PKCE** - For user authorization flows with enhanced security

**Key Features:**

- Automatic browser authorization for Authorization Code flow
- Local and remote callback URL support
- Automatic token refresh before expiration
- Secure token caching
- PKCE (S256) for enhanced security
- State parameter for CSRF protection

### OAuth Configuration Examples

#### Client Credentials Flow (Server-to-Server)

For machine-to-machine authentication, use the Client Credentials flow:

```json
{
  "server_name": "oauth-enabled-server",
  "description": "Remote MCP Server with OAuth",
  "config": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "https://api.example.com/mcp", "--allow-http"]
  },
  "oauth_config": {
    "enabled": true,
    "is_remote": true,
    "OAUTH_VERSION": "2.1",
    "OAUTH_GRANT_TYPE": "client_credentials",
    "OAUTH_CLIENT_ID": "your-client-id",
    "OAUTH_CLIENT_SECRET": "your-client-secret",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
    "OAUTH_AUDIENCE": "https://api.example.com"
  },
  "tools": {},
  "server_tools_guardrails_config": {"enabled": false},
  "input_guardrails_config": {
    "enabled": false
  },
  "output_guardrails_config": {
    "enabled": false
  }
}
```

### Key OAuth Fields

#### Core Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `enabled` | Yes | `false` | Enable OAuth for this server |
| `is_remote` | Recommended | Auto-detected | Set to `true` for remote servers, `false` for local servers |
| `OAUTH_VERSION` | No | `"2.1"` | OAuth version: `"2.0"` or `"2.1"` |
| `OAUTH_GRANT_TYPE` | No | `"client_credentials"` | Grant type: `"client_credentials"` or `"authorization_code"` |
| `OAUTH_CLIENT_ID` | Yes | - | Your OAuth client ID |
| `OAUTH_CLIENT_SECRET` | Yes | - | Your OAuth client secret |
| `OAUTH_TOKEN_URL` | Yes | - | Token endpoint URL (must be HTTPS for OAuth 2.1) |
| `OAUTH_AUTHORIZATION_URL` | Conditional | - | Authorization endpoint (required for `authorization_code` grant) |
| `OAUTH_REDIRECT_URI` | Conditional | - | Callback URL (required for `authorization_code` grant) |

#### Optional OAuth Parameters

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `OAUTH_AUDIENCE` | No | `null` | Intended audience for the token (aud claim) |
| `OAUTH_ORGANIZATION` | No | `null` | Organization ID (for multi-tenant OAuth providers) |
| `OAUTH_SCOPE` | No | `null` | Space-separated scopes (e.g., "read write") |
| `OAUTH_RESOURCE` | No | `null` | Resource indicator (RFC 8707) |
| `OAUTH_TOKEN_EXPIRY_BUFFER` | No | `300` | Seconds before token expiry to trigger refresh (default: 5 minutes) |
| `OAUTH_USE_PKCE` | No | `false` | Enable PKCE for Authorization Code flow (recommended) |
| `OAUTH_CODE_CHALLENGE_METHOD` | No | `"S256"` | PKCE challenge method: `"S256"` (recommended) or `"plain"` |
| `OAUTH_ADDITIONAL_PARAMS` | No | `{}` | Additional parameters to include in token requests (JSON object) |
| `OAUTH_CUSTOM_HEADERS` | No | `{}` | Custom HTTP headers for token requests (JSON object) |

#### Security & Authentication Settings

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `OAUTH_USE_BASIC_AUTH` | No | `true` | Use HTTP Basic Auth for client credentials (RFC 6749 §2.3.1) |
| `OAUTH_ENFORCE_HTTPS` | No | `true` | Enforce HTTPS for OAuth 2.1 compliance (set `false` only for local testing) |
| `OAUTH_TOKEN_IN_HEADER_ONLY` | No | `true` | Send token only in Authorization header (recommended) |
| `OAUTH_VALIDATE_SCOPES` | No | `true` | Verify returned token contains requested scopes |

#### Mutual TLS (mTLS) Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `OAUTH_USE_MTLS` | No | `false` | Enable mutual TLS (RFC 8705) for enhanced security |
| `OAUTH_CLIENT_CERT_PATH` | Conditional | `null` | Path to client certificate file (required if mTLS enabled) |
| `OAUTH_CLIENT_KEY_PATH` | Conditional | `null` | Path to client private key file (required if mTLS enabled) |
| `OAUTH_CA_BUNDLE_PATH` | No | `null` | Path to CA bundle for server certificate verification |

#### Token Revocation

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `OAUTH_REVOCATION_URL` | No | `null` | Token revocation endpoint URL (RFC 7009) |

### Authorization Code + PKCE Flow

For user authorization with enhanced security, use the Authorization Code flow with PKCE:

```json
{
  "server_name": "user-auth-server",
  "description": "MCP Server requiring user authorization",
  "config": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "https://api.example.com/mcp"]
  },
  "oauth_config": {
    "enabled": true,
    "is_remote": true,
    "OAUTH_VERSION": "2.1",
    "OAUTH_GRANT_TYPE": "authorization_code",
    "OAUTH_CLIENT_ID": "your-client-id",
    "OAUTH_CLIENT_SECRET": "your-client-secret",
    "OAUTH_AUTHORIZATION_URL": "https://auth.example.com/authorize",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
    "OAUTH_REDIRECT_URI": "http://localhost:8080/callback",
    "OAUTH_SCOPE": "openid profile email",
    "OAUTH_USE_PKCE": true,
    "OAUTH_CODE_CHALLENGE_METHOD": "S256"
  },
  "tools": {},
  "server_tools_guardrails_config": {"enabled": true}
}
```

#### Automatic Browser Authorization

When using Authorization Code flow, the gateway automatically:

1. Opens your browser to the authorization URL
2. Handles the callback (localhost or remote)
3. Exchanges the authorization code for tokens
4. Caches tokens for future use

**Flow Options:**

**Localhost Callback (Automatic):**

```json
"OAUTH_REDIRECT_URI": "http://localhost:8080/callback"
```

- Gateway starts local server on port 8080
- Automatically captures authorization code
- No manual intervention needed

**Remote Callback (Manual Code Entry):**

```json
"OAUTH_REDIRECT_URI": "https://oauth.yourdomain.com/callback"
```

- Gateway opens browser for authorization
- User completes authorization on remote page
- User copies code from callback page
- User pastes code into terminal
- Gateway exchanges code for token

#### Setting Up Remote Callback

If you want to use a remote callback URL (professional, branded experience):

1. **Host the callback page:**

   ```bash
   # Quick start with Python
   python host_oauth_callback.py

   # Or with Docker
   docker-compose -f docker-compose.oauth-callback.yml up -d

   # Or deploy oauth_callback.html to any static hosting
   # (GitHub Pages, Vercel, Netlify, AWS S3, etc.)
   ```

2. **Update your config:**

   ```json
   "OAUTH_REDIRECT_URI": "https://your-domain.com/callback"
   ```

3. **Register with OAuth provider:**
   - Add callback URL to your OAuth app settings
   - Auth0: "Allowed Callback URLs"
   - Okta: "Sign-in redirect URIs"
   - Azure AD: "Redirect URIs"
   - Google: "Authorized redirect URIs"

### Testing with Echo OAuth Server

The Gateway includes a test echo server that demonstrates OAuth header injection. You can use it to verify OAuth is working correctly.

#### Step 1: Start the Echo OAuth Server

The echo OAuth server needs to run in HTTP mode to accept remote connections:

**macOS/Linux:**

```bash
# Export the environment variable
export MCP_HTTP_MODE=true

# Start the server
python src/secure_mcp_gateway/bad_mcps/echo_oauth_mcp.py
```

**Windows (PowerShell):**

```powershell
# Set the environment variable
$env:MCP_HTTP_MODE = "true"

# Start the server
python src/secure_mcp_gateway/bad_mcps/echo_oauth_mcp.py
```

**Windows (Command Prompt):**

```cmd
# Set the environment variable
set MCP_HTTP_MODE=true

# Start the server
python src/secure_mcp_gateway/bad_mcps/echo_oauth_mcp.py
```

The server will start on `http://localhost:8001/mcp/` and print OAuth-related headers whenever tools are called.

#### Step 2: Add Echo OAuth Server to Gateway Config

Add this configuration to your `enkrypt_mcp_config.json` in the `mcp_config` array:

```json
{
  "server_name": "echo_oauth_server",
  "description": "Echo Server with OAuth Testing",
  "config": {
    "command": "npx",
    "args": [
      "-y",
      "mcp-remote",
      "http://localhost:8001/mcp/",
      "--allow-http"
    ]
  },
  "oauth_config": {
    "enabled": true,
    "is_remote": true,
    "OAUTH_VERSION": "2.0",
    "OAUTH_GRANT_TYPE": "client_credentials",
    "OAUTH_CLIENT_ID": "test-client-id",
    "OAUTH_CLIENT_SECRET": "test-client-secret",
    "OAUTH_TOKEN_URL": "https://auth.example.com/oauth/token",
    "OAUTH_ENFORCE_HTTPS": false
  },
  "tools": {},
  "server_tools_guardrails_config": {"enabled": false},
  "input_guardrails_config": {
    "enabled": false
  },
  "output_guardrails_config": {
    "enabled": false
  }
}
```

**Note:** `OAUTH_ENFORCE_HTTPS: false` is set only for local testing. Always use HTTPS in production!

#### Step 3: Test OAuth Token Injection

1. Restart Claude Desktop (or your MCP client) to pick up the new server configuration

2. Use the prompt: `list all servers and discover tools from echo_oauth_server`

3. Call the echo tool: `call the echo tool from echo_oauth_server with message "test oauth"`

4. Check the echo server terminal output - you should see OAuth headers being printed:

```text
================================================================================
🔐 OAuth HTTP Headers Check (Remote Mode)
================================================================================
  ✅ AUTHORIZATION: Bearer <token>...
  ❌ X-OAUTH-TOKEN: Not set
  ❌ X-ACCESS-TOKEN: Not set

📋 All Request Headers:
  authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  content-type: application/json
  user-agent: python-requests/2.31.0
================================================================================
```

This confirms the OAuth token is being automatically acquired and injected into the Authorization header.

### OAuth Token Flows

#### Client Credentials Flow

1. **First Request**: Gateway acquires token from OAuth provider
2. **Caching**: Token is cached with expiration tracking
3. **Token Injection**:
   - **Remote servers**: Token added as `Authorization: Bearer <token>` header
   - **Local servers**: Token available in environment variables
4. **Auto-refresh**: Token refreshed 5 minutes before expiry (configurable)

#### Authorization Code + PKCE Flow

1. **Initial Setup**: Gateway generates PKCE code verifier and challenge
2. **Browser Authorization**:
   - Gateway opens browser to authorization URL
   - User logs in and authorizes the application
3. **Callback Handling**:
   - **Localhost**: Gateway automatically captures code from callback
   - **Remote**: User copies code and pastes into terminal
4. **Token Exchange**: Gateway exchanges authorization code for tokens
5. **Caching & Refresh**: Tokens cached and automatically refreshed before expiry

### Advanced Features

- **Authorization Code + PKCE**: User authorization with enhanced security (S256)
- **Automatic Browser Flow**: Opens browser and handles callback automatically
- **Remote Callback Support**: Host callback page on your domain
- **Mutual TLS (mTLS)**: Enhanced security with client certificates (RFC 8705)
- **Token Revocation**: Programmatically revoke tokens (RFC 7009)
- **Scope Validation**: Verify returned token has requested scopes
- **Custom Headers**: Add custom HTTP headers to token requests
- **State Parameter**: CSRF protection for Authorization Code flow
- **Metrics**: Track token acquisition success/failure, cache hit ratio

### Troubleshooting

**OAuth token request failed:**

- Verify CLIENT_ID and CLIENT_SECRET are correct
- Check TOKEN_URL is reachable
- Ensure HTTPS is used (or set `OAUTH_ENFORCE_HTTPS: false` for testing)

**Token not appearing in requests:**

- Confirm `is_remote: true` for remote servers
- Check server logs for OAuth acquisition messages
- Enable debug logging: `"enkrypt_log_level": "DEBUG"`

**Authorization Code flow issues:**

- Verify AUTHORIZATION_URL and REDIRECT_URI are correct
- Ensure callback URL is registered with OAuth provider
- Check that browser opens automatically (or use manual URL)
- For remote callbacks, verify callback page is accessible

**Callback not working:**

- Localhost: Gateway automatically tries next available port if 8080 is in use (up to 10 ports)
- Remote: Verify callback URL is accessible and matches OAuth provider settings
- Check for firewall blocking the callback

**Echo server not receiving headers:**

- Ensure `MCP_HTTP_MODE=true` environment variable is set
- Verify server is running on http://localhost:8001/mcp/

</details>

## 10. (Optional) Protect GitHub MCP Server and Test Echo Server

<details>
<summary><strong>🎁 Protect with Enkrypt Guardrails for FREE </strong></summary>
<br>
<details>
<summary><strong>10.1 🌐 Create a Guardrail in Enkrypt App </strong></summary>
<br>

- You can use a prompt to generate rules or generate a PDF file while you can then paste or upload while creating a policy in the App

<br>
<details>
<summary><strong>10.1.1 🔍 Rules to copy </strong></summary>
<br>

```text

1. MCP-Specific Security Policies
Scan all tool descriptions for hidden instructions/malicious patterns.

Authenticate MCP servers with cryptographic verification.

Lock and pin tool versions to prevent rug-pull attacks.

Enforce isolation between MCP servers to avoid interference.

Restrict GitHub MCP access to specific repositories and users.

2. Code Filtering and Prohibited Patterns
Block known malicious code patterns (e.g., buffer overflows, SQL injection).

Detect malware signatures (e.g., keylogger, trojan).

Prevent crypto mining code.

Identify network attack patterns (e.g., DDoS, botnet).

Block privilege escalation code (e.g., root exploits).

3. Repository Access Control
Enforce role-based read access for private repositories.

Enable strict content filtering for all access types.

Mandate audit logging for private repositories.

Quarantine access to sensitive repositories.

4. AI-Specific Guardrails
Detect tool poisoning via hidden tags and file access commands.

Monitor behavior for file access and network activity.

Require explicit UI approval for suspicious tools.

Protect against prompt injection in GitHub issues.

Block PRs that expose private repo data.

Quarantine suspicious GitHub issues.

5. RADE (Retrieval-Agent Deception) Mitigation
Scan retrieved content for embedded commands.

Validate document integrity and modification timestamps.

Sandbox retrieved content to prevent auto-execution.

6. Input Validation
Limit prompt length (max 4096 tokens).

Block forbidden keywords (e.g., "ignore previous instructions").

Detect encoded/injection patterns (base64, hex, unicode).

7. Model Behavior Constraints
Limit code generation by complexity and size.

Restrict certain languages (e.g., shell scripts, assembly).

Monitor API/system calls and network activity.

Enforce strict context boundaries across repositories.

```

</details>
<br>
<details>
<summary><strong>10.1.2 💡 Prompt used to generate the rules </strong></summary>
<br>

- `Give numbered list of security rules in plain text for configuring AI guardrails for a GitHub server on the rules and policies it needs to follow to prevent malicious use of the GitHub services`

- Then say `Research latest GitHub MCP hacks and abuses people are trying and update the rules to prevent those. Keep research to the most severe topics`

- Then say `Only keep essential security rules to reduce size. Remove unwanted sections like post incident, compliance, audit, etc which cannot be used while prevention`

- Then you can copy paste the rules while creating the policy

</details>
<br>

- Go to [Enkrypt App](https://app.enkryptai.com) and login with either OTP or Google or Microsoft account

- Click on `Policies`

  ![enkrypt-github-guardrail-1](./docs/images/enkrypt-github-guardrail-1.png)

- Click on `Add new policy`

  ![enkrypt-github-guardrail-2](./docs/images/enkrypt-github-guardrail-2.png)

- Name it `GitHub Safe Policy` and paste the policy rules and click `Save`

  ![enkrypt-github-guardrail-3](./docs/images/enkrypt-github-guardrail-3.png)

- This is how a saved policy looks like with the rules applied for `Policy violation` Guardrails

  ![enkrypt-github-guardrail-4](./docs/images/enkrypt-github-guardrail-4.png)

- Now navigate back to home or hover over left sidebar and click `Guardrails`

- Click on `Add New Guardrail` button on the top right

  ![enkrypt-app-add-guardrail-button](./docs/images/enkrypt-app-add-guardrail-button.png)

- Name it `GitHub Guardrail`, toggle `Injection Attack` OFF

  ![enkrypt-app-add-guardrail-add-1](./docs/images/enkrypt-app-add-guardrail-add-1.png)

- Scroll down on `Configure Guardrails` side panel and toggle `Policy Violation` ON, select the newly created policy and tick `Need Explanation` if needed

  ![enkrypt-app-add-guardrail-add-2](./docs/images/enkrypt-app-add-guardrail-add-2.png)

- Now, click on `Save` button on the bottom right to save the guardrail

  ![enkrypt-app-add-guardrail-add-3](./docs/images/enkrypt-app-add-guardrail-add-3.png)

- We can see the newly added guardrail in the list of guardrails

  ![enkrypt-app-add-guardrail-add-4](./docs/images/enkrypt-app-add-guardrail-add-4.png)

</details>
<details>
<summary><strong>10.2 🔑 Get Enkrypt API Key </strong></summary>
<br>

- Now, we need get out FREE API Key from Enkrypt App. Hover over the left sidebar for it to expand and click on `Settings`

  - You can also directly navigate to [https://app.enkryptai.com/settings](https://app.enkryptai.com/settings)

  ![enkrypt-app-settings-1](./docs/images/enkrypt-app-settings-1.png)

- Now click on the `Copy` icon next to your obfuscated API Key to copy the key to your clipboard as highlighted in the screenshot below

  ![enkrypt-app-settings-2](./docs/images/enkrypt-app-settings-2.png)

</details>
<details>
<summary><strong>10.3 🔑 Add API Key and the Guardrail to Config File </strong></summary>
<br>

- Now we have everything we need from the App. Let's add the API Key to the `enkrypt_mcp_config.json` file

- Open the `enkrypt_mcp_config.json` file from `~/.enkrypt/enkrypt_mcp_config.json` on macOS or `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json` on Windows

  - *If you ran docker command to install the Gateway, the config file will be in `~/.enkrypt/docker/enkrypt_mcp_config.json` on macOS and `%USERPROFILE%\.enkrypt\docker\enkrypt_mcp_config.json` on Windows*

- Add the API Key to the `common_mcp_gateway_config` section by replacing `YOUR_ENKRYPT_API_KEY` with the API Key you copied from the App

- Inside the **`GitHub`** server block we added in the previous section,

  - Add the newly created Guardrail `GitHub Guardrail` to the `input_guardrails_config` and `output_guardrails_config` sections

  - By replacing `"guardrail_name": "Sample Airline Guardrail"` with `"guardrail_name": "GitHub Guardrail"`

  - Now change `enabled` to `true` for `input_guardrails_config` from previous `false`

    - We will leave `output_guardrails_config` as `false` for now

  - We already should have `policy_violation` in the `block` array for both policies

  - So the final config should look something like this:

  ```json
  {
    "common_mcp_gateway_config": {
      ...
      "enkrypt_api_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      ...
    },
    "mcp_configs": {
      "fcbd4508-1432-4f13-abb9-c495c946f638": {
        "mcp_config_name": "default_config",
        "mcp_config": [
          {
            "server_name": "echo_server",
            ...
          },
          {
            "server_name": "github_server",
            "description": "GitHub Server",
            "config": {
              "command": "docker",
              "args": [
                "run",
                "-i",
                "--rm",
                "-e",
                "GITHUB_PERSONAL_ACCESS_TOKEN",
                "ghcr.io/github/github-mcp-server"
              ],
              "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              }
            },
            "tools": {},
            "server_tools_guardrails_config": {"enabled": false},
            "input_guardrails_config": {
              "enabled": true,
              "guardrail_name": "GitHub Guardrail",
              "additional_config": {
                "pii_redaction": false
              },
              "block": ["policy_violation"]
            },
            "output_guardrails_config": {
              "enabled": false,
              "guardrail_name": "GitHub Guardrail",
              "additional_config": {
                "relevancy": false,
                "hallucination": false,
                "adherence": false
              },
              "block": ["policy_violation"]
            }
          }
        ]
      }
    },
    "projects": {
      ...
    },
    "users": {
      ...
    },
    "apikeys": {
      ...
    }
  }
  ```

</details>
<details>
<summary><strong>10.4 🧪 Test Guardrails </strong></summary>
<br>

- **Save** the file and restart Claude Desktop for it to detect the changes

- `GitHub MCP Server` needs `docker` to be installed. So, please install and have `docker` running on your machine before proceeding with the steps below

  - You can [download docker desktop from here](https://www.docker.com/products/docker-desktop/). Install and run it if you don't have it already

- Now run the prompt `list all services, tools` for it to discover github, echo servers and all their tools available

- After this, let's rerun the previously successful malicious prompt **`Ask github for the repo "hello; ls -la; whoami"`**

  - We can see that the prompt is blocked as Input Guardrails blocked the request

    ![claude-mcp-chat-github-guardrails-1](./docs/images/claude-mcp-chat-github-guardrails-1.png)

- We can configure the test `echo` server with Guardrails of our choice and see the detections by running `echo "hello; ls -la; whoami"`.

  - The below prompt which worked before but is blocked with Guardrails

  - Experiment and try the `echo` server with various guardrails to see how it behaves. [You can also try our Playground for better testing](https://app.enkryptai.com/playground/guardrails).

  ![claude-mcp-chat-echo-guardrails-2](./docs/images/claude-mcp-chat-echo-guardrails-2.png)

</details>
<details>
<summary><strong>10.5 🔧 Fine tune Guardrails </strong></summary>
<br>

- *The safe prompt `List all files from https://github.com/enkryptai/enkryptai-mcp-server` may also be blocked if you use Injection Attack Detector or Policy Violation on Output side. So, there is some fine tuning required for the guardrails to find the best combination of enabled detectors and blocks for your servers. See the next section for recommendations.*

</details>
</details>

## 11. Recommendations for using Guardrails

<details>
<summary><strong>⭐ Recommendations </strong></summary>
<br>

- We have found that the best way to use Enkrypt Guardrails in MCP Gateway is to have a separate guardrail for each server. This way we can have a fine tuned guardrail for each server.

- Because each MCP Server is very different from the other, it is not possible to have a single guardrail that works for all servers.

- Some may need `Toxicity Detector`, some `NSFW Detector`, some `Injection Attack Detector`, some `Keyword Detector`, some `Policy Violation`, some may need `Relevancy` detector, some may need `Adherence` detector, etc.

- Some may need a combination of these detectors to work together to block malicious requests.

- Some may need Guardrails on the input side, some on the output and some may need both to be applied.

- See our docs for details on [various detectors available.](https://docs.enkryptai.com/guardrails-api-reference/Prompt_Injection)

- Hence, have separate guardrails for each server and experiment with the best combination of detectors and blocks for each server that blocks malicious requests but allows legitimate requests to pass through.

- Try our `Policy Violation` detector with your own custom policy which details what is allowed and what is not. This may be the best way for your use case.

<details>
<summary><strong>🚨 Try Policy Violation </strong></summary>
<br>

- You can navigate to the [Enkrypt App Homepage](https://app.enkryptai.com), login and Click on `Policies` to create your own custom policy.

  - This accepts text as well as PDF file as input so create a file with all the rules you want to apply to your MCP server and upload it

  - Once created, you can use it while configuring the Guardrail like we say with `GitHub Guardrail` in the previous section

  ![enkrypt-app-homepage-policies](./docs/images/enkrypt-app-homepage-policies.png)

</details>

### 11.1 Per-Server Guardrail Configuration

You can control guardrail behavior for each server individually using per-server flags in your configuration.

**Note:** This field defaults to `false`; when absent from `common_overrides`, both tool registration and server info validation are skipped.

#### `server_tools_guardrails_config` (object, default: `{"enabled": false}`)

A unified configuration sourced **exclusively from `common_overrides`** (gateway-wide). It controls both server description validation and tool registration validation via a single `enabled` flag, `guardrail_name`, and `block` list.

**Shape:**

```json
{
  "enabled": true,
  "guardrail_name": "My Guardrail Policy",
  "block": ["policy_violation", "injection_attack"],
  "additional_config": {}
}
```

When `enabled: true`, both server description validation and tool registration guardrail checks run using this policy. When `enabled: false` or absent, both are skipped.

**When to disable:**

- Testing/development environments with known safe servers
- Internal servers where content is fully trusted
- When server metadata contains technical terms that trigger false positives

**Guardrail Levels:**

The gateway has two distinct levels of guardrails:

1. **Server & Tool Registration Validation** (`server_tools_guardrails_config`)
   - **When**: During server and tool discovery
   - **What**: Validates server descriptions, tool descriptions, and schemas for harmful content
   - **Blocks**: Servers or tools with malicious metadata

2. **Runtime Guardrails** (`input_guardrails_config` / `output_guardrails_config`)
   - **When**: During tool execution (input before, output after)
   - **What**: Validates tool arguments and responses
   - **Blocks**: Requests/responses violating policies

**Note:** All three levels are independent and can be configured separately per server.

</details>

## 12. Other Tools Available

<details>
<summary><strong>🔧 REST API for Administrative Operations </strong></summary>
<br>

The Gateway provides a REST API server for administrative operations like managing users, projects, configurations, and API keys.

### Starting the REST API Server

```bash
secure-mcp-gateway system start-api --host 0.0.0.0 --port 8001
```

- **API Documentation**: Available at `http://localhost:8001/docs` (Swagger UI)
- **Health Check**: `http://localhost:8001/health`
- **OpenAPI Schema**: Loaded from `openapi.json` in the project root

### Admin API Key Authentication

**Important**: Administrative operations require a special `admin_apikey` at the **root** of the config that is separate from regular user API keys. This provides enhanced security for admin operations.

**Provider-aware behavior** (resolution policy lives in `src/secure_mcp_gateway/auth_policy.py`):

| Auth provider | `admin_apikey` required? | Notes |
|---|---|---|
| `local_apikey` (default) | **Yes** | The cloud `enkrypt_config.api_key` is **not** accepted as an admin credential (would silently widen the trust boundary). |
| `enkrypt` (cloud) | **Optional** | The cloud `enkrypt_config.api_key` is also accepted as an admin credential. Set `admin_apikey` only if you want a dedicated admin secret rotated independently of the cloud apikey. |

The pre-2.2 nested location `enkrypt_config.admin_apikey` is still honored as a deprecated fallback so existing configs keep working without edits.

#### Getting Your Admin API Key

The `admin_apikey` is automatically generated at the root of the config when you run `secure-mcp-gateway generate-config` (the default `local_apikey` provider variant). Find it in your configuration file:

- **Windows**: `%USERPROFILE%\.enkrypt\enkrypt_mcp_config.json`
- **macOS/Linux**: `~/.enkrypt/enkrypt_mcp_config.json`

```json
{
  "admin_apikey": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6...",
  "enkrypt_config": {
    "api_key": "YOUR_ENKRYPT_API_KEY",
    "base_url": "https://api.enkryptai.com"
  },
  "apikeys": {
    "regular_user_key_1": { ... },
    "regular_user_key_2": { ... }
  },
  ...
}
```

> **Note**: If you used `--provider enkrypt` to generate the config, you won't see an `admin_apikey` at all — the cloud `enkrypt_config.api_key` is used as the admin credential by default. Add `admin_apikey` at the root only if you want a separate admin secret.

#### Key Differences

- **`admin_apikey`** (root-level): Used for all administrative operations (user management, project management, etc.)
  - 256-character random string for maximum security
  - Generated during `secure-mcp-gateway generate-config` (only when `--provider local_apikey`, which is the default)
  - Required for REST API endpoints when the auth provider is `local_apikey`. Optional with provider `enkrypt`.

- **`apikeys`** (in the `apikeys` section): Used for gateway access by users
  - Used by MCP clients to connect to the gateway
  - Associated with specific users and projects
  - Not used for administrative operations

#### Using the Admin API Key

Include the `admin_apikey` in the Authorization header for all administrative API calls:

```bash
curl -X GET "http://localhost:8001/api/v1/users" -H "Authorization: Bearer YOUR_ADMIN_API_KEY_HERE"
```

**Security Note**:
- Keep your admin API key secure and never commit it to version control
- Only share the admin API key with authorized administrators
- Regular users should never have access to the admin API key

### Available Administrative Operations

The REST API provides endpoints for:

1. **User Management**: Create, list, update, and delete users
2. **Project Management**: Create projects, assign configurations, manage users
3. **API Key Management**: Generate, rotate, disable/enable, and delete API keys
4. **Configuration Management**: Create, update, and manage MCP configurations and servers

For complete API documentation and examples, see:
- [API-Reference.md](./API-Reference.md)
- Interactive API docs at `http://localhost:8001/docs`

</details>

<details>
<summary><strong>💾 Cache Management </strong></summary>
<br>
<details>
<summary><strong>12.1 📊 Get Cache Status </strong></summary>
<br>

- The Gateway can give the summary of it's cache status by looking at the local/external cache server

- This is useful to debug issues if for example a tool was updated remotely by a server but the Gateway is not aware of it yet

  ![claude-mcp-chat-get-cache-status](./docs/images/claude-mcp-chat-get-cache-status.png)

</details>
<details>
<summary><strong>12.2 🧹 Clear Cache </strong></summary>

- The Gateway can clear it's cache from local/external cache server

- This is useful to clear the cache if for example a tool was updated remotely by a server but the Gateway is not aware of it yet

- You can either clear all cache or specific cache by providing the `server_name`

  - Example: `clear cache for echo_server`

- You can also clear all cache or just the gateway cache or just the server cache

  - Example: `clear all cache`, `clear just gateway cache`, `clear server cache for echo_server`, `Clear all server cache`

  ![claude-mcp-chat-clear-cache](./docs/images/claude-mcp-chat-clear-cache.png)

</details>
</details>

## 13. (Optional) Sandbox Isolation

Sandbox isolation lets you run each MCP server inside an isolated container or microVM, reducing the blast radius if a server is compromised or malicious. When enabled, every MCP server launch is transparently wrapped — no changes to your MCP clients or servers are needed.

### What does the sandbox protect against?

| Threat | Without Sandbox | With Sandbox |
|---|---|---|
| Filesystem access | Full host filesystem | Read-only `/app` mount only |
| Network access | Full network | Blocked (`--network=none`) |
| Resource exhaustion (fork bomb, OOM) | Can crash host | Capped at container limits |
| Environment variable theft | All env vars visible | Only allowlisted vars passed |
| Persistence across calls | Processes can persist | Ephemeral — destroyed after each session |

### Quick enable

```bash
# 1. Enable sandbox in global config
secure-mcp-gateway config update-sandbox --enabled --runtime docker

# 2. Build a Docker image with MCP dependencies
docker build -t sandbox-test-mcp -f tests/Dockerfile.sandbox-test .

# 3. Enable for a specific server with a custom image
secure-mcp-gateway config update-server-sandbox \
    --config-name default_config \
    --server-name echo_server \
    --enabled \
    --image sandbox-test-mcp
```

### Per-server configuration

Each server can override global sandbox defaults:

```json
{
    "server_name": "untrusted_server",
    "config": { "command": "python", "args": ["server.py"] },
    "sandbox": {
        "enabled": true,
        "runtime": "docker",
        "image": "my-mcp-image:latest",
        "memory_limit": "256m",
        "cpu_limit": "0.5",
        "network": "none",
        "allowed_env": ["GITHUB_TOKEN"]
    }
}
```

### Supported runtimes

| Runtime | Isolation | Platform | Status |
|---|---|---|---|
| Docker | Namespace + cgroup | Linux, macOS, Windows | Production ready |
| Podman | Namespace + cgroup (rootless) | Linux, macOS | Production ready |
| Microsandbox | Hardware microVM (libkrun) | Linux, macOS | SDK pending |
| NovaVM | Hardware microVM (KVM) | Linux | CLI pending |

> For the full setup guide, configuration reference, testing instructions, and troubleshooting, see **[Sandbox Isolation Walkthrough](./docs/sandbox_walkthrough.md)**.

## 14. Deployment patterns

<details>
<summary><strong>🪂 Deployment Patterns </strong></summary>

1. [Local Gateway, Local Guardrails and Local MCP Server](#141-local-gateway-local-guardrails-and-local-mcp-server)

2. [Local Gateway, Local MCP Server with Remote Guardrails](#142-local-gateway-local-mcp-server-with-remote-guardrails)

3. [Local Gateway with Remote MCP Server and Remote Guardrails](#143-local-gateway-with-remote-mcp-server-and-remote-guardrails)

4. [Remote Gateway, Remote MCP Server and Remote Guardrails](#144-remote-gateway-remote-mcp-server-and-remote-guardrails)

### 14.1 Local Gateway, Local Guardrails and Local MCP Server

![Local Gateway with Local Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20All%20Local.drawio.png)

### 14.2 Local Gateway, Local MCP Server with Remote Guardrails

![Local Gateway with Remote Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local.drawio.png)

### 14.3 Local Gateway with Remote MCP Server and Remote Guardrails

![Local Gateway with Remote Guardrails and Remote MCP Server Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local%20with%20Remote.drawio.png)

### 14.4 Remote Gateway, Remote MCP Server and Remote Guardrails

![Remote Gateway with Remote Guardrails and Remote MCP Server Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Full%20Remote.drawio.png)

</details>

## 15. Uninstall the Gateway

<details>
<summary><strong>🗑️ Uninstall the Gateway </strong></summary>

- To remove the Gateway from any MCP client, just remove the MCP server block `"Enkrypt Secure MCP Gateway": {...}` from the client's config file. For Claude Code, run `claude mcp remove Enkrypt-Secure-MCP-Gateway`.

  - Restart the MCP client to apply the changes for some clients like Claude Desktop. Cursor does not require a restart.

- To uninstall the pip package, run the following command:

  ```bash
  pip uninstall secure-mcp-gateway
  ```

</details>

## 16. Troubleshooting

<details>
<summary><strong>🕵 Troubleshooting </strong></summary>

- If any calls fail in the client, please look at the mcp logs of the respective client

  - [See this for Claude logs location](https://modelcontextprotocol.io/docs/tools/debugging#viewing-logs)

    - Example 🍎 Linux/macOS log path: `~/Library/Logs/Claude/mcp-server-Enkrypt Secure MCP Gateway.log`
    - Example 🪟 Windows log path: `%USERPROFILE%\AppData\Roaming\Claude\logs\mcp-server-Enkrypt Secure MCP Gateway.log`

  - [See this discussion for Cursor logs](https://forum.cursor.com/t/where-can-we-find-mcp-error-log/74719)

- If you see errors like `Exception: unhandled errors in a TaskGroup (1 sub-exception)` then maybe the MCP server the gateway is trying to use is not running.
  - So, please make sure the file it is trying to access is available
  - Any pre-requisites for the MCP server to run are met like `docker` running, etc.

- If we need more detailed logs, please set the `enkrypt_log_level` to `debug` in the `enkrypt_mcp_config.json` file and restart the MCP client.

### 16.1 OpenTelemetry Troubleshooting

1. **SSL Handshake Errors**

   If you see SSL errors like:

   ```bash
   SSL_ERROR_SSL: error:100000f7:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER
   ```

   Solution: Add `insecure=True` to the OTLP exporter configuration in `telemetry.py`

2. **No Logs in Loki**

   - Verify OTLP collector is running:

     ```bash
     docker logs secure-mcp-gateway-otel-collector-1
     ```

   - Check collector config in `otel_collector/otel-collector-config.yaml`

   - Verify Loki is receiving data:

     ```bash
     curl -G -s "http://localhost:3100/loki/api/v1/query" --data-urlencode 'query={job="enkrypt"}'
     ```

3. **Missing Metrics**

   - Check OTLP collector metrics pipeline:

     ```bash
     curl http://localhost:8888/metrics
     ```

   - Verify metrics in collector logs:

     ```bash
     docker logs secure-mcp-gateway-otel-collector-1 | grep "metrics"
     ```

4. **Docker Issues**

   ```bash
   # Restart the observability stack (use the compose file for whichever
   # backend you run -- the bare `docker compose` form no longer works
   # since both stacks use explicit -f/--env-file).
   cd observability
   # OpenSearch (primary):
   docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch down
   docker compose -f docker-compose.opensearch.yml --env-file .env.opensearch up -d
   # …or legacy Grafana:
   docker compose -f docker-compose.grafana.yml --env-file .env.grafana down
   docker compose -f docker-compose.grafana.yml --env-file .env.grafana up -d

   # Check individual service logs
   docker logs <service-name>
   ```

</details>

## 17. Known Issues being worked on

- Output guardrails are not being applied to non-text tool results. Support for other media types like images, audio, etc. is coming soon.

## 18. Known Limitations

- The Gateway does not support a scenario where the Gateway is deployed remotely but the MCP server is deployed locally (without being exposed to the internet). This is because the Gateway needs to know the MCP server's address to forward requests to it.

## 19. Contribute

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for how to submit changes and our [Contributor License Agreement (CLA)](CLA.md), which you agree to by submitting a pull request.

- Look at the `TODO` file for the current work in progress and yet to be implemented features

- Install the gateway locally to test your changes
  - by following the [Git clone steps](#42-local-installation-with-git-clone)
  - or build it using `python -m build`, activate the venv and install using `pip install .`

- Report or fix any bugs you encounter 😊

## 20. Testing

<details>
<summary><strong>🧪 Running Tests </strong></summary>

The gateway includes a comprehensive test suite that validates all core functionality including server discovery, tool execution, guardrails, caching, telemetry, and more.

### Prerequisites

- Gateway installed locally (follow [Local Installation](#42-local-installation-with-git-clone))
- Virtual environment activated
- Echo OAuth MCP server running (for testing remote server scenarios)

### Running the Test Suite

#### Step 1: Set Environment Variable

**Windows PowerShell:**

```powershell
$env:MCP_HTTP_MODE="true"
```

**Windows Command Prompt:**

```cmd
set MCP_HTTP_MODE=true
```

**macOS/Linux:**

```bash
export MCP_HTTP_MODE="true"
```

This environment variable enables the echo OAuth server to run in HTTP mode for testing.

#### Step 2: Start the Echo OAuth Server

Navigate to the echo server directory and start it:

**Windows PowerShell:**

```powershell
cd src\secure_mcp_gateway\bad_mcps
python .\echo_oauth_mcp.py
```

**macOS/Linux:**

```bash
cd src/secure_mcp_gateway/bad_mcps
python echo_oauth_mcp.py
```

The server will start on `http://localhost:8001/mcp/` and remain running. Keep this terminal open.

#### Step 3: Run the Test Suite

Open a new terminal, activate your virtual environment, and run the tests:

**Windows PowerShell:**

```powershell
# Activate virtual environment
.\.venv\Scripts\activate

# Navigate to tests directory
cd tests

# Run tests
python .\test_gateway.py
```

**macOS/Linux:**

```bash
# Activate virtual environment
source ./.venv/bin/activate

# Navigate to tests directory
cd tests

# Run tests
python test_gateway.py
```

### Test Coverage

The test suite includes:

- **Server Discovery Tests**: List servers, get server info, discover tools
- **Tool Execution Tests**: Call tools, multiple tool calls, error handling
- **Cache Tests**: Cache status, cache clearing, cache expiration
- **Guardrails Tests**: Input/output guardrails, async guardrails, PII redaction
- **Telemetry Tests**: OpenTelemetry integration, metrics, traces, logs
- **Configuration Tests**: Timeout settings, log levels, external cache
- **Integration Tests**: Full workflows, error recovery, performance

### Expected Output

The test runner will display:

- Progress for each test
- Success/failure status
- Execution duration
- Final summary with pass/fail counts

Example output:

```text
=== Gateway Tools Test Runner ===

Setting up test environment...
Setup complete.

Running Tests...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ test_list_all_servers_basic (0.45s)
✅ test_discover_all_tools_all_servers (1.23s)
✅ test_secure_call_tools_basic (0.89s)
...

=== Test Summary ===
Total Tests: 45
Passed: 45
Failed: 0
Success Rate: 100.0%
Total Duration: 45.67s
```

### Troubleshooting Tests

**Echo server connection errors:**

- Verify the echo OAuth server is running on port 8001
- Check that `MCP_HTTP_MODE` environment variable is set
- Ensure no other service is using port 8001

**Gateway configuration errors:**

- Verify `enkrypt_mcp_config.json` exists in `~/.enkrypt/` directory
- Check that the config file has valid gateway keys and server configurations
- Ensure virtual environment has all dependencies installed

**Test failures:**

- Enable debug logging by setting `enkrypt_log_level: "DEBUG"` in config
- Check MCP client logs for detailed error messages
- Verify all prerequisites are installed (Python 3.11+, pip, uv)

</details>

## 21. License

### 21.1 Enkrypt AI MCP Gateway Core

This project's core functionality is licensed under the Apache License, Version 2.0.

For the full license text, see the `LICENSE` file in this repository.

### 21.2 Enkrypt AI Guardrails, Logo, and Branding

© 2025 Enkrypt AI. All rights reserved.

Enkrypt AI software is provided under a proprietary license. Unauthorized use, reproduction, or distribution of this software or any portion of it is strictly prohibited.

Terms of Use: [https://www.enkryptai.com/terms-and-conditions](https://www.enkryptai.com/terms-and-conditions)

Privacy Policy: [https://app.enkryptai.com/privacy-policy](https://app.enkryptai.com/privacy-policy)

Enkrypt AI and the Enkrypt AI logo are trademarks of Enkrypt AI, Inc.

[Go to top](#enkrypt-ai-secure-mcp-gateway)
