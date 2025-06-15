# Enkrypt AI Secure MCP Gateway

![enkrypt-secure-mcp-gateway-hld](./docs/images/enkrypt-secure-mcp-gateway-hld.png)

## Overview

This Secure MCP Gateway is built with authentication, automatic tool discovery, caching, and guardrail enforcement.

It sits between your MCP client and MCP servers. So, by it's nature it itself also acts as an MCP server as well as an MCP client :)

When your MCP client connects to the Gateway, it acts as an MCP server. When the Gateway connects to the actual MCP server, it acts as an MCP client.

## Table of Contents

- [1. Features 🚀](#1-features)
  - [1.1 Guardrails 🔒 🚧](#11-guardrails)
- [2. High level steps of how the MCP Gateway works 🪜](#2-high-level-steps-of-how-the-mcp-gateway-works)
- [3. Prerequisites 🧩](#3-prerequisites)
- [4. Gateway Setup 👨‍💻](#4-gateway-setup)
  - [4.1 Local Installation with pip 📥](#41-local-installation-with-pip)
  - [4.2 Local Installation with git clone 📥](#42-local-installation-with-git-clone)
    <!-- - [4.2.1 Clone the repo, setup virtual environment and install dependencies 📥](#421-clone-the-repo-setup-virtual-environment-and-install-dependencies)
    - [4.2.2 Run the setup script 📥](#422-run-the-setup-script)
    - [4.2.3 Example MCP config file generated 📄](#423-example-mcp-config-file-generated)
    - [4.2.4 Restart Claude Desktop to run the Gateway 🔄](#424-restart-claude-desktop-to-run-the-gateway)
    - [4.2.5 Example prompts 💬](#425-example-prompts)
    - [4.2.6 Example config file generated ⚙️](#426-example-config-file-generated)
    - [4.2.7 Setup Other MCP Clients 🤖](#427-setup-other-mcp-clients) -->
  - [4.3 Remote Installation 📥](#43-remote-installation)
- [5. Edit the Gateway config as needed ✏️](#5-edit-the-gateway-config-as-needed)
- [6. (Optional) Add GitHub MCP Server to the Gateway 🤖](#6-optional-add-github-mcp-server-to-the-gateway)
- [7. (Optional) Protect GitHub MCP Server and Test Echo Server with Enkrypt Guardrails for FREE 🔒](#7-optional-protect-github-mcp-server-and-test-echo-server-with-enkrypt-guardrails-for-free)
  <!-- - [7.1 Fine Tune Guardrails 🔧](#71-fine-tune-guardrails) -->
- [8. Recommendations for using Guardrails 💡](#8-recommendations-for-using-guardrails)
- [9. Other tools available 🔧](#9-other-tools-available)
- [10. Deployment Patterns 🪂](#10-deployment-patterns)
- [11. Uninstall the Gateway 🗑️](#11-uninstall-the-gateway)
- [12. Known Issues being worked on 🏗️](#12-known-issues-being-worked-on)
- [13. Known Limitations ⚠️](#13-known-limitations)
- [14. Contribute 🤝](#14-contribute)

## 1. Features

![enkrypt-secure-mcp-gateway-features](./docs/images/enkrypt-secure-mcp-gateway-features.png)

Below are the list of features Enkrypt AI Secure MCP Gateway provides:

1. **Authentication**: We use Unique Key to authenticate with the Gateway. We also use Enkrypt API Key if you want to protect your MCPs with Enkrypt Guardrails

2. **Ease of use**: You can configure all your MCP servers locally in the config file or better yet in Enkrypt *(Coming soon)* and use them in the Gateway by using their name

3. **Dynamic Tool Discovery**: The Gateway discovers tools from the MCP servers dynamically and makes them available to the MCP client

4. **Restrict Tool Invocation**: If you don't want all tools to be accessible of a an MCP server, you can restrict them by explicitly mentioning the tools in the Gateway config so that only the allowed tools are accessible to the MCP client

5. **Caching**: We cache the user gateway config and tools discovered from various MCP servers locally or in an external cache server like KeyDB if configured to improve performance

6. **Guardrails**: You can configure guardrails for each MCP server in Enkrypt both on input side (before sending the request to the MCP server) and output side (after receiving the response from the MCP server)

7. **Logging**: We log every request and response from the Gateway locally in your MCP logs and also forward them to Enkrypt *(Coming soon)* for monitoring. This enables you to see all the calls made in your account, servers used, tools invoked, requests blocked, etc.

### 1.1 Guardrails

![enkrypt-secure-mcp-gateway-guardrails](./docs/images/enkrypt-secure-mcp-gateway-guardrails.png)

**Input Protection:** Topic detection, NSFW filtering, toxicity detection, injection attack prevention, keyword detection, policy violation detection, bias detection, and PII redaction (More coming soon like system prompt protection, copyright protection, etc.)  

**Output Protection:** All input protections plus adherence checking and relevancy validation (More coming soon like hallucination detection, etc.) We also auto unredact the response if it was redacted on input.

## 2. High level steps of how the MCP Gateway works

![Local Gateway with Remote Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local.drawio.png)

<br>
<details>
<summary><strong>Steps 🪜 </strong> 🔽</summary>
<br>

1. Your MCP client connects to the Secure MCP Gateway server with API Key (handled by `src/gateway.py`).

2. Gateway server fetches gateway config from local `enkrypt_mcp_config.json` file or remote Enkrypt Auth server *(Coming soon)*.

    - It caches the config locally or in an external cache server like KeyDB if configured to improve performance.

3. If input guardrails are enabled, request is validated before the tool call (handled by `src/guardrail.py`).
    - Request is blocked if it violates any of the configured guardrails and the specific detector is configured to block.

4. Requests are forwarded to the Gateway Client (handled by `src/client.py`).

5. The Gateway client forwards the request to the appropriate MCP server (handled by `src/client.py`).

6. The MCP server processes the request and returns the response to the Gateway client.

7. If it was a discover tools call, the Gateway client caches the tools locally or in an external cache server like KeyDB if configured. It then forwards the response to the Gateway server.

8. The Gateway server receives the response from the Gateway client and if output guardrails are enabled, it validates the response against the configured guardrails (handled by `src/guardrail.py`).

    - Response is blocked if it violates any of the configured guardrails and the specific detector is configured to block.

9. The Gateway server forwards the response back to the MCP client if everything is fine.

</details>

## 3. Prerequisites

<details>
<summary><strong>Dependencies 🔗 </strong> 🔽</summary>
<br>

- `Git 2.43` or higher

- `Python 3.11` or higher installed on your system and is accessible from the command line using either `python` or `python3` command

- `pip 25.0.1` or higher is installed on your system and is accessible from the command line using either `pip` or `python -m pip` command

- `uv 0.7.9` or higher is installed on your system and is accessible from the command line using either `uv` or `python -m uv` command

<br>
<details>
<summary><strong>Check versions 🔍 </strong> 🔽</summary>
<br>

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
<br>

<!-- - Set `PYTHONPATH` in your system environment variables

  - For reference, see [How to Add Python to PATH on Windows, Linux, and Mac](https://phoenixnap.com/kb/add-python-to-path)

    - In Windows, if you can't find python in the folder mentioned in the article, try `C:\Users\PC\AppData\Local\Microsoft\WindowsApps` -->

- Install **Claude Desktop** as the MCP Client from [their website](https://claude.ai/download) if you haven't already and login to it

  - *If you are using Linux and cannot run any [unofficial version](https://www.greghilston.com/post/claude-desktop-on-linux/) of Claude Desktop, you can use [any supported MCP Client](https://modelcontextprotocol.io/quickstart/server#testing-your-server-with-claude-for-desktop) to test the Gateway. If it does not support mcp cli `mcp install` command, then go through the scripts code and run the commands supported manually.*

- Any other dependencies required for the MCP servers we want to proxy requests to

  - Follow the instructions of the respective MCP server to install its dependencies

  - Like `Node.js`, `npx`, `docker`, etc.

- (Optional) A cache server like KeyDB installed and running (If you want to cache externally and not locally)

<br>
<details>
<summary><strong>Optional Protection with Enkrypt Guardrails 🔒 </strong> 🔽</summary>
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
<summary><strong>Pip Installation steps 🪜 </strong> 🔽</summary>

#### 4.1.1 Download and Install the Package

- Activate a virtual environment

  ```bash
  python -m venv .secure-mcp-gateway-venv

  # Activate the virtual environment
  .secure-mcp-gateway-venv\Scripts\activate

  # Run the below to exit the virtual environment later if needed
  deactivate
  ```

- Install the package

  ```bash
  pip install secure-mcp-gateway
  ```

#### 4.1.2 Run the Generate Command

- This generates the config file at `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `C:\Users\<User>\.enkrypt\enkrypt_mcp_config.json` on Windows

  ```bash
  secure-mcp-gateway generate-config
  ```

<details>
<summary><strong>Example output ℹ️ </strong> 🔽</summary>
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
config: {'common_mcp_gateway_config': {'enkrypt_log_level': 'INFO', 'enkrypt_guardrails_enabled': False, 'enkrypt_base_url': 'https://api.enkryptai.com', 'enkrypt_api_key': 'YOUR_ENKRYPT_API_KEY', 'enkrypt_use_remote_mcp_config': False, 'enkrypt_remote_mcp_gateway_name': 'enkrypt-secure-mcp-gateway-1', 'enkrypt_remote_mcp_gateway_version': 'v1', 'enkrypt_mcp_use_external_cache': False, 'enkrypt_cache_host': 'localhost', 'enkrypt_cache_port': 6379, 'enkrypt_cache_db': 0, 'enkrypt_cache_password': None, 'enkrypt_tool_cache_expiration': 4, 'enkrypt_gateway_cache_expiration': 24, 'enkrypt_async_input_guardrails_enabled': False, 'enkrypt_async_output_guardrails_enabled': False}, 'gateways': {'UNIQUE_GATEWAY_KEY': {'id': 'UNIQUE_UUID', 'mcp_config': [{'server_name': 'echo_server', 'description': 'Dummy Echo Server', 'config': {'command': 'python', 'args': ['DUMMY_ECHO_MCP_FILE_PATH']}, 'tools': {}, 'input_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'pii_redaction': False}, 'block': ['policy_violation']}, 'output_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'relevancy': False, 'hallucination': False, 'adherence': False}, 'block': ['policy_violation']}}]}}}
CONFIG:
ENKRYPT_GATEWAY_KEY: ****NULL
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_use_remote_mcp_config: False
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

#### 4.1.3 Example of the generated config file

<details>
<summary><strong>Example file in Windows 🪟  ℹ️ </strong> 🔽</summary>
<br>

This is an example of the default configuration file generated by the CLI on Windows:

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_log_level": "INFO",
    "enkrypt_guardrails_enabled": false,
    "enkrypt_base_url": "https://api.enkryptai.com",
    "enkrypt_api_key": "YOUR_ENKRYPT_API_KEY",
    "enkrypt_use_remote_mcp_config": false,
    "enkrypt_remote_mcp_gateway_name": "enkrypt-secure-mcp-gateway-1",
    "enkrypt_remote_mcp_gateway_version": "v1",
    "enkrypt_mcp_use_external_cache": false,
    "enkrypt_cache_host": "localhost",
    "enkrypt_cache_port": 6379,
    "enkrypt_cache_db": 0,
    "enkrypt_cache_password": null,
    "enkrypt_tool_cache_expiration": 4,
    "enkrypt_gateway_cache_expiration": 24,
    "enkrypt_async_input_guardrails_enabled": false,
    "enkrypt_async_output_guardrails_enabled": false
  },
  "gateways": {
    "q6ppy8f79oWi4wouSfYVWp0jc7-DIJIaibqtFjCekyPPjpjg": {
      "id": "d35c88c5-10c7-4594-92e1-7029e9c4be3e",
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Dummy Echo Server",
          "config": {
            "command": "python",
            "args": [
              "C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\test_mcps\\echo_mcp.py"
            ]
          },
          "tools": {},
          "input_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation"
            ]
          },
          "output_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
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
  }
}
```

</details>

#### 4.1.4 Install the Gateway for Claude Desktop

- Run the following command to install the gateway for Claude:

  ```bash
  secure-mcp-gateway install --client claude-desktop
  ```

- This will register Enkrypt Secure MCP Gateway with Claude Desktop.

- **NOTE: Please restart Claude Desktop after installation**

<details>
<summary><strong>Example output ℹ️ </strong> 🔽</summary>
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
config: {'common_mcp_gateway_config': {'enkrypt_log_level': 'INFO', 'enkrypt_guardrails_enabled': False, 'enkrypt_base_url': 'https://api.enkryptai.com', 'enkrypt_api_key': 'YOUR_ENKRYPT_API_KEY', 'enkrypt_use_remote_mcp_config': False, 'enkrypt_remote_mcp_gateway_name': 'enkrypt-secure-mcp-gateway-1', 'enkrypt_remote_mcp_gateway_version': 'v1', 'enkrypt_mcp_use_external_cache': False, 'enkrypt_cache_host': 'localhost', 'enkrypt_cache_port': 6379, 'enkrypt_cache_db': 0, 'enkrypt_cache_password': None, 'enkrypt_tool_cache_expiration': 4, 'enkrypt_gateway_cache_expiration': 24, 'enkrypt_async_input_guardrails_enabled': False, 'enkrypt_async_output_guardrails_enabled': False}, 'gateways': {'q6ppy8f79oWi4wouSfYVWp0jc7-DIJIaibqtFjCekyPPjpjg': {'id': 'd35c88c5-10c7-4594-92e1-7029e9c4be3e', 'mcp_config': [{'server_name': 'echo_server', 'description': 'Dummy Echo Server', 'config': {'command': 'python', 'args': ['C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\test_mcps\\echo_mcp.py']}, 'tools': {}, 'input_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'pii_redaction': False}, 'block': ['policy_violation']}, 'output_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'relevancy': False, 'hallucination': False, 'adherence': False}, 'block': ['policy_violation']}}]}}}
CONFIG:
ENKRYPT_GATEWAY_KEY: ****NULL
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_use_remote_mcp_config: False
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

<details>
<summary><strong>Example file in Windows 🪟  ℹ️ </strong> 🔽</summary>
<br>

- `C:\Users\PC\AppData\Roaming\Claude\claude_desktop_config.json`

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "C:\\Users\\PC\\.local\\bin\\uv.EXE",
        "args": [
          "run",
          "--with",
          "mcp[cli]",
          "mcp",
          "run",
          "C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "q6ppy8f79oWi4wouSfYVWp0jc7-DIJIaibqtFjCekyPPjpjg"
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

- This automatically updates your ~/.cursor/mcp.json (on Windows: C:\Users\<User>\.cursor\mcp.json) with the correct entry.

<details>
<summary><strong>Example file in Windows 🪟  ℹ️ </strong> 🔽</summary>
<br>

- `C:\Users\<User>\.cursor\mcp.json`

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "uv",
        "args": [
          "run",
          "--with",
          "mcp[cli]",
          "mcp",
          "run",
          "C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "q6ppy8f79oWi4wouSfYVWp0jc7-DIJIaibqtFjCekyPPjpjg"
        }
      }
    }
  }
  ```

</details>

</details>

### 4.2 Local Installation with git clone

- *NOTE: Needs to be revalidated and steps, examples needs to be updated after pip changes*

<details>

<summary><strong>Git Clone Installation steps 🪜 </strong> 🔽</summary>

#### 4.2.1 Clone the repo, setup virtual environment and install dependencies

- Clone the repository:

```bash
git clone https://github.com/enkryptai/secure-mcp-gateway

cd secure-mcp-gateway
```

<br>
<details>
<summary><strong>Activate a virtual environment ⚡ </strong> 🔽</summary>
<br>

```bash
# ------------------
# uv
# ------------------

uv init

# Example output
Initialized project `enkrypt-secure-mcp-gateway`

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

# For Windows, run the following
.\.venv\Scripts\activate

# For Linux/Mac, run the following
source ./.venv/Scripts/activate

# After activating, you should see (enkrypt-secure-mcp-gateway) before the file path in the terminal
# Example:
# (enkrypt-secure-mcp-gateway) C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway>

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

- This script creates the config file at `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `C:\Users\<User>\.enkrypt\enkrypt_mcp_config.json` on Windows based on `src/secure_mcp_gateway/example_enkrypt_mcp_config.json` file

- It replaces `UNIQUE_GATEWAY_KEY` and `UNIQUE_UUID` with auto generated values and also replaces `DUMMY_MCP_FILE_PATH` with the actual path to the test MCP file `test_mcps/echo_mcp.py`

- It also installs the MCP client in Claude Desktop

- *NOTE: Please restart Claude Desktop after running the setup script to see the Gateway running in Claude Desktop*

```bash
# On Linux/Mac run the below
cd scripts
chmod +x *.sh
./setup.sh

# On Windows run the below
cd scripts
setup.bat

# Now restart Claude Desktop to see the Gateway running
```

<br>
<details>
<summary><strong>Example output ℹ️ </strong> 🔽</summary>
<br>

```bash
-------------------------------
Setting up Enkrypt Secure MCP Gateway enkrypt_mcp_config.json config file
-------------------------------
        1 file(s) copied.
Generated unique gateway key: WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_
Generated unique uuid: 7920749a-228e-47fe-a6a9-cd2d64a2283b
DUMMY_MCP_FILE_PATH: C:\Users\PC\Documents\GitHub\EnkryptAI\secure-mcp-gateway\src\secure_mcp_gateway\test_mcps\echo_mcp.py
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
config: {'common_mcp_gateway_config': {'enkrypt_log_level': 'INFO', 'enkrypt_guardrails_enabled': False, 'enkrypt_base_url': 'https://api.enkryptai.com', 'enkrypt_api_key': 'YOUR_ENKRYPT_API_KEY', 'enkrypt_use_remote_mcp_config': False, 'enkrypt_remote_mcp_gateway_name': 'enkrypt-secure-mcp-gateway-1', 'enkrypt_remote_mcp_gateway_version': 'v1', 'enkrypt_mcp_use_external_cache': False, 'enkrypt_cache_host': 'localhost', 'enkrypt_cache_port': 6379, 'enkrypt_cache_db': 0, 'enkrypt_cache_password': None, 'enkrypt_tool_cache_expiration': 4, 'enkrypt_gateway_cache_expiration': 24, 'enkrypt_async_input_guardrails_enabled': False, 'enkrypt_async_output_guardrails_enabled': False}, 'gateways': {'WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_': {'id': '7920749a-228e-47fe-a6a9-cd2d64a2283b', 'mcp_config': [{'server_name': 'echo_server', 'description': 'Dummy Echo Server', 'config': {'command': 'python', 'args': ['C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\test_mcps\\echo_mcp.py']}, 'tools': {}, 'input_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'pii_redaction': False}, 'block': ['policy_violation']}, 'output_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'relevancy': False, 'hallucination': False, 'adherence': False}, 'block': ['policy_violation']}}]}}}
CONFIG:
ENKRYPT_GATEWAY_KEY: ****BN8_
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_use_remote_mcp_config: False
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
config: {'common_mcp_gateway_config': {'enkrypt_log_level': 'INFO', 'enkrypt_guardrails_enabled': False, 'enkrypt_base_url': 'https://api.enkryptai.com', 'enkrypt_api_key': 'YOUR_ENKRYPT_API_KEY', 'enkrypt_use_remote_mcp_config': False, 'enkrypt_remote_mcp_gateway_name': 'enkrypt-secure-mcp-gateway-1', 'enkrypt_remote_mcp_gateway_version': 'v1', 'enkrypt_mcp_use_external_cache': False, 'enkrypt_cache_host': 'localhost', 'enkrypt_cache_port': 6379, 'enkrypt_cache_db': 0, 'enkrypt_cache_password': None, 'enkrypt_tool_cache_expiration': 4, 'enkrypt_gateway_cache_expiration': 24, 'enkrypt_async_input_guardrails_enabled': False, 'enkrypt_async_output_guardrails_enabled': False}, 'gateways': {'WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_': {'id': '7920749a-228e-47fe-a6a9-cd2d64a2283b', 'mcp_config': [{'server_name': 'echo_server', 'description': 'Dummy Echo Server', 'config': {'command': 'python', 'args': ['C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\test_mcps\\echo_mcp.py']}, 'tools': {}, 'input_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'pii_redaction': False}, 'block': ['policy_violation']}, 'output_guardrails_policy': {'enabled': False, 'policy_name': 'Sample Airline Guardrail', 'additional_config': {'relevancy': False, 'hallucination': False, 'adherence': False}, 'block': ['policy_violation']}}]}}}
CONFIG:
ENKRYPT_GATEWAY_KEY: ****BN8_
enkrypt_log_level: info
is_debug_log_level: False
enkrypt_base_url: https://api.enkryptai.com
enkrypt_use_remote_mcp_config: False
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

- To verify, navigate to `claude_desktop_config.json` file by [following these instructions](https://modelcontextprotocol.io/quickstart/user#2-add-the-filesystem-mcp-server)

  - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

  - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

#### 4.2.3 Example MCP config file generated

<br>
<details>
<summary><strong>Example file in Windows 🪟  ℹ️ </strong> 🔽</summary>
<br>

- `C:\Users\PC\AppData\Roaming\Claude\claude_desktop_config.json`

  ```json
  {
    "mcpServers": {
      "Enkrypt Secure MCP Gateway": {
        "command": "C:\\Users\\PC\\.local\\bin\\uv.EXE",
        "args": [
          "run",
          "--with",
          "mcp[cli]",
          "mcp",
          "run",
          "C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\gateway.py"
        ],
        "env": {
          "ENKRYPT_GATEWAY_KEY": "WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_"
        }
      }
    }
  }
  ```

</details>

#### 4.2.4 Restart Claude Desktop to run the Gateway

- After restarting, navigate to Claude Desktop `Settings`

  ![Claude Desktop Settings](./docs/images/claude-desktop-settings.png)

- Click on `Developer` -> `Enkrypt Secure MCP Gateway`

  ![Claude Desktop MCP Gateway Running](./docs/images/claude-desktop-mcp-running.png)

<br>
<details>
<summary><strong>Check tools and logs 🧾  ℹ️ </strong> 🔽</summary>
<br>

- You can also click on the settings icon below the search bar to see the Gateway in available

  ![Claude Desktop Gateway in Search](./docs/images/claude-desktop-gateway-in-search.png)

- Click on `Enkrypt Secure MCP Gateway` to see the list of tools available

  ![Claude Desktop MCP Gateway Tools](./docs/images/claude-desktop-gateway-tools-in-search.png)

- You can check Claude logs while asking Claude to do something to see the Gateway in action

  - Example windows log path: `C:\Users\PC\AppData\Roaming\Claude\logs\mcp-server-Enkrypt Secure MCP Gateway.log`

  - Example linux/mac log path: `~/Library/Application Support/Claude/logs/mcp-server-Enkrypt Secure MCP Gateway.log`

</details>

#### 4.2.5 Example prompts

- `list all servers, get all tools available and echo test`
  - This uses a test MCP server `echo_server` which is in `test_mcps/echo_mcp.py`

![claude-mcp-chat-1](./docs/images/claude-mcp-chat-1.png)

<br>
<details>
<summary><strong>Other examples ℹ️ </strong> 🔽</summary>
<br>

- We can also combine multiple prompts into one that trigger multiple tool calls at once

- Example: `echo test and also echo best`

![claude-mcp-chat-multiple](./docs/images/claude-mcp-chat-multiple.png)

- **Example: `echo "hello; ls -la; whoami"`**

- This could be a malicious prompt but because no guardrails are enabled, it will not be blocked

![claude-mcp-chat-echo-not-blocked](./docs/images/claude-mcp-chat-echo-not-blocked.png)

</details>

#### 4.2.6 Example config file generated

- Example `enkrypt_mcp_config.json` generated by the `setup` script in `~/.enkrypt/enkrypt_mcp_config.json` on macOS and `C:\Users\<User>\.enkrypt\enkrypt_mcp_config.json` on Windows:

  ```json
  {
    "common_mcp_gateway_config": {
      "enkrypt_log_level": "INFO",
      "enkrypt_guardrails_enabled": false,
      "enkrypt_base_url": "https://api.enkryptai.com",
      "enkrypt_api_key": "YOUR_ENKRYPT_API_KEY",
      "enkrypt_use_remote_mcp_config": false,
      "enkrypt_remote_mcp_gateway_name": "enkrypt-secure-mcp-gateway-1",
      "enkrypt_remote_mcp_gateway_version": "v1",
      "enkrypt_mcp_use_external_cache": false,
      "enkrypt_cache_host": "localhost",
      "enkrypt_cache_port": 6379,
      "enkrypt_cache_db": 0,
      "enkrypt_cache_password": null,
      "enkrypt_tool_cache_expiration": 4,
      "enkrypt_gateway_cache_expiration": 24,
      "enkrypt_async_input_guardrails_enabled": false,
      "enkrypt_async_output_guardrails_enabled": false
    },
    "gateways": {
      "WTZOpoU1mXJz8b_ZJQ42DuSXlQCSCtWOn3FX0jG8sO_FKYNJetjYEgSluvhtBN8_": {
        "id": "7920749a-228e-47fe-a6a9-cd2d64a2283b",
        "mcp_config": [
          {
            "server_name": "echo_server",
            "description": "Dummy Echo Server",
            "config": {
              "command": "python",
              "args": [
                "C:\\Users\\PC\\Documents\\GitHub\\EnkryptAI\\secure-mcp-gateway\\src\\secure_mcp_gateway\\test_mcps\\echo_mcp.py"
              ]
            },
            "tools": {},
            "input_guardrails_policy": {
              "enabled": false,
              "policy_name": "Sample Airline Guardrail",
              "additional_config": {
                "pii_redaction": false
              },
              "block": [
                "policy_violation"
              ]
            },
            "output_guardrails_policy": {
              "enabled": false,
              "policy_name": "Sample Airline Guardrail",
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
    }
  }
  ```

#### 4.2.7 Setup Other MCP Clients

<details>
<summary><strong>Cursor ⬡ </strong> 🔽</summary>
<br>

- You can navigate to cursor's **Global MCP** file at `C:\Users\PC\.cursor\mcp.json` on Windows or at `~/.cursor/mcp.json` on Linux/macOS

  - If you would like to use at a **Project level** place it inside your project. For details see [Cursor's docs](https://docs.cursor.com/context/model-context-protocol#configuration-locations)

- You can also navigate to the file Via cursor's UI by clicking on `settings` gear icon on the top right  

  ![cursor-settings-icon](./docs/images/cursor-settings-icon.png)

- Click on `MCP` and then click on `Add new global MCP server` which takes you to the `mcp.json` file

  ![cursor-settings-mcp](./docs/images/cursor-settings-mcp.png)

- Example `mcp.json` file opened in the editor

  ![cursor-mcp-file](./docs/images/cursor-mcp-file.png)

- Once the file is opened at Global or Project level, you can copy paste the same config we used in `Claude Desktop`. For reference, you can refer to [Installation - 4.2.3 Example MCP config file generated 📄](#423-example-mcp-config-file-generated)

  - *Be sure to use your own file that was generated by the `setup` script in [Installation - 4.2.2 Run the setup script 📥](#422-run-the-setup-script). Please do not copy paste the example config file in this repo.*

- Once your mcp config is pasted and the file is saved, you can see the MCP server in the list of MCP servers in cursor

  ![cursor-mcp-running](./docs/images/cursor-mcp-running.png)

- Now you can chat with the MCP server.

  - **Example prompts:**

    - *(Click `Run Tool` when Cursor asks you to)*

    - `list all servers, get all tools available and echo test`
      - This uses a test MCP server `echo_server` which is in `test_mcps/echo_mcp.py`

    ![cursor-mcp-chat](./docs/images/cursor-mcp-chat.png)

</details>
</details>

### 4.3 Remote Installation

- *(Coming soon)*

## 5. Edit the Gateway config as needed

- **Important:**

  - **We need to restart Claude Desktop after editing the config file**
  - **To make all new tools accessible, please use prompt "`list all servers, get all tools available`" for the MCP Client to discover all new tools. After this the MCP Client should be able to use all tools of the servers configured in the Gateway config file**

- You can add many MCP servers inside the `mcp_config` array of this gateway config

  - You can [look here for example servers](https://github.com/modelcontextprotocol/servers)

  - You can also try the [Enkrypt MCP Server](https://github.com/enkryptai/enkryptai-mcp-server)

  - Example:

      ```json
      {
        "common_mcp_gateway_config": {...},
        "gateways": { 
          "UNIQUE_GATEWAY_KEY_1": {
            "id": "UNIQUE_UUID_1",
            "mcp_config": [
              {
                "server_name": "MCP_SERVER_NAME_1",
                "description": "MCP_SERVER_DESCRIPTION_1",
                "config": {
                  "command": "python/npx/etc.",
                  "args": ["arg1", "arg2", ...],
                  "env": { "key": "value" }
                },
                // Set explicit tools to restrict access to only the allowed tools
                // Example: "tools": { "tool_name": "tool_description" }
                // Example: "tools": { "echo": "Echo a message" }
                // Or leave the tools empty {} to discover all tools dynamically
                "tools": {},
                "input_guardrails_policy": {...},
                "output_guardrails_policy": {...}
              },
              {
                "server_name": "MCP_SERVER_NAME_2",
                "description": "MCP_SERVER_DESCRIPTION_2",
                "config": {...},
                "tools": {},
                "input_guardrails_policy": {...},
                "output_guardrails_policy": {...}
              }
            ]
          },
        }
      }
      ```

<br>
<details>
<summary><strong>Gateway Config Schema ℹ️ </strong> 🔽</summary>
<br>

- If you want a different set of MCP servers for a separate client/user, you can generate a new unqiue `key` and unique `UUID` by looking at the `setup` scripts and add it to the `gateways` section of the config file

  - Example: `{ gateways: { UNIQUE_GATEWAY_KEY_1: {...}, UNIQUE_GATEWAY_KEY_2: {...}, ... }, ... }`

  - Make sure you also set different `UNIQUE_UUID` inside the various gateways

- Set `enkrypt_log_level` to `DEBUG` to get more detailed logs inside `common_mcp_gateway_config` part of the config file

  - This defaults to `INFO`

- Now, inside `gateways` array, inside `mcp_config` array, for each individual MCP server config, you can set the following:

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
<summary><strong>Optional Guardrails Schema 🔒 ℹ️ </strong> 🔽</summary>
<br>

- Set `enkrypt_guardrails_enabled` to `true` in your `common_mcp_gateway_config`

- Get your `enkrypt_api_key` from [Enkrypt Dashboard](https://app.enkryptai.com/settings) and add it to `common_mcp_gateway_config` section of the config file

- `enkrypt_use_remote_mcp_config` is used to fetch MCP server config from Enkrypt server remotely *(Coming soon)*

  - Please use `false` for now

  - This enables you to configure and manage MCP gateway config in Enkrypt Dashboard in a centralized place *(Coming soon)*

- If you have any external cache server like KeyDB running, you can set `enkrypt_mcp_use_external_cache` to `true` in your `common_mcp_gateway_config`

  - Set other relevant keys related to cache in your `common_mcp_gateway_config`

- `enkrypt_tool_cache_expiration` (in hours) decides how long the tools discovered from the MCP servers are cached locally or in the external cache server

- `enkrypt_gateway_cache_expiration` (in hours) decides how long the gateway config is cached locally or in the external cache server. This is useful when we integrate this with Enkrypt Auth server *(Coming soon)*

- `enkrypt_async_input_guardrails_enabled`

  - `false` by default

  - **Async mode is not recommended for tools that perform actions which cannot be undone**

  - Because the tool call is made parallel to guardrails call, it can't be blocked if input guardrails violations are detected

  - Useful for servers that return just info without performing actions i.e., only read operations

- `enkrypt_async_output_guardrails_enabled` *(Coming soon)*

  - This makes output side guardrails calls asynchronously to save time

  - i.e., Guardrails detect call, relevancy check, adherence check, PII unredaction, etc. are made in parallel after getting the response from the MCP server

- **Inside each MCP server config, you can set the following:**

  - `input_guardrails_policy`: Use this if we plan to use Enkrypt Guardrails on input side

  - `policy_name`: Name of the guardrails policy that you have created in the Enkrypt App or using the API/SDK

  - `enabled`: Whether to enable guardrails on the input side or not. This is `false` in the example config file

  - `additional_config`: Additional config for the guardrails policy

    - `pii_redaction`: Whether to redact PII in the request sent to the MCP server or not

      - If `true`, this also auto unredacts the PII in the response from the MCP server

  - `block`: List of guardrails to block

    - Possible values in the array are:

      - `topic_detector, nsfw, toxicity, pii, injection_attack, keyword_detector, policy_violation, bias`

      - `system_prompt_protection, copyright_protection` *(Coming soon)*

      - This is similar to our AI Proxy deployments config. [Refer to our docs](https://docs.enkryptai.com/deployments-api-reference/endpoint/add-deployment#body-input-guardrails-policy-block)

- `output_guardrails_policy`: Use this if we plan to use Enkrypt Guardrails on output side

  - `policy_name`: Name of the guardrails policy that you have created in the Enkrypt App or using the API/SDK

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

## 6. (Optional) Add GitHub MCP Server to the Gateway

- `GitHub MCP Server` needs `docker` to be installed. So, please install and have `docker` running on your machine before proceeding with the steps below

  - You can [download docker desktop from here](https://www.docker.com/products/docker-desktop/). Install and run it if you don't have it already

<br>
<details>
<summary><strong>Configure GitHub 👨🏻‍💻 </strong> 🔽</summary>
<br>

- [Create a personal access token from GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

  - Create a token that has access to only public repos and set expiry very low initially for testing

  - Add the below GitHub server block to `enkrypt_mcp_config.json` inside `"mcp_config": []` array. It should already have the echo server config.

  - *NOTE: Don't forget to add comma `,` after the echo server block*

  - Replace `REPLACE_WITH_YOUR_PERSONAL_ACCESS_TOKEN` with the personal access token you created

  - Example:

  ```json
      "mcp_config": [
        {
          "server_name": "echo_server",
          "description": "Dummy Echo Server",
          "config": {...},
          "tools": {},
          "input_guardrails_policy": {...},
          "output_guardrails_policy": {...}
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
          "input_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": {
              "pii_redaction": false
            },
            "block": [
              "policy_violation"
            ]
          },
          "output_guardrails_policy": {
            "enabled": false,
            "policy_name": "Sample Airline Guardrail",
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

</details>

## 7. (Optional) Protect GitHub MCP Server and Test Echo Server with Enkrypt Guardrails for FREE

<br>
<details>
<summary><strong>Create a Guardrail in Enkrypt App 🌐 </strong> 🔽</summary>
<br>

- You can use a prompt to generate rules or generate a PDF file while you can then paste or upload while creating a policy in the App

<br>
<details>
<summary><strong>Rules to copy ❗ </strong> 🔽</summary>
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
<summary><strong>Prompt used to generate the rules 💡 </strong> 🔽</summary>
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
<summary><strong>Get Enkrypt API Key 🔑 </strong> 🔽</summary>
<br>

- Now, we need get out FREE API Key from Enkrypt App. Hover over the left sidebar for it to expand and click on `Settings`

  - You can also directly navigate to [https://app.enkryptai.com/settings](https://app.enkryptai.com/settings)

  ![enkrypt-app-settings-1](./docs/images/enkrypt-app-settings-1.png)

- Now click on the `Copy` icon next to your obfuscated API Key to copy the key to your clipboard as highlighted in the screenshot below

  ![enkrypt-app-settings-2](./docs/images/enkrypt-app-settings-2.png)

</details>
<details>
<summary><strong>Add API Key and the Guardrail to Config File 🔑 </strong> 🔽</summary>
<br>

- Now we have everything we need from the App. Let's add the API Key to the `enkrypt_mcp_config.json` file

- Open the `enkrypt_mcp_config.json` file from `~/.enkrypt/enkrypt_mcp_config.json` on macOS or `C:\Users\<User>\.enkrypt\enkrypt_mcp_config.json` on Windows

- Add the API Key to the `common_mcp_gateway_config` section by replacing `YOUR_ENKRYPT_API_KEY` with the API Key you copied from the App

- Inside the **`GitHub`** server block we added in the previous section,

  - Add the newly created Guardrail `GitHub Guardrail` to the `input_guardrails_policy` and `output_guardrails_policy` sections

  - By replacing `"policy_name": "Sample Airline Guardrail"` with `"policy_name": "GitHub Guardrail"`

  - Now change `enabled` to `true` for `input_guardrails_policy` from previous `false`

    - We will leave `output_guardrails_policy` as `false` for now

  - We already should have `policy_violation` in the `block` array for both policies

  - So the final config should look something like this:

  ```json
  {
    "common_mcp_gateway_config": {
      ...
      "enkrypt_api_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      ...
    },
    "gateways": {
      "tLIYf0YEFTIPLXDO337zPRQhmnoXnLqLUKB3XuDX1inent9vGRFvwLDJGoeaktWu": {
        "id": "2536722c-e5d7-4719-97ab-2cdd4ce942c0",
        "mcp_config": [
          {
            "server_name": "echo_server",
            "...": "..."
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
            "input_guardrails_policy": {
              "enabled": true,
              "policy_name": "GitHub Guardrail",
              "additional_config": {
                "pii_redaction": false
              },
              "block": [
                "policy_violation"
              ]
            },
            "output_guardrails_policy": {
              "enabled": false,
              "policy_name": "GitHub Guardrail",
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
    }
  }
  ```

</details>
<details>
<summary><strong>Test Guardrails 🧪 </strong> 🔽</summary>
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

### 7.1 Fine Tune Guardrails

- *The safe prompt `List all files from https://github.com/enkryptai/enkryptai-mcp-server` may also be blocked if you use Injection Attack Detector or Policy Violation on Output side. So, there is some fine tuning required for the guardrails to find the best combination of enabled detectors and blocks for your servers. See the next section for recommendations.*

## 8. Recommendations for using Guardrails

- We have found that the best way to use Enkrypt Guardrails in MCP Gateway is to have a separate guardrail for each server. This way we can have a fine tuned guardrail for each server.

- Because each MCP Server is very different from the other, it is not possible to have a single guardrail that works for all servers.

- Some may need `Toxicity Detector`, some `NSFW Detector`, some `Injection Attack Detector`, some `Keyword Detector`, some `Policy Violation`, some may need `Relevancy` detector, some may need `Adherence` detector, etc.

- Some may need a combination of these detectors to work together to block malicious requests.

- Some may need Guardrails on the input side, some on the output and some may need both to be applied.

- See our docs for details on [various detectors available.](https://docs.enkryptai.com/guardrails-api-reference/Prompt_Injection)

- Hence, have separate guardrails for each server and experiment with the best combination of detectors and blocks for each server that blocks malicious requests but allows legitimate requests to pass through.

- Try our `Policy Violation` detector with your own custom policy which details what is allowed and what is not. This may be the best way for your use case.

<details>
<summary><strong>Try Policy Violation 🚨 </strong> 🔽</summary>
<br>

- You can navigate to the [Enkrypt App Homepage](https://app.enkryptai.com), login and Click on `Policies` to create your own custom policy.

  - This accepts text as well as PDF file as input so create a file with all the rules you want to apply to your MCP server and upload it

  - Once created, you can use it while configuring the Guardrail like we say with `GitHub Guardrail` in the previous section

  ![enkrypt-app-homepage-policies](./docs/images/enkrypt-app-homepage-policies.png)

</details>

## 9. Other Tools Available

<details>
<summary><strong>Get Cache Status 📊 </strong> 🔽</summary>
<br>

- The Gateway can give the summary of it's cache status by looking at the local/external cache server

- This is useful to debug issues if for example a tool was updated remotely by a server but the Gateway is not aware of it yet

  ![claude-mcp-chat-get-cache-status](./docs/images/claude-mcp-chat-get-cache-status.png)

</details>
<details>
<summary><strong>Clear Cache 🧹 </strong> 🔽</summary>
<br>

- The Gateway can clear it's cache from local/external cache server

- This is useful to clear the cache if for example a tool was updated remotely by a server but the Gateway is not aware of it yet

- You can either clear all cache or specific cache by providing the `server_name`

  - Example: `clear cache for echo_server`

- You can also clear all cache or just the gateway cache or just the server cache

  - Example: `clear all cache`, `clear just gateway cache`, `clear server cache for echo_server`, `Clear all server cache`

  ![claude-mcp-chat-clear-cache](./docs/images/claude-mcp-chat-clear-cache.png)

</details>

## 10. Deployment patterns

1. [Local Gateway, Local Guardrails and Local MCP Server](#1-local-gateway-local-guardrails-and-local-mcp-server)
2. [Local Gateway, Local MCP Server with Remote Guardrails](#2-local-gateway-local-mcp-server-with-remote-guardrails)
3. [Local Gateway with Remote MCP Server and Remote Guardrails](#3-local-gateway-with-remote-mcp-server-and-remote-guardrails)
4. [Remote Gateway, Remote MCP Server and Remote Guardrails](#4-remote-gateway-remote-mcp-server-and-remote-guardrails)

### 1. Local Gateway, Local Guardrails and Local MCP Server

![Local Gateway with Local Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20All%20Local.drawio.png)

### 2. Local Gateway, Local MCP Server with Remote Guardrails

![Local Gateway with Remote Guardrails Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local.drawio.png)

### 3. Local Gateway with Remote MCP Server and Remote Guardrails

![Local Gateway with Remote Guardrails and Remote MCP Server Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Local%20with%20Remote.drawio.png)

### 4. Remote Gateway, Remote MCP Server and Remote Guardrails

![Remote Gateway with Remote Guardrails and Remote MCP Server Flow](./docs/images/enkryptai-apiaas-MCP%20Gateway%20Full%20Remote.drawio.png)

## 11. Uninstall the Gateway

- To remove the Gateway from any MCP client, just remove the MCP server block `"Enkrypt Secure MCP Gateway": {...}` from the client's config file.

  - Restart the MCP client to apply the changes for some clients like Claude Desktop. Cursor does not require a restart.

- To uninstall the pip package, run the following command:

  ```bash
  pip uninstall secure-mcp-gateway
  ```

## 12. Known Issues being worked on

- Output guardrails are not being applied to non-text tool results. Support for other media types like images, audio, etc. is coming soon.

## 13. Known Limitations

- The Gateway does not support a scenario where the Gateway is deployed remotely but the MCP server is deployed locally (without being exposed to the internet). This is because the Gateway needs to know the MCP server's address to forward requests to it.

## 14. Contribute

- Look at the `TODO` file for the current work in progress and yet to be implemented features

- Install the gateway locally to test your changes
  - by following the [Git clone steps](#42-local-installation-with-git-clone)
  - or build it using `python -m build`, activate the venv and install using `pip install .`

- Report or fix any bugs you encounter 😊

## 15. License

### 15.1 Enkrypt AI MCP Gateway Core

This project's core functionality is licensed under the MIT License.

<!-- In addition to the MIT License, the following additional terms apply:

- You can freely use, modify, and distribute this software as part of your commercial product
- You can use this as part of your commercial product if your product is not an MCP gateway or gateway-based service
- You cannot sell this gateway as a standalone product -->

For the full license text, see the `LICENSE.txt` file in this repository.

### 15.2 Enkrypt AI Guardrails, Logo, and Branding

© 2025 Enkrypt AI. All rights reserved.

Enkrypt AI software is provided under a proprietary license. Unauthorized use, reproduction, or distribution of this software or any portion of it is strictly prohibited.

Terms of Use: [https://www.enkryptai.com/terms-and-conditions](https://www.enkryptai.com/terms-and-conditions)

Privacy Policy: [https://app.enkryptai.com/privacy-policy](https://app.enkryptai.com/privacy-policy)

Enkrypt AI and the Enkrypt AI logo are trademarks of Enkrypt AI, Inc.

[Go to top](#enkrypt-ai-secure-mcp-gateway)
