import os
import sys
import uuid
import json
import base64
import argparse
import subprocess
from importlib.resources import files

# BASE_DIR = os.path.dirname(secure_mcp_gateway.__file__)
BASE_DIR = files('secure_mcp_gateway')
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.utils import sys_print, is_docker, CONFIG_PATH, DOCKER_CONFIG_PATH

sys_print(f"Initializing Enkrypt Secure MCP Gateway CLI Module v{__version__}")

HOME_DIR = os.path.expanduser("~")
sys_print("HOME_DIR: ", HOME_DIR)

is_docker_running = is_docker()
sys_print("is_docker_running: ", is_docker_running)

if is_docker_running:
    HOST_OS = os.environ.get("HOST_OS", None)
    HOST_ENKRYPT_HOME = os.environ.get("HOST_ENKRYPT_HOME", None)
    if not HOST_OS or not HOST_ENKRYPT_HOME:
        sys_print("HOST_OS and HOST_ENKRYPT_HOME environment variables are not set.", is_error=True)
        sys_print("Please set them when running the Docker container:\n  docker run -e HOST_OS=<your_os> -e HOST_ENKRYPT_HOME=<path_to_enkrypt_home> ...", is_error=True)
        sys.exit(1)
    sys_print("HOST_OS: ", HOST_OS)
    sys_print("HOST_ENKRYPT_HOME: ", HOST_ENKRYPT_HOME)
else:
    HOST_OS = None
    HOST_ENKRYPT_HOME = None

GATEWAY_PY_PATH = os.path.join(BASE_DIR, "gateway.py")
# ECHO_SERVER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_mcps", "echo_mcp.py")
ECHO_SERVER_PATH = os.path.join(BASE_DIR, "test_mcps", "echo_mcp.py")
PICKED_CONFIG_PATH = DOCKER_CONFIG_PATH if is_docker_running else CONFIG_PATH
sys_print("GATEWAY_PY_PATH: ", GATEWAY_PY_PATH)
sys_print("ECHO_SERVER_PATH: ", ECHO_SERVER_PATH)
sys_print("PICKED_CONFIG_PATH: ", PICKED_CONFIG_PATH)

DOCKER_COMMAND = "docker"
DOCKER_ARGS = [
    "run", "--rm", "-i",
    "-v", f"{HOST_ENKRYPT_HOME}:/app/.enkrypt",
    "-e", "ENKRYPT_GATEWAY_KEY",
    "secure-mcp-gateway"
]


def generate_default_config():
    """Generate a default config with a unique gateway key and uuid."""
    gateway_key = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
    unique_uuid = str(uuid.uuid4())
    # For Echo server path, first get the 
    return {
        "common_mcp_gateway_config": {
            "enkrypt_log_level": "INFO",
            "enkrypt_guardrails_enabled": False,
            "enkrypt_base_url": "https://api.enkryptai.com",
            "enkrypt_api_key": "YOUR_ENKRYPT_API_KEY",
            "enkrypt_use_remote_mcp_config": False,
            "enkrypt_remote_mcp_gateway_name": "enkrypt-secure-mcp-gateway-1",
            "enkrypt_remote_mcp_gateway_version": "v1",
            "enkrypt_mcp_use_external_cache": False,
            "enkrypt_cache_host": "localhost",
            "enkrypt_cache_port": 6379,
            "enkrypt_cache_db": 0,
            "enkrypt_cache_password": None,
            "enkrypt_tool_cache_expiration": 4,
            "enkrypt_gateway_cache_expiration": 24,
            "enkrypt_async_input_guardrails_enabled": False,
            "enkrypt_async_output_guardrails_enabled": False,
             "enkrypt_telemetry": {
                "enabled": False,
                "insecure": True,
                "endpoint": "http://localhost:4317"
            }
        },
        "gateways": {
            gateway_key: {
                "id": unique_uuid,
                "mcp_config": [
                    {
                        "server_name": "echo_server",
                        "description": "Dummy Echo Server",
                        "config": {
                            "command": "python",
                            "args": [
                                ECHO_SERVER_PATH
                            ]
                        },
                        "tools": {},
                        "input_guardrails_policy": {
                            "enabled": False,
                            "policy_name": "Sample Airline Guardrail",
                            "additional_config": {
                                "pii_redaction": False
                            },
                            "block": [
                                "policy_violation"
                            ]
                        },
                        "output_guardrails_policy": {
                            "enabled": False,
                            "policy_name": "Sample Airline Guardrail",
                            "additional_config": {
                                "relevancy": False,
                                "hallucination": False,
                                "adherence": False
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


def get_gateway_key(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at path: {config_path}. Please generate a new config file using 'generate-config' subcommand and try again.")
    with open(config_path, "r") as f:
        config = json.load(f)
    # Assumes the first key in 'gateways' is the gateway key
    return next(iter(config["gateways"].keys()))


def add_or_update_cursor_server(config_path, server_name, command, args, env):
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            sys_print(f"Error parsing {config_path}. The file may be corrupted: {str(e)}", is_error=True)
            sys.exit(1)

    if "mcpServers" not in config:
        config["mcpServers"] = {}

    server_already_exists = server_name in config["mcpServers"]

    config["mcpServers"][server_name] = {
        "command": command,
        "args": args,
        "env": env
    }

    # Create directory with restricted permissions (0o700 = rwx-----)
    dir_path = os.path.dirname(config_path)
    os.makedirs(dir_path, exist_ok=True)
    if os.name == 'posix':  # Unix-like systems
        os.chmod(dir_path, 0o700)

    # Write config file with restricted permissions (0o600 = rw-------)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    if os.name == 'posix':  # Unix-like systems
        os.chmod(config_path, 0o600)
    
    sys_print(f"{'Updated' if server_already_exists else 'Added'} '{server_name}' in {config_path}")


def main():
    parser = argparse.ArgumentParser(description="Enkrypt Secure MCP Gateway CLI")
    subparsers = parser.add_subparsers(dest="command")

    # generate-config subcommand
    gen_config_parser = subparsers.add_parser(
        "generate-config", help="Generate a new default config file"
    )

    # install subcommand
    install_parser = subparsers.add_parser(
        "install", help="Install gateway for a client"
    )
    install_parser.add_argument(
        "--client", type=str, required=True, help="Client name (e.g., claude-desktop)"
    )
    # install_parser.add_argument(
    #     "--dry-run", action="store_true", help="Dry run the install process"
    # )

    args = parser.parse_args()
    
    if args.command == "generate-config":
        if os.path.exists(PICKED_CONFIG_PATH):
            sys_print(f"Config file already exists at {PICKED_CONFIG_PATH}.", is_error=True)
            sys_print("Not overwriting. Please run install to install on Claude Desktop or Cursor.", is_error=True)
            sys_print("If you want to start fresh, delete the config file and run again.", is_error=True)
            sys.exit(1)
        # Create .enkrypt directory if it doesn't exist
        os.makedirs(os.path.dirname(PICKED_CONFIG_PATH), exist_ok=True)
        if os.name == 'posix':  # Unix-like systems
            os.chmod(os.path.dirname(PICKED_CONFIG_PATH), 0o700)
        config = generate_default_config()
        with open(PICKED_CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        sys_print(f"Generated default config at {PICKED_CONFIG_PATH}")
        sys.exit(0)

    elif args.command == "install":
        gateway_key = get_gateway_key(PICKED_CONFIG_PATH)
        if not gateway_key:
            sys_print(f"Gateway key not found in {PICKED_CONFIG_PATH}. Please generate a new config file using 'generate-config' subcommand and try again.", is_error=True)
            sys.exit(1)

        env = {
            "ENKRYPT_GATEWAY_KEY": gateway_key
        }
    
        if args.client.lower() == "claude" or args.client.lower() == "claude-desktop":
            client = args.client
            sys_print("client name from args: ", client)

            if is_docker_running:
                claude_desktop_config_path = os.path.join("/app", ".claude", "claude_desktop_config.json")
                if os.path.exists(claude_desktop_config_path):
                    sys_print(f"Loading claude_desktop_config.json file from {claude_desktop_config_path}")
                    with open(claude_desktop_config_path, "r") as f:
                        try:
                            claude_desktop_config = json.load(f)
                        except json.JSONDecodeError as e:
                            sys_print(f"Error parsing {claude_desktop_config_path}. The file may be corrupted: {str(e)}", is_error=True)
                            sys.exit(1)
                else:
                    claude_desktop_config = {"mcpServers": {}}

                claude_desktop_config["mcpServers"]["Enkrypt Secure MCP Gateway"] = {
                    "command": DOCKER_COMMAND,
                    "args": DOCKER_ARGS,
                    "env": env
                }
                with open(claude_desktop_config_path, "w") as f:
                    json.dump(claude_desktop_config, f, indent=2)
                sys_print(f"Successfully installed gateway for {client} in docker container.")
                sys_print(f"Config updated at: {claude_desktop_config_path}")
                sys_print("Please restart Claude Desktop to use the new gateway.")
                sys.exit(0)
            else:
                # non-Docker logic
                cmd = [
                    "mcp", "install", GATEWAY_PY_PATH,
                    "--name", "Enkrypt Secure MCP Gateway",
                    "--env-var", f"ENKRYPT_GATEWAY_KEY={gateway_key}"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    sys_print(f"Error installing gateway: {result.stderr}", is_error=True)
                    sys.exit(1)
                else:
                    sys_print(f"Successfully installed gateway for {client}")
                    # Now, look at the claude_desktop_config.json file to see if the path to gateway is correct or not
                    # As we get double path when installed locally in windows like
                    # C:\\Users\\PC\\Documents\\GitHub\\enkryptai\\secure-mcp-gateway\\C:\\Users\\PC\\Documents\\GitHub\\enkryptai\\secure-mcp-gateway\\.secure-mcp-gateway-venv\\Lib\\site-packages\\secure_mcp_gateway\\gateway.py
                    if sys.platform == "darwin":
                        claude_desktop_config_path = os.path.join(HOME_DIR, "Library", "Application Support", "Claude", "claude_desktop_config.json")
                    elif sys.platform == "win32":
                        appdata = os.environ.get("APPDATA")
                        if appdata:
                            claude_desktop_config_path = os.path.join(appdata, "Claude", "claude_desktop_config.json")
                        else:
                            claude_desktop_config_path = None
                    else:
                        # Fallback for Linux or unknown OS
                        claude_desktop_config_path = os.path.join(HOME_DIR, ".claude", "claude_desktop_config.json")

                    if not os.path.exists(claude_desktop_config_path):
                        sys_print(f"claude_desktop_config.json file at: {claude_desktop_config_path} not found. Please check if Claude Desktop is installed and try again.", is_error=True)
                        sys.exit(1)

                    try:
                        with open(claude_desktop_config_path, "r") as f:
                            claude_desktop_config = json.load(f)
                    except json.JSONDecodeError as e:
                        sys_print(f"Error parsing {claude_desktop_config_path}. The file may be corrupted: {str(e)}", is_error=True)
                        sys.exit(1)
                    
                    if "mcpServers" not in claude_desktop_config or "Enkrypt Secure MCP Gateway" not in claude_desktop_config.get("mcpServers", {}):
                        sys_print("Enkrypt Secure MCP Gateway not found in Claude Desktop configuration. Something went wrong. Please reinstall the gateway.", is_error=True)
                        sys.exit(1)

                    args_list = claude_desktop_config["mcpServers"]["Enkrypt Secure MCP Gateway"].get("args", [])

                    if not args_list:
                        sys_print("No args found for Enkrypt Secure MCP Gateway in Claude Desktop configuration. Something went wrong. Please reinstall the gateway.", is_error=True)
                        sys.exit(1)

                    if args_list and args_list[-1] == GATEWAY_PY_PATH:
                        sys_print("Path to gateway is correct. No need to modify the claude_desktop_config.json file.")
                    else:
                        sys_print("Path to gateway is incorrect. Modifying the path to gateway in claude_desktop_config.json file...")
                        args_list[-1] = GATEWAY_PY_PATH
                        try:
                            with open(claude_desktop_config_path, "w") as f:
                                json.dump(claude_desktop_config, f, indent=2)
                            sys_print("Path to gateway modified in claude_desktop_config.json file")
                        except IOError as e:
                            sys_print(f"Error writing to {claude_desktop_config_path}: {e}", is_error=True)
                            sys_print("Please retry or manually edit the file to set the correct gateway path.", is_error=True)
                            sys.exit(1)
                sys_print("Please restart Claude Desktop to use the gateway.")
                sys.exit(0)

        elif args.client.lower() == "cursor":
            base_path = '/app' if is_docker_running else HOME_DIR
            cursor_config_path = os.path.join(base_path, '.cursor', 'mcp.json')
            sys_print("cursor_config_path: ", cursor_config_path)

            if is_docker_running:
                args_list = DOCKER_ARGS
                command = DOCKER_COMMAND
            else:
                # non-Docker uv configuration
                command = "uv"
                args_list = [
                    "run",
                    "--with",
                    "mcp[cli]",
                    "mcp",
                    "run",
                    GATEWAY_PY_PATH
                ]

            try:
                add_or_update_cursor_server(
                    config_path=cursor_config_path,
                    server_name="Enkrypt Secure MCP Gateway",
                    command=command,
                    args=args_list,
                    env=env
                )
                sys_print(f"Successfully configured Cursor")
                sys.exit(0)
            except Exception as e:
                sys_print(f"Error configuring Cursor: {str(e)}", is_error=True)
                sys.exit(1)
        else:
            sys_print(f"Invalid client name: {args.client}. Please use 'claude-desktop' or 'cursor'.", is_error=True)
            sys.exit(1)

    else:
        sys_print(f"Invalid command: {args.command}. Please use 'generate-config' or 'install'.", is_error=True)
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
