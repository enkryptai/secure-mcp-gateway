import os
import sys
import uuid
import json
import base64
import argparse
import subprocess


def generate_default_config():
    """Generate a default config with a unique gateway key and uuid."""
    gateway_key = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
    unique_uuid = str(uuid.uuid4())
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
            "enkrypt_async_output_guardrails_enabled": False
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
                                "test_mcps/echo_mcp.py"
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
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            config = json.load(f)
    else:
        config = {}

    if "mcpServers" not in config:
        config["mcpServers"] = {}

    server_already_exists = server_name in config["mcpServers"]

    config["mcpServers"][server_name] = {
        "command": command,
        "args": args,
        "env": env
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"{'Updated' if server_already_exists else 'Added'} '{server_name}' in {config_path}")


def main():
    parser = argparse.ArgumentParser(description="Enkrypt Secure MCP Gateway CLI")
    subparsers = parser.add_subparsers(dest="command")

    # generate-config subcommand
    gen_config_parser = subparsers.add_parser(
        "generate-config", help="Generate a new default config file"
    )
    gen_config_parser.add_argument(
        "--config-path", type=str, required=True,
        help="Path to generate a new enkrypt_mcp_config.json"
    )

    # install subcommand
    install_parser = subparsers.add_parser(
        "install", help="Install gateway for a client"
    )
    install_parser.add_argument(
        "--client", type=str, required=True, help="Client name (e.g., claude-desktop)"
    )
    install_parser.add_argument(
        "--config-path", type=str, required=True,
        help="Path to existing enkrypt_mcp_config.json"
    )

    args = parser.parse_args()

    if args.command == "generate-config":
        config_path = args.config_path
        if os.path.exists(config_path):
            print(f"Config file already exists at {config_path}. Not overwriting. Please delete if needed and run again.")
            sys.exit(1)
        config = generate_default_config()
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        print(f"Generated default config at {config_path}")
        sys.exit(0)

    elif args.command == "install":
        if args.client.lower() == "claude" or args.client.lower() == "claude-desktop":
            config_path = args.config_path
            client = args.client
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            gateway_py = os.path.join(base_dir, "gateway.py")

            print("config_path: ", config_path)
            print("gateway_py path: ", gateway_py)
            print("client name from args: ", client)

            if not os.path.exists(config_path):
                print(f"Config file not found at path: {config_path}. Please generate a new config file using 'generate-config' subcommand and try again.")
                sys.exit(1)

            gateway_key = get_gateway_key(config_path)
            cmd = [
                "mcp", "install", gateway_py,
                "--env-var", f"ENKRYPT_GATEWAY_KEY={gateway_key}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error installing gateway: {result.stderr}")
            else:
                print(f"Successfully installed gateway for {client}")
            sys.exit(result.returncode)

        elif args.client.lower() == "cursor":
            config_path = args.config_path

            if not os.path.exists(config_path):
                print(f"Config file not found at path: {config_path}. Please generate a new config file using 'generate-config' subcommand and try again.")
                sys.exit(1)

            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            gateway_py = os.path.join(base_dir, "gateway.py")
            gateway_key = get_gateway_key(config_path)
            env = {
                "ENKRYPT_GATEWAY_KEY": gateway_key
            }
            args_list = [
                "run",
                "--with",
                "mcp[cli]",
                "mcp",
                "run",
                gateway_py
            ]
            uv_path = "uv"
            cursor_config_path = os.path.join(os.path.expanduser("~"), ".cursor", "mcp.json")
            print("cursor_config_path: ", cursor_config_path)
            try:
                add_or_update_cursor_server(
                    config_path=cursor_config_path,
                    server_name="Enkrypt Secure MCP Gateway",
                    command=uv_path,
                    args=args_list,
                    env=env
                )
                print(f"Successfully configured Cursor")
                sys.exit(0)
            except Exception as e:
                print(f"Error configuring Cursor: {str(e)}")
                sys.exit(1)
        else:
            print(f"Invalid client name: {args.client}. Please use 'claude-desktop' or 'cursor'.")
            sys.exit(1)

    else:
        print(f"Invalid command: {args.command}. Please use 'generate-config' or 'install'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
