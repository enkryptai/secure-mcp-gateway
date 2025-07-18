import os
import re
import sys
import uuid
import json
import shutil
import base64
import argparse
import subprocess
from datetime import datetime
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
ECHO_SERVER_PATH = os.path.join(BASE_DIR, "test_mcps", "echo_mcp.py")
PICKED_CONFIG_PATH = DOCKER_CONFIG_PATH if is_docker_running else CONFIG_PATH
sys_print("GATEWAY_PY_PATH: ", GATEWAY_PY_PATH)
sys_print("ECHO_SERVER_PATH: ", ECHO_SERVER_PATH)
sys_print("PICKED_CONFIG_PATH: ", PICKED_CONFIG_PATH)
print("--------------------------------\n\nOUTPUT:\n\n", file=sys.stderr)

DOCKER_COMMAND = "docker"
DOCKER_ARGS = [
    "run", "--rm", "-i",
    "-v", f"{HOST_ENKRYPT_HOME}:/app/.enkrypt",
    "-e", "ENKRYPT_GATEWAY_KEY",
    "secure-mcp-gateway"
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def load_config(config_path):
    """Load configuration from file with proper error handling."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at path: {config_path}")
    
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        sys_print(f"Error: Config file is corrupted or invalid JSON: {e}", is_error=True)
        sys.exit(1)
    except Exception as e:
        sys_print(f"Error reading config file: {e}", is_error=True)
        sys.exit(1)

def save_config(config_path, config):
    """Save configuration to file with proper error handling."""
    try:
        # Create backup before saving
        if os.path.exists(config_path):
            backup_path = f"{config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(config_path, backup_path)
        
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        if os.name == 'posix':
            os.chmod(config_path, 0o600)
    except Exception as e:
        sys_print(f"Error saving config file: {e}", is_error=True)
        sys.exit(1)

def validate_json_input(json_string, field_name):
    """Validate JSON input from command line."""
    if not json_string:
        return None
    
    # Handle PowerShell quote issues on Windows
    # Remove surrounding single quotes if present (PowerShell wraps JSON in single quotes)
    if json_string.startswith("'") and json_string.endswith("'"):
        json_string = json_string[1:-1]
    
    # Handle PowerShell backtick escaping
    if sys.platform == "win32":
        # Replace PowerShell backtick-escaped quotes with proper quotes
        json_string = json_string.replace('`"', '"')
        
        # Handle case where PowerShell might escape backslashes
        json_string = json_string.replace('\\`"', '\\"')
    
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        sys_print(f"Error: Invalid JSON for {field_name}: {e}", is_error=True)
        if sys.platform == "win32":
            sys_print(f"PowerShell tip: Try using a variable or JSON file instead", is_error=True)
            sys_print(f"Example: $env = '{{\"key\": \"value\"}}'; python cli.py ... --env $env", is_error=True)
        else:
            sys_print(f"Tip: Use single quotes around JSON or escape inner quotes", is_error=True)
        sys.exit(1)

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_uuid(uuid_string):
    """Validate UUID format."""
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False

def validate_config_structure(config):
    """Validate entire config structure."""
    required_sections = ["common_mcp_gateway_config", "projects", "users", "apikeys"]
    for section in required_sections:
        if section not in config:
            return False, f"Missing required section: {section}"
    return True, "Valid"

def find_config_by_name_or_id(config, identifier):
    """Find MCP config by name or ID - works with actual config structure."""
    # Check if we have top-level mcp_configs (new structure)
    if "mcp_configs" in config:
        for config_id, config_data in config["mcp_configs"].items():
            if (config_id == identifier or 
                config_data.get("mcp_config_name") == identifier):
                return config_id, config_data
    
    # Check in projects (current structure)
    for project_id, project_data in config.get("projects", {}).items():
        for mcp_config in project_data.get("mcp_configs", []):
            if (mcp_config.get("mcp_config_id") == identifier or 
                mcp_config.get("mcp_config_name") == identifier):
                return mcp_config.get("mcp_config_id"), mcp_config
    
    return None, None

def find_project_by_name_or_id(config, identifier):
    """Find project by name or ID."""
    for project_id, project_data in config.get("projects", {}).items():
        if (project_id == identifier or 
            project_data.get("project_name") == identifier):
            return project_id, project_data
    return None, None

def find_user_by_email_or_id(config, identifier):
    """Find user by email or ID in users section."""
    for user_id, user_data in config.get("users", {}).items():
        if (user_id == identifier or 
            user_data.get("email") == identifier):
            return user_id, user_data
    return None, None

def check_duplicate_config_name(config, config_name):
    """Check if config name already exists."""
    # Check top-level mcp_configs
    if "mcp_configs" in config:
        for config_data in config["mcp_configs"].values():
            if config_data.get("mcp_config_name") == config_name:
                return True
    
    # Check in projects
    for project_data in config.get("projects", {}).values():
        for mcp_config in project_data.get("mcp_configs", []):
            if mcp_config.get("mcp_config_name") == config_name:
                return True
    
    return False

def check_duplicate_server_name(config_data, server_name):
    """Check if server name already exists in config."""
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            return True
    return False

def check_duplicate_project_name(config, project_name):
    """Check if project name already exists."""
    for project_data in config.get("projects", {}).values():
        if project_data.get("project_name") == project_name:
            return True
    return False

# =============================================================================
# ORIGINAL FUNCTIONS (UPDATED)
# =============================================================================

def generate_default_config():
    """Generate a default config with both structures for compatibility."""
    gateway_key = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
    project_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    mcp_config_id = str(uuid.uuid4())
    
    config = {
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
        "mcp_configs": {
            mcp_config_id: {
                "mcp_config_name": "default_config",
                "mcp_config": [
                    {
                        "server_name": "echo_server",
                        "description": "Dummy Echo Server",
                        "config": {
                            "command": "python",
                            "args": [ECHO_SERVER_PATH]
                        },
                        "tools": {},
                        "input_guardrails_policy": {
                            "enabled": False,
                            "policy_name": "Sample Airline Guardrail",
                            "additional_config": {"pii_redaction": False},
                            "block": ["policy_violation"]
                        },
                        "output_guardrails_policy": {
                            "enabled": False,
                            "policy_name": "Sample Airline Guardrail",
                            "additional_config": {
                                "relevancy": False,
                                "hallucination": False,
                                "adherence": False
                            },
                            "block": ["policy_violation"]
                        }
                    }
                ]
            }
        },
        "projects": {
            project_id: {
                "project_name": "default_project",
                "mcp_config_id": mcp_config_id,
                "users": [user_id],
                "created_at": datetime.now().isoformat()
            }
        },
        "users": {
            user_id: {
                "email": "default@example.com",
                "created_at": datetime.now().isoformat()
            }
        },
        "apikeys": {
            gateway_key: {
                "project_id": project_id,
                "user_id": user_id,
                "created_at": datetime.now().isoformat()
            }
        }
    }
    
    return config

def get_gateway_credentials(config_path):
    """Extract gateway credentials from config."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at path: {config_path}")
    
    config = load_config(config_path)
    
    # Get gateway_key
    if not config.get("apikeys"):
        raise ValueError("No API keys found in config")
    
    gateway_key = next(iter(config["apikeys"].keys()))
    project_id = config["apikeys"][gateway_key]["project_id"]
    user_id = config["apikeys"][gateway_key]["user_id"]
    
    # Get mcp_config_id
    mcp_config_id = None
    if "projects" in config and project_id in config["projects"]:
        project_data = config["projects"][project_id]
        if "mcp_config_id" in project_data:
            mcp_config_id = project_data["mcp_config_id"]
        elif "mcp_configs" in project_data and project_data["mcp_configs"]:
            mcp_config_id = project_data["mcp_configs"][0].get("mcp_config_id")
    
    return {
        "gateway_key": gateway_key,
        "project_id": project_id,
        "user_id": user_id,
        "mcp_config_id": mcp_config_id
    }

def add_or_update_cursor_server(config_path, server_name, command, args, env):
    """Add or update cursor server configuration."""
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            sys_print(f"Error parsing {config_path}. The file may be corrupted: {str(e)}", is_error=True)
            sys_print(f"Error parsing {config_path}: {e}", is_error=True)
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
    # Create directory with restricted permissions
    dir_path = os.path.dirname(config_path)
    os.makedirs(dir_path, exist_ok=True)
    if os.name == 'posix':  # Unix-like systems
        os.chmod(dir_path, 0o700)

    # Write config file with restricted permissions
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    if os.name == 'posix':  # Unix-like systems
        os.chmod(config_path, 0o600)
    
    sys_print(f"{'Updated' if server_already_exists else 'Added'} '{server_name}' in {config_path}")

# =============================================================================
# MCP CONFIG COMMANDS (ENHANCED)
# =============================================================================

def list_configs(config_path):
    """List all MCP configurations."""
    config = load_config(config_path)
    configs = []
    
    # Check top-level mcp_configs
    if "mcp_configs" in config:
        for config_id, config_data in config["mcp_configs"].items():
            using_projects = []
            for project_id, project_data in config.get("projects", {}).items():
                if project_data.get("mcp_config_id") == config_id:
                    using_projects.append({
                        "project_id": project_id,
                        "project_name": project_data.get("project_name", "Unnamed Project")
                    })
            
            configs.append({
                "mcp_config_id": config_id,
                "mcp_config_name": config_data.get("mcp_config_name", "Unnamed Config"),
                "servers": len(config_data.get("mcp_config", [])),
                "used_by_projects": using_projects
            })
    
    # Check in projects (legacy structure)
    for project_id, project_data in config.get("projects", {}).items():
        for mcp_config in project_data.get("mcp_configs", []):
            configs.append({
                "mcp_config_id": mcp_config.get("mcp_config_id"),
                "mcp_config_name": mcp_config.get("mcp_config_name", "Unnamed Config"),
                "servers": len(mcp_config.get("mcp_config", [])),
                "used_by_projects": [{
                    "project_id": project_id,
                    "project_name": project_data.get("project_name", "Unnamed Project")
                }]
            })
    
    print(json.dumps(configs, indent=2))

def add_config(config_path, config_name):
    """Add new MCP configuration with validation."""
    config = load_config(config_path)
    
    # Check for duplicate names
    if check_duplicate_config_name(config, config_name):
        sys_print(f"Error: Config with name '{config_name}' already exists.", is_error=True)
        sys.exit(1)
    
    mcp_config_id = str(uuid.uuid4())
    
    # Initialize mcp_configs if it doesn't exist
    if "mcp_configs" not in config:
        config["mcp_configs"] = {}
    
    config["mcp_configs"][mcp_config_id] = {
        "mcp_config_name": config_name,
        "mcp_config": [],
        "created_at": datetime.now().isoformat()
    }
    
    save_config(config_path, config)
    print(f"mcp_config_id: {mcp_config_id}")

def copy_config(config_path, source_config, target_config):
    """Copy MCP configuration."""
    config = load_config(config_path)
    
    # Find source config
    source_id, source_data = find_config_by_name_or_id(config, source_config)
    if not source_data:
        sys_print(f"Error: Source config '{source_config}' not found.", is_error=True)
        sys.exit(1)
    
    # Check if target name already exists
    if check_duplicate_config_name(config, target_config):
        sys_print(f"Error: Target config name '{target_config}' already exists.", is_error=True)
        sys.exit(1)
    
    # Create new config
    new_config_id = str(uuid.uuid4())
    new_config_data = source_data.copy()
    new_config_data["mcp_config_name"] = target_config
    new_config_data["created_at"] = datetime.now().isoformat()
    
    # Initialize mcp_configs if needed
    if "mcp_configs" not in config:
        config["mcp_configs"] = {}
    
    config["mcp_configs"][new_config_id] = new_config_data
    
    save_config(config_path, config)
    sys_print(f"Config '{source_config}' copied to '{target_config}' with ID: {new_config_id}")

def rename_config(config_path, config_identifier, new_name):
    """Rename MCP configuration."""
    config = load_config(config_path)
    
    # Find config
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    old_name = config_data.get("mcp_config_name", "Unnamed Config")
    
    # Check if new name already exists
    if check_duplicate_config_name(config, new_name):
        sys_print(f"Error: Config name '{new_name}' already exists.", is_error=True)
        sys.exit(1)
    
    # Update name
    config_data["mcp_config_name"] = new_name
    config_data["updated_at"] = datetime.now().isoformat()
    
    save_config(config_path, config)
    sys_print(f"Config '{old_name}' renamed to '{new_name}'")

def list_config_projects(config_path, config_identifier):
    """List projects using a specific config."""
    config = load_config(config_path)
    
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    using_projects = []
    for project_id, project_data in config.get("projects", {}).items():
        if project_data.get("mcp_config_id") == config_id:
            using_projects.append({
                "project_id": project_id,
                "project_name": project_data.get("project_name", "Unnamed Project"),
                "users": len(project_data.get("users", []))
            })
    
    print(json.dumps(using_projects, indent=2))

def list_config_servers(config_path, config_identifier):
    """List servers in a specific config."""
    config = load_config(config_path)
    
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    servers = []
    for server in config_data.get("mcp_config", []):
        servers.append({
            "server_name": server.get("server_name"),
            "description": server.get("description", ""),
            "command": server.get("config", {}).get("command"),
            "args": server.get("config", {}).get("args", []),
            "tools": len(server.get("tools", {})),
            "input_guardrails_enabled": server.get("input_guardrails_policy", {}).get("enabled", False),
            "output_guardrails_enabled": server.get("output_guardrails_policy", {}).get("enabled", False)
        })
    
    print(json.dumps(servers, indent=2))

def get_config_server(config_path, config_identifier, server_name):
    """Get specific server details from config."""
    config = load_config(config_path)
    
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Find server
    server_data = None
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            server_data = server
            break
    
    if not server_data:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    print(json.dumps(server_data, indent=2))

def update_config_server(config_path, config_identifier, server_name, command=None, args=None, env=None, tools=None, description=None):
    """Update server configuration."""
    config = load_config(config_path)
    
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Find server
    server_data = None
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            server_data = server
            break
    
    if not server_data:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    # Update server data
    if command:
        server_data["config"]["command"] = command
    if args:
        server_data["config"]["args"] = args
    if env:
        server_data["config"]["env"] = validate_json_input(env, "environment variables")
    if tools:
        server_data["tools"] = validate_json_input(tools, "tools configuration")
    if description:
        server_data["description"] = description
    
    server_data["updated_at"] = datetime.now().isoformat()
    
    save_config(config_path, config)
    sys_print(f"Server '{server_name}' updated in config '{config_identifier}'")

def add_server_to_config(config_path, config_identifier, server_name, command, 
                        args=None, env=None, tools=None, description="",
                        input_guardrails=None, output_guardrails=None):
    """Add server to MCP configuration with validation."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Check for duplicate server names
    if check_duplicate_server_name(config_data, server_name):
        sys_print(f"Error: Server '{server_name}' already exists in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    # Validate JSON inputs
    env_data = validate_json_input(env, "environment variables") if env else None
    tools_data = validate_json_input(tools, "tools configuration") if tools else None
    input_guardrails_data = validate_json_input(input_guardrails, "input guardrails policy") if input_guardrails else None
    output_guardrails_data = validate_json_input(output_guardrails, "output guardrails policy") if output_guardrails else None
    
    # Build server config
    server_config = {
        "server_name": server_name,
        "description": description,
        "config": {
            "command": command,
            "args": args or []
        },
        "tools": tools_data or {},
        "input_guardrails_policy": input_guardrails_data or {
            "enabled": False,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": {"pii_redaction": False},
            "block": ["policy_violation"]
        },
        "output_guardrails_policy": output_guardrails_data or {
            "enabled": False,
            "policy_name": "Sample Airline Guardrail",
            "additional_config": {
                "relevancy": False,
                "hallucination": False,
                "adherence": False
            },
            "block": ["policy_violation"]
        },
        "created_at": datetime.now().isoformat()
    }
    
    if env_data:
        server_config["config"]["env"] = env_data
    
    config_data["mcp_config"].append(server_config)
    save_config(config_path, config)
    sys_print(f"Server '{server_name}' added to config '{config_identifier}'")

def get_config(config_path, config_identifier):
    """Return specific MCP configuration."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    result = {
        "mcp_config_id": config_id,
        **config_data
    }
    print(json.dumps(result, indent=2))

def remove_server_from_config(config_path, config_identifier, server_name):
    """Remove server from MCP configuration."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    original_count = len(config_data["mcp_config"])
    config_data["mcp_config"] = [
        server for server in config_data["mcp_config"] 
        if server.get("server_name") != server_name
    ]
    
    if len(config_data["mcp_config"]) == original_count:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    save_config(config_path, config)
    sys_print(f"Server '{server_name}' removed from config '{config_identifier}'")

def remove_all_servers_from_config(config_path, config_identifier):
    """Remove all servers from MCP configuration."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    server_count = len(config_data["mcp_config"])
    config_data["mcp_config"] = []
    
    save_config(config_path, config)
    sys_print(f"Removed {server_count} servers from config '{config_identifier}'")

def remove_config(config_path, config_identifier):
    """Remove MCP configuration after checking usage."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Check if config is being used by projects
    referenced_projects = []
    for project_id, project_data in config.get("projects", {}).items():
        if project_data.get("mcp_config_id") == config_id:
            referenced_projects.append({
                "project_id": project_id,
                "project_name": project_data.get("project_name", "Unnamed Project")
            })
    
    if referenced_projects:
        sys_print(f"Error: Config '{config_identifier}' is being used by projects:", is_error=True)
        for proj in referenced_projects:
            sys_print(f"  - {proj['project_name']} ({proj['project_id']})", is_error=True)
        sys.exit(1)
    
    # Remove the config
    if "mcp_configs" in config and config_id in config["mcp_configs"]:
        del config["mcp_configs"][config_id]
    
    save_config(config_path, config)
    sys_print(f"Config '{config_identifier}' removed successfully")

def validate_config(config_path, config_identifier):
   """Validate MCP configuration."""
   config = load_config(config_path)
   config_id, config_data = find_config_by_name_or_id(config, config_identifier)
   
   if not config_data:
       sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   issues = []
   
   # Validate config structure
   if "mcp_config_name" not in config_data:
       issues.append("Missing 'mcp_config_name' field")
   
   if "mcp_config" not in config_data:
       issues.append("Missing 'mcp_config' field")
   else:
       # Validate servers
       for i, server in enumerate(config_data["mcp_config"]):
           server_issues = []
           
           if "server_name" not in server:
               server_issues.append("Missing 'server_name'")
           
           if "config" not in server:
               server_issues.append("Missing 'config' section")
           else:
               if "command" not in server["config"]:
                   server_issues.append("Missing 'command' in config")
               if "args" not in server["config"]:
                   server_issues.append("Missing 'args' in config")
           
           if server_issues:
               issues.append(f"Server {i+1} ({server.get('server_name', 'unknown')}): {', '.join(server_issues)}")
   
   if issues:
       sys_print(f"Config '{config_identifier}' validation failed:", is_error=True)
       for issue in issues:
           sys_print(f"  - {issue}", is_error=True)
       sys.exit(1)
   else:
       sys_print(f"Config '{config_identifier}' is valid")

def export_config(config_path, config_identifier, output_file):
   """Export MCP configuration to file."""
   config = load_config(config_path)
   config_id, config_data = find_config_by_name_or_id(config, config_identifier)
   
   if not config_data:
       sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   export_data = {
       "mcp_config_id": config_id,
       "exported_at": datetime.now().isoformat(),
       "config": config_data
   }
   
   try:
       with open(output_file, "w") as f:
           json.dump(export_data, f, indent=2)
       sys_print(f"Config '{config_identifier}' exported to {output_file}")
   except Exception as e:
       sys_print(f"Error exporting config: {e}", is_error=True)
       sys.exit(1)

def import_config(config_path, input_file, config_name):
   """Import MCP configuration from file."""
   config = load_config(config_path)
   
   try:
       with open(input_file, "r") as f:
           import_data = json.load(f)
   except Exception as e:
       sys_print(f"Error reading import file: {e}", is_error=True)
       sys.exit(1)
   
   if "config" not in import_data:
       sys_print("Error: Invalid import file format", is_error=True)
       sys.exit(1)
   
   # Check for duplicate names
   if check_duplicate_config_name(config, config_name):
       sys_print(f"Error: Config name '{config_name}' already exists.", is_error=True)
       sys.exit(1)
   
   # Import config
   new_config_id = str(uuid.uuid4())
   imported_config = import_data["config"].copy()
   imported_config["mcp_config_name"] = config_name
   imported_config["imported_at"] = datetime.now().isoformat()
   
   if "mcp_configs" not in config:
       config["mcp_configs"] = {}
   
   config["mcp_configs"][new_config_id] = imported_config
   
   save_config(config_path, config)
   sys_print(f"Config imported as '{config_name}' with ID: {new_config_id}")

def search_configs(config_path, search_term):
   """Search for configs by name or server name."""
   config = load_config(config_path)
   results = []
   
   # Search in top-level mcp_configs
   if "mcp_configs" in config:
       for config_id, config_data in config["mcp_configs"].items():
           config_name = config_data.get("mcp_config_name", "")
           match_type = None
           
           # Check config name
           if search_term.lower() in config_name.lower():
               match_type = "config_name"
           else:
               # Check server names
               for server in config_data.get("mcp_config", []):
                   if search_term.lower() in server.get("server_name", "").lower():
                       match_type = "server_name"
                       break
           
           if match_type:
               results.append({
                   "mcp_config_id": config_id,
                   "mcp_config_name": config_name,
                   "match_type": match_type,
                   "servers": len(config_data.get("mcp_config", []))
               })
   
   print(json.dumps(results, indent=2))

def load_policy_from_file_or_string(policy_file, policy_string, policy_type):
    """Load policy configuration from file or string."""
    if policy_file and policy_string:
        sys_print(f"Error: Cannot specify both --{policy_type}-policy-file and --{policy_type}-policy", is_error=True)
        sys.exit(1)
    
    if policy_file:
        try:
            with open(policy_file, "r") as f:
                return json.load(f)
        except Exception as e:
            sys_print(f"Error reading {policy_type} policy file: {e}", is_error=True)
            sys.exit(1)
    elif policy_string:
        return validate_json_input(policy_string, f"{policy_type} guardrails policy")
    else:
        sys_print(f"Error: Either --{policy_type}-policy-file or --{policy_type}-policy is required", is_error=True)
        sys.exit(1)

def update_server_input_guardrails(config_path, config_identifier, server_name, policy_file=None, policy_string=None):
    """Update server input guardrails policy."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Find server
    server_data = None
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            server_data = server
            break
    
    if not server_data:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    # Load policy
    policy_data = load_policy_from_file_or_string(policy_file, policy_string, "input")
    
    # Update policy
    server_data["input_guardrails_policy"] = policy_data
    server_data["updated_at"] = datetime.now().isoformat()
    
    save_config(config_path, config)
    sys_print(f"Input guardrails policy updated for server '{server_name}' in config '{config_identifier}'")

def update_server_output_guardrails(config_path, config_identifier, server_name, policy_file=None, policy_string=None):
    """Update server output guardrails policy."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Find server
    server_data = None
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            server_data = server
            break
    
    if not server_data:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    # Load policy
    policy_data = load_policy_from_file_or_string(policy_file, policy_string, "output")
    
    # Update policy
    server_data["output_guardrails_policy"] = policy_data
    server_data["updated_at"] = datetime.now().isoformat()
    
    save_config(config_path, config)
    sys_print(f"Output guardrails policy updated for server '{server_name}' in config '{config_identifier}'")

def update_server_guardrails(config_path, config_identifier, server_name, 
                           input_policy_file=None, input_policy_string=None,
                           output_policy_file=None, output_policy_string=None):
    """Update server guardrails policies (both input and output)."""
    config = load_config(config_path)
    config_id, config_data = find_config_by_name_or_id(config, config_identifier)
    
    if not config_data:
        sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
        sys.exit(1)
    
    # Find server
    server_data = None
    for server in config_data.get("mcp_config", []):
        if server.get("server_name") == server_name:
            server_data = server
            break
    
    if not server_data:
        sys_print(f"Error: Server '{server_name}' not found in config '{config_identifier}'.", is_error=True)
        sys.exit(1)
    
    updated_policies = []
    
    # Update input policy if provided
    if input_policy_file or input_policy_string:
        input_policy_data = load_policy_from_file_or_string(input_policy_file, input_policy_string, "input")
        server_data["input_guardrails_policy"] = input_policy_data
        updated_policies.append("input")
    
    # Update output policy if provided
    if output_policy_file or output_policy_string:
        output_policy_data = load_policy_from_file_or_string(output_policy_file, output_policy_string, "output")
        server_data["output_guardrails_policy"] = output_policy_data
        updated_policies.append("output")
    
    if not updated_policies:
        sys_print("Error: At least one policy (input or output) must be provided", is_error=True)
        sys.exit(1)
    
    server_data["updated_at"] = datetime.now().isoformat()
    save_config(config_path, config)
    sys_print(f"Updated {' and '.join(updated_policies)} guardrails policies for server '{server_name}' in config '{config_identifier}'")

# =============================================================================
# PROJECT COMMANDS (ENHANCED)
# =============================================================================

def list_projects(config_path):
   """List all projects."""
   config = load_config(config_path)
   projects = []
   
   for project_id, project_data in config.get("projects", {}).items():
       # Get config info
       config_info = None
       config_id = project_data.get("mcp_config_id")
       if config_id:
           if "mcp_configs" in config and config_id in config["mcp_configs"]:
               config_info = {
                   "mcp_config_id": config_id,
                   "mcp_config_name": config["mcp_configs"][config_id].get("mcp_config_name", "Unnamed Config")
               }
       
       # Count API keys
       api_key_count = 0
       for key_data in config.get("apikeys", {}).values():
           if key_data.get("project_id") == project_id:
               api_key_count += 1
       
       projects.append({
           "project_name": project_data.get("project_name", "Unnamed Project"),
           "project_id": project_id,
           "mcp_config": config_info,
           "users": len(project_data.get("users", [])),
           "api_keys": api_key_count,
           "created_at": project_data.get("created_at")
       })
   
   print(json.dumps(projects, indent=2))

def create_project(config_path, project_name):
   """Create new project with validation."""
   config = load_config(config_path)
   
   # Check for duplicate names
   if check_duplicate_project_name(config, project_name):
       sys_print(f"Error: Project with name '{project_name}' already exists.", is_error=True)
       sys.exit(1)
   
   project_id = str(uuid.uuid4())
   
   if "projects" not in config:
       config["projects"] = {}
   
   config["projects"][project_id] = {
       "project_name": project_name,
       "mcp_config_id": None,
       "users": [],
       "created_at": datetime.now().isoformat()
   }
   
   save_config(config_path, config)
   print(f"project_id: {project_id}")

def assign_config_to_project(config_path, project_identifier, config_identifier):
   """Assign MCP config to project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   config_id, config_data = find_config_by_name_or_id(config, config_identifier)
   if not config_data:
       sys_print(f"Error: Config '{config_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Assign config to project
   old_config_id = project_data.get("mcp_config_id")
   project_data["mcp_config_id"] = config_id
   project_data["updated_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   
   if old_config_id:
       sys_print(f"Config '{config_identifier}' assigned to project '{project_identifier}' (replaced previous config)")
   else:
       sys_print(f"Config '{config_identifier}' assigned to project '{project_identifier}'")

def unassign_config_from_project(config_path, project_identifier):
   """Unassign MCP config from project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   if not project_data.get("mcp_config_id"):
       sys_print(f"Error: Project '{project_identifier}' has no assigned config.", is_error=True)
       sys.exit(1)
   
   project_data["mcp_config_id"] = None
   project_data["updated_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   sys_print(f"Config unassigned from project '{project_identifier}'")

def get_project_config(config_path, project_identifier):
   """Get config assigned to project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   config_id = project_data.get("mcp_config_id")
   if not config_id:
       sys_print(f"Error: Project '{project_identifier}' has no assigned config.", is_error=True)
       sys.exit(1)
   
   config_data = None
   if "mcp_configs" in config and config_id in config["mcp_configs"]:
       config_data = config["mcp_configs"][config_id]
   
   if not config_data:
       sys_print(f"Error: Config '{config_id}' not found.", is_error=True)
       sys.exit(1)
   
   result = {
       "mcp_config_id": config_id,
       **config_data
   }
   print(json.dumps(result, indent=2))

def list_project_users(config_path, project_identifier):
   """List users in a project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   users = []
   for user_id in project_data.get("users", []):
       user_data = config.get("users", {}).get(user_id, {})
       
       # Count API keys for this user in this project
       api_key_count = 0
       for key_data in config.get("apikeys", {}).values():
           if key_data.get("user_id") == user_id and key_data.get("project_id") == project_id:
               api_key_count += 1
       
       users.append({
           "user_id": user_id,
           "email": user_data.get("email", "Unknown"),
           "api_keys": api_key_count,
           "created_at": user_data.get("created_at")
       })
   
   print(json.dumps(users, indent=2))

def get_project(config_path, project_identifier):
   """Return specific project."""
   config = load_config(config_path)
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Get config info
   config_info = None
   config_id = project_data.get("mcp_config_id")
   if config_id and "mcp_configs" in config and config_id in config["mcp_configs"]:
       config_info = {
           "mcp_config_id": config_id,
           "mcp_config_name": config["mcp_configs"][config_id].get("mcp_config_name")
       }
   
   # Get user details
   user_details = []
   for user_id in project_data.get("users", []):
       user_data = config.get("users", {}).get(user_id, {})
       user_details.append({
           "user_id": user_id,
           "email": user_data.get("email"),
           "created_at": user_data.get("created_at")
       })
   
   # Get API key count
   api_key_count = 0
   for key_data in config.get("apikeys", {}).values():
       if key_data.get("project_id") == project_id:
           api_key_count += 1
   
   result = {
       "project_id": project_id,
       "project_name": project_data.get("project_name"),
       "mcp_config": config_info,
       "users": user_details,
       "api_keys": api_key_count,
       "created_at": project_data.get("created_at")
   }
   print(json.dumps(result, indent=2))

def add_user_to_project(config_path, project_identifier, user_identifier):
   """Add user to project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   if "users" not in project_data:
       project_data["users"] = []
   
   if user_id not in project_data["users"]:
       project_data["users"].append(user_id)
       project_data["updated_at"] = datetime.now().isoformat()
       save_config(config_path, config)
       sys_print(f"User '{user_identifier}' added to project '{project_identifier}'")
   else:
       sys_print(f"User '{user_identifier}' is already in project '{project_identifier}'")

def remove_user_from_project(config_path, project_identifier, user_identifier):
   """Remove user from project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   if user_id in project_data.get("users", []):
       project_data["users"].remove(user_id)
       project_data["updated_at"] = datetime.now().isoformat()
       save_config(config_path, config)
       sys_print(f"User '{user_identifier}' removed from project '{project_identifier}'")
   else:
       sys_print(f"User '{user_identifier}' is not in project '{project_identifier}'")

def remove_all_users_from_project(config_path, project_identifier):
   """Remove all users from project."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   user_count = len(project_data.get("users", []))
   project_data["users"] = []
   project_data["updated_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   sys_print(f"Removed {user_count} users from project '{project_identifier}'")

def remove_project(config_path, project_identifier):
   """Remove project."""
   config = load_config(config_path)
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Check if project has API keys
   api_keys_to_remove = []
   for api_key, key_data in config.get("apikeys", {}).items():
       if key_data.get("project_id") == project_id:
           api_keys_to_remove.append(api_key)
   
   if api_keys_to_remove:
       sys_print(f"Error: Project '{project_identifier}' has {len(api_keys_to_remove)} active API keys:", is_error=True)
       for api_key in api_keys_to_remove:
           sys_print(f"  - {api_key[:20]}...", is_error=True)
       sys_print("Please delete these API keys first using:", is_error=True)
       for api_key in api_keys_to_remove:
           sys_print(f"  python cli.py user delete-api-key --api-key {api_key}", is_error=True)
       sys.exit(1)
   
   del config["projects"][project_id]
   save_config(config_path, config)
   sys_print(f"Project '{project_identifier}' removed successfully")

def export_project(config_path, project_identifier, output_file):
   """Export project to file."""
   config = load_config(config_path)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Get associated config
   config_data = None
   config_id = project_data.get("mcp_config_id")
   if config_id and "mcp_configs" in config and config_id in config["mcp_configs"]:
       config_data = config["mcp_configs"][config_id]
   
   # Get user details
   user_details = []
   for user_id in project_data.get("users", []):
       user_data = config.get("users", {}).get(user_id, {})
       user_details.append({
           "user_id": user_id,
           "email": user_data.get("email"),
           "created_at": user_data.get("created_at")
       })
   
   export_data = {
       "project_id": project_id,
       "exported_at": datetime.now().isoformat(),
       "project": project_data,
       "config": config_data,
       "users": user_details
   }
   
   try:
       with open(output_file, "w") as f:
           json.dump(export_data, f, indent=2)
       sys_print(f"Project '{project_identifier}' exported to {output_file}")
   except Exception as e:
       sys_print(f"Error exporting project: {e}", is_error=True)
       sys.exit(1)

def search_projects(config_path, search_term):
   """Search for projects by name or user email."""
   config = load_config(config_path)
   results = []
   
   for project_id, project_data in config.get("projects", {}).items():
       project_name = project_data.get("project_name", "")
       match_type = None
       
       # Check project name
       if search_term.lower() in project_name.lower():
           match_type = "project_name"
       else:
           # Check user emails
           for user_id in project_data.get("users", []):
               user_data = config.get("users", {}).get(user_id, {})
               if search_term.lower() in user_data.get("email", "").lower():
                   match_type = "user_email"
                   break
       
       if match_type:
           results.append({
               "project_id": project_id,
               "project_name": project_name,
               "match_type": match_type,
               "users": len(project_data.get("users", []))
           })
   
   print(json.dumps(results, indent=2))

# =============================================================================
# USER COMMANDS (ENHANCED)
# =============================================================================

def list_users(config_path):
   """List all users."""
   config = load_config(config_path)
   users = []
   
   for user_id, user_data in config.get("users", {}).items():
       # Find projects this user is in
       user_projects = []
       for project_id, project_data in config.get("projects", {}).items():
           if user_id in project_data.get("users", []):
               user_projects.append({
                   "project_id": project_id,
                   "project_name": project_data.get("project_name", "Unnamed Project")
               })
       
       # Count API keys for this user
       api_key_count = 0
       for key_data in config.get("apikeys", {}).values():
           if key_data.get("user_id") == user_id:
               api_key_count += 1
       
       users.append({
           "user_id": user_id,
           "email": user_data.get("email"),
           "created_at": user_data.get("created_at"),
           "projects": user_projects,
           "api_keys": api_key_count
       })
   
   print(json.dumps(users, indent=2))

def create_user(config_path, email):
   """Create new user with validation."""
   config = load_config(config_path)
   
   # Validate email format
   if not validate_email(email):
       sys_print(f"Error: Invalid email format: {email}", is_error=True)
       sys.exit(1)
   
   if "users" not in config:
       config["users"] = {}
   
   # Check if user already exists
   for existing_user in config["users"].values():
       if existing_user.get("email") == email:
           sys_print(f"Error: User with email '{email}' already exists.", is_error=True)
           sys.exit(1)
   
   user_id = str(uuid.uuid4())
   config["users"][user_id] = {
       "email": email,
       "created_at": datetime.now().isoformat()
   }
   
   save_config(config_path, config)
   print(f"user_id: {user_id}")

def update_user(config_path, user_identifier, new_email):
   """Update user email."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Validate new email format
   if not validate_email(new_email):
       sys_print(f"Error: Invalid email format: {new_email}", is_error=True)
       sys.exit(1)
   
   # Check if new email already exists
   for existing_user in config["users"].values():
       if existing_user.get("email") == new_email:
           sys_print(f"Error: User with email '{new_email}' already exists.", is_error=True)
           sys.exit(1)
   
   old_email = user_data.get("email")
   user_data["email"] = new_email
   user_data["updated_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   sys_print(f"User email updated from '{old_email}' to '{new_email}'")

def get_user(config_path, user_identifier):
   """Return specific user."""
   config = load_config(config_path)
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Find projects this user is in
   user_projects = []
   for project_id, project_data in config.get("projects", {}).items():
       if user_id in project_data.get("users", []):
           user_projects.append({
               "project_id": project_id,
               "project_name": project_data.get("project_name", "Unnamed Project")
           })
   
   # Find API keys for this user
   user_api_keys = []
   for api_key, key_data in config.get("apikeys", {}).items():
       if key_data.get("user_id") == user_id:
           project_data = config.get("projects", {}).get(key_data.get("project_id"), {})
           user_api_keys.append({
               "api_key": api_key[:20] + "...",
               "project_id": key_data.get("project_id"),
               "project_name": project_data.get("project_name", "Unnamed Project"),
               "created_at": key_data.get("created_at")
           })
   
   result = {
       "user_id": user_id,
       "email": user_data.get("email"),
       "created_at": user_data.get("created_at"),
       "projects": user_projects,
       "api_keys": user_api_keys
   }
   print(json.dumps(result, indent=2))

def list_user_projects(config_path, user_identifier):
   """List projects for a specific user."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   user_projects = []
   for project_id, project_data in config.get("projects", {}).items():
       if user_id in project_data.get("users", []):
           # Count API keys for this user in this project
           api_key_count = 0
           for key_data in config.get("apikeys", {}).values():
               if key_data.get("user_id") == user_id and key_data.get("project_id") == project_id:
                   api_key_count += 1
           
           user_projects.append({
               "project_id": project_id,
               "project_name": project_data.get("project_name", "Unnamed Project"),
               "api_keys": api_key_count,
               "created_at": project_data.get("created_at")
           })
   
   print(json.dumps(user_projects, indent=2))

def delete_user(config_path, user_identifier, force=False):
   """Delete user with optional force cleanup."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   if force:
       # Force delete with cleanup
       # Delete all API keys
       api_keys_to_delete = []
       for api_key, key_data in config.get("apikeys", {}).items():
           if key_data.get("user_id") == user_id:
               api_keys_to_delete.append(api_key)
       
       for api_key in api_keys_to_delete:
           del config["apikeys"][api_key]
           sys_print(f"Deleted API key: {api_key[:20]}...")
       
       # Remove from all projects
       for project_id, project_data in config.get("projects", {}).items():
           if user_id in project_data.get("users", []):
               project_data["users"].remove(user_id)
               project_data["updated_at"] = datetime.now().isoformat()
               sys_print(f"Removed user from project: {project_data.get('project_name', project_id)}")
       
       # Delete user
       del config["users"][user_id]
       save_config(config_path, config)
       sys_print(f"User '{user_identifier}' force deleted successfully")
   else:
       # Check for dependencies
       user_api_keys = []
       for api_key, key_data in config.get("apikeys", {}).items():
           if key_data.get("user_id") == user_id:
               user_api_keys.append(api_key)
       
       if user_api_keys:
           sys_print(f"Error: Cannot delete user '{user_identifier}'. User has {len(user_api_keys)} active API keys:", is_error=True)
           for api_key in user_api_keys:
               project_data = config.get("projects", {}).get(config.get("apikeys", {}).get(api_key, {}).get("project_id"), {})
               project_name = project_data.get("project_name", "Unknown Project")
               sys_print(f"  - {api_key[:20]}... (Project: {project_name})", is_error=True)
           sys_print("Use --force to delete user and clean up all references", is_error=True)
           sys.exit(1)
       
       # Check project assignments
       user_projects = []
       for project_id, project_data in config.get("projects", {}).items():
           if user_id in project_data.get("users", []):
               user_projects.append({
                   "project_id": project_id,
                   "project_name": project_data.get("project_name", "Unknown Project")
               })
       
       if user_projects:
           sys_print(f"Error: Cannot delete user '{user_identifier}'. User is assigned to {len(user_projects)} projects:", is_error=True)
           for project in user_projects:
               sys_print(f"  - {project['project_name']} ({project['project_id']})", is_error=True)
           sys_print("Use --force to delete user and clean up all references", is_error=True)
           sys.exit(1)
       
       # Safe to delete user
       del config["users"][user_id]
       save_config(config_path, config)
       sys_print(f"User '{user_identifier}' deleted successfully")

def generate_user_api_key(config_path, user_identifier, project_identifier):
   """Generate API key for user in project."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   project_id, project_data = find_project_by_name_or_id(config, project_identifier)
   if not project_data:
       sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Check if user is in project
   if user_id not in project_data.get("users", []):
       sys_print(f"Error: User '{user_identifier}' is not in project '{project_identifier}'. Add user to project first.", is_error=True)
       sys.exit(1)
   
   # Generate API key
   api_key = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
   
   if "apikeys" not in config:
       config["apikeys"] = {}
   
   config["apikeys"][api_key] = {
       "user_id": user_id,
       "project_id": project_id,
       "created_at": datetime.now().isoformat()
   }
   
   save_config(config_path, config)
   print(f"api_key: {api_key}")

def rotate_user_api_key(config_path, old_api_key):
   """Rotate user API key."""
   config = load_config(config_path)
   
   if old_api_key not in config.get("apikeys", {}):
       sys_print(f"Error: API key '{old_api_key}' not found.", is_error=True)
       sys.exit(1)
   
   # Get old key data
   old_key_data = config["apikeys"][old_api_key]
   
   # Generate new API key
   new_api_key = base64.urlsafe_b64encode(os.urandom(36)).decode().rstrip("=")
   
   # Create new key with same data
   config["apikeys"][new_api_key] = {
       "user_id": old_key_data["user_id"],
       "project_id": old_key_data["project_id"],
       "created_at": datetime.now().isoformat(),
       "rotated_from": old_api_key
   }
   
   # Delete old key
   del config["apikeys"][old_api_key]
   
   save_config(config_path, config)
   sys_print(f"API key rotated successfully")
   print(f"new_api_key: {new_api_key}")

def disable_user_api_key(config_path, api_key):
   """Disable user API key."""
   config = load_config(config_path)
   
   if api_key not in config.get("apikeys", {}):
       sys_print(f"Error: API key '{api_key}' not found.", is_error=True)
       sys.exit(1)
   
   config["apikeys"][api_key]["disabled"] = True
   config["apikeys"][api_key]["disabled_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   sys_print(f"API key '{api_key[:20]}...' disabled successfully")

def enable_user_api_key(config_path, api_key):
   """Enable user API key."""
   config = load_config(config_path)
   
   if api_key not in config.get("apikeys", {}):
       sys_print(f"Error: API key '{api_key}' not found.", is_error=True)
       sys.exit(1)
   
   config["apikeys"][api_key]["disabled"] = False
   config["apikeys"][api_key]["enabled_at"] = datetime.now().isoformat()
   
   save_config(config_path, config)
   sys_print(f"API key '{api_key[:20]}...' enabled successfully")

def delete_user_api_key(config_path, api_key):
   """Delete specific API key."""
   config = load_config(config_path)
   
   if api_key not in config.get("apikeys", {}):
       sys_print(f"Error: API key '{api_key}' not found.", is_error=True)
       sys.exit(1)
   
   del config["apikeys"][api_key]
   save_config(config_path, config)
   sys_print(f"API key '{api_key[:20]}...' deleted successfully")

def delete_all_user_api_keys(config_path, user_identifier):
   """Delete all API keys for a user."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   # Find all API keys for this user
   keys_to_delete = []
   for api_key, key_data in config.get("apikeys", {}).items():
       if key_data.get("user_id") == user_id:
           keys_to_delete.append(api_key)
   
   if not keys_to_delete:
       sys_print(f"User '{user_identifier}' has no API keys to delete.")
       return
   
   # Delete all keys
   for api_key in keys_to_delete:
       del config["apikeys"][api_key]
   
   save_config(config_path, config)
   sys_print(f"Deleted {len(keys_to_delete)} API keys for user '{user_identifier}'")

def list_user_api_keys(config_path, user_identifier, project_identifier=None):
   """List all API keys for a user."""
   config = load_config(config_path)
   
   user_id, user_data = find_user_by_email_or_id(config, user_identifier)
   if not user_data:
       sys_print(f"Error: User '{user_identifier}' not found.", is_error=True)
       sys.exit(1)
   
   project_id = None
   if project_identifier:
       project_id, _ = find_project_by_name_or_id(config, project_identifier)
       if not project_id:
           sys_print(f"Error: Project '{project_identifier}' not found.", is_error=True)
           sys.exit(1)
   
   api_keys = []
   for api_key, key_data in config.get("apikeys", {}).items():
       if key_data.get("user_id") == user_id:
           if project_id and key_data.get("project_id") != project_id:
               continue
           
           project_data = config.get("projects", {}).get(key_data.get("project_id"), {})
           api_keys.append({
               "api_key": api_key,
               "project_id": key_data.get("project_id"),
               "project_name": project_data.get("project_name", "Unnamed Project"),
               "created_at": key_data.get("created_at"),
               "disabled": key_data.get("disabled", False)
           })
   
   print(json.dumps(api_keys, indent=2))

def list_all_api_keys(config_path):
   """List all API keys across all users."""
   config = load_config(config_path)
   
   all_keys = []
   for api_key, key_data in config.get("apikeys", {}).items():
       user_data = config.get("users", {}).get(key_data.get("user_id"), {})
       project_data = config.get("projects", {}).get(key_data.get("project_id"), {})
       
       all_keys.append({
           "api_key": api_key[:20] + "...",
           "user_id": key_data.get("user_id"),
           "user_email": user_data.get("email", "Unknown"),
           "project_id": key_data.get("project_id"),
           "project_name": project_data.get("project_name", "Unknown Project"),
           "created_at": key_data.get("created_at"),
           "disabled": key_data.get("disabled", False)
       })
   
   print(json.dumps(all_keys, indent=2))

def search_users(config_path, search_term):
   """Search for users by email or project name."""
   config = load_config(config_path)
   results = []
   
   for user_id, user_data in config.get("users", {}).items():
       email = user_data.get("email", "")
       match_type = None
       
       # Check email
       if search_term.lower() in email.lower():
           match_type = "email"
       else:
           # Check project names
           for project_id, project_data in config.get("projects", {}).items():
               if user_id in project_data.get("users", []):
                   if search_term.lower() in project_data.get("project_name", "").lower():
                       match_type = "project_name"
                       break
       
       if match_type:
           # Count API keys
           api_key_count = 0
           for key_data in config.get("apikeys", {}).values():
               if key_data.get("user_id") == user_id:
                   api_key_count += 1
           
           results.append({
               "user_id": user_id,
               "email": email,
               "match_type": match_type,
               "api_keys": api_key_count
           })
   
   print(json.dumps(results, indent=2))

# =============================================================================
# SYSTEM COMMANDS
# =============================================================================

def system_health_check(config_path):
   """Check system health."""
   config = load_config(config_path)
   
   issues = []
   warnings = []
   
   # Validate config structure
   is_valid, message = validate_config_structure(config)
   if not is_valid:
       issues.append(f"Config structure: {message}")
   
   # Check for orphaned data
   project_ids = set(config.get("projects", {}).keys())
   user_ids = set(config.get("users", {}).keys())
   
   # Check API keys
   for api_key, key_data in config.get("apikeys", {}).items():
       if key_data.get("project_id") not in project_ids:
           issues.append(f"API key {api_key[:20]}... references non-existent project {key_data.get('project_id')}")
       if key_data.get("user_id") not in user_ids:
           issues.append(f"API key {api_key[:20]}... references non-existent user {key_data.get('user_id')}")
   
   # Check projects
   for project_id, project_data in config.get("projects", {}).items():
       for user_id in project_data.get("users", []):
           if user_id not in user_ids:
               issues.append(f"Project {project_data.get('project_name', project_id)} references non-existent user {user_id}")
       
       config_id = project_data.get("mcp_config_id")
       if config_id and "mcp_configs" in config and config_id not in config["mcp_configs"]:
           issues.append(f"Project {project_data.get('project_name', project_id)} references non-existent config {config_id}")
   
   # Check for duplicate emails
   emails = []
   for user_data in config.get("users", {}).values():
       email = user_data.get("email")
       if email in emails:
           issues.append(f"Duplicate email found: {email}")
       emails.append(email)
   
   # Check for duplicate project names
   project_names = []
   for project_data in config.get("projects", {}).values():
       name = project_data.get("project_name")
       if name in project_names:
           warnings.append(f"Duplicate project name found: {name}")
       project_names.append(name)
   
   # Check for duplicate config names
   config_names = []
   if "mcp_configs" in config:
       for config_data in config["mcp_configs"].values():
           name = config_data.get("mcp_config_name")
           if name in config_names:
               warnings.append(f"Duplicate config name found: {name}")
           config_names.append(name)
   
   # Generate report
   health_report = {
       "timestamp": datetime.now().isoformat(),
       "status": "healthy" if not issues else "unhealthy",
       "issues": issues,
       "warnings": warnings,
       "statistics": {
           "total_projects": len(config.get("projects", {})),
           "total_users": len(config.get("users", {})),
           "total_configs": len(config.get("mcp_configs", {})),
           "total_api_keys": len(config.get("apikeys", {})),
           "disabled_api_keys": len([k for k in config.get("apikeys", {}).values() if k.get("disabled")])
       }
   }
   
   print(json.dumps(health_report, indent=2))
   
   if issues:
       sys.exit(1)

def system_backup(config_path, output_file):
   """Backup entire configuration."""
   config = load_config(config_path)
   
   backup_data = {
       "backup_version": "1.0",
       "timestamp": datetime.now().isoformat(),
       "config": config
   }
   
   try:
       with open(output_file, "w") as f:
           json.dump(backup_data, f, indent=2)
       sys_print(f"System backup created: {output_file}")
   except Exception as e:
       sys_print(f"Error creating backup: {e}", is_error=True)
       sys.exit(1)

def system_restore(config_path, input_file):
   """Restore configuration from backup."""
   try:
       with open(input_file, "r") as f:
           backup_data = json.load(f)
   except Exception as e:
       sys_print(f"Error reading backup file: {e}", is_error=True)
       sys.exit(1)
   
   if "config" not in backup_data:
       sys_print("Error: Invalid backup file format", is_error=True)
       sys.exit(1)
   
   # Validate restored config
   is_valid, message = validate_config_structure(backup_data["config"])
   if not is_valid:
       sys_print(f"Error: Backup contains invalid config: {message}", is_error=True)
       sys.exit(1)
   
   save_config(config_path, backup_data["config"])
   sys_print(f"System restored from backup: {input_file}")

def system_reset(config_path, confirm=False):
   """Reset system to default configuration."""
   if not confirm:
       sys_print("Error: This will delete all data. Use --confirm to proceed.", is_error=True)
       sys.exit(1)
   
   # Create backup before reset
   backup_file = f"{config_path}.backup.before_reset.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
   if os.path.exists(config_path):
       shutil.copy2(config_path, backup_file)
       sys_print(f"Backup created: {backup_file}")
   
   # Generate new default config
   default_config = generate_default_config()
   save_config(config_path, default_config)
   sys_print("System reset to default configuration")

# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Enkrypt Secure MCP Gateway CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # generate-config subcommand
    gen_config_parser = subparsers.add_parser("generate-config", help="Generate a new default config file")

    # install subcommand
    install_parser = subparsers.add_parser("install", help="Install gateway for a client")
    install_parser.add_argument("--client", type=str, required=True, help="Client name (e.g., claude-desktop)")

    # =========================================================================
    # CONFIG COMMANDS
    # =========================================================================
    config_parser = subparsers.add_parser("config", help="MCP configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_command", help="Config commands")

    # config list
    config_subparsers.add_parser("list", help="List all MCP configurations")

    # config add
    config_add_parser = config_subparsers.add_parser("add", help="Add new MCP configuration")
    config_add_parser.add_argument("--config-name", required=True, help="Configuration name")

    # config copy
    config_copy_parser = config_subparsers.add_parser("copy", help="Copy MCP configuration")
    config_copy_parser.add_argument("--source-config", required=True, help="Source config name or ID")
    config_copy_parser.add_argument("--target-config", required=True, help="Target config name")

    # config rename
    config_rename_parser = config_subparsers.add_parser("rename", help="Rename MCP configuration")
    config_rename_parser.add_argument("--config-name", help="Current config name")
    config_rename_parser.add_argument("--config-id", help="Current config ID")
    config_rename_parser.add_argument("--new-name", required=True, help="New config name")

    # config list-projects
    config_list_projects_parser = config_subparsers.add_parser("list-projects", help="List projects using config")
    config_list_projects_parser.add_argument("--config-name", help="Configuration name")
    config_list_projects_parser.add_argument("--config-id", help="Configuration ID")

    # config list-servers
    config_list_servers_parser = config_subparsers.add_parser("list-servers", help="List servers in config")
    config_list_servers_parser.add_argument("--config-name", help="Configuration name")
    config_list_servers_parser.add_argument("--config-id", help="Configuration ID")

    # config get-server
    config_get_server_parser = config_subparsers.add_parser("get-server", help="Get server details")
    config_get_server_parser.add_argument("--config-name", help="Configuration name")
    config_get_server_parser.add_argument("--config-id", help="Configuration ID")
    config_get_server_parser.add_argument("--server-name", required=True, help="Server name")

    # config update-server
    config_update_server_parser = config_subparsers.add_parser("update-server", help="Update server configuration")
    config_update_server_parser.add_argument("--config-name", help="Configuration name")
    config_update_server_parser.add_argument("--config-id", help="Configuration ID")
    config_update_server_parser.add_argument("--server-name", required=True, help="Server name")
    config_update_server_parser.add_argument("--server-command", help="Server command")
    config_update_server_parser.add_argument("--args", nargs="*", help="Server arguments")
    config_update_server_parser.add_argument("--env", help="Environment variables (JSON)")
    config_update_server_parser.add_argument("--tools", help="Tools configuration (JSON)")
    config_update_server_parser.add_argument("--description", help="Server description")

    # config add-server
    config_add_server_parser = config_subparsers.add_parser("add-server", help="Add server to configuration")
    config_add_server_parser.add_argument("--config-name", help="Configuration name")
    config_add_server_parser.add_argument("--config-id", help="Configuration ID")
    config_add_server_parser.add_argument("--server-name", required=True, help="Server name")
    config_add_server_parser.add_argument("--server-command", required=True, help="Server command")
    config_add_server_parser.add_argument("--args", nargs="*", help="Server arguments")
    config_add_server_parser.add_argument("--env", help="Environment variables (JSON)")
    config_add_server_parser.add_argument("--tools", help="Tools configuration (JSON)")
    config_add_server_parser.add_argument("--description", default="", help="Server description")
    config_add_server_parser.add_argument("--input-guardrails-policy", help="Input guardrails policy (JSON)")
    config_add_server_parser.add_argument("--output-guardrails-policy", help="Output guardrails policy (JSON)")

    # config get
    config_get_parser = config_subparsers.add_parser("get", help="Get configuration")
    config_get_parser.add_argument("--config-name", help="Configuration name")
    config_get_parser.add_argument("--config-id", help="Configuration ID")

    # config remove-server
    config_remove_server_parser = config_subparsers.add_parser("remove-server", help="Remove server from configuration")
    config_remove_server_parser.add_argument("--config-name", help="Configuration name")
    config_remove_server_parser.add_argument("--config-id", help="Configuration ID")
    config_remove_server_parser.add_argument("--server-name", required=True, help="Server name to remove")

    # config remove-all-servers
    config_remove_all_servers_parser = config_subparsers.add_parser("remove-all-servers", help="Remove all servers from configuration")
    config_remove_all_servers_parser.add_argument("--config-name", help="Configuration name")
    config_remove_all_servers_parser.add_argument("--config-id", help="Configuration ID")

    # config remove
    config_remove_parser = config_subparsers.add_parser("remove", help="Remove configuration")
    config_remove_parser.add_argument("--config-name", help="Configuration name")
    config_remove_parser.add_argument("--config-id", help="Configuration ID")

    # config validate
    config_validate_parser = config_subparsers.add_parser("validate", help="Validate configuration")
    config_validate_parser.add_argument("--config-name", help="Configuration name")
    config_validate_parser.add_argument("--config-id", help="Configuration ID")

    # config export
    config_export_parser = config_subparsers.add_parser("export", help="Export configuration")
    config_export_parser.add_argument("--config-name", help="Configuration name")
    config_export_parser.add_argument("--config-id", help="Configuration ID")
    config_export_parser.add_argument("--output-file", required=True, help="Output file path")

    # config import
    config_import_parser = config_subparsers.add_parser("import", help="Import configuration")
    config_import_parser.add_argument("--input-file", required=True, help="Input file path")
    config_import_parser.add_argument("--config-name", required=True, help="Configuration name")

    # config search
    config_search_parser = config_subparsers.add_parser("search", help="Search configurations")
    config_search_parser.add_argument("--search-term", required=True, help="Search term")

    # config update-server-input-guardrails
    config_update_input_guardrails_parser = config_subparsers.add_parser("update-server-input-guardrails", help="Update server input guardrails policy")
    config_update_input_guardrails_parser.add_argument("--config-name", help="Configuration name")
    config_update_input_guardrails_parser.add_argument("--config-id", help="Configuration ID")
    config_update_input_guardrails_parser.add_argument("--server-name", required=True, help="Server name")
    config_update_input_guardrails_parser.add_argument("--policy-file", help="JSON file with policy configuration")
    config_update_input_guardrails_parser.add_argument("--policy", help="Policy configuration as JSON string")

    # config update-server-output-guardrails
    config_update_output_guardrails_parser = config_subparsers.add_parser("update-server-output-guardrails", help="Update server output guardrails policy")
    config_update_output_guardrails_parser.add_argument("--config-name", help="Configuration name")
    config_update_output_guardrails_parser.add_argument("--config-id", help="Configuration ID")
    config_update_output_guardrails_parser.add_argument("--server-name", required=True, help="Server name")
    config_update_output_guardrails_parser.add_argument("--policy-file", help="JSON file with policy configuration")
    config_update_output_guardrails_parser.add_argument("--policy", help="Policy configuration as JSON string")

    # config update-server-guardrails
    config_update_guardrails_parser = config_subparsers.add_parser("update-server-guardrails", help="Update server guardrails policies")
    config_update_guardrails_parser.add_argument("--config-name", help="Configuration name")
    config_update_guardrails_parser.add_argument("--config-id", help="Configuration ID")
    config_update_guardrails_parser.add_argument("--server-name", required=True, help="Server name")
    config_update_guardrails_parser.add_argument("--input-policy-file", help="JSON file with input policy configuration")
    config_update_guardrails_parser.add_argument("--input-policy", help="Input policy configuration as JSON string")
    config_update_guardrails_parser.add_argument("--output-policy-file", help="JSON file with output policy configuration")
    config_update_guardrails_parser.add_argument("--output-policy", help="Output policy configuration as JSON string")
    
    # =========================================================================
    # PROJECT COMMANDS
    # =========================================================================
    project_parser = subparsers.add_parser("project", help="Project management")
    project_subparsers = project_parser.add_subparsers(dest="project_command", help="Project commands")

    # project list
    project_subparsers.add_parser("list", help="List all projects")

    # project create
    project_create_parser = project_subparsers.add_parser("create", help="Create new project")
    project_create_parser.add_argument("--project-name", required=True, help="Project name")

    # project assign-config
    project_assign_config_parser = project_subparsers.add_parser("assign-config", help="Assign MCP config to project")
    project_assign_config_parser.add_argument("--project-name", help="Project name")
    project_assign_config_parser.add_argument("--project-id", help="Project ID")
    project_assign_config_parser.add_argument("--config-name", help="Configuration name")
    project_assign_config_parser.add_argument("--config-id", help="Configuration ID")

    # project unassign-config
    project_unassign_config_parser = project_subparsers.add_parser("unassign-config", help="Unassign MCP config from project")
    project_unassign_config_parser.add_argument("--project-name", help="Project name")
    project_unassign_config_parser.add_argument("--project-id", help="Project ID")

    # project get-config
    project_get_config_parser = project_subparsers.add_parser("get-config", help="Get config assigned to project")
    project_get_config_parser.add_argument("--project-name", help="Project name")
    project_get_config_parser.add_argument("--project-id", help="Project ID")

    # project list-users
    project_list_users_parser = project_subparsers.add_parser("list-users", help="List users in project")
    project_list_users_parser.add_argument("--project-name", help="Project name")
    project_list_users_parser.add_argument("--project-id", help="Project ID")

    # project add-user
    project_add_user_parser = project_subparsers.add_parser("add-user", help="Add user to project")
    project_add_user_parser.add_argument("--project-name", help="Project name")
    project_add_user_parser.add_argument("--project-id", help="Project ID")
    project_add_user_parser.add_argument("--user-id", help="User ID")
    project_add_user_parser.add_argument("--email", help="User email")

    # project remove-user
    project_remove_user_parser = project_subparsers.add_parser("remove-user", help="Remove user from project")
    project_remove_user_parser.add_argument("--project-name", help="Project name")
    project_remove_user_parser.add_argument("--project-id", help="Project ID")
    project_remove_user_parser.add_argument("--user-id", help="User ID")
    project_remove_user_parser.add_argument("--email", help="User email")

    # project remove-all-users
    project_remove_all_users_parser = project_subparsers.add_parser("remove-all-users", help="Remove all users from project")
    project_remove_all_users_parser.add_argument("--project-name", help="Project name")
    project_remove_all_users_parser.add_argument("--project-id", help="Project ID")

    # project get
    project_get_parser = project_subparsers.add_parser("get", help="Get project")
    project_get_parser.add_argument("--project-name", help="Project name")
    project_get_parser.add_argument("--project-id", help="Project ID")

    # project remove
    project_remove_parser = project_subparsers.add_parser("remove", help="Remove project")
    project_remove_parser.add_argument("--project-name", help="Project name")
    project_remove_parser.add_argument("--project-id", help="Project ID")

    # project export
    project_export_parser = project_subparsers.add_parser("export", help="Export project")
    project_export_parser.add_argument("--project-name", help="Project name")
    project_export_parser.add_argument("--project-id", help="Project ID")
    project_export_parser.add_argument("--output-file", required=True, help="Output file path")

    # project search
    project_search_parser = project_subparsers.add_parser("search", help="Search projects")
    project_search_parser.add_argument("--search-term", required=True, help="Search term")

    # =========================================================================
    # USER COMMANDS
    # =========================================================================
    user_parser = subparsers.add_parser("user", help="User management")
    user_subparsers = user_parser.add_subparsers(dest="user_command", help="User commands")

    # user list
    user_subparsers.add_parser("list", help="List all users")

    # user create
    user_create_parser = user_subparsers.add_parser("create", help="Create new user")
    user_create_parser.add_argument("--email", required=True, help="User email")

    # user update
    user_update_parser = user_subparsers.add_parser("update", help="Update user")
    user_update_parser.add_argument("--user-id", help="User ID")
    user_update_parser.add_argument("--email", help="Current email")
    user_update_parser.add_argument("--new-email", required=True, help="New email")

    # user get
    user_get_parser = user_subparsers.add_parser("get", help="Get user")
    user_get_parser.add_argument("--user-id", help="User ID")
    user_get_parser.add_argument("--email", help="User email")

    # user list-projects
    user_list_projects_parser = user_subparsers.add_parser("list-projects", help="List projects for user")
    user_list_projects_parser.add_argument("--user-id", help="User ID")
    user_list_projects_parser.add_argument("--email", help="User email")

    # user delete
    user_delete_parser = user_subparsers.add_parser("delete", help="Delete user")
    user_delete_parser.add_argument("--user-id", help="User ID")
    user_delete_parser.add_argument("--email", help="User email")
    user_delete_parser.add_argument("--force", action="store_true", help="Force delete with cleanup")

    # user generate-api-key
    user_api_key_parser = user_subparsers.add_parser("generate-api-key", help="Generate API key for user")
    user_api_key_parser.add_argument("--user-id", help="User ID")
    user_api_key_parser.add_argument("--email", help="User email")
    user_api_key_parser.add_argument("--project-name", help="Project name")
    user_api_key_parser.add_argument("--project-id", help="Project ID")

    # user rotate-api-key
    user_rotate_api_key_parser = user_subparsers.add_parser("rotate-api-key", help="Rotate API key")
    user_rotate_api_key_parser.add_argument("--api-key", required=True, help="API key to rotate")

    # user disable-api-key
    user_disable_api_key_parser = user_subparsers.add_parser("disable-api-key", help="Disable API key")
    user_disable_api_key_parser.add_argument("--api-key", required=True, help="API key to disable")

    # user enable-api-key
    user_enable_api_key_parser = user_subparsers.add_parser("enable-api-key", help="Enable API key")
    user_enable_api_key_parser.add_argument("--api-key", required=True, help="API key to enable")

    # user delete-api-key
    user_delete_api_key_parser = user_subparsers.add_parser("delete-api-key", help="Delete API key")
    user_delete_api_key_parser.add_argument("--api-key", required=True, help="API key to delete")

    # user delete-all-api-keys
    user_delete_all_api_keys_parser = user_subparsers.add_parser("delete-all-api-keys", help="Delete all API keys for user")
    user_delete_all_api_keys_parser.add_argument("--user-id", help="User ID")
    user_delete_all_api_keys_parser.add_argument("--email", help="User email")

    # user list-api-keys
    user_list_api_keys_parser = user_subparsers.add_parser("list-api-keys", help="List API keys for user")
    user_list_api_keys_parser.add_argument("--user-id", help="User ID")
    user_list_api_keys_parser.add_argument("--email", help="User email")
    user_list_api_keys_parser.add_argument("--project-name", help="Project name (optional)")
    user_list_api_keys_parser.add_argument("--project-id", help="Project ID (optional)")

    # user list-all-api-keys
    user_subparsers.add_parser("list-all-api-keys", help="List all API keys across all users")

    # user search
    user_search_parser = user_subparsers.add_parser("search", help="Search users")
    user_search_parser.add_argument("--search-term", required=True, help="Search term")

    # =========================================================================
    # SYSTEM COMMANDS
    # =========================================================================
    system_parser = subparsers.add_parser("system", help="System management")
    system_subparsers = system_parser.add_subparsers(dest="system_command", help="System commands")

    # system health-check
    system_subparsers.add_parser("health-check", help="Check system health")

    # system backup
    system_backup_parser = system_subparsers.add_parser("backup", help="Backup configuration")
    system_backup_parser.add_argument("--output-file", required=True, help="Output file path")

    # system restore
    system_restore_parser = system_subparsers.add_parser("restore", help="Restore configuration")
    system_restore_parser.add_argument("--input-file", required=True, help="Input file path")

    # system reset
    system_reset_parser = system_subparsers.add_parser("reset", help="Reset system configuration")
    system_reset_parser.add_argument("--confirm", action="store_true", help="Confirm reset operation")

    # =========================================================================
    # ARGUMENT PARSING
    # =========================================================================
    args = parser.parse_args()
    
    # Handle missing subcommands
    if args.command == "config" and not args.config_command:
        sys_print("Error: Please specify a config subcommand.", is_error=True)
        config_parser.print_help()
        sys.exit(1)

    if args.command == "project" and not args.project_command:
        sys_print("Error: Please specify a project subcommand.", is_error=True)
        project_parser.print_help()
        sys.exit(1)

    if args.command == "user" and not args.user_command:
        sys_print("Error: Please specify a user subcommand.", is_error=True)
        user_parser.print_help()
        sys.exit(1)

    if args.command == "system" and not args.system_command:
        sys_print("Error: Please specify a system subcommand.", is_error=True)
        system_parser.print_help()
        sys.exit(1)

    # =========================================================================
    # CONFIG COMMAND HANDLING
    # =========================================================================
    if args.command == "config":
        if args.config_command == "list":
            list_configs(PICKED_CONFIG_PATH)
        elif args.config_command == "add":
            add_config(PICKED_CONFIG_PATH, args.config_name)
        elif args.config_command == "copy":
            copy_config(PICKED_CONFIG_PATH, args.source_config, args.target_config)
        elif args.config_command == "rename":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            rename_config(PICKED_CONFIG_PATH, config_identifier, args.new_name)
        elif args.config_command == "list-projects":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            list_config_projects(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "list-servers":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            list_config_servers(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "get-server":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            get_config_server(PICKED_CONFIG_PATH, config_identifier, args.server_name)
        elif args.config_command == "update-server":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            update_config_server(PICKED_CONFIG_PATH, config_identifier, args.server_name, 
                            args.server_command, args.args, args.env, args.tools, args.description)  # Changed from args.command to args.server_command
        elif args.config_command == "add-server":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            add_server_to_config(PICKED_CONFIG_PATH, config_identifier, args.server_name, 
                            args.server_command, args.args, args.env, args.tools, args.description,  # Changed from args.command to args.server_command
                            args.input_guardrails_policy, args.output_guardrails_policy)
        elif args.config_command == "get":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            get_config(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "remove-server":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            remove_server_from_config(PICKED_CONFIG_PATH, config_identifier, args.server_name)
        elif args.config_command == "remove-all-servers":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            remove_all_servers_from_config(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "remove":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            remove_config(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "validate":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            validate_config(PICKED_CONFIG_PATH, config_identifier)
        elif args.config_command == "export":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            export_config(PICKED_CONFIG_PATH, config_identifier, args.output_file)
        elif args.config_command == "import":
            import_config(PICKED_CONFIG_PATH, args.input_file, args.config_name)
        elif args.config_command == "search":
            search_configs(PICKED_CONFIG_PATH, args.search_term)
        elif args.config_command == "update-server-input-guardrails":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            update_server_input_guardrails(PICKED_CONFIG_PATH, config_identifier, args.server_name, 
                                        args.policy_file, args.policy)

        elif args.config_command == "update-server-output-guardrails":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            update_server_output_guardrails(PICKED_CONFIG_PATH, config_identifier, args.server_name, 
                                        args.policy_file, args.policy)

        elif args.config_command == "update-server-guardrails":
            config_identifier = args.config_name or args.config_id
            if not config_identifier:
                sys_print("Error: Either --config-name or --config-id is required", is_error=True)
                sys.exit(1)
            update_server_guardrails(PICKED_CONFIG_PATH, config_identifier, args.server_name,
                                args.input_policy_file, args.input_policy,
                                args.output_policy_file, args.output_policy)
        
        sys.exit(0)

    # =========================================================================
    # PROJECT COMMAND HANDLING
    # =========================================================================
    elif args.command == "project":
        if args.project_command == "list":
            list_projects(PICKED_CONFIG_PATH)
        elif args.project_command == "create":
            create_project(PICKED_CONFIG_PATH, args.project_name)
        elif args.project_command == "assign-config":
            project_identifier = args.project_name or args.project_id
            config_identifier = args.config_name or args.config_id
            if not project_identifier or not config_identifier:
                sys_print("Error: Project and config identifiers are required", is_error=True)
                sys.exit(1)
            assign_config_to_project(PICKED_CONFIG_PATH, project_identifier, config_identifier)
        elif args.project_command == "unassign-config":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            unassign_config_from_project(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "get-config":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            get_project_config(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "list-users":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            list_project_users(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "add-user":
            project_identifier = args.project_name or args.project_id
            user_identifier = args.user_id or args.email
            if not project_identifier or not user_identifier:
                sys_print("Error: Project and user identifiers are required", is_error=True)
                sys.exit(1)
            add_user_to_project(PICKED_CONFIG_PATH, project_identifier, user_identifier)
        elif args.project_command == "remove-user":
            project_identifier = args.project_name or args.project_id
            user_identifier = args.user_id or args.email
            if not project_identifier or not user_identifier:
                sys_print("Error: Project and user identifiers are required", is_error=True)
                sys.exit(1)
            remove_user_from_project(PICKED_CONFIG_PATH, project_identifier, user_identifier)
        elif args.project_command == "remove-all-users":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            remove_all_users_from_project(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "get":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            get_project(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "remove":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            remove_project(PICKED_CONFIG_PATH, project_identifier)
        elif args.project_command == "export":
            project_identifier = args.project_name or args.project_id
            if not project_identifier:
                sys_print("Error: Either --project-name or --project-id is required", is_error=True)
                sys.exit(1)
            export_project(PICKED_CONFIG_PATH, project_identifier, args.output_file)
        elif args.project_command == "search":
            search_projects(PICKED_CONFIG_PATH, args.search_term)
        sys.exit(0)

    # =========================================================================
    # USER COMMAND HANDLING
    # =========================================================================
    elif args.command == "user":
        if args.user_command == "list":
            list_users(PICKED_CONFIG_PATH)
        elif args.user_command == "create":
            create_user(PICKED_CONFIG_PATH, args.email)
        elif args.user_command == "update":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            update_user(PICKED_CONFIG_PATH, user_identifier, args.new_email)
        elif args.user_command == "get":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            get_user(PICKED_CONFIG_PATH, user_identifier)
        elif args.user_command == "list-projects":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            list_user_projects(PICKED_CONFIG_PATH, user_identifier)
        elif args.user_command == "delete":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            delete_user(PICKED_CONFIG_PATH, user_identifier, args.force)
        elif args.user_command == "generate-api-key":
            user_identifier = args.user_id or args.email
            project_identifier = args.project_name or args.project_id
            if not user_identifier or not project_identifier:
                sys_print("Error: User and project identifiers are required", is_error=True)
                sys.exit(1)
            generate_user_api_key(PICKED_CONFIG_PATH, user_identifier, project_identifier)
        elif args.user_command == "rotate-api-key":
            rotate_user_api_key(PICKED_CONFIG_PATH, args.api_key)
        elif args.user_command == "disable-api-key":
            disable_user_api_key(PICKED_CONFIG_PATH, args.api_key)
        elif args.user_command == "enable-api-key":
            enable_user_api_key(PICKED_CONFIG_PATH, args.api_key)
        elif args.user_command == "delete-api-key":
            delete_user_api_key(PICKED_CONFIG_PATH, args.api_key)
        elif args.user_command == "delete-all-api-keys":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            delete_all_user_api_keys(PICKED_CONFIG_PATH, user_identifier)
        elif args.user_command == "list-api-keys":
            user_identifier = args.user_id or args.email
            if not user_identifier:
                sys_print("Error: Either --user-id or --email is required", is_error=True)
                sys.exit(1)
            project_identifier = args.project_name or args.project_id
            list_user_api_keys(PICKED_CONFIG_PATH, user_identifier, project_identifier)
        elif args.user_command == "list-all-api-keys":
            list_all_api_keys(PICKED_CONFIG_PATH)
        elif args.user_command == "search":
            search_users(PICKED_CONFIG_PATH, args.search_term)
        sys.exit(0)

    # =========================================================================
    # SYSTEM COMMAND HANDLING
    # =========================================================================
    elif args.command == "system":
        if args.system_command == "health-check":
            system_health_check(PICKED_CONFIG_PATH)
        elif args.system_command == "backup":
            system_backup(PICKED_CONFIG_PATH, args.output_file)
        elif args.system_command == "restore":
            system_restore(PICKED_CONFIG_PATH, args.input_file)
        elif args.system_command == "reset":
            system_reset(PICKED_CONFIG_PATH, args.confirm)
        sys.exit(0)

    # =========================================================================
    # ORIGINAL COMMAND HANDLING
    # =========================================================================
    elif args.command == "generate-config":
        if os.path.exists(PICKED_CONFIG_PATH):
            sys_print(f"Config file already exists at {PICKED_CONFIG_PATH}.", is_error=True)
            sys_print("Not overwriting. Please run install to install on Claude Desktop or Cursor.", is_error=True)
            sys_print("If you want to start fresh, delete the config file and run again.", is_error=True)
            sys.exit(1)
        
        os.makedirs(os.path.dirname(PICKED_CONFIG_PATH), exist_ok=True)
        if os.name == 'posix':
            os.chmod(os.path.dirname(PICKED_CONFIG_PATH), 0o700)
        
        config = generate_default_config()
        with open(PICKED_CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        
        sys_print(f"Generated default config at {PICKED_CONFIG_PATH}")
        sys.exit(0)

    elif args.command == "install":
        credentials = get_gateway_credentials(PICKED_CONFIG_PATH)
        gateway_key = credentials.get("gateway_key")
        project_id = credentials.get("project_id")
        user_id = credentials.get("user_id")
        
        if not gateway_key:
            sys_print(f"Gateway key not found in {PICKED_CONFIG_PATH}. Please generate a new config file using 'generate-config' subcommand and try again.", is_error=True)
            sys.exit(1)

        env = {
            "ENKRYPT_GATEWAY_KEY": gateway_key,
            "ENKRYPT_PROJECT_ID": project_id,
            "ENKRYPT_USER_ID": user_id
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
                    "--env-var", f"ENKRYPT_GATEWAY_KEY={gateway_key}",
                    "--env-var", f"ENKRYPT_PROJECT_ID={project_id}",
                    "--env-var", f"ENKRYPT_USER_ID={user_id}"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    sys_print(f"Error installing gateway: {result.stderr}", is_error=True)
                    sys.exit(1)
                else:
                    sys_print(f"Successfully installed gateway for {client}")
                    
                    # Check and fix path
                    if sys.platform == "darwin":
                        claude_desktop_config_path = os.path.join(HOME_DIR, "Library", "Application Support", "Claude", "claude_desktop_config.json")
                    elif sys.platform == "win32":
                        appdata = os.environ.get("APPDATA")
                        if appdata:
                            claude_desktop_config_path = os.path.join(appdata, "Claude", "claude_desktop_config.json")
                        else:
                            claude_desktop_config_path = None
                    else:
                        claude_desktop_config_path = os.path.join(HOME_DIR, ".claude", "claude_desktop_config.json")

                    if os.path.exists(claude_desktop_config_path):
                        try:
                            with open(claude_desktop_config_path, "r") as f:
                                claude_desktop_config = json.load(f)
                                if ("mcpServers" in claude_desktop_config and 
                                    "Enkrypt Secure MCP Gateway" in claude_desktop_config["mcpServers"]):
                                    args_list = claude_desktop_config["mcpServers"]["Enkrypt Secure MCP Gateway"].get("args", [])
                                    if args_list and args_list[-1] != GATEWAY_PY_PATH:
                                        args_list[-1] = GATEWAY_PY_PATH
                                    with open(claude_desktop_config_path, "w") as f:
                                        json.dump(claude_desktop_config, f, indent=2)
                                    sys_print("Path to gateway corrected in claude_desktop_config.json")
                        except Exception as e:
                            sys_print(f"Warning: Could not verify/fix gateway path: {e}", is_error=True)
                sys_print("Please restart Claude Desktop to use the gateway.")
                sys.exit(0)

        elif args.client.lower() == "cursor":
            base_path = '/app' if is_docker_running else HOME_DIR
            cursor_config_path = os.path.join(base_path, '.cursor', 'mcp.json')

            if is_docker_running:
                args_list = DOCKER_ARGS
                command = DOCKER_COMMAND
            else:
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
        sys_print(f"Invalid command: {args.command}. Please use 'generate-config', 'install', 'config', 'project', 'user', or 'system'.", is_error=True)
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
