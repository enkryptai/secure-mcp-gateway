#! /bin/bash

echo -------------------------------
echo "Installing Enkrypt Secure MCP Gateway with gateway key and dependencies"
echo -------------------------------

# Check if mcp is installed using mcp version command
mcp version >nul 2>&1
if [ $? -ne 0 ]; then
    echo "mcp could not be found. Please install it first."
    exit 1
fi

echo "mcp is installed. Proceeding with installation..."

# Get absolute path of this script dir
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd $SCRIPT_DIR/..

config_file="enkrypt_mcp_config.json"

# Change to ~\.enkrypt directory
cd $HOME/.enkrypt

# Check if enkrypt_mcp_config.json exists
if [ ! -f "$config_file" ]; then
    echo "$config_file file does not exist. Please run the setup script first."
    exit 1
fi

ENKRYPT_GATEWAY_KEY=$(cat $config_file | jq -r '.gateways | keys[0]')

echo "ENKRYPT_GATEWAY_KEY: $ENKRYPT_GATEWAY_KEY"

# Get array of dependencies from requirements.txt, preserving package names
DEPENDENCIES=$(cat $SCRIPT_DIR/../requirements.txt | grep -v '^#' | grep -v '^$' | sed 's/;.*$//' | sed 's/>.*$//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '\n' ' ' | sed 's/[[:space:]]*$//')

echo "Dependencies list: $DEPENDENCIES"

# https://pypi.org/project/mcp/
# Convert dependencies into --with format, handling each package separately
DEPENDENCIES_STRING=$(echo "$DEPENDENCIES" | sed 's/[[:space:]]\+/ --with /g' | sed 's/^/--with /')

echo "Dependencies string for the cli install command: $DEPENDENCIES_STRING"

cd $SCRIPT_DIR/../src/secure_mcp_gateway

CLI_CMD="mcp install gateway.py --env-var ENKRYPT_GATEWAY_KEY=$ENKRYPT_GATEWAY_KEY $DEPENDENCIES_STRING"

echo "Running the cli install command: $CLI_CMD"

$CLI_CMD
if [ $? -ne 0 ]; then
    echo "Installation failed"
    exit 1
fi

echo -------------------------------
echo "✅ Installation complete. Check the claude_desktop_config.json file as per the readme instructions and restart Claude Desktop."
echo -------------------------------
