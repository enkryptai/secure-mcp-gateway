#! /bin/bash

# --------------------------------------------------------------
# Not using the script for installation of dependencies
# --------------------------------------------------------------

# echo "Checking if Python, pip and uv are installed ..."

# PYTHON_CMD="python"
# echo "Checking if Python is installed with command: $PYTHON_CMD"
# $PYTHON_CMD --version
# if [ $? -ne 0 ]; then
#   PYTHON_CMD="python3"
#   echo "Python is not installed with command: python. Trying with $PYTHON_CMD"
#   $PYTHON_CMD --version
#   if [ $? -ne 0 ]; then
#     echo "❌ Python is not installed. Please install Python 3.11 or higher and try again."
#     exit 1
#   fi
# fi
# echo "✅ Python is installed and command is: $PYTHON_CMD"

# PIP_CMD="pip"
# echo "Checking if pip is installed with command: $PIP_CMD. Running ensurepip"
# $PYTHON_CMD -m ensurepip
# $PIP_CMD --version
# if [ $? -ne 0 ]; then
#   PIP_CMD="$PYTHON_CMD -m pip"
#   echo "pip is not installed with command: pip. Trying with $PIP_CMD"
#   $PIP_CMD --version
#   if [ $? -ne 0 ]; then
#     echo "❌ pip is not installed. Please install pip and try again."
#     exit 1
#   fi
# fi
# echo "✅ pip is installed with command: $PIP_CMD"

# UV_CMD="uv"
# echo "Checking if uv is installed with command: $UV_CMD"
# $UV_CMD --version
# if [ $? -ne 0 ]; then
#   UV_CMD="$PYTHON_CMD -m uv"
#   echo "uv is not installed with command: uv. Trying with $UV_CMD"
#   $UV_CMD --version
#   if [ $? -ne 0 ]; then
#     echo "uv is not installed. Attempting to install uv using $PIP_CMD install uv"
#     $PIP_CMD install uv
#     # sudo apt install python3-uv
#     # Retry checking uv
#     $UV_CMD --version
#     if [ $? -ne 0 ]; then
#       echo "❌ Failed to install uv. Please install uv and try again."
#       exit 1
#     fi
#   fi
# fi
# echo "✅ uv is installed with command: $UV_CMD"

# # Install dependencies
# echo "Installing dependencies ..."
# $UV_CMD pip install -r requirements.txt

# if [ $? -ne 0 ]; then
#   echo "❌ Failed to install dependencies. Please install the dependencies and try again."
#   exit 1
# fi

# echo "✅ Dependencies installed"

# --------------------------------------------------------------

echo -------------------------------
echo "Setting up Enkrypt Secure MCP Gateway enkrypt_mcp_config.json config file"
echo -------------------------------

# Get absolute path of this script dir
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

example_enkrypt_mcp_config_file="example_enkrypt_mcp_config.json"
enkrypt_mcp_config_file="enkrypt_mcp_config.json"

cd $SCRIPT_DIR/..

if [ -f "$enkrypt_mcp_config_file" ]; then
  echo "enkrypt_mcp_config.json file already exists. You may have configured it already. If not, please remove it and run the setup script again."
  echo "❌ Exiting..."
  exit 1
fi

cp $example_enkrypt_mcp_config_file $enkrypt_mcp_config_file

# Generate unique gateway key
unique_gateway_key=$(openssl rand -base64 64 | tr -d '\n' | tr '+/-' '_' | tr -d '=')

echo "✅ Generated unique gateway key: $unique_gateway_key"

# Replace UNIQUE_GATEWAY_KEY in enkrypt_mcp_config.json with the unique gateway key
perl -pi -e "s/UNIQUE_GATEWAY_KEY/$unique_gateway_key/g" $enkrypt_mcp_config_file

# Generate unique uuid
unique_uuid=$(uuidgen)

echo "✅ Generated unique uuid: $unique_uuid"

# Replace UNIQUE_UUID in enkrypt_mcp_config.json with the unique uuid
perl -pi -e "s/UNIQUE_UUID/$unique_uuid/g" $enkrypt_mcp_config_file

cd test_mcps
export DUMMY_MCP_DIR=$(pwd)
export DUMMY_MCP_FILE_PATH="$DUMMY_MCP_DIR/echo_mcp.py"

cd ..
echo "DUMMY_MCP_FILE_PATH: $DUMMY_MCP_FILE_PATH"

# Escape forward slashes for Perl replacement
DUMMY_MCP_FILE_PATH_ESCAPED=$(echo "$DUMMY_MCP_FILE_PATH" | sed 's/\//\\\//g')
perl -pi -e "s/DUMMY_ECHO_MCP_FILE_PATH/$DUMMY_MCP_FILE_PATH_ESCAPED/g" $enkrypt_mcp_config_file

echo -------------------------------
echo "✅ Setup complete. Please check the enkrypt_mcp_config.json file in the root directory and update with your MCP server configs as needed."
echo -------------------------------

# Run the install script
cd $SCRIPT_DIR
./install.sh
