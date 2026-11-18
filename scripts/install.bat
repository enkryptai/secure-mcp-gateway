@echo off
setlocal enabledelayedexpansion

echo -------------------------------
echo Installing Enkrypt Secure MCP Gateway with gateway key and dependencies
echo -------------------------------

@REM Check if mcp is installed by running mcp --version
mcp version >nul 2>&1
if errorlevel 1 (
    echo mcp could not be found. Please install it first.
    exit /b 1
)

echo mcp is installed. Proceeding with installation...

:: Get the script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%\.."

set "config_file=enkrypt_mcp_config.json"

@REM Change to ~\.enkrypt directory
cd /d "%USERPROFILE%\.enkrypt"

:: Check if config file exists
if not exist "%config_file%" (
    echo %config_file% file does not exist. Please run the setup script first.
    exit /b 1
)

:: Get the gateway key using powershell to parse JSON
powershell -Command "$json = Get-Content '%config_file%' -Raw | ConvertFrom-Json; $keys = @($json.gateways.PSObject.Properties.Name); [System.IO.File]::WriteAllText('temp_key.txt', $keys[0])"
set /p ENKRYPT_GATEWAY_KEY=<temp_key.txt
del temp_key.txt

echo ENKRYPT_GATEWAY_KEY: %ENKRYPT_GATEWAY_KEY%

cd /d %SCRIPT_DIR%\..\src\secure_mcp_gateway

echo Installing the gateway from %SCRIPT_DIR%\..

mcp install gateway.py --with-editable "%SCRIPT_DIR%\.." --env-var ENKRYPT_GATEWAY_KEY=%ENKRYPT_GATEWAY_KEY%
if errorlevel 1 (
    echo Installation failed
    exit /b 1
)

echo -------------------------------
echo Installation complete. Check the claude_desktop_config.json file as per the readme instructions and restart Claude Desktop.
echo -------------------------------
