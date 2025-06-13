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

:: Process requirements.txt and create dependencies string
:: First, create a temporary file without comments and empty lines
type %SCRIPT_DIR%\..\%requirements_file% | findstr /v "^#" | findstr /v "^$" > temp_req.txt

:: Initialize empty strings
set "DEPENDENCIES="
set "DEPENDENCIES_STRING="

:: Read each line from temp file and build the dependencies
for /f "usebackq tokens=1 delims==> " %%a in ("temp_req.txt") do (
    set "dep=%%a"
    :: Special handling for mcp[cli]
    echo !dep! | findstr /i "mcp" >nul
    if !errorlevel! equ 0 (
        set "dep=mcp[cli]"
    )
    :: Skip uvloop on Windows
    echo !dep! | findstr /i "uvloop" >nul
    if !errorlevel! equ 0 (
        echo Skipping uvloop as it is not supported on Windows
    ) else (
        if defined DEPENDENCIES (
            set "DEPENDENCIES=!DEPENDENCIES! !dep!"
        ) else (
            set "DEPENDENCIES=!dep!"
        )
    )
)

:: Delete temporary file
del temp_req.txt

echo Package names only: %DEPENDENCIES%

:: Create the --with string for each dependency
for %%a in (%DEPENDENCIES%) do (
    if defined DEPENDENCIES_STRING (
        set "DEPENDENCIES_STRING=!DEPENDENCIES_STRING! --with %%a"
    ) else (
        set "DEPENDENCIES_STRING=--with %%a"
    )
)

echo Dependencies string for the cli install command: %DEPENDENCIES_STRING%

cd %SCRIPT_DIR%\..\src\secure_mcp_gateway

set "CLI_CMD=mcp install gateway.py --env-var ENKRYPT_GATEWAY_KEY=%ENKRYPT_GATEWAY_KEY% %DEPENDENCIES_STRING%"

echo Running the cli install command: %CLI_CMD%

%CLI_CMD%
if errorlevel 1 (
    echo Installation failed
    exit /b 1
)

echo -------------------------------
echo Installation complete. Check the claude_desktop_config.json file as per the readme instructions and restart Claude Desktop.
echo -------------------------------
