@echo off
setlocal enabledelayedexpansion

@REM -------------------------------------------------------------
@REM Not using the script for installation of dependencies
@REM -------------------------------------------------------------

@REM REM Check for admin privileges
@REM net session >nul 2>&1
@REM if errorlevel 1 (
@REM     echo This script requires administrator privileges to install packages system-wide.
@REM     echo Please right-click on the script and select "Run as administrator"
@REM     exit /b 1
@REM )

@REM echo Checking if Python, pip and uv are installed ...

@REM set "PYTHON_CMD=python"
@REM echo Checking if Python is installed with command: %PYTHON_CMD%
@REM %PYTHON_CMD% --version 2>nul
@REM if errorlevel 1 (
@REM     set "PYTHON_CMD=python3"
@REM     echo Python is not installed with command: python. Trying with %PYTHON_CMD%
@REM     %PYTHON_CMD% --version 2>nul
@REM     if errorlevel 1 (
@REM         echo Python is not installed. Please install Python 3.11 or higher and try again.
@REM         exit /b 1
@REM     )
@REM )
@REM echo Python is installed and command is: %PYTHON_CMD%

@REM set "PIP_CMD=pip"
@REM echo Checking if pip is installed with command: %PIP_CMD%. Running ensurepip
@REM %PYTHON_CMD% -m ensurepip
@REM %PIP_CMD% --version 2>nul
@REM if errorlevel 1 (
@REM     set "PIP_CMD=%PYTHON_CMD% -m pip"
@REM     echo pip is not installed with command: pip. Trying with %PIP_CMD%
@REM     %PIP_CMD% --version 2>nul
@REM     if errorlevel 1 (
@REM         echo pip is not installed. Please install pip and try again.
@REM         exit /b 1
@REM     )
@REM )
@REM echo pip is installed with command: %PIP_CMD%

@REM set "UV_CMD=uv"
@REM echo Checking if uv is installed with command: %UV_CMD%
@REM %UV_CMD% --version 2>nul
@REM if errorlevel 1 (
@REM     echo "PYTHON_CMD: %PYTHON_CMD%"
@REM     echo "Setting UV_CMD to %PYTHON_CMD% -m uv"
@REM     set "UV_CMD=%PYTHON_CMD% -m uv"
@REM     @REM Make sure UV_CMD is not equal to uv
@REM     if "!UV_CMD!"=="uv" (
@REM         echo Unexpected error. uv command is still uv. Not python -m uv.
@REM         exit /b 1
@REM     )
@REM     echo uv is not installed with command: uv. Trying with !UV_CMD!
@REM     !UV_CMD! --version 2>nul
@REM     if errorlevel 1 (
@REM         echo uv is not installed. Attempting to install uv using %PIP_CMD% install uv
@REM         %PIP_CMD% install uv
@REM         REM Retry checking uv version
@REM         set "UV_CMD=%PYTHON_CMD% -m uv"
@REM         !UV_CMD! --version 2>nul
@REM         if errorlevel 1 (
@REM             echo Failed to install uv. Please install uv and try again.
@REM             exit /b 1
@REM         )
@REM     )
@REM )
@REM echo uv is installed with command: %UV_CMD%

@REM REM Install dependencies
@REM echo Installing dependencies ...
@REM %UV_CMD% pip install -r requirements.txt
@REM if errorlevel 1 (
@REM     echo Failed to install dependencies. Please make sure you are running as administrator.
@REM     exit /b 1
@REM )

@REM echo Dependencies installed

echo -------------------------------
echo Setting up Enkrypt Secure MCP Gateway enkrypt_mcp_config.json config file
echo -------------------------------

:: Get absolute path of this script dir
set "SCRIPT_DIR=%~dp0"

set "example_enkrypt_mcp_config_file=example_enkrypt_mcp_config.json"
set "enkrypt_mcp_config_file=enkrypt_mcp_config.json"

:: Change to parent directory
cd /d "%SCRIPT_DIR%\.."

@REM Change to ~\.enkrypt directory
cd /d "%USERPROFILE%\.enkrypt"

if exist "%enkrypt_mcp_config_file%" (
    echo enkrypt_mcp_config.json file already exists. You may have configured it already. If not, please remove it and run the setup script again.
    echo Exiting...
    exit /b 1
)

:: Copy example config
copy "%SCRIPT_DIR%\..\src\secure_mcp_gateway\%example_enkrypt_mcp_config_file%" "%enkrypt_mcp_config_file%"

:: Generate unique gateway key (using PowerShell for secure random generation)
for /f "delims=" %%a in ('powershell -Command "$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider; $bytes = New-Object byte[] 48; $rng.GetBytes($bytes); $key = [Convert]::ToBase64String($bytes); $key.Replace('+','_').Replace('/','_').Replace('=','')"') do set "unique_gateway_key=%%a"

echo Generated unique gateway key: %unique_gateway_key%

REM Replace UNIQUE_GATEWAY_KEY in enkrypt_mcp_config.json
powershell -Command "(Get-Content '%enkrypt_mcp_config_file%') -replace 'UNIQUE_GATEWAY_KEY', '%unique_gateway_key%' | Set-Content '%enkrypt_mcp_config_file%'"

REM Generate unique uuid using PowerShell
for /f "delims=" %%a in ('powershell -Command "[guid]::NewGuid().ToString()"') do set "unique_uuid=%%a"

echo Generated unique uuid: %unique_uuid%

REM Replace UNIQUE_UUID in enkrypt_mcp_config.json
powershell -Command "(Get-Content '%enkrypt_mcp_config_file%') -replace 'UNIQUE_UUID', '%unique_uuid%' | Set-Content '%enkrypt_mcp_config_file%'"

:: Get dummy MCP path inside src/secure_mcp_gateway
pushd "%SCRIPT_DIR%\..\src\secure_mcp_gateway\bad_mcps"
set "DUMMY_MCP_DIR=%CD%"
set "DUMMY_MCP_FILE_PATH=%DUMMY_MCP_DIR%\echo_mcp.py"
popd

:: Convert any remaining forward slashes to backslashes
set "DUMMY_MCP_FILE_PATH=%DUMMY_MCP_FILE_PATH:/=\%"
:: Escape backslashes for PowerShell -replace
set "DUMMY_MCP_FILE_PATH_ESCAPED=%DUMMY_MCP_FILE_PATH:\=\\%"
echo DUMMY_MCP_FILE_PATH: %DUMMY_MCP_FILE_PATH%

:: Replace DUMMY_ECHO_MCP_FILE_PATH in config file
powershell -Command "(Get-Content '%enkrypt_mcp_config_file%') -replace 'DUMMY_ECHO_MCP_FILE_PATH', '%DUMMY_MCP_FILE_PATH_ESCAPED%' | Set-Content '%enkrypt_mcp_config_file%'"

echo -------------------------------
echo Setup complete. Please check the enkrypt_mcp_config.json file in the ~\.enkrypt directory and update with your MCP server configs as needed.
echo -------------------------------

endlocal

REM Parse --install argument (default true)
set INSTALL=true
:parse_args
if "%~1"=="" goto after_args
if "%~1"=="--install" (
    set INSTALL=%~2
    shift
    shift
    goto parse_args
)
for /f "tokens=1,2 delims==" %%A in ("%~1") do (
    if "%%A"=="--install" set INSTALL=%%B
)
shift
goto parse_args
:after_args

REM Run the install script if INSTALL is true
if /i "%INSTALL%"=="true" call "%SCRIPT_DIR%install.bat"
