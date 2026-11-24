@echo off
setlocal
cd /d "%~dp0"
title PHP-WebVPN Client

REM Verify Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not found in PATH!
    echo Please download and install Python 3 from https://python.org
    echo Make sure to check "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

REM Verify and install required Python packages
python -c "import cryptography, requests, colorama" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing required Python packages...
    pip install -r requirements.txt --quiet
)

REM Launch PHP-WebVPN Client
python proxy_client.py %*

if errorlevel 1 (
    echo.
    echo [!] Client exited with error code %errorlevel%.
    pause
)
