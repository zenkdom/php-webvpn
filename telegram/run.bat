@echo off
setlocal
cd /d "%~dp0"
title Telegram SOCKS5 Proxy Server

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not found in PATH!
    echo Please install Python 3 from https://python.org and check "Add python.exe to PATH".
    pause
    exit /b 1
)

REM Check required dependencies
python -c "import requests, cryptography, colorama, urllib3" >nul 2>&1
if errorlevel 1 (
    echo [*] Checking dependencies...
    python -m pip --version >nul 2>&1
    if errorlevel 1 (
        echo [*] pip not found. Bootstrapping pip via ensurepip...
        python -m ensurepip --upgrade >nul 2>&1
    )
    echo [*] Installing required packages...
    python -m pip install -r requirements.txt
)

REM Run Telegram SOCKS5 Proxy Server
python socks_server.py %*

if errorlevel 1 (
    echo.
    echo [!] Server exited with error.
    pause
)
