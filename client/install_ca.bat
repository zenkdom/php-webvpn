@echo off
setlocal
cd /d "%~dp0"
title Install Root CA Certificate - PHP-WebVPN

python proxy_client.py --install-ca
echo.
pause
