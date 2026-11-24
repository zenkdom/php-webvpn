@echo off
setlocal
cd /d "%~dp0"
title Remove Root CA Certificate - PHP-WebVPN

python proxy_client.py --remove-ca
echo.
pause
