#!/usr/bin/env bash
# ==============================================================================
# Telegram Multi-Proxy Systemd Service Installer
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root (or use sudo)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="tgproxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "[*] Creating systemd service for ${SCRIPT_DIR}..."

PYTHON_BIN="$(which python3 2>/dev/null || echo /usr/bin/python3)"

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Telegram Multi-Protocol Proxy Server (MTProto + SOCKS5)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYTHON_BIN} -u ${SCRIPT_DIR}/socks_server.py
Restart=always
RestartSec=3
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo "[*] Enabling service to start on boot..."
systemctl enable "$SERVICE_NAME"

echo "[*] Starting service..."
systemctl restart "$SERVICE_NAME"

echo ""
echo "================================================================================"
echo "✅ Service ${SERVICE_NAME} installed and enabled on boot successfully!"
echo "================================================================================"
echo "  • Check status : systemctl status ${SERVICE_NAME}"
echo "  • View logs    : journalctl -u ${SERVICE_NAME} -f"
echo "  • Restart      : systemctl restart ${SERVICE_NAME}"
echo "  • Stop         : systemctl stop ${SERVICE_NAME}"
echo "================================================================================"
