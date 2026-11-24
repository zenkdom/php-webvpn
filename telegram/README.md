# ✈️ Telegram Multi-Protocol Proxy Server (MTProto + SOCKS5 + HTTP)

Universal local and edge proxy server specifically optimized for Telegram (Desktop, Android, iOS), tunneling MTProto and SOCKS5 traffic across a distributed pool of PHP web backends (`proxy.php`) with Connection Affinity and IPv6 translation.

---

## ⚡ Supported Protocols

1. **MTProto Proxy (Port `8443`)** — **RECOMMENDED FOR MOBILE (ANDROID & IOS)**
   - Telegram's native obfuscated protocol with 32-character secret key encryption.
   - Connects in **1 click** via `tg://proxy?...` link.
   - Shows active ping and blue shield icon in the Telegram app.
2. **SOCKS5 Proxy (Port `1080`)**
   - Full support for **Obfuscated2 (transport-level obfuscation)** used by official Telegram apps.
   - Support for Plain Abridged and Intermediate framing protocols.
3. **HTTP / Web Tunnel (Port `1080`)**
   - Supports `CONNECT` tunneling for general web traffic through your PHP backend.

---

## 🚀 Quick Start

### Windows:
Double-click:
```cmd
run.bat
```

### Linux / macOS / Android (Termux):
```bash
chmod +x run.sh
./run.sh
```
Or run directly:
```bash
python3 socks_server.py
```

### Linux Background Daemon (Systemd):
```bash
sudo ./install_service.sh
```
Management commands:
```bash
systemctl status tgproxy   # Status
journalctl -u tgproxy -f   # Live logs
systemctl restart tgproxy  # Restart
systemctl stop tgproxy     # Stop
```

---

## ⚙️ Configuration (`config.json`)

```json
{
  "server_urls": [
    "https://your-domain.com/proxy.php"
  ],
  "secret_key": "ChangeThisSecretKey",
  "listen_host": "0.0.0.0",
  "socks_port": 1080,
  "mtproto_port": 8443,
  "mtproto_secret": "d41d8cd98f00b204e9800998ecf8427e",
  "auth_username": "",
  "auth_password": "",
  "timeout": 35,
  "verify_ssl": false
}
```

---

## 📱 Telegram One-Click Connection Links

When the server starts, it prints one-click connection links:
- **MTProto (Android / iOS / Desktop):**
  ```text
  tg://proxy?server=<YOUR_SERVER_IP>&port=8443&secret=d41d8cd98f00b204e9800998ecf8427e
  ```
- **SOCKS5 (Android / iOS / Desktop):**
  ```text
  tg://socks?server=<YOUR_SERVER_IP>&port=1080
  ```
