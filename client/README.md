# 💻 PHP-WebVPN Client (Windows & Cross-Platform)

Local proxy tunnel and system VPN switcher for Windows and other desktop environments. Routes all browser and system HTTP/HTTPS requests through your remote PHP backend without requiring third-party VPN software.

---

## 📁 Files Included

- **`proxy_client.py`** — Main client application and local HTTP/HTTPS MITM proxy server.
- **`config.json`** — Local configuration (backend URL pool, secret key, port, auto-proxy toggles).
- **`config.example.json`** — Example configuration template.
- **`cert_manager.py`** — Generates local Root CA and dynamically signs SSL/TLS certificates for HTTPS sites.
- **`sysproxy.py`** — Automatic Windows system-wide proxy switcher via WinINet API.
- **`requirements.txt`** — Python dependencies (`cryptography`, `requests`, `colorama`).
- **`run.bat`** — 1-click startup launcher for Windows.
- **`install_ca.bat`** — Helper script to install Root CA into Windows store without admin rights.
- **`remove_ca.bat`** — Helper script to remove Root CA from Windows store.

---

## 🚀 Quick Start (Windows)

### 1. Configure Backend URL & Secret Key
Edit `config.json`:
```json
{
  "server_urls": [
    "https://your-domain.com/proxy.php"
  ],
  "secret_key": "YourSuperSecretKeyGoesHere",
  "listen_host": "127.0.0.1",
  "listen_port": 8080,
  "auto_system_proxy": true,
  "ask_system_proxy": false,
  "timeout": 45,
  "verify_ssl": false
}
```

### 2. Start the Client
Double-click:
```text
run.bat
```
Or run directly from PowerShell or Command Prompt:
```bash
python proxy_client.py
```

### 3. Verify Connection
1. Open Google Chrome, Microsoft Edge, Brave, Opera, or any browser.
2. Visit an IP checker like [browserleaks.com/ip](https://browserleaks.com/ip) or [ipinfo.io](https://ipinfo.io).
3. You will see the IP address and geolocation of your PHP web hosting!
4. Press `Ctrl + C` in the console at any time to stop the client and instantly restore your standard network settings.

---

## 🦊 Firefox Configuration
Firefox uses its own isolated certificate store by default. To make Firefox trust the Windows Root CA:
1. Navigate to `about:config` in Firefox.
2. Search for `security.enterprise_roots.enabled`.
3. Set it to `true`.
