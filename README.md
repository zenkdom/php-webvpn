# 🌐 PHP-WebVPN: The World's First Serverless PHP Web VPN & Stealth Tunnel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://python.org)
[![PHP: 7.4 - 8.3+](https://img.shields.io/badge/PHP-7.4%20--%208.3%2B-purple.svg)](https://php.net)
[![Protocols: HTTP | HTTPS | SOCKS5 | MTProto](https://img.shields.io/badge/Protocols-HTTP%20%7C%20HTTPS%20%7C%20SOCKS5%20%7C%20MTProto-orange.svg)]()
[![DPI-Bypass: Stealth HTTPS Encapsulation](https://img.shields.io/badge/DPI--Bypass-Stealth%20HTTPS-red.svg)]()

> **Turn ANY standard PHP web hosting into a censorship-resistant stealth VPN & multi-protocol proxy. Zero VPS needed. Zero server costs. Completely invisible to DPI firewalls.**

---

### 🔍 Discovery Tags & Keywords
`php-vpn` • `web-vpn` • `stealth-vpn` • `anti-censorship` • `dpi-bypass` • `php-proxy` • `cpanel-vpn` • `shared-hosting-proxy` • `socks5-proxy` • `mtproto-proxy` • `telegram-proxy` • `webtunnel` • `http-tunnel` • `free-vpn` • `proxy-server`

---

## 💡 Why PHP-WebVPN?

Traditional VPN protocols (OpenVPN, WireGuard, IPsec) and proxy tools (Shadowsocks, V2Ray) require dedicated Linux virtual private servers (VPS) with root access and open UDP/TCP ports. Furthermore, modern Deep Packet Inspection (DPI) systems actively detect and throttle or block their handshakes.

**PHP-WebVPN solves this problem with a revolutionary serverless approach:**
1. **Zero VPS Costs:** Runs on any cheap or free shared PHP web hosting (cPanel, DirectAdmin, Apache, Nginx, ByetHost, InfinityFree).
2. **Stealth HTTPS Traffic Camouflage:** All network packets are encapsulated inside standard HTTPS POST requests. To internet service providers, firewalls, and DPI censors, your connection looks like ordinary browsing of a standard website.
3. **Decoy Mode:** Direct visits without your secret authorization key return an authentic Apache `404 Not Found` page, keeping your endpoint hidden from automated scanners.
4. **Transparent Windows System VPN:** Automatically configures Windows system proxy settings via native WinINet API. All web browsers (Chrome, Edge, Brave, Opera) work out of the box.
5. **Dynamic SSL/TLS MITM Engine:** Generates on-the-fly domain certificates using a local User Root CA without requiring administrator privileges.
6. **Multi-Protocol Telegram Support:** Built-in MTProto Proxy (`8443`) and SOCKS5 Obfuscated2 (`1080`) servers allow seamless 1-click connectivity on Android, iOS, and Desktop.
7. **Round-Robin Load Balancing:** Chain multiple free or cheap PHP backends together into a resilient, high-speed proxy cluster with automatic failover.

---

## 🏗️ Architecture Overview

```text
+---------------------------------------------------------------------------------+
|                                 CLIENT DEVICE                                   |
|                                                                                 |
|  +--------------------+        +--------------------+        +---------------+  |
|  |   Web Browsers     |        |  Telegram Client   |        |  System Apps  |  |
|  | (Chrome/Edge/etc.) |        | (Mobile & Desktop) |        | (HTTP/SOCKS)  |  |
|  +---------+----------+        +---------+----------+        +-------+-------+  |
|            |                             |                           |          |
|            v                             v                           v          |
|  +---------------------------------------------------------------------------+  |
|  |                          Local Client Daemon                              |  |
|  |  • Local Root CA & Dynamic TLS Minting (Port 8080)                        |  |
|  |  • MTProto Proxy (Port 8443) & SOCKS5 Obfuscated2 (Port 1080)             |  |
|  |  • Round-Robin Scheduler & Connection Affinity Pool                       |  |
|  |  • Anti-Bot JS Challenge Resolver (for free hosting providers)            |  |
|  +-------------------------------------+-------------------------------------+  |
+----------------------------------------|----------------------------------------+
                                         |
                                         | Encrypted HTTPS POST Tunnels
                                         | (Indistinguishable from Web Traffic)
                                         v
+---------------------------------------------------------------------------------+
|                       REMOTE PHP BACKEND POOL (Shared Hosting)                  |
|                                                                                 |
|  +----------------------------+             +--------------------------------+  |
|  | Hosting Node A (proxy.php) |             | Hosting Node B (proxy.php)     |  |
|  | IP: 185.x.x.x              |             | IP: 194.x.x.x                  |  |
|  | • cURL Execution Engine    |             | • cURL Execution Engine        |  |
|  | • 404 Decoy Protection     |             | • 404 Decoy Protection         |  |
|  +--------------+-------------+             +---------------+----------------+  |
+-----------------|-------------------------------------------|-------------------+
                  |                                           |
                  +---------------------+---------------------+
                                        |
                                        v
                               +-----------------+
                               | Target Internet |
                               |  Sites & APIs   |
                               +-----------------+
```

---

## 📊 Feature Comparison

| Feature | OpenVPN / WireGuard | Shadowsocks / V2Ray | Tor Network | **PHP-WebVPN** |
| :--- | :---: | :---: | :---: | :---: |
| **Requires Dedicated VPS** | Yes | Yes | No | **No ($0/mo Hosting)** |
| **Root Access Required** | Yes | Yes | No | **No (Plain PHP script)** |
| **DPI Firewall Resistance** | Poor (Easily blocked) | Moderate | High | **High (Standard HTTPS)** |
| **Decoy 404 Protection** | No | Optional | No | **Built-in** |
| **No-Admin Windows Proxy** | No | Requires drivers | No | **Yes (WinINet API)** |
| **Telegram MTProto Support** | No | No | No | **Built-in (Port 8443)** |
| **Multi-Host Load Balancing**| Manual setup | Complex config | Dynamic | **Built-in (Round-Robin)**|

---

## ⚡ Quickstart Guide

### 1. Deploy Remote Backend (30 seconds)
1. Open `server/proxy.php` and set your secret authorization key:
   ```php
   $CONFIG = [
       'secret_key' => 'YourStrongSecretKeyHere',
       ...
   ];
   ```
2. Upload `proxy.php` and `.htaccess` to your web hosting via FTP or cPanel File Manager (e.g., `public_html/proxy.php`).
3. Verify the deployment in your browser:
   ```text
   https://your-domain.com/proxy.php?test=1&key=YourStrongSecretKeyHere
   ```
   A JSON response confirming `status: ok` and server IP confirms successful setup.

---

### 2. Launch Client on Windows
1. Open `client/config.json` and configure your server URL and key:
   ```json
   {
     "server_urls": [
       "https://your-domain.com/proxy.php"
     ],
     "secret_key": "YourStrongSecretKeyHere",
     "listen_host": "127.0.0.1",
     "listen_port": 8080,
     "auto_system_proxy": true,
     "verify_ssl": false
   }
   ```
2. Double-click `client/run.bat` (or execute `python proxy_client.py`).
3. The client will automatically:
   - Generate and install a local Root CA into your user certificate store (no admin rights needed).
   - Enable the Windows system proxy.
   - Route all web browser traffic through your PHP server.
4. Verify your new IP on [browserleaks.com/ip](https://browserleaks.com/ip).
5. Press `Ctrl + C` at any time to shut down the tunnel and restore default network settings.

---

### 3. Telegram Multi-Protocol Proxy (Android, iOS & Desktop)
Run the dedicated Telegram proxy server:
- **Windows:** Double-click `telegram/run.bat`.
- **Linux / macOS / Termux:** Run `telegram/run.sh` or `python3 socks_server.py`.
- **Connect in 1 click:** Click the generated `tg://proxy?...` link printed in the terminal.

---

## 🛠️ CLI Options

### Browser Client (`client/proxy_client.py`)
```text
options:
  --url URL          Remote proxy.php backend URL (can be repeated or comma-separated)
  --key KEY          Secret authorization key
  --port PORT        Local proxy listening port (default: 8080)
  --host HOST        Local binding address (default: 127.0.0.1)
  --sysproxy         Enable Windows system-wide proxy automatically
  --no-sysproxy      Disable automatic Windows system proxy
  --install-ca       Install Root CA into Windows store and exit
  --remove-ca        Remove Root CA from Windows store and exit
  --test             Test backend connectivity and exit
```

### Telegram Proxy (`telegram/socks_server.py`)
```text
options:
  --socks-port PORT    SOCKS5 listening port (default: 1080)
  --mtproto-port PORT  MTProto listening port (default: 8443)
  --host HOST          Local listening host (default: 0.0.0.0)
  --secret SECRET      32-character hexadecimal MTProto secret
  --url URL            Remote proxy.php backend URL
  --key KEY            Secret authorization key
  --test               Check backend health and exit
```

---

## 🧪 Testing

Run the automated integration test suite:
```bash
python tests/test_system.py
```
Validates Root CA generation, dynamic TLS minting, system proxy toggling, mock PHP backend communications, HTTP GET/POST relay, and HTTPS CONNECT tunneling (6/6 tests passing).

---

## 📄 License
This project is open-source under the [MIT License](LICENSE) (see [Open Source Initiative](https://opensource.org/licenses/MIT)).
