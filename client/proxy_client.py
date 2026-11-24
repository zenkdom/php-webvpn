"""
PHP-WebVPN Client for Windows & Cross-Platform
-------------------------------------------------------------
Local proxy client and VPN tunnel daemon.
Intercepts browser and system HTTP/HTTPS traffic and tunnels it through
your remote PHP backend script (proxy.php) on any shared web hosting.
Supports automatic Windows system-wide proxy activation and transparent
on-the-fly SSL/TLS certificate minting via a local Root CA.
"""

import os
import sys
import re
import json
import time
import base64
import random
import socket
import select
import signal
import http.client
import argparse
from pathlib import Path
from urllib.parse import urlparse
import threading

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def solve_byethost_challenge(html_text: str) -> str:
    """
    Solves the client-side AES challenge (aes.js / testcookie) common on free
    hosting providers (ByetHost / InfinityFree / FreeDev / iFastNet) and returns
    the decrypted __test cookie value.
    """
    try:
        m = re.search(
            r'a\s*=\s*toNumbers\(\s*["\']([0-9a-fA-F]+)["\']\s*\)'
            r'[\s\S]*?b\s*=\s*toNumbers\(\s*["\']([0-9a-fA-F]+)["\']\s*\)'
            r'[\s\S]*?c\s*=\s*toNumbers\(\s*["\']([0-9a-fA-F]+)["\']\s*\)',
            html_text
        )
        if not m:
            return ""

        key = bytes.fromhex(m.group(1))
        iv = bytes.fromhex(m.group(2))
        ct = bytes.fromhex(m.group(3))

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt.hex().lower()
    except Exception:
        return ""

def normalize_target_host(host: str) -> str:
    """
    Translates IPv6 addresses into standard IPv4 addresses since shared
    PHP hosting providers rarely support outbound IPv6 cURL routing.
    """
    h = host.strip("[]").strip().lower()
    if ":" in h:
        # 1. Telegram DC IPv6 mapping
        if "f001" in h:
            return "149.154.175.50"   # DC 1
        elif "f002" in h:
            return "149.154.167.50"   # DC 2
        elif "f003" in h:
            return "149.154.175.100"  # DC 3
        elif "f004" in h:
            return "149.154.167.91"   # DC 4
        elif "f005" in h:
            return "91.108.56.170"    # DC 5
        elif "2001:67c:4e8" in h or "2001:b28:f23f" in h:
            return "149.154.167.50"   # Fallback

        # 2. Reverse DNS lookup fallback
        try:
            domain_name = socket.gethostbyaddr(h)[0]
            if domain_name and domain_name != h:
                ipv4 = socket.gethostbyname(domain_name)
                if ipv4 and ":" not in ipv4:
                    return ipv4
        except Exception:
            pass

    return host

def normalize_url_host(url: str) -> str:
    """
    Normalizes IPv6 in URL netloc to IPv4 equivalent when needed.
    """
    try:
        if "://" in url:
            scheme, rest = url.split("://", 1)
            slash_pos = rest.find("/")
            if slash_pos != -1:
                netloc = rest[:slash_pos]
                path = rest[slash_pos:]
            else:
                netloc = rest
                path = ""
        else:
            return url

        host, port = parse_host_port(netloc, default_port=None)
        norm_h = normalize_target_host(host)
        if norm_h != host.strip("[]"):
            port_str = f":{port}" if port is not None else ""
            return f"{scheme}://{norm_h}{port_str}{path}"
        elif ":" in host and not netloc.startswith("["):
            port_str = f":{port}" if port is not None else ""
            return f"{scheme}://[{host}]{port_str}{path}"
    except Exception:
        pass
    return url

def parse_host_port(target: str, default_port: int = 443) -> tuple:
    """
    Accurately splits host and port handling IPv6 brackets [::]:443 and standard host:port.
    """
    target = target.strip()
    if target.startswith("["):
        bracket_end = target.find("]")
        if bracket_end != -1:
            host = target[1:bracket_end]
            port_part = target[bracket_end + 1:]
            port = int(port_part[1:]) if port_part.startswith(":") and port_part[1:].isdigit() else default_port
            return host, port
    if target.count(":") > 1:
        last_colon = target.rfind(":")
        possible_port = target[last_colon + 1:]
        if possible_port.isdigit():
            return target[:last_colon], int(possible_port)
        return target, default_port
    elif ":" in target:
        host, port_str = target.split(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, default_port
    return target, default_port

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
from requests.adapters import HTTPAdapter

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except ImportError:
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()

from cert_manager import CertManager
from sysproxy import WindowsSystemProxy

CONFIG_FILE = Path(__file__).resolve().parent / "config.json"

def load_config() -> dict:
    default_config = {
        "server_urls": [
            "https://your-domain.com/proxy.php"
        ],
        "server_url": "https://your-domain.com/proxy.php",
        "secret_key": "ChangeThisSecretKey",
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "auto_system_proxy": True,
        "ask_system_proxy": False,
        "timeout": 45,
        "verify_ssl": False,
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to read config.json, using defaults: {e}{Style.RESET_ALL}")
    else:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    # Normalize backend server URL list (supports single server_url or multiple server_urls)
    urls = []
    raw = default_config.get("server_urls") or default_config.get("server_url")
    if isinstance(raw, str):
        urls = [u.strip() for u in raw.split(",") if u.strip()]
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                for sub in item.split(","):
                    if sub.strip():
                        urls.append(sub.strip())

    if not urls:
        urls = ["https://your-domain.com/proxy.php"]

    default_config["server_urls"] = urls
    default_config["server_url"] = urls[0]

    return default_config

def read_chunked(rfile) -> bytes:
    """Reads an HTTP request body encoded with chunked transfer encoding."""
    body = bytearray()
    while True:
        line = rfile.readline(128)
        if not line:
            break
        chunk_len_str = line.split(b";")[0].strip()
        if not chunk_len_str:
            continue
        try:
            chunk_len = int(chunk_len_str, 16)
        except ValueError:
            break
        if chunk_len == 0:
            while True:
                trailer = rfile.readline(1024)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        chunk_data = rfile.read(chunk_len)
        body.extend(chunk_data)
        rfile.readline()
    return bytes(body)

class ProxyServer:
    def __init__(self, config: dict):
        self.config = config
        self.secret_key = config.get("secret_key", "").strip()
        self.listen_host = config.get("listen_host", "127.0.0.1")
        self.listen_port = int(config.get("listen_port", 8080))
        self.timeout = int(config.get("timeout", 45))
        self.verify_ssl = bool(config.get("verify_ssl", False))

        # Parse backend server pool for load balancing
        raw_urls = config.get("server_urls") or config.get("server_url")
        if isinstance(raw_urls, str):
            raw_urls = [u.strip() for u in raw_urls.split(",") if u.strip()]
        elif isinstance(raw_urls, list):
            cleaned = []
            for item in raw_urls:
                if isinstance(item, str):
                    for sub in item.split(","):
                        if sub.strip():
                            cleaned.append(sub.strip())
            raw_urls = cleaned
        else:
            raw_urls = []

        self.server_urls = raw_urls if raw_urls else ["https://your-domain.com/proxy.php"]
        self.server_url = self.server_urls[0]

        # Extract backend endpoints to prevent routing loops and bypass system proxy
        self.server_endpoints = []
        self.bypass_hosts = []
        for s_url in self.server_urls:
            parsed = urlparse(s_url)
            h = parsed.hostname.lower() if parsed.hostname else ""
            p = parsed.port or (443 if parsed.scheme == "https" else 80)
            if h:
                self.server_endpoints.append((h, p))
                if h not in self.bypass_hosts:
                    self.bypass_hosts.append(h)

        self.server_host = self.server_endpoints[0][0] if self.server_endpoints else ""
        self.server_port = self.server_endpoints[0][1] if self.server_endpoints else 80

        self.cert_manager = CertManager()
        self.sys_proxy = None
        self.running = False
        self.server_sock = None

        # Round-robin load balancer state
        self._rr_index = 0
        self._rr_lock = threading.Lock()

        # Connection pool for remote PHP backends
        self.session = requests.Session()
        # CRITICAL: Prevent local proxy inheritance loop
        self.session.trust_env = False
        self.session.proxies = {"http": None, "https": None}

        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=100, max_retries=1)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Proxy-Key": self.secret_key,
            "Accept-Encoding": "gzip",
        })

    def check_remote_server(self) -> bool:
        """Health-checks all configured remote PHP backend endpoints."""
        print(f"[*] Checking backend connectivity ({len(self.server_urls)} configured)...")
        active_count = 0
        for i, s_url in enumerate(self.server_urls, 1):
            try:
                url = f"{s_url}?test=1&key={self.secret_key}"
                resp = self.session.get(url, timeout=10, verify=self.verify_ssl)

                # Solve ByetHost / FreeDev / InfinityFree challenge if encountered
                if ("aes.js" in resp.text or "__test" in resp.text) and "<html" in resp.text.lower():
                    cookie_val = solve_byethost_challenge(resp.text)
                    if cookie_val:
                        parsed = urlparse(s_url)
                        self.session.cookies.set("__test", cookie_val, domain=parsed.hostname, path="/")
                        resp = self.session.get(url, timeout=10, verify=self.verify_ssl)

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("status") == "ok":
                            php_ver = data.get("php_version", "unknown")
                            curl_ok = data.get("curl_loaded", False)
                            srv_ip = data.get("server_ip", "unknown")
                            print(f"{Fore.GREEN}[+] [{i}/{len(self.server_urls)}] {s_url} -> OK! PHP: {php_ver}, cURL: {curl_ok}, IP: {srv_ip}{Style.RESET_ALL}")
                            active_count += 1
                            continue
                    except Exception:
                        pass

                preview = resp.text.strip().replace('\r', ' ').replace('\n', ' ')
                if len(preview) > 100:
                    preview = preview[:97] + "..."
                if "<html" in resp.text.lower():
                    print(f"{Fore.YELLOW}[!] [{i}/{len(self.server_urls)}] {s_url} -> Non-JSON response (HTML page): {preview}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] [{i}/{len(self.server_urls)}] {s_url} -> Status {resp.status_code}: {preview}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] [{i}/{len(self.server_urls)}] {s_url} -> Connection error: {e}{Style.RESET_ALL}")

        if active_count > 0:
            print(f"{Fore.GREEN}[+] Active backends available: {active_count} of {len(self.server_urls)}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[-] None of the configured backend servers answered the health check!{Style.RESET_ALL}")
            return False

    def forward_request_to_php(self, target_url: str, method: str, headers: dict, body: bytes) -> tuple:
        """
        Encapsulates and dispatches the request to a remote PHP backend.
        Performs round-robin load distribution and automatic failover.
        Returns: (status, headers, body, used_backend_url)
        """
        target_url = normalize_url_host(target_url)

        formatted_headers = []
        hop_by_hop = {
            "proxy-connection", "connection", "keep-alive",
            "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "upgrade"
        }
        for k, v in headers.items():
            if k.lower() not in hop_by_hop:
                formatted_headers.append([k, v])

        payload = {
            "url": target_url,
            "method": method,
            "headers": formatted_headers,
            "timeout": self.timeout,
            "key": self.secret_key,
        }

        if body and len(body) > 0:
            payload["body"] = base64.b64encode(body).decode("ascii")

        # Round-robin selection across backend servers
        n = len(self.server_urls)
        with self._rr_lock:
            start_idx = self._rr_index
            self._rr_index = (self._rr_index + 1) % n

        candidate_servers = [self.server_urls[(start_idx + i) % n] for i in range(n)]

        last_error = None
        used_server = candidate_servers[0] if candidate_servers else self.server_url

        for backend_url in candidate_servers:
            used_server = backend_url
            try:
                resp = self.session.post(
                    backend_url,
                    json=payload,
                    timeout=self.timeout + 5,
                    verify=self.verify_ssl
                )

                # Handle free hosting anti-bot challenge
                if ("aes.js" in resp.text or "__test" in resp.text) and "<html" in resp.text.lower():
                    cookie_val = solve_byethost_challenge(resp.text)
                    if cookie_val:
                        parsed = urlparse(backend_url)
                        self.session.cookies.set("__test", cookie_val, domain=parsed.hostname, path="/")
                        resp = self.session.post(
                            backend_url,
                            json=payload,
                            timeout=self.timeout + 5,
                            verify=self.verify_ssl
                        )

                if resp.status_code != 200:
                    err_text = f"Remote proxy ({backend_url}) returned HTTP {resp.status_code}\n{resp.text}"
                    if resp.status_code in (500, 502, 503, 504) and len(candidate_servers) > 1 and backend_url != candidate_servers[-1]:
                        continue
                    return resp.status_code, [["Content-Type", "text/plain; charset=utf-8"]], err_text.encode("utf-8"), used_server

                try:
                    res_data = resp.json()
                except Exception:
                    preview = resp.text.strip().replace('\r', ' ').replace('\n', ' ')
                    if len(preview) > 120:
                        preview = preview[:117] + "..."
                    err_msg = f"Remote host ({backend_url}) returned non-JSON (HTML / Bot Challenge): {preview}"
                    last_error = err_msg
                    if len(candidate_servers) > 1 and backend_url != candidate_servers[-1]:
                        continue
                    return 502, [["Content-Type", "text/plain; charset=utf-8"]], err_msg.encode("utf-8"), used_server

                if res_data.get("error"):
                    err_msg = res_data.get("message", "Unknown proxy error")
                    return 502, [["Content-Type", "text/plain; charset=utf-8"]], f"Proxy Error: {err_msg}".encode("utf-8"), used_server

                status = res_data.get("status", 200)
                res_headers = res_data.get("headers", [])
                body_b64 = res_data.get("body", "")
                resp_body = base64.b64decode(body_b64) if body_b64 else b""

                return status, res_headers, resp_body, used_server

            except requests.exceptions.SSLError as e:
                last_error = f"SSL Verification Error to {backend_url}: {e}"
                continue
            except requests.Timeout:
                last_error = f"Timeout connecting to {backend_url}"
                continue
            except Exception as e:
                last_error = f"Error with {backend_url}: {e}"
                continue

        err_text = f"All proxy servers failed. Last error: {last_error}"
        return 502, [["Content-Type", "text/plain; charset=utf-8"]], err_text.encode("utf-8"), used_server

    def _send_http_response(self, sock, status: int, headers: list, body: bytes):
        """Sends a clean HTTP response back to the client browser."""
        reason = http.client.responses.get(status, "OK")
        header_lines = [f"HTTP/1.1 {status} {reason}".encode("latin1")]

        hop_by_hop = {
            "connection", "proxy-connection", "keep-alive",
            "transfer-encoding", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "upgrade", "content-length"
        }

        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                hname, hval = str(item[0]), str(item[1])
            elif isinstance(item, str) and ":" in item:
                hname, hval = item.split(":", 1)
            else:
                continue

            hname = hname.strip()
            hval = hval.strip()
            if hname.lower() in hop_by_hop:
                continue

            header_lines.append(f"{hname}: {hval}".encode("latin1", errors="replace"))

        header_lines.append(f"Content-Length: {len(body)}".encode("latin1"))
        header_lines.append(b"Connection: keep-alive")
        header_lines.append(b"")
        header_lines.append(b"")

        raw_data = b"\r\n".join(header_lines) + body
        sock.sendall(raw_data)

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        """Dispatches an incoming browser or client request."""
        client_sock.settimeout(20.0)
        try:
            rfile = client_sock.makefile("rb")
            req_line = rfile.readline(65536)
            if not req_line:
                client_sock.close()
                return

            line_str = req_line.decode("latin1", errors="replace").strip()
            parts = line_str.split()
            if len(parts) < 2:
                client_sock.close()
                return

            method = parts[0].upper()
            target = parts[1]

            # -------------------------------------------------------------
            # Branch 1: HTTPS Tunnel via CONNECT (e.g. CONNECT example.com:443)
            # -------------------------------------------------------------
            if method == "CONNECT":
                target_host, t_port = parse_host_port(target, default_port=443)
                norm_host = normalize_target_host(target_host)

                # Loop prevention
                is_loop = any(
                    s_host and (target_host.lower() == s_host or norm_host.lower() == s_host) and t_port == s_port
                    for s_host, s_port in self.server_endpoints
                )
                if is_loop:
                    client_sock.sendall(b"HTTP/1.1 403 Forbidden (Proxy Loop Prevention)\r\n\r\n")
                    client_sock.close()
                    return

                # Read CONNECT headers
                while True:
                    hdr = rfile.readline(4096)
                    if not hdr or hdr in (b"\r\n", b"\n"):
                        break

                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Wrap with dynamic TLS certificate generated on the fly
                ssl_ctx = self.cert_manager.get_ssl_context(target_host)
                tls_sock = ssl_ctx.wrap_socket(client_sock, server_side=True)
                tls_sock.settimeout(15.0)
                tls_rfile = tls_sock.makefile("rb")

                # Keep-Alive loop for encapsulated HTTPS requests
                while self.running:
                    try:
                        sub_line = tls_rfile.readline(65536)
                    except (socket.timeout, ConnectionResetError, BrokenPipeError):
                        break

                    if not sub_line:
                        break

                    sub_parts = sub_line.decode("latin1", errors="replace").strip().split()
                    if len(sub_parts) < 2:
                        break

                    sub_method = sub_parts[0].upper()
                    sub_path = sub_parts[1]

                    headers = http.client.parse_headers(tls_rfile)

                    body = b""
                    if "Content-Length" in headers:
                        try:
                            clen = int(headers["Content-Length"])
                            body = tls_rfile.read(clen)
                        except ValueError:
                            pass
                    elif headers.get("Transfer-Encoding", "").lower() == "chunked":
                        body = read_chunked(tls_rfile)

                    req_host = headers.get("Host", target_host)
                    full_url = normalize_url_host(f"https://{req_host}{sub_path}")

                    t0 = time.perf_counter()
                    status, resp_headers, resp_body, used_server = self.forward_request_to_php(
                        full_url, sub_method, headers, body
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000

                    self._log_request(sub_method, full_url, status, len(resp_body), elapsed_ms, used_server)
                    self._send_http_response(tls_sock, status, resp_headers, resp_body)

                    if headers.get("Connection", "").lower() == "close":
                        break

                try:
                    tls_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                tls_sock.close()
                return

            # -------------------------------------------------------------
            # Branch 2: Standard HTTP Request (e.g. GET http://example.com/...)
            # -------------------------------------------------------------
            headers = http.client.parse_headers(rfile)
            body = b""
            if "Content-Length" in headers:
                try:
                    clen = int(headers["Content-Length"])
                    body = rfile.read(clen)
                except ValueError:
                    pass
            elif headers.get("Transfer-Encoding", "").lower() == "chunked":
                body = read_chunked(rfile)

            if target.startswith("http://") or target.startswith("https://"):
                full_url = normalize_url_host(target)
            else:
                host_hdr = headers.get("Host", "")
                full_url = normalize_url_host(f"http://{host_hdr}{target}")

            t0 = time.perf_counter()
            status, resp_headers, resp_body, used_server = self.forward_request_to_php(
                full_url, method, headers, body
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000

            self._log_request(method, full_url, status, len(resp_body), elapsed_ms, used_server)
            self._send_http_response(client_sock, status, resp_headers, resp_body)

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _log_request(self, method: str, url: str, status: int, size: int, elapsed_ms: float, backend_url: str = ""):
        """Outputs formatted request log to console with backend identifier."""
        now_str = time.strftime("%H:%M:%S")

        if status < 300:
            status_color = Fore.GREEN
        elif status < 400:
            status_color = Fore.CYAN
        elif status < 500:
            status_color = Fore.YELLOW
        else:
            status_color = Fore.RED

        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"

        display_url = url
        if len(display_url) > 65:
            display_url = display_url[:62] + "..."

        srv_badge = ""
        if backend_url:
            srv_name = urlparse(backend_url).hostname or backend_url
            srv_badge = f"{Fore.BLUE}[{srv_name:<12}]{Style.RESET_ALL} "

        print(
            f"[{now_str}] {srv_badge}"
            f"{Fore.MAGENTA}{method:<6}{Style.RESET_ALL} "
            f"{display_url:<65} "
            f"{status_color}{status}{Style.RESET_ALL} "
            f"({size_str:>8}) "
            f"{Fore.LIGHTBLACK_EX}{elapsed_ms:>6.0f}ms{Style.RESET_ALL}"
        )

    def start(self):
        """Initializes and runs the proxy server daemon."""
        self.running = True
        self.is_ready = getattr(self, "is_ready", threading.Event())

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.listen_port))
        self.server_sock.listen(128)
        self.is_ready.set()

        # Check and install Root CA certificate if needed
        if sys.platform == "win32" and self.config.get("auto_install_ca", True):
            if not self.cert_manager.is_ca_installed():
                print(f"{Fore.YELLOW}[!] Root CA certificate 'PHP-WebVPN Root CA' is not installed yet.{Style.RESET_ALL}")
                print(f"[*] Installing Root CA certificate into Windows CurrentUser store (no admin required)...")
                if self.cert_manager.install_ca():
                    print(f"{Fore.GREEN}[+] Root CA successfully installed! Browsers will seamlessly trust HTTPS sites.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Automatic install failed. Run install_ca.bat manually if required.{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Root CA certificate verified and active.{Style.RESET_ALL}")

        # Check whether to enable Windows system proxy
        enable_sys = False
        if sys.platform == "win32":
            if self.config.get("auto_system_proxy") is False:
                enable_sys = False
            elif self.config.get("ask_system_proxy") is False:
                enable_sys = bool(self.config.get("auto_system_proxy", True))
            elif sys.stdin and sys.stdin.isatty():
                try:
                    prompt_text = (
                        f"{Fore.CYAN}[?] Enable Windows system-wide proxy? "
                        f"[Y/n] (Enter = Yes): {Style.RESET_ALL}"
                    )
                    ans = input(prompt_text).strip().lower()
                    enable_sys = ans in ("", "y", "yes", "1")
                except (EOFError, KeyboardInterrupt):
                    enable_sys = False
            else:
                enable_sys = bool(self.config.get("auto_system_proxy", False))

            if enable_sys:
                proxy_sys_host = "127.0.0.1" if (not self.listen_host or self.listen_host in ("0.0.0.0", "::")) else self.listen_host
                self.sys_proxy = WindowsSystemProxy(
                    proxy_sys_host,
                    self.listen_port,
                    bypass_hosts=self.bypass_hosts
                )
                if self.sys_proxy.enable():
                    print(f"{Fore.GREEN}[+] Windows System Proxy ENABLED: {proxy_sys_host}:{self.listen_port}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[i] All browsers (Chrome, Edge, Opera, Brave, etc.) will route through PHP-WebVPN.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[i] Windows System Proxy is DISABLED. System network configuration remains untouched.{Style.RESET_ALL}")

        print("\n" + "=" * 75)
        print(f"🌐  {Fore.GREEN}PHP-WebVPN Client is running and active!{Style.RESET_ALL}")
        print(f"    Backend Pool ({len(self.server_urls)} nodes, Round-Robin load balancing):")
        for i, s_url in enumerate(self.server_urls, 1):
            print(f"      {i}. {s_url}")
        print(f"    Local Socket    : http://{self.listen_host}:{self.listen_port}")
        if self.sys_proxy and self.sys_proxy.is_enabled:
            print(f"    System Proxy    : {Fore.GREEN}ENABLED{Style.RESET_ALL} (http://127.0.0.1:{self.listen_port})")
        else:
            print(f"    System Proxy    : {Fore.YELLOW}DISABLED{Style.RESET_ALL} (Manual config / Android / LAN mode)")
        if self.listen_host in ("0.0.0.0", "::"):
            print(f"    LAN / Android   : http://<YOUR-PC-IP>:{self.listen_port}")
        print(f"    Termination     : Press {Fore.YELLOW}Ctrl + C{Style.RESET_ALL} to stop")
        print("=" * 75 + "\n")

        try:
            while self.running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                except socket.error:
                    break

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                t.start()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Stops the proxy server and restores network settings."""
        if not self.running:
            return
        self.running = False
        print(f"\n{Fore.YELLOW}[*] Shutting down PHP-WebVPN client...{Style.RESET_ALL}")

        if self.sys_proxy:
            self.sys_proxy.disable()
            print(f"{Fore.GREEN}[+] Windows System Proxy disabled. Original settings restored.{Style.RESET_ALL}")

        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        print(f"{Fore.GREEN}[+] Proxy server stopped cleanly.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="PHP-WebVPN Client — High-speed stealth VPN & proxy over any PHP web hosting"
    )
    parser.add_argument("--url", action="append", help="URL of remote proxy.php (can be repeated or comma-separated)")
    parser.add_argument("--key", help="Secret authorization key")
    parser.add_argument("--port", type=int, help="Local proxy listening port (default: 8080)")
    parser.add_argument("--host", help="Local proxy listening address (default: 127.0.0.1)")
    parser.add_argument("--no-sysproxy", action="store_true", help="Do not modify Windows system proxy (headless/manual)")
    parser.add_argument("--sysproxy", action="store_true", help="Enable Windows system proxy automatically without prompt")
    parser.add_argument("--ask-sysproxy", action="store_true", help="Prompt before enabling Windows system proxy")
    parser.add_argument("--install-ca", action="store_true", help="Install Root CA into Windows store and exit")
    parser.add_argument("--remove-ca", action="store_true", help="Remove Root CA from Windows store and exit")
    parser.add_argument("--test", action="store_true", help="Check remote backend connectivity and exit")

    args = parser.parse_args()

    cert_mgr = CertManager()

    if args.install_ca:
        print("[*] Installing Root CA certificate into Windows CurrentUser store...")
        if cert_mgr.install_ca():
            print(f"{Fore.GREEN}[+] Root CA certificate successfully installed!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Failed to install Root CA certificate.{Style.RESET_ALL}")
        return

    if args.remove_ca:
        print("[*] Removing Root CA certificate from Windows CurrentUser store...")
        if cert_mgr.remove_ca():
            print(f"{Fore.GREEN}[+] Root CA certificate successfully removed!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Failed to remove Root CA certificate.{Style.RESET_ALL}")
        return

    config = load_config()

    if args.url:
        urls = []
        for u in args.url:
            for sub in u.split(","):
                if sub.strip():
                    urls.append(sub.strip())
        config["server_urls"] = urls
        config["server_url"] = urls[0] if urls else ""

    if args.key:
        config["secret_key"] = args.key
    if args.port:
        config["listen_port"] = args.port
    if args.host:
        config["listen_host"] = args.host

    if args.no_sysproxy:
        config["auto_system_proxy"] = False
        config["ask_system_proxy"] = False
    elif args.sysproxy:
        config["auto_system_proxy"] = True
        config["ask_system_proxy"] = False
    elif args.ask_sysproxy:
        config["ask_system_proxy"] = True

    proxy = ProxyServer(config)

    if args.test:
        proxy.check_remote_server()
        return

    proxy.start()

if __name__ == "__main__":
    main()
