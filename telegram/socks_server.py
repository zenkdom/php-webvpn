"""
Telegram Multi-Protocol Proxy Server (MTProto + SOCKS5 + HTTP)
---------------------------------------------------------------------
Universal local and edge proxy server for Telegram (Desktop, Android, iOS),
tunneling traffic across a pool of remote PHP backends (proxy.php) with
Connection Affinity load-balancing, asynchronous packet pipelining,
and automatic IPv6 to IPv4 translation.
"""

import os
import sys
import re
import json
import time
import base64
import socket
import select
import struct
import signal
import hashlib
import argparse
import threading
from pathlib import Path
from urllib.parse import urlparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
from requests.adapters import HTTPAdapter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except ImportError:
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()

CONFIG_FILE = Path(__file__).resolve().parent / "config.json"

# Official Telegram Production Data Centers (IPv4)
TELEGRAM_DCS = {
    1: "149.154.175.50",
    2: "149.154.167.50",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "91.108.56.170",
}

def normalize_target_host(host: str) -> str:
    """
    Translates Telegram IPv6 addresses into standard IPv4 addresses,
    ensuring compatibility with shared web hostings lacking IPv6 routing.
    """
    h = host.strip("[]").lower()
    if ":" in h:
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
        return "149.154.167.50"       # Default to DC 2
    return host

def solve_byethost_challenge(html_text: str) -> str:
    """Solves the client-side AES challenge on free hosting providers."""
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

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt.hex().lower()
    except Exception:
        return ""

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Reads exactly n bytes from a TCP socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)

def load_config() -> dict:
    default_config = {
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
        "verify_ssl": False,
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to read config.json: {e}{Style.RESET_ALL}")
    else:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

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

class TelegramProxyServer:
    def __init__(self, config: dict):
        self.config = config
        self.secret_key = config.get("secret_key", "").strip()
        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.socks_port = int(config.get("socks_port", config.get("listen_port", 1080)))
        self.mtproto_port = int(config.get("mtproto_port", 8443))
        self.mtproto_secret_hex = config.get("mtproto_secret", "d41d8cd98f00b204e9800998ecf8427e").strip()
        try:
            self.mtproto_secret = bytes.fromhex(self.mtproto_secret_hex)
        except Exception:
            self.mtproto_secret = hashlib.md5(self.mtproto_secret_hex.encode("utf-8")).digest()
            self.mtproto_secret_hex = self.mtproto_secret.hex()

        self.timeout = int(config.get("timeout", 35))
        self.verify_ssl = bool(config.get("verify_ssl", False))
        self.auth_username = config.get("auth_username", "").strip()
        self.auth_password = config.get("auth_password", "").strip()

        raw_urls = config.get("server_urls", [])
        self.server_urls = raw_urls if raw_urls else ["https://your-domain.com/proxy.php"]
        self.server_url = self.server_urls[0]

        self._rr_index = 0
        self._rr_lock = threading.Lock()

        # High-performance HTTP session pool
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.proxies = {"http": None, "https": None}

        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=200, max_retries=1)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Proxy-Key": self.secret_key,
            "Accept-Encoding": "gzip",
        })

        self.running = False
        self.socks_sock = None
        self.mtproto_sock = None

    def get_preferred_backend(self) -> str:
        """Selects a backend via Round-Robin to bind to a new connection."""
        with self._rr_lock:
            srv = self.server_urls[self._rr_index]
            self._rr_index = (self._rr_index + 1) % len(self.server_urls)
            return srv

    def check_remote_servers(self) -> bool:
        """Health-checks all configured remote PHP backend endpoints."""
        print(f"[*] Checking PHP backend nodes ({len(self.server_urls)} configured)...")
        active_count = 0
        for i, s_url in enumerate(self.server_urls, 1):
            try:
                url = f"{s_url}?test=1&key={self.secret_key}"
                resp = self.session.get(url, timeout=10, verify=self.verify_ssl)

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
                print(f"{Fore.YELLOW}[!] [{i}/{len(self.server_urls)}] {s_url} -> Status {resp.status_code}: {preview}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] [{i}/{len(self.server_urls)}] {s_url} -> Connection error: {e}{Style.RESET_ALL}")

        if active_count > 0:
            print(f"{Fore.GREEN}[+] Active backends available for Telegram: {active_count} of {len(self.server_urls)}{Style.RESET_ALL}\n")
            return True
        else:
            print(f"{Fore.RED}[-] None of the configured backends answered the health check!{Style.RESET_ALL}\n")
            return False

    def forward_payload_to_php(self, target_url: str, method: str, headers: dict, body: bytes, preferred_srv: str = None) -> tuple:
        """
        Forwards encapsulated MTProto/SOCKS payload to remote PHP backend
        with Connection Affinity and automatic failover.
        """
        formatted_headers = []
        for k, v in headers.items():
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

        if preferred_srv and preferred_srv in self.server_urls:
            candidate_servers = [preferred_srv] + [s for s in self.server_urls if s != preferred_srv]
        else:
            candidate_servers = list(self.server_urls)

        used_server = candidate_servers[0]

        for backend_url in candidate_servers:
            used_server = backend_url
            try:
                resp = self.session.post(
                    backend_url,
                    json=payload,
                    timeout=self.timeout + 5,
                    verify=self.verify_ssl
                )

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
                    if resp.status_code in (500, 502, 503, 504) and len(candidate_servers) > 1 and backend_url != candidate_servers[-1]:
                        continue
                    return resp.status_code, [], b"", used_server

                try:
                    res_data = resp.json()
                except Exception:
                    if len(candidate_servers) > 1 and backend_url != candidate_servers[-1]:
                        continue
                    return 502, [], b"", used_server

                if res_data.get("error"):
                    return 502, [], b"", used_server

                status = res_data.get("status", 200)
                res_headers = res_data.get("headers", [])
                body_b64 = res_data.get("body", "")
                resp_body = base64.b64decode(body_b64) if body_b64 else b""
                return status, res_headers, resp_body, used_server

            except Exception:
                continue

        return 502, [], b"", used_server

    def _log_packet(self, proto_name: str, host: str, port: int, in_len: int, out_len: int, status: int, elapsed_ms: float, backend_url: str):
        """Outputs formatted packet telemetry to console."""
        now_str = time.strftime("%H:%M:%S")
        status_color = Fore.GREEN if status == 200 else Fore.RED
        srv_name = urlparse(backend_url).hostname or backend_url
        srv_badge = f"{Fore.BLUE}[{srv_name:<14}]{Style.RESET_ALL} "
        target_str = f"{host}:{port}"
        if len(target_str) > 22:
            target_str = target_str[:22]

        print(
            f"[{now_str}] {srv_badge}"
            f"{Fore.MAGENTA}{proto_name:<14}{Style.RESET_ALL} "
            f"{target_str:<22} "
            f"{status_color}{status}{Style.RESET_ALL} "
            f"({in_len:>4}B -> {out_len:>5}B) "
            f"{Fore.LIGHTBLACK_EX}{elapsed_ms:>5.0f}ms{Style.RESET_ALL}"
        )

    # =========================================================================
    # SOCKS5 + HTTP + AUTO-DETECT HANDLER
    # =========================================================================
    def _handle_socks_connection(self, client_sock: socket.socket, client_addr: tuple):
        """Dispatches connection on SOCKS5 port (1080)."""
        client_sock.settimeout(40.0)
        preferred_backend = self.get_preferred_backend()
        try:
            peek = client_sock.recv(1)
            if not peek:
                client_sock.close()
                return

            if peek == b"\x05":
                self._process_socks5(client_sock, client_addr, preferred_backend)
                return

            if peek in (b"G", b"P", b"C", b"H"):
                initial = peek + client_sock.recv(4096)
                self._process_http_proxy(client_sock, initial, preferred_backend)
                return

            initial = peek + _recv_exact(client_sock, 63)
            if len(initial) == 64:
                self._process_mtproto_stream(client_sock, initial, preferred_backend)
            else:
                client_sock.close()

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_socks5(self, client_sock: socket.socket, client_addr: tuple, preferred_backend: str):
        """Performs RFC 1928 SOCKS5 handshake and begins packet loop."""
        nmethods_byte = client_sock.recv(1)
        if not nmethods_byte:
            return
        nmethods = nmethods_byte[0]
        methods = _recv_exact(client_sock, nmethods)

        if self.auth_username and self.auth_password:
            if 0x02 not in methods:
                client_sock.sendall(b"\x05\xff")
                return
            client_sock.sendall(b"\x05\x02")
            auth_ver = client_sock.recv(1)
            if not auth_ver or auth_ver[0] != 0x01:
                return
            ulen = client_sock.recv(1)[0]
            uname = _recv_exact(client_sock, ulen).decode("latin1", errors="replace")
            plen = client_sock.recv(1)[0]
            passwd = _recv_exact(client_sock, plen).decode("latin1", errors="replace")
            if uname != self.auth_username or passwd != self.auth_password:
                client_sock.sendall(b"\x01\x01")
                return
            client_sock.sendall(b"\x01\x00")
        else:
            client_sock.sendall(b"\x05\x00")

        req = _recv_exact(client_sock, 4)
        if len(req) < 4:
            return
        r_ver, cmd, rsv, atyp = req[0], req[1], req[2], req[3]
        if r_ver != 0x05 or cmd != 0x01:
            client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        target_host = ""
        if atyp == 0x01:  # IPv4
            target_host = socket.inet_ntoa(_recv_exact(client_sock, 4))
        elif atyp == 0x03:  # Domain
            dlen = client_sock.recv(1)[0]
            target_host = _recv_exact(client_sock, dlen).decode("latin1", errors="replace")
        elif atyp == 0x04:  # IPv6 -> Translate to Telegram IPv4 DC
            raw_ip6 = _recv_exact(client_sock, 16)
            ip6_str = socket.inet_ntop(socket.AF_INET6, raw_ip6)
            target_host = normalize_target_host(ip6_str)
        else:
            client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        port_bytes = _recv_exact(client_sock, 2)
        target_port = struct.unpack("!H", port_bytes)[0]

        # SOCKS5 Connection Granted
        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        target_host = normalize_target_host(target_host)
        dc_url = f"http://{target_host}:80/api"

        first_byte = client_sock.recv(1)
        if not first_byte:
            return

        if first_byte == b"\xef":
            self._loop_abridged(client_sock, target_host, target_port, dc_url, None, None, "S5-Abridged", preferred_backend)
            return

        if first_byte == b"\xee":
            next3 = _recv_exact(client_sock, 3)
            if next3 == b"\xee\xee\xee":
                self._loop_intermediate(client_sock, target_host, target_port, dc_url, None, None, "S5-Intermed", preferred_backend)
                return
            first_byte = first_byte + next3

        if first_byte == b"\xdd":
            next3 = _recv_exact(client_sock, 3)
            if next3 == b"\xdd\xdd\xdd":
                self._loop_intermediate(client_sock, target_host, target_port, dc_url, None, None, "S5-Padded", preferred_backend)
                return
            first_byte = first_byte + next3

        rem_len = 64 - len(first_byte)
        handshake = first_byte + _recv_exact(client_sock, rem_len)
        if len(handshake) != 64:
            return

        dec_key = handshake[8:40]
        dec_iv = handshake[40:56]
        enc_key = handshake[8:56][::-1][:32]
        enc_iv = handshake[8:56][::-1][32:48]

        c_dec = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()
        s_enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()

        dec_hdr = c_dec.update(handshake)
        proto = dec_hdr[56:60]

        if proto not in (b"\xef\xef\xef\xef", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
            alt_dec_key = hashlib.sha256(handshake[8:40] + self.mtproto_secret).digest()
            alt_c_dec = Cipher(algorithms.AES(alt_dec_key), modes.CTR(dec_iv)).decryptor()
            alt_dec_hdr = alt_c_dec.update(handshake)
            if alt_dec_hdr[56:60] in (b"\xef\xef\xef\xef", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
                proto = alt_dec_hdr[56:60]
                c_dec = alt_c_dec
                alt_enc_key = hashlib.sha256(handshake[8:56][::-1][:32] + self.mtproto_secret).digest()
                s_enc = Cipher(algorithms.AES(alt_enc_key), modes.CTR(enc_iv)).encryptor()

        if proto == b"\xef\xef\xef\xef":
            self._loop_abridged(client_sock, target_host, target_port, dc_url, c_dec, s_enc, "S5-Obf-EF", preferred_backend)
        elif proto in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
            mode_name = "S5-Obf-EE" if proto == b"\xee\xee\xee\xee" else "S5-Obf-DD"
            self._loop_intermediate(client_sock, target_host, target_port, dc_url, c_dec, s_enc, mode_name, preferred_backend)
        else:
            self._handle_raw_http_fallback(client_sock, target_host, target_port, handshake, preferred_backend)

    # =========================================================================
    # DEDICATED MTPROTO PROXY HANDLER (8443)
    # =========================================================================
    def _handle_mtproto_connection(self, client_sock: socket.socket, client_addr: tuple):
        """Dispatches connection on MTProto port (8443)."""
        client_sock.settimeout(60.0)
        preferred_backend = self.get_preferred_backend()
        try:
            handshake = _recv_exact(client_sock, 64)
            if len(handshake) != 64:
                return
            self._process_mtproto_stream(client_sock, handshake, preferred_backend)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_mtproto_stream(self, client_sock: socket.socket, handshake: bytes, preferred_backend: str):
        """Decrypts and processes MTProto encrypted stream with secret."""
        dec_prekey = handshake[8:40]
        dec_iv = handshake[40:56]
        enc_prekey = handshake[8:56][::-1][:32]
        enc_iv = handshake[8:56][::-1][32:48]

        dec_key = hashlib.sha256(dec_prekey + self.mtproto_secret).digest()
        enc_key = hashlib.sha256(enc_prekey + self.mtproto_secret).digest()

        c_dec = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()
        s_enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()

        dec_hdr = c_dec.update(handshake)
        proto = dec_hdr[56:60]

        if proto not in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\xef\xef\xef\xef"):
            c_dec = Cipher(algorithms.AES(dec_prekey), modes.CTR(dec_iv)).decryptor()
            s_enc = Cipher(algorithms.AES(enc_prekey), modes.CTR(enc_iv)).encryptor()
            dec_hdr = c_dec.update(handshake)
            proto = dec_hdr[56:60]

        if proto not in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\xef\xef\xef\xef"):
            return

        dc_idx = abs(int.from_bytes(dec_hdr[60:62], "little", signed=True))
        if dc_idx not in TELEGRAM_DCS:
            dc_idx = 2

        target_host = TELEGRAM_DCS[dc_idx]
        target_port = 80
        dc_url = f"http://{target_host}:80/api"

        tag = f"MTProto-DC{dc_idx}"
        if proto == b"\xef\xef\xef\xef":
            self._loop_abridged(client_sock, target_host, target_port, dc_url, c_dec, s_enc, tag, preferred_backend)
        else:
            self._loop_intermediate(client_sock, target_host, target_port, dc_url, c_dec, s_enc, tag, preferred_backend)

    # =========================================================================
    # ASYNCHRONOUS PIPELINED MTPROTO PACKET PROCESSING LOOPS
    # =========================================================================
    def _loop_abridged(self, sock: socket.socket, host: str, port: int, dc_url: str, c_dec, s_enc, tag: str, preferred_srv: str):
        """Asynchronous packet loop for Abridged MTProto protocol."""
        sock.settimeout(60.0)
        send_lock = threading.Lock()
        is_alive = [True]

        def _forward_worker(payload: bytes):
            if not is_alive[0]:
                return
            t0 = time.perf_counter()
            status, _, resp_body, used_srv = self.forward_payload_to_php(
                dc_url, "POST", {"Content-Type": "application/x-www-form-urlencoded"}, payload, preferred_srv=preferred_srv
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._log_packet(tag, host, port, len(payload), len(resp_body), status, elapsed_ms, used_srv)

            if not is_alive[0]:
                return

            if status == 200 and resp_body:
                words = len(resp_body) // 4
                if words < 0x7f:
                    out_hdr = bytes([words])
                else:
                    out_hdr = b"\x7f" + int.to_bytes(words, 3, "little")
                framed = out_hdr + resp_body
            elif status != 200:
                err_bytes = struct.pack("<i", -status)
                framed = bytes([1]) + err_bytes
            else:
                return

            try:
                with send_lock:
                    if is_alive[0]:
                        wire = s_enc.update(framed) if s_enc else framed
                        sock.sendall(wire)
            except Exception:
                is_alive[0] = False

        while self.running and is_alive[0]:
            try:
                raw_hdr = sock.recv(1)
                if not raw_hdr:
                    break

                val = c_dec.update(raw_hdr)[0] if c_dec else raw_hdr[0]

                if val == 0x7f or val == 0xff:
                    ext = _recv_exact(sock, 3)
                    if not ext:
                        break
                    dec_ext = c_dec.update(ext) if c_dec else ext
                    pkt_len = int.from_bytes(dec_ext, "little") * 4
                elif val >= 0x80:
                    pkt_len = (val - 0x80) * 4
                else:
                    pkt_len = val * 4

                if pkt_len == 0:
                    continue

                enc_payload = _recv_exact(sock, pkt_len)
                if not enc_payload or len(enc_payload) < pkt_len:
                    break

                payload = c_dec.update(enc_payload) if c_dec else enc_payload
                threading.Thread(target=_forward_worker, args=(payload,), daemon=True).start()

            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                break
            except Exception:
                break

        is_alive[0] = False

    def _loop_intermediate(self, sock: socket.socket, host: str, port: int, dc_url: str, c_dec, s_enc, tag: str, preferred_srv: str):
        """Asynchronous packet loop for Intermediate / Padded MTProto protocol."""
        sock.settimeout(60.0)
        send_lock = threading.Lock()
        is_alive = [True]

        def _forward_worker(payload: bytes):
            if not is_alive[0]:
                return
            t0 = time.perf_counter()
            status, _, resp_body, used_srv = self.forward_payload_to_php(
                dc_url, "POST", {"Content-Type": "application/x-www-form-urlencoded"}, payload, preferred_srv=preferred_srv
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._log_packet(tag, host, port, len(payload), len(resp_body), status, elapsed_ms, used_srv)

            if not is_alive[0]:
                return

            if status == 200 and resp_body:
                framed = struct.pack("<I", len(resp_body)) + resp_body
            elif status != 200:
                err_bytes = struct.pack("<i", -status)
                framed = struct.pack("<I", 4) + err_bytes
            else:
                return

            try:
                with send_lock:
                    if is_alive[0]:
                        wire = s_enc.update(framed) if s_enc else framed
                        sock.sendall(wire)
            except Exception:
                is_alive[0] = False

        while self.running and is_alive[0]:
            try:
                raw_len = _recv_exact(sock, 4)
                if not raw_len or len(raw_len) < 4:
                    break

                dec_len = c_dec.update(raw_len) if c_dec else raw_len
                pkt_len = struct.unpack("<I", dec_len)[0]

                if pkt_len == 0:
                    continue

                enc_payload = _recv_exact(sock, pkt_len)
                if not enc_payload or len(enc_payload) < pkt_len:
                    break

                payload = c_dec.update(enc_payload) if c_dec else enc_payload
                threading.Thread(target=_forward_worker, args=(payload,), daemon=True).start()

            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                break
            except Exception:
                break

        is_alive[0] = False

    # =========================================================================
    # HTTP / WEB PROXY HANDLER (CONNECT & GET/POST)
    # =========================================================================
    def _process_http_proxy(self, sock: socket.socket, initial_data: bytes, preferred_backend: str):
        """Processes requests on the HTTP/Web proxy port."""
        try:
            sock.settimeout(15.0)
            data = initial_data
            if b"\r\n\r\n" not in data:
                data += sock.recv(4096)

            lines = data.split(b"\r\n")
            req_line = lines[0].decode("latin1", errors="replace").split()
            if len(req_line) < 2:
                return

            method = req_line[0].upper()
            target = req_line[1]

            if method == "CONNECT":
                parts = target.split(":")
                host = normalize_target_host(parts[0])
                port = int(parts[1]) if len(parts) > 1 else 443
                sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

                first = sock.recv(1)
                if not first:
                    return

                dc_url = f"http://{host}:80/api"
                if first == b"\xef":
                    self._loop_abridged(sock, host, port, dc_url, None, None, "HTTP-EF", preferred_backend)
                elif first == b"\xee":
                    next3 = _recv_exact(sock, 3)
                    self._loop_intermediate(sock, host, port, dc_url, None, None, "HTTP-EE", preferred_backend)
                else:
                    rem = _recv_exact(sock, 63)
                    handshake = first + rem
                    if len(handshake) == 64:
                        dec_key = handshake[8:40]
                        dec_iv = handshake[40:56]
                        enc_key = handshake[8:56][::-1][:32]
                        enc_iv = handshake[8:56][::-1][32:48]
                        c_dec = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()
                        s_enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
                        dec_hdr = c_dec.update(handshake)
                        proto = dec_hdr[56:60]
                        if proto == b"\xef\xef\xef\xef":
                            self._loop_abridged(sock, host, port, dc_url, c_dec, s_enc, "HTTP-Obf-EF", preferred_backend)
                        elif proto in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
                            self._loop_intermediate(sock, host, port, dc_url, c_dec, s_enc, "HTTP-Obf-EE", preferred_backend)
            else:
                parsed = urlparse(target)
                target_url = target if parsed.scheme else f"http://{target}"
                t0 = time.perf_counter()
                status, headers, body, used_srv = self.forward_payload_to_php(target_url, method, {}, b"", preferred_srv=preferred_backend)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                self._log_packet("HTTP", parsed.hostname or target, parsed.port or 80, len(data), len(body), status, elapsed_ms, used_srv)
                sock.sendall(f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("latin1") + body)

        except Exception:
            pass

    def _handle_raw_http_fallback(self, sock: socket.socket, host: str, port: int, initial: bytes, preferred_backend: str):
        """Fallback for standard HTTP/HTTPS traffic through SOCKS5."""
        if initial.startswith(b"GET ") or initial.startswith(b"POST "):
            self._process_http_proxy(sock, initial, preferred_backend)

    # =========================================================================
    # SERVER LIFECYCLE
    # =========================================================================
    def start(self):
        """Starts SOCKS5 and MTProto servers."""
        self.running = True

        self.socks_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socks_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socks_sock.bind((self.listen_host, self.socks_port))
        self.socks_sock.listen(128)

        self.mtproto_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mtproto_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.mtproto_sock.bind((self.listen_host, self.mtproto_port))
            self.mtproto_sock.listen(128)
            mtproto_enabled = True
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not bind port {self.mtproto_port} for MTProto: {e}{Style.RESET_ALL}")
            mtproto_enabled = False

        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        print("=" * 80)
        print(f"✈️   {Fore.CYAN}Telegram Multi-Protocol Proxy Server is active!{Style.RESET_ALL}")
        print(f"    Backend Pool ({len(self.server_urls)} nodes, connection affinity balancing):")
        for i, s_url in enumerate(self.server_urls, 1):
            print(f"      {i}. {s_url}")
        print("-" * 80)
        print(f"📱  {Fore.YELLOW}FOR TELEGRAM ON MOBILE (Android / iPhone on your local Wi-Fi):{Style.RESET_ALL}")
        print(f"    1. MTProto (RECOMMENDED — connects in 1 click):")
        print(f"       {Fore.GREEN}tg://proxy?server={local_ip}&port={self.mtproto_port}&secret={self.mtproto_secret_hex}{Style.RESET_ALL}")
        print(f"    2. SOCKS5 (with Obfuscated2 and IPv6 translation):")
        print(f"       {Fore.GREEN}tg://socks?server={local_ip}&port={self.socks_port}{Style.RESET_ALL}")
        print("-" * 80)
        print(f"💻  {Fore.YELLOW}FOR TELEGRAM DESKTOP (PC / Mac / Linux):{Style.RESET_ALL}")
        print(f"    1. MTProto : tg://proxy?server=127.0.0.1&port={self.mtproto_port}&secret={self.mtproto_secret_hex}")
        print(f"    2. SOCKS5  : tg://socks?server=127.0.0.1&port={self.socks_port}")
        print("-" * 80)
        print(f"    Termination: Press {Fore.YELLOW}Ctrl + C{Style.RESET_ALL} to stop")
        print("=" * 80 + "\n")

        if mtproto_enabled:
            threading.Thread(target=self._mtproto_accept_loop, daemon=True).start()

        self._socks_accept_loop()

    def _socks_accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.socks_sock.accept()
            except socket.error:
                break
            threading.Thread(
                target=self._handle_socks_connection,
                args=(client_sock, client_addr),
                daemon=True
            ).start()

    def _mtproto_accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.mtproto_sock.accept()
            except socket.error:
                break
            threading.Thread(
                target=self._handle_mtproto_connection,
                args=(client_sock, client_addr),
                daemon=True
            ).start()

    def stop(self):
        """Stops the proxy servers."""
        if not self.running:
            return
        self.running = False
        print(f"\n{Fore.YELLOW}[*] Shutting down Telegram proxy server...{Style.RESET_ALL}")
        if self.socks_sock:
            try:
                self.socks_sock.close()
            except Exception:
                pass
        if self.mtproto_sock:
            try:
                self.mtproto_sock.close()
            except Exception:
                pass
        print(f"{Fore.GREEN}[+] Telegram proxy servers stopped cleanly.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="Telegram Multi-Protocol Proxy Server (MTProto + SOCKS5 + HTTP Tunnel)"
    )
    parser.add_argument("--socks-port", type=int, help="SOCKS5 port (default: 1080)")
    parser.add_argument("--mtproto-port", type=int, help="MTProto port (default: 8443)")
    parser.add_argument("--host", help="Local listening host (default: 0.0.0.0)")
    parser.add_argument("--secret", help="MTProto Proxy secret (32 hex characters)")
    parser.add_argument("--url", action="append", help="Remote proxy.php backend URL")
    parser.add_argument("--key", help="Secret authorization key")
    parser.add_argument("--test", action="store_true", help="Health-check remote backends and exit")

    args = parser.parse_args()
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
    if args.socks_port:
        config["socks_port"] = args.socks_port
    if args.mtproto_port:
        config["mtproto_port"] = args.mtproto_port
    if args.secret:
        config["mtproto_secret"] = args.secret
    if args.host:
        config["listen_host"] = args.host

    server = TelegramProxyServer(config)

    if args.test:
        server.check_remote_servers()
        return

    server.check_remote_servers()
    server.start()

if __name__ == "__main__":
    main()
