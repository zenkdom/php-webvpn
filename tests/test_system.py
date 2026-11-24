"""
Integration & System Test Suite for PHP-WebVPN
-------------------------------------------------------------
Validates complete end-to-end functionality:
1. Root CA generation, dynamic domain SSL certificate minting.
2. Windows System Proxy registry switching and restoration.
3. PHP Backend health check diagnostics (?test=1&key=...).
4. Mock target servers (HTTP & HTTPS).
5. Direct HTTP GET request proxying through PHP backend.
6. HTTP POST request with body and headers proxying.
7. HTTPS CONNECT tunneling with dynamic TLS MITM interception.
"""

import os
import sys
import time
import json
import base64
import socket
import ssl
import threading
import urllib.request
import http.server
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "client"))

from cert_manager import CertManager
from sysproxy import WindowsSystemProxy
from proxy_client import ProxyServer

TEST_SECRET_KEY = "test_secret_12345"
MOCK_PHP_PORT = 19090
TARGET_HTTP_PORT = 19091
TARGET_HTTPS_PORT = 19092
PROXY_PORT = 19080

class TargetHttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        body = json.dumps({
            "status": "target_reached",
            "path": self.path,
            "headers": dict(self.headers),
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "user_session=abc123xyz; Path=/")
        self.send_header("X-Target-Server", "MockTarget/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(length).decode("utf-8")
        resp = json.dumps({
            "status": "post_received",
            "received_body": req_body,
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

class MockPhpHandler(http.server.BaseHTTPRequestHandler):
    """Accurately mimics the server/proxy.php backend behavior."""
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if "?test=1" in self.path:
            key = self.headers.get("X-Proxy-Key", "")
            if not key and "key=" in self.path:
                key = self.path.split("key=")[1].split("&")[0]

            if key != TEST_SECRET_KEY:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

            resp = json.dumps({
                "status": "ok",
                "message": "Mock PHP-WebVPN Server running",
                "php_version": "8.2.0-mock",
                "curl_loaded": True,
                "server_ip": "127.0.0.1",
            }).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        key = self.headers.get("X-Proxy-Key", "")
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        data = json.loads(raw_body.decode("utf-8"))

        if not key:
            key = data.get("key", "")

        if key != TEST_SECRET_KEY:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        target_url = data["url"]
        method = data.get("method", "GET")
        req_headers = data.get("headers", [])
        body_b64 = data.get("body")
        body_bytes = base64.b64decode(body_b64) if body_b64 else None

        req = urllib.request.Request(target_url, data=body_bytes, method=method)
        for item in req_headers:
            if isinstance(item, list) and len(item) >= 2:
                req.add_header(item[0], item[1])

        unverified_ssl = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=10, context=unverified_ssl) as resp:
                resp_status = resp.status
                resp_headers = []
                for k, v in resp.getheaders():
                    if k.lower() not in ["connection", "transfer-encoding"]:
                        resp_headers.append([k, v])
                resp_body = resp.read()

                payload = json.dumps({
                    "status": resp_status,
                    "headers": resp_headers,
                    "body": base64.b64encode(resp_body).decode("ascii"),
                }).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except Exception as e:
            err_payload = json.dumps({
                "error": True,
                "status": 502,
                "message": str(e),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_payload)))
            self.end_headers()
            self.wfile.write(err_payload)

def run_tests():
    print("=" * 65)
    print("Running Automated Test Suite for PHP-WebVPN")
    print("=" * 65)

    # 1. CertManager Test
    print("\n[Test 1/6] CertManager: Root CA generation and dynamic domain minting...")
    cert_mgr = CertManager(certs_dir=ROOT_DIR / "client" / "certs")
    assert cert_mgr.ca_crt_path.exists(), "ca.crt was not generated!"
    assert cert_mgr.ca_key_path.exists(), "ca.key was not generated!"
    ctx1 = cert_mgr.get_ssl_context("test.local")
    assert ctx1 is not None, "Failed to create SSLContext for domain!"
    print("  -> OK: Root CA and domain SSLContext generated successfully.")

    # 2. WindowsSystemProxy Test
    print("\n[Test 2/6] WindowsSystemProxy: Registry proxy toggling & restoration...")
    sp = WindowsSystemProxy("127.0.0.1", PROXY_PORT)
    assert sp.enable(), "Failed to enable Windows system proxy!"
    assert sp.disable(), "Failed to disable Windows system proxy!"
    print("  -> OK: System proxy safely enabled and restored in registry.")

    # 3. Launch Mock Target Server (HTTP)
    target_server = http.server.ThreadingHTTPServer(("127.0.0.1", TARGET_HTTP_PORT), TargetHttpHandler)
    t_target = threading.Thread(target=target_server.serve_forever, daemon=True)
    t_target.start()

    # 3b. Launch Mock Target Server (HTTPS)
    target_ssl_ctx = cert_mgr.get_ssl_context("127.0.0.1")
    target_https_server = http.server.ThreadingHTTPServer(("127.0.0.1", TARGET_HTTPS_PORT), TargetHttpHandler)
    target_https_server.socket = target_ssl_ctx.wrap_socket(target_https_server.socket, server_side=True)
    t_https_target = threading.Thread(target=target_https_server.serve_forever, daemon=True)
    t_https_target.start()

    # 4. Launch Mock PHP Backend Server
    php_server = http.server.ThreadingHTTPServer(("127.0.0.1", MOCK_PHP_PORT), MockPhpHandler)
    t_php = threading.Thread(target=php_server.serve_forever, daemon=True)
    t_php.start()

    # 5. Launch Proxy Client Daemon
    print("\n[Test 3/6] Health check: Client connectivity to remote PHP backend (?test=1)...")
    config = {
        "server_url": f"http://127.0.0.1:{MOCK_PHP_PORT}/proxy.php",
        "secret_key": TEST_SECRET_KEY,
        "listen_host": "127.0.0.1",
        "listen_port": PROXY_PORT,
        "auto_system_proxy": False,
        "auto_install_ca": False,
        "timeout": 15,
        "verify_ssl": False,
    }

    proxy = ProxyServer(config)
    assert proxy.check_remote_server() is True, "Remote backend health check failed!"
    print("  -> OK: Remote PHP backend responded to health check successfully.")

    proxy.is_ready = threading.Event()
    t_proxy = threading.Thread(target=proxy.start, daemon=True)
    t_proxy.start()
    proxy.is_ready.wait(timeout=5)

    # 6. Test Direct HTTP GET Request Through Proxy
    print("\n[Test 4/6] Proxying standard HTTP GET request...")
    proxy_handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{PROXY_PORT}",
        "https": f"http://127.0.0.1:{PROXY_PORT}",
    })
    opener = urllib.request.build_opener(proxy_handler)
    target_url = f"http://127.0.0.1:{TARGET_HTTP_PORT}/api/test?user=antigravity"

    with opener.open(target_url, timeout=5) as response:
        assert response.status == 200, f"Expected 200, got {response.status}"
        resp_data = json.loads(response.read().decode("utf-8"))
        assert resp_data["status"] == "target_reached", "Target server did not return expected payload!"
        assert "/api/test?user=antigravity" in resp_data["path"]
        print("  -> OK: HTTP GET successfully proxied via PHP backend.")

    # 7. Test HTTP POST Request With Body
    print("\n[Test 5/6] Proxying HTTP POST request with payload...")
    post_req = urllib.request.Request(
        f"http://127.0.0.1:{TARGET_HTTP_PORT}/login",
        data=b"username=admin&secret_token=999",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with opener.open(post_req, timeout=5) as response:
        assert response.status == 200
        resp_data = json.loads(response.read().decode("utf-8"))
        assert resp_data["status"] == "post_received"
        assert resp_data["received_body"] == "username=admin&secret_token=999"
        print("  -> OK: HTTP POST request with payload successfully proxied.")

    # 8. Test HTTPS Tunnel (CONNECT) with Dynamic TLS Handshake
    print("\n[Test 6/6] Verifying HTTPS CONNECT tunneling and dynamic TLS MITM...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", PROXY_PORT))
    connect_cmd = f"CONNECT 127.0.0.1:{TARGET_HTTPS_PORT} HTTP/1.1\r\nHost: 127.0.0.1:{TARGET_HTTPS_PORT}\r\n\r\n"
    sock.sendall(connect_cmd.encode("latin1"))

    resp_line = sock.makefile("rb").readline()
    assert b"200 Connection Established" in resp_line, f"Unexpected response to CONNECT: {resp_line}"

    client_ssl_ctx = ssl.create_default_context(cafile=str(cert_mgr.ca_crt_path))
    tls_client_sock = client_ssl_ctx.wrap_socket(sock, server_hostname="127.0.0.1")

    http_req = (
        f"GET /secure-page HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{TARGET_HTTPS_PORT}\r\n"
        f"User-Agent: SecureTestClient\r\n"
        f"Connection: close\r\n\r\n"
    )
    tls_client_sock.sendall(http_req.encode("latin1"))

    tls_rfile = tls_client_sock.makefile("rb")
    status_line = tls_rfile.readline()
    assert b"200 OK" in status_line, f"Expected 200 OK inside TLS, got: {status_line}"

    headers = http.client.parse_headers(tls_rfile)
    clen = int(headers.get("Content-Length", 0))
    tls_body = tls_rfile.read(clen)
    data = json.loads(tls_body.decode("utf-8"))
    assert data["status"] == "target_reached"
    print("  -> OK: HTTPS CONNECT + dynamic TLS handshake & data relay succeeded!")

    proxy.stop()
    target_server.shutdown()
    php_server.shutdown()

    print("\n" + "=" * 65)
    print("ALL TESTS (6/6) PASSED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()
