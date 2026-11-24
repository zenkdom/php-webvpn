"""
Certificate Manager for HTTPS MITM Proxy
-------------------------------------------------------------
Generates and manages a local Root Certificate Authority (Root CA)
and dynamically signs SSL/TLS certificates for visited domains on the fly.
Includes Windows User Certificate Store integration (Current User)
allowing zero-friction, non-administrator installation.
"""

import os
import sys
import ssl
import ipaddress
import datetime
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CA_COMMON_NAME = "PHP-WebVPN Root CA"
CA_ORGANIZATION = "PHP-WebVPN"

class CertManager:
    def __init__(self, certs_dir=None):
        if certs_dir is None:
            self.certs_dir = Path(__file__).resolve().parent / "certs"
        else:
            self.certs_dir = Path(certs_dir).resolve()

        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.domains_dir = self.certs_dir / "domains"
        self.domains_dir.mkdir(parents=True, exist_ok=True)

        self.ca_key_path = self.certs_dir / "ca.key"
        self.ca_crt_path = self.certs_dir / "ca.crt"
        self.server_key_path = self.certs_dir / "server.key"

        self.ca_key = None
        self.ca_cert = None
        self.server_key = None
        self._contexts = {}

        self._init_ca()
        self._init_server_key()

    def _init_ca(self):
        """Loads an existing Root CA or generates a fresh one."""
        if self.ca_key_path.exists() and self.ca_crt_path.exists():
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_crt_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            return

        # Generate a new 2048-bit RSA key for CA
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years validity
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.ca_crt_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def _init_server_key(self):
        """Loads or creates a shared RSA server key for fast on-the-fly domain signing."""
        if self.server_key_path.exists():
            with open(self.server_key_path, "rb") as f:
                self.server_key = serialization.load_pem_private_key(f.read(), password=None)
            return

        self.server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.server_key_path, "wb") as f:
            f.write(self.server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    def get_ssl_context(self, host: str) -> ssl.SSLContext:
        """
        Returns a configured SSLContext for the given target domain.
        Dynamically mints and caches the certificate if not already present.
        """
        clean_host = host.strip("[]").strip().lower()
        if clean_host.count(":") == 1:
            clean_host = clean_host.split(":")[0]

        if clean_host in self._contexts:
            return self._contexts[clean_host]

        safe_name = "".join(c if c.isalnum() or c in ".-" else "_" for c in clean_host)
        cert_file = self.domains_dir / f"{safe_name}.crt"

        if not cert_file.exists():
            self._create_domain_cert(clean_host, cert_file)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError):
            pass

        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(self.server_key_path))
        self._contexts[clean_host] = ctx
        return ctx

    def _create_domain_cert(self, host: str, output_path: Path):
        """Signs and saves a domain certificate under our local Root CA."""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PHP-WebVPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])

        try:
            ip = ipaddress.ip_address(host)
            san = [x509.IPAddress(ip)]
        except ValueError:
            san = [x509.DNSName(host)]

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(self.server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(output_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    # =========================================================
    # Windows Certificate Store Integration
    # =========================================================
    def is_ca_installed(self) -> bool:
        """Checks if the Root CA certificate is installed in the Windows CurrentUser store."""
        if sys.platform != "win32":
            return False
        try:
            cmd = ["certutil", "-verifystore", "-user", "Root", CA_COMMON_NAME]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.returncode == 0 and CA_COMMON_NAME in res.stdout
        except Exception:
            return False

    def install_ca(self) -> bool:
        """
        Installs the Root CA into the user's Trusted Root Certification Authorities store.
        Does NOT require administrative privileges!
        """
        if sys.platform != "win32":
            return False
        try:
            cmd = ["certutil", "-addstore", "-user", "Root", str(self.ca_crt_path)]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.returncode == 0
        except Exception as e:
            print(f"[-] Error installing CA certificate: {e}")
            return False

    def remove_ca(self) -> bool:
        """Removes the Root CA from the user's Trusted Root Certification Authorities store."""
        if sys.platform != "win32":
            return False
        try:
            cmd = ["certutil", "-delstore", "-user", "Root", CA_COMMON_NAME]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.returncode == 0
        except Exception as e:
            print(f"[-] Error removing CA certificate: {e}")
            return False
