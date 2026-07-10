"""
runssl — HTTPS-enabled Django development server with auto-generated self-signed certificate.

Usage:
    python manage.py runssl 0.0.0.0:8443

What it does:
1. Detects the machine's LAN IP (via socket routing trick).
2. Auto-generates a self-signed TLS certificate that includes the LAN IP
   in Subject Alternative Names — so browsers can form a chain of trust.
3. Starts Django's WSGIServer wrapped in SSL on the given address.

On mobile devices:
    - Open https://<LAN-IP>:8443 once.
    - Tap "Advanced → Proceed" (Chrome) or "Details → Visit this website" (Safari).
    - File downloads and camera (getUserMedia) will work after trust is granted.
"""

import ipaddress
import os
import socket
import ssl
import sys
import datetime

from django.core.management.commands.runserver import Command as RunServer
from django.core.servers.basehttp import WSGIServer


# ── Certificate generation ──────────────────────────────────────────────────

def _detect_lan_ip() -> str:
    """Returns the machine's best LAN IP (same logic as api/views.py)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != '127.0.0.1':
            return ip
    except Exception:
        pass
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        for addr in addrs:
            if not addr.startswith('127.'):
                return addr
    except Exception:
        pass
    return '127.0.0.1'


def _generate_cert(cert_file: str, key_file: str, lan_ip: str) -> None:
    """Generate a self-signed RSA-2048 certificate using the cryptography package."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print(
            '\n[runssl] ERROR: The "cryptography" package is required.\n'
            '         Install it with:  pip install cryptography\n'
        )
        sys.exit(1)

    print(f'[runssl] Generating self-signed TLS certificate for {lan_ip}…')

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build SAN list — include all IPs / hostnames this cert should cover
    san: list = [
        x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
    ]
    if lan_ip and lan_ip not in ('127.0.0.1', 'localhost'):
        try:
            san.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
        except ValueError:
            san.append(x509.DNSName(lan_ip))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, lan_ip or 'localhost'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Aegix Share (Dev)'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    with open(key_file, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    # Write certificate
    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f'[runssl]   cert -> {cert_file}')
    print(f'[runssl]   key  -> {key_file}')


def _ensure_certs(cert_file: str, key_file: str, lan_ip: str) -> None:
    """Generate the cert only if it doesn't already exist (or is stale)."""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        # Re-generate if cert was issued more than 800 days ago
        age = datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(
            os.path.getmtime(cert_file)
        )
        if age.days < 800:
            print(f'[runssl] Using existing certificate ({age.days}d old): {cert_file}')
            return
    _generate_cert(cert_file, key_file, lan_ip)


# ── SSL-wrapped WSGIServer ───────────────────────────────────────────────────

def _make_ssl_server_class(cert_file: str, key_file: str):
    """Return a WSGIServer subclass that wraps its socket in TLS."""

    class SSLWSGIServer(WSGIServer):
        def server_bind(self):
            super().server_bind()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert_file, key_file)
            # wrap_socket replaces self.socket with the TLS socket
            self.socket = ctx.wrap_socket(self.socket, server_side=True)

    return SSLWSGIServer


# ── Management command ───────────────────────────────────────────────────────

class Command(RunServer):
    help = (
        'HTTPS-enabled development server. Auto-generates a self-signed certificate '
        'covering the machine\'s LAN IP so that mobile devices can download files '
        'and the camera (getUserMedia) works without browser security blocks.'
    )

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '--cert',
            default='cert.pem',
            dest='cert_file',
            help='Path to TLS certificate (PEM). Created automatically if absent.',
        )
        parser.add_argument(
            '--key',
            default='key.pem',
            dest='key_file',
            help='Path to private key (PEM). Created automatically if absent.',
        )

    def handle(self, *args, **options):
        cert_file = options.pop('cert_file', 'cert.pem')
        key_file  = options.pop('key_file',  'key.pem')

        lan_ip = _detect_lan_ip()
        _ensure_certs(cert_file, key_file, lan_ip)

        # Inject the SSL server class BEFORE super().handle() runs
        self.server_cls = _make_ssl_server_class(cert_file, key_file)

        # Determine the address/port from positional args (e.g. "0.0.0.0:8443")
        addr_port = options.get('addrport') or '0.0.0.0:8443'
        port = addr_port.split(':')[-1] if ':' in addr_port else '8443'

        print('\n' + '=' * 62)
        print('  Aegix Share — HTTPS Dev Server')
        print('=' * 62)
        print(f'  Local:  https://localhost:{port}')
        print(f'  LAN:    https://{lan_ip}:{port}')
        print()
        print('  =>  On mobile: open the LAN URL, tap "Advanced -> Proceed"')
        print('      to accept the self-signed certificate once.')
        print('  =>  After accepting, file downloads & camera will work.')
        print('=' * 62 + '\n')

        super().handle(*args, **options)
