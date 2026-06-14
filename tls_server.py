#!/usr/bin/env python3
"""
TLS / SSL troubleshooting MCP server.

Answers the everyday "why is HTTPS unhappy" questions: certificate subject/issuer,
expiry, SAN coverage, chain, and which protocols/ciphers a server actually accepts.

Design:
- Certificate inspection uses Python's own ssl module, so it works with no extra
  binaries AND can fetch certs even when they're expired or the hostname doesn't
  match (validation is intentionally relaxed for troubleshooting — that's the
  whole point when something is broken).
- Protocol/cipher enumeration shells out to `sslscan` when available.
"""

import json
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tls")

SSLSCAN = shutil.which("sslscan") or "sslscan"


def _get_peer_cert(host: str, port: int, timeout: float):
    """Fetch the peer cert in DER form with validation relaxed.

    Validation is disabled on purpose so this still works against expired or
    name-mismatched certs — exactly when you're troubleshooting. We grab the
    raw DER (which works even with CERT_NONE) and parse it offline below.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der, ssock.version(), ssock.cipher()


def _name_to_dict(name: x509.Name) -> dict:
    out = {}
    for attr in name:
        out[attr.oid._name or attr.oid.dotted_string] = attr.value
    return out


def _parse_cert(der: bytes) -> dict:
    """Parse a DER certificate into structured fields using cryptography."""
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_left = (not_after - datetime.now(timezone.utc)).days
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "expired": days_left < 0,
        "subject_alt_names": sans,
        "serial_number": format(cert.serial_number, "x"),
        "signature_algorithm": cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm else None,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
    }


@mcp.tool()
def tls_cert_info(host: str, port: int = 443, timeout: float = 10.0) -> str:
    """Inspect a server's TLS certificate: subject, issuer, validity, SANs, expiry.

    Works even if the cert is expired or the name doesn't match — which is exactly
    when you need it.

    Args:
        host: Hostname to connect to (also used for SNI).
        port: TLS port. Default 443.
        timeout: Connection timeout in seconds.
    """
    try:
        der, version, cipher = _get_peer_cert(host, port, timeout)
    except (socket.timeout, OSError, ssl.SSLError) as e:
        return json.dumps({"host": host, "port": port, "error": str(e)}, indent=2)
    if not der:
        return json.dumps({"host": host, "port": port,
                           "error": "no certificate presented"}, indent=2)

    info = _parse_cert(der)
    info.update({
        "host": host, "port": port,
        "negotiated_protocol": version,
        "negotiated_cipher": cipher[0] if cipher else None,
    })
    return json.dumps(info, indent=2)


@mcp.tool()
def tls_check_expiry(host: str, port: int = 443, warn_days: int = 30,
                     timeout: float = 10.0) -> str:
    """Quick certificate-expiry check with a warning threshold.

    Args:
        host: Hostname.
        port: TLS port. Default 443.
        warn_days: Flag the cert if it expires within this many days.
        timeout: Connection timeout in seconds.
    """
    try:
        der, _, _ = _get_peer_cert(host, port, timeout)
    except (socket.timeout, OSError, ssl.SSLError) as e:
        return json.dumps({"host": host, "port": port, "error": str(e)}, indent=2)
    if not der:
        return json.dumps({"host": host, "port": port,
                           "error": "no certificate presented"}, indent=2)
    info = _parse_cert(der)
    days_left = info["days_until_expiry"]
    return json.dumps({
        "host": host, "port": port,
        "not_after": info["not_after"],
        "days_until_expiry": days_left,
        "expired": days_left < 0,
        "warning": days_left < warn_days,
    }, indent=2)


@mcp.tool()
def tls_scan(host: str, port: int = 443, timeout: int = 60) -> str:
    """Enumerate supported TLS/SSL protocols and cipher suites via sslscan.

    Use to spot weak/deprecated protocols (SSLv3, TLS 1.0/1.1) still enabled.

    Args:
        host: Hostname or IP.
        port: TLS port. Default 443.
        timeout: Max seconds.
    """
    try:
        proc = subprocess.run([SSLSCAN, "--no-colour", f"{host}:{port}"],
                              capture_output=True, text=True, timeout=timeout,
                              check=False)
    except FileNotFoundError:
        return json.dumps({"error": "sslscan not found. Install sslscan, or use "
                           "tls_cert_info for cert details without it."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"sslscan timed out after {timeout}s"})
    return json.dumps({"host": host, "port": port,
                       "output": proc.stdout.strip() or proc.stderr.strip()}, indent=2)


if __name__ == "__main__":
    mcp.run()
