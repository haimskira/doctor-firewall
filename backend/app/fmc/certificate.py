"""Read the certificate an FMC presents, for an admin to confirm and pin.

This is the only place that opens a TLS connection without verifying the peer, and it is
safe by construction: no credentials and no request are ever sent on it, the handshake is
closed right after the certificate is read, and the result is only displayed. Trust is
granted later by an admin who compares the fingerprint (``build_pinned_ssl_context``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.fmc.client import validate_pem_certificate
from app.fmc.errors import FmcTlsError, FmcUnavailableError


@dataclass(frozen=True)
class ServerCertificate:
    pem: str
    sha256: str  # colon-separated upper-case hex of the DER encoding
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    self_signed: bool


def fingerprint(cert: x509.Certificate) -> str:
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def pem_fingerprint(pem: str) -> str:
    return fingerprint(validate_pem_certificate(pem))


def _name(name: x509.Name) -> str:
    return name.rfc4514_string() or "-"


def describe(cert: x509.Certificate) -> ServerCertificate:
    return ServerCertificate(
        pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        sha256=fingerprint(cert),
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        self_signed=cert.subject == cert.issuer,
    )


def fetch_server_certificate(host: str, port: int, timeout: float = 5.0) -> ServerCertificate:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # read-only look at the certificate; nothing is sent
    try:
        ipaddress.ip_address(host)
        server_name: str | None = None
    except ValueError:
        server_name = host
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=server_name) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        raise FmcTlsError(f"TLS handshake failed: {type(exc).__name__}") from exc
    except OSError as exc:
        raise FmcUnavailableError(f"FMC unreachable: {type(exc).__name__}") from exc
    if not der:
        raise FmcTlsError("the server presented no certificate")
    return describe(x509.load_der_x509_certificate(der))


__all__ = ["ServerCertificate", "fetch_server_certificate", "pem_fingerprint"]
