"""Certificate pinning: the pinned context trusts exactly one certificate, whatever the name."""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.fmc.certificate import fetch_server_certificate, pem_fingerprint
from app.fmc.client import (
    FmcSession,
    PinnedSSLContext,
    build_pinned_ssl_context,
    connection_ssl_context,
    validate_pem_certificate,
)
from app.fmc.errors import FmcCertificateChangedError, FmcTlsError


def _make_cert(tmp: Path, name: str, expired: bool = False) -> tuple[str, Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    start, end = (
        (now - timedelta(days=10), now - timedelta(days=1))
        if expired
        else (now - timedelta(days=1), now + timedelta(days=30))
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_file, key_file = tmp / f"{name}.pem", tmp / f"{name}.key"
    cert_file.write_bytes(pem)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pem.decode(), cert_file, key_file


@contextmanager
def _tls_server(cert_file: Path, key_file: Path) -> Iterator[int]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(1)
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield int(srv.getsockname()[1])
    finally:
        stop.set()
        thread.join(2)
        srv.close()


def _handshake(ctx: ssl.SSLContext, port: int) -> None:
    with (
        socket.create_connection(("127.0.0.1", port), timeout=3) as raw,
        ctx.wrap_socket(raw),
    ):
        pass


async def _open_session(pem: str, port: int) -> None:
    async with FmcSession(
        host="127.0.0.1",
        port=port,
        username="u",
        password_provider=lambda: bytearray(b"p"),
        ssl_context=build_pinned_ssl_context(pem),
        timeout=3,
    ):
        pass  # pragma: no cover


def test_pinned_context_accepts_exact_cert_even_when_name_differs(tmp_path: Path) -> None:
    pem, cert_file, key_file = _make_cert(tmp_path, "firepower")
    with _tls_server(cert_file, key_file) as port:
        ctx = build_pinned_ssl_context(pem)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is False
        _handshake(ctx, port)  # connected to 127.0.0.1, certificate is for "firepower"


def test_pinned_context_rejects_a_different_certificate(tmp_path: Path) -> None:
    pem, _, _ = _make_cert(tmp_path, "firepower")
    _, other_cert, other_key = _make_cert(tmp_path, "firepower2")
    with (
        _tls_server(other_cert, other_key) as port,
        pytest.raises(ssl.SSLCertVerificationError),
    ):
        _handshake(build_pinned_ssl_context(pem), port)


def test_session_reports_certificate_changed_for_a_pinned_connection(tmp_path: Path) -> None:
    pem, _, _ = _make_cert(tmp_path, "firepower")
    _, other_cert, other_key = _make_cert(tmp_path, "firepower2")
    with (
        _tls_server(other_cert, other_key) as port,
        pytest.raises(FmcCertificateChangedError) as info,
    ):
        asyncio.run(_open_session(pem, port))
    assert info.value.code == "certificate_changed"


def test_expired_pinned_certificate_is_a_plain_tls_error(tmp_path: Path) -> None:
    pem, cert_file, key_file = _make_cert(tmp_path, "old", expired=True)
    with _tls_server(cert_file, key_file) as port, pytest.raises(FmcTlsError) as info:
        asyncio.run(_open_session(pem, port))
    assert not isinstance(info.value, FmcCertificateChangedError)


def test_fetch_server_certificate_describes_what_the_server_presents(tmp_path: Path) -> None:
    pem, cert_file, key_file = _make_cert(tmp_path, "firepower")
    with _tls_server(cert_file, key_file) as port:
        got = fetch_server_certificate("127.0.0.1", port, timeout=3)
    assert got.sha256 == pem_fingerprint(pem)
    assert got.self_signed is True
    assert "firepower" in got.subject
    assert len(got.sha256.split(":")) == 32


def test_connection_context_chooses_pin_or_bundle(tmp_path: Path) -> None:
    pem, _, _ = _make_cert(tmp_path, "firepower")
    ca = tmp_path / "ca.pem"
    ca.write_text(pem)
    assert isinstance(connection_ssl_context(ca, pem), PinnedSSLContext)
    plain = connection_ssl_context(ca, None)
    assert not isinstance(plain, PinnedSSLContext)
    assert plain.check_hostname is True
    assert plain.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize(
    "bad",
    ["", "garbage", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "x" * 20000],
)
def test_pem_validation_rejects_junk(bad: str) -> None:
    with pytest.raises(ValueError, match="single PEM"):
        validate_pem_certificate(bad)
    with pytest.raises(FmcTlsError):
        build_pinned_ssl_context(bad)


def test_pem_validation_rejects_two_certificates(tmp_path: Path) -> None:
    pem, _, _ = _make_cert(tmp_path, "a")
    with pytest.raises(ValueError, match="single PEM"):
        validate_pem_certificate(pem + pem)
