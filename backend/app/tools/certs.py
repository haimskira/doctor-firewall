"""Generate a local CA and server certificates.

Used for (a) the dev environment (UI cert + the FMC mock's cert, both signed by a
throw-away dev CA that the backend trusts), and (b) a default self-signed UI
certificate in production until the organisation's PKI issues a real one.

    python -m app.tools.certs --out /out --ca-name "Doctor Firewall Dev CA" \
        --leaf ui:localhost,127.0.0.1 --leaf fmc-mock:fmc-mock

Writes ``ca.pem``/``ca.key`` and ``<name>.pem``/``<name>.key`` per leaf. Existing
files are never overwritten. Private keys default to mode 0600; ``--key-mode 0644`` is
for hosts where the containing directory itself is root-only (0700) and the keys
must be readable by a different, unprivileged container user (nginx).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PrivateKey = ec.EllipticCurvePrivateKey


def _key() -> PrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _write_private(path: Path, key: PrivateKey, mode: int) -> None:
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))


def make_ca(common_name: str, days: int) -> tuple[PrivateKey, x509.Certificate]:
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    ca_key: PrivateKey, ca_cert: x509.Certificate, names: list[str], days: int
) -> tuple[PrivateKey, x509.Certificate]:
    key = _key()
    sans: list[x509.GeneralName] = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.tools.certs")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ca-name", default="Doctor Firewall Local CA")
    parser.add_argument("--days", type=int, default=825)
    parser.add_argument("--key-mode", choices=["0600", "0644"], default="0600")
    parser.add_argument(
        "--leaf",
        action="append",
        required=True,
        help="name:san1,san2  (e.g. ui:localhost,127.0.0.1)",
    )
    args = parser.parse_args(argv)

    out: Path = args.out
    key_mode = int(args.key_mode, 8)
    out.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = make_ca(args.ca_name, args.days)
    _write_private(out / "ca.key", ca_key, key_mode)
    _write_cert(out / "ca.pem", ca_cert)
    for spec in args.leaf:
        label, _, sans = spec.partition(":")
        names = [s.strip() for s in sans.split(",") if s.strip()]
        if not label or not names:
            parser.error(f"invalid --leaf value: {spec!r}")
        key, cert = make_leaf(ca_key, ca_cert, names, args.days)
        _write_private(out / f"{label}.key", key, key_mode)
        _write_cert(out / f"{label}.pem", cert)
        print(f"wrote {label}.pem for {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
