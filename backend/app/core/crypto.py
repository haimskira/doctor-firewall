"""Keyring, authenticated encryption for stored secrets, and key derivation.

Keyring file format (a Docker secret, never in Git)::

    {"active": "k2026a", "keys": {"k2026a": "<base64 32 bytes>", "k2025b": "<...>"}}

* ``active`` encrypts new values; every key in ``keys`` can still decrypt.
* Rotation: add a new key, make it ``active``, run ``python -m app.cli rotate-secrets``
  (re-encrypts every stored secret), then remove the retired key from encryption use.
  Retired keys must stay in the file as long as audit rows signed with them must
  remain verifiable (see :mod:`app.audit.chain`).

The master key is never used directly: purpose-specific subkeys are derived with
HKDF-SHA256, so the encryption key and the audit HMAC key are independent.

Python cannot guarantee memory scrubbing (immutable ``str``/``bytes`` may be copied
by the runtime). Decrypted values are therefore returned as ``bytearray`` so the
caller can :func:`zeroize` them as soon as they are no longer needed, and plaintext
is never cached.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
NONCE_BYTES = 12
CIPHERTEXT_FORMAT = "v1"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class KeyringError(RuntimeError):
    """The keyring file is missing or malformed."""


class DecryptionError(RuntimeError):
    """A ciphertext could not be authenticated or decrypted."""


def zeroize(buf: bytearray) -> None:
    """Overwrite a mutable buffer in place."""
    for i in range(len(buf)):
        buf[i] = 0


@dataclass(frozen=True)
class Keyring:
    active_id: str
    keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        if self.active_id not in self.keys:
            raise KeyringError("active key id is not present in keyring")
        for key_id, key in self.keys.items():
            if not _KEY_ID_RE.fullmatch(key_id):
                raise KeyringError("invalid key id in keyring")
            if len(key) != KEY_BYTES:
                raise KeyringError(f"key {key_id} must be exactly {KEY_BYTES} bytes")

    def __repr__(self) -> str:  # never print key material
        return f"Keyring(active_id={self.active_id!r}, key_ids={sorted(self.keys)!r})"

    def key(self, key_id: str) -> bytes:
        try:
            return self.keys[key_id]
        except KeyError as exc:
            raise DecryptionError("unknown key id") from exc

    @property
    def active_key(self) -> bytes:
        return self.keys[self.active_id]


def parse_keyring(raw: str) -> Keyring:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KeyringError("keyring is not valid JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("active"), str):
        raise KeyringError("keyring must contain an 'active' key id")
    raw_keys = doc.get("keys")
    if not isinstance(raw_keys, dict) or not raw_keys:
        raise KeyringError("keyring must contain a non-empty 'keys' object")
    keys: dict[str, bytes] = {}
    for key_id, encoded in raw_keys.items():
        if not isinstance(key_id, str) or not isinstance(encoded, str):
            raise KeyringError("keyring entries must be strings")
        try:
            keys[key_id] = base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise KeyringError(f"key {key_id} is not valid base64") from exc
    return Keyring(active_id=doc["active"], keys=MappingProxyType(keys))


def load_keyring(path: Path) -> Keyring:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyringError(f"cannot read keyring file {path}") from exc
    return parse_keyring(raw)


def generate_keyring_json(key_id: str) -> str:
    """Return a fresh single-key keyring document (used by init-secrets)."""
    if not _KEY_ID_RE.fullmatch(key_id):
        raise KeyringError("invalid key id")
    key = base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return json.dumps({"active": key_id, "keys": {key_id: key}}, indent=2)


def derive_subkey(master: bytes, purpose: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=f"doctor-firewall:{purpose}".encode(),
    )
    return hkdf.derive(master)


class SecretBox:
    """AES-256-GCM encryption of small secrets, bound to a context string.

    Token format: ``v1:<key_id>:<b64 nonce>:<b64 ciphertext+tag>``. The context
    (e.g. ``"fmc_connection:3:password"``) is authenticated as associated data, so
    a ciphertext copied to another row or column fails to decrypt.
    """

    _PURPOSE = "secretbox"

    def __init__(self, keyring: Keyring) -> None:
        self._keyring = keyring

    def _aead(self, key_id: str) -> AESGCM:
        return AESGCM(derive_subkey(self._keyring.key(key_id), self._PURPOSE))

    def encrypt(self, plaintext: bytes | bytearray, context: str) -> str:
        key_id = self._keyring.active_id
        nonce = os.urandom(NONCE_BYTES)
        ct = self._aead(key_id).encrypt(nonce, bytes(plaintext), context.encode())
        return ":".join(
            (
                CIPHERTEXT_FORMAT,
                key_id,
                base64.b64encode(nonce).decode("ascii"),
                base64.b64encode(ct).decode("ascii"),
            )
        )

    def decrypt(self, token: str, context: str) -> bytearray:
        parts = token.split(":")
        if len(parts) != 4 or parts[0] != CIPHERTEXT_FORMAT:
            raise DecryptionError("malformed ciphertext")
        _, key_id, nonce_b64, ct_b64 = parts
        try:
            nonce = base64.b64decode(nonce_b64, validate=True)
            ct = base64.b64decode(ct_b64, validate=True)
        except binascii.Error as exc:
            raise DecryptionError("malformed ciphertext") from exc
        if len(nonce) != NONCE_BYTES:
            raise DecryptionError("malformed ciphertext")
        try:
            return bytearray(self._aead(key_id).decrypt(nonce, ct, context.encode()))
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc

    def key_id_of(self, token: str) -> str:
        parts = token.split(":")
        if len(parts) != 4 or parts[0] != CIPHERTEXT_FORMAT:
            raise DecryptionError("malformed ciphertext")
        return parts[1]

    def needs_rotation(self, token: str) -> bool:
        return self.key_id_of(token) != self._keyring.active_id

    def rotate(self, token: str, context: str) -> str:
        plaintext = self.decrypt(token, context)
        try:
            return self.encrypt(plaintext, context)
        finally:
            zeroize(plaintext)
