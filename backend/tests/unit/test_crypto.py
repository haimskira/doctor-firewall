from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.core.crypto import (
    DecryptionError,
    Keyring,
    KeyringError,
    SecretBox,
    derive_subkey,
    generate_keyring_json,
    load_keyring,
    parse_keyring,
    zeroize,
)


def test_roundtrip(keyring: Keyring) -> None:
    box = SecretBox(keyring)
    token = box.encrypt(b"s3cret!", "ctx:1")
    assert token.startswith("v1:k1:")
    assert b"s3cret" not in token.encode()
    assert box.decrypt(token, "ctx:1") == bytearray(b"s3cret!")


def test_nonce_is_random(keyring: Keyring) -> None:
    box = SecretBox(keyring)
    assert box.encrypt(b"same", "c") != box.encrypt(b"same", "c")


def test_context_is_bound(keyring: Keyring) -> None:
    box = SecretBox(keyring)
    token = box.encrypt(b"pw", "fmc_connection:1:password")
    with pytest.raises(DecryptionError):
        box.decrypt(token, "fmc_connection:2:password")


def test_tampered_ciphertext_rejected(keyring: Keyring) -> None:
    box = SecretBox(keyring)
    version, key_id, nonce, ct = box.encrypt(b"pw", "c").split(":")
    raw = bytearray(base64.b64decode(ct))
    raw[0] ^= 0x01
    forged = ":".join((version, key_id, nonce, base64.b64encode(bytes(raw)).decode()))
    with pytest.raises(DecryptionError):
        box.decrypt(forged, "c")


@pytest.mark.parametrize(
    "token",
    ["", "v1:k1:abc", "v2:k1:AAAA:AAAA", "v1:k1:!!!:AAAA", "v1:k1:AAAA:AAAA", "v1:nokey:AAAA:AAAA"],
)
def test_malformed_tokens_rejected(keyring: Keyring, token: str) -> None:
    with pytest.raises(DecryptionError):
        SecretBox(keyring).decrypt(token, "c")


def test_rotation(two_key_keyring: tuple[Keyring, Keyring]) -> None:
    old, new = two_key_keyring
    token = SecretBox(old).encrypt(b"pw", "c")
    box = SecretBox(new)
    assert box.needs_rotation(token)
    rotated = box.rotate(token, "c")
    assert box.key_id_of(rotated) == "k2"
    assert not box.needs_rotation(rotated)
    assert box.decrypt(rotated, "c") == bytearray(b"pw")
    # The old keyring alone cannot read the rotated value.
    with pytest.raises(DecryptionError):
        SecretBox(old).decrypt(rotated, "c")


def test_subkeys_are_purpose_separated(keyring: Keyring) -> None:
    master = keyring.active_key
    assert derive_subkey(master, "a") != derive_subkey(master, "b")
    assert derive_subkey(master, "a") == derive_subkey(master, "a")
    assert derive_subkey(master, "a") != master


def test_repr_hides_key_material(keyring: Keyring) -> None:
    text = repr(keyring)
    assert base64.b64encode(keyring.active_key).decode() not in text
    assert "k1" in text


def test_zeroize() -> None:
    buf = bytearray(b"secret")
    zeroize(buf)
    assert buf == bytearray(6)


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        json.dumps([]),
        json.dumps({"active": "k1"}),
        json.dumps({"active": "k1", "keys": {}}),
        json.dumps({"active": "k2", "keys": {"k1": base64.b64encode(b"x" * 32).decode()}}),
        json.dumps({"active": "k1", "keys": {"k1": "%%%"}}),
        json.dumps({"active": "k1", "keys": {"k1": base64.b64encode(b"short").decode()}}),
        json.dumps({"active": "bad id", "keys": {"bad id": base64.b64encode(b"x" * 32).decode()}}),
    ],
)
def test_bad_keyrings_rejected(doc: str) -> None:
    with pytest.raises(KeyringError):
        parse_keyring(doc)


def test_generate_and_load(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    path.write_text(generate_keyring_json("k2026"), encoding="utf-8")
    ring = load_keyring(path)
    assert ring.active_id == "k2026"
    assert len(ring.active_key) == 32
    with pytest.raises(KeyringError):
        generate_keyring_json("bad id!")
    with pytest.raises(KeyringError):
        load_keyring(tmp_path / "missing.json")
