from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.core.crypto import Keyring, parse_keyring


@pytest.fixture
def keyring() -> Keyring:
    return parse_keyring(
        json.dumps({"active": "k1", "keys": {"k1": base64.b64encode(os.urandom(32)).decode()}})
    )


@pytest.fixture
def two_key_keyring() -> tuple[Keyring, Keyring]:
    """(old, new): ``new`` contains both keys with k2 active."""
    k1 = base64.b64encode(os.urandom(32)).decode()
    k2 = base64.b64encode(os.urandom(32)).decode()
    old = parse_keyring(json.dumps({"active": "k1", "keys": {"k1": k1}}))
    new = parse_keyring(json.dumps({"active": "k2", "keys": {"k1": k1, "k2": k2}}))
    return old, new


@pytest.fixture(autouse=True)
def _fresh_settings() -> None:
    get_settings.cache_clear()


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path
