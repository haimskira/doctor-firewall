"""Password hashing (Argon2id) and local password policy."""

from __future__ import annotations

from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 128  # bounds hashing cost; argon2 itself has no practical limit

_hasher = PasswordHasher()  # argon2id, library defaults (RFC 9106 recommended profile)


class PasswordPolicyError(ValueError):
    pass


def check_policy(password: str, username: str) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_LENGTH} characters")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("password must not contain the username")
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 3:
        raise PasswordPolicyError(
            "password must mix at least three of: lowercase, uppercase, digits, symbols"
        )


def hash_password(password: str) -> str:
    return _hasher.hash(password)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash("timing-equaliser-not-a-real-password")


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-work verification: unknown users still pay the full Argon2 cost."""
    if len(password) > MAX_LENGTH:
        return False
    target = password_hash or _dummy_hash()
    try:
        _hasher.verify(target, password)  # returns True or raises
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
