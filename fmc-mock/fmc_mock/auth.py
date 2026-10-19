"""FMC token lifecycle: generatetoken / refreshtoken / revokeaccess."""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field

MAX_REFRESHES = 3


@dataclass
class _Token:
    refresh: str
    expires_at: float
    refreshes: int = 0


@dataclass
class TokenStore:
    username: str
    password: str
    ttl_seconds: float = 30 * 60
    tokens: dict[str, _Token] = field(default_factory=dict)

    def check_basic(self, header: str | None) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:], validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            return False
        user, sep, password = raw.partition(":")
        if not sep:
            return False
        ok_user = hmac.compare_digest(user.encode(), self.username.encode())
        ok_pass = hmac.compare_digest(password.encode(), self.password.encode())
        return ok_user and ok_pass

    def issue(self, refreshes: int = 0) -> tuple[str, str]:
        access = str(uuid.uuid4())
        refresh = str(uuid.uuid4())
        self.tokens[access] = _Token(refresh, time.monotonic() + self.ttl_seconds, refreshes)
        return access, refresh

    def valid(self, access: str | None) -> bool:
        tok = self.tokens.get(access or "")
        return tok is not None and tok.expires_at > time.monotonic()

    def refresh(self, access: str | None, refresh: str | None) -> tuple[str, str] | None:
        tok = self.tokens.get(access or "")
        if tok is None or not secrets.compare_digest(tok.refresh, refresh or ""):
            return None
        if tok.refreshes >= MAX_REFRESHES:
            return None
        del self.tokens[access or ""]
        return self.issue(tok.refreshes + 1)

    def revoke(self, access: str | None) -> bool:
        return self.tokens.pop(access or "", None) is not None

    def expire_all(self) -> None:
        """Test helper: force every token past its expiry."""
        for tok in self.tokens.values():
            tok.expires_at = 0
