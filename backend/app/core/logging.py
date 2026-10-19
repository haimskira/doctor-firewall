"""Structured JSON logging with secret masking.

Two layers of protection:

* Structured fields (``extra={...}``) whose key looks sensitive are replaced wholesale.
* Free text (message and exception text) is scrubbed with patterns for the
  credential shapes this system handles (FMC tokens, Basic auth, cookies, passwords).

Code should still never log secrets on purpose; masking is the safety net.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

REDACTED = "***"

_SENSITIVE_KEY_RE = re.compile(
    r"(pass(word)?|secret|token|authorization|cookie|session|csrf|api[_-]?key|private|credential)",
    re.IGNORECASE,
)

_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Credentials after an auth scheme. Must run before the header rule, which would
    # otherwise consume only the scheme word of "Authorization: Basic <creds>".
    (re.compile(r"(?i)\b(basic|bearer)\s+[A-Za-z0-9+/=._-]{6,}"), rf"\1 {REDACTED}"),
    # Header-style "Name: value" / "Name=value" for sensitive names.
    (
        re.compile(
            r"(?i)\b(x-auth-access-token|x-auth-refresh-token|authorization|cookie|set-cookie|"
            r"x-csrf-token|password|passwd|secret|token)(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
    # URL userinfo: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+):[^@\s/]+@"), rf"\1:{REDACTED}@"),
)

# Attributes that every LogRecord has; anything else came from ``extra=``.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
) | {"message", "asctime", "taskName"}


def scrub_text(text: str) -> str:
    for pattern, replacement in _TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def scrub_value(key: str, value: Any) -> Any:
    if _SENSITIVE_KEY_RE.search(key):
        return REDACTED
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {str(k): scrub_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [scrub_value(key, v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return scrub_text(str(value))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": scrub_text(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = scrub_value(key, value)
        if record.exc_info:
            payload["exc"] = scrub_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx logs full request URLs at INFO; keep it at WARNING.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
