from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import REDACTED, JsonFormatter, configure_logging, scrub_text, scrub_value


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("X-auth-access-token: 1f2e3d4c-aaaa-bbbb", "1f2e3d4c-aaaa-bbbb"),
        ("x-auth-refresh-token=abcdef123456", "abcdef123456"),
        ("Authorization: Basic YXBpOnBhc3N3b3Jk", "YXBpOnBhc3N3b3Jk"),
        ("got Bearer eyJhbGciOiJIUzI1NiJ9.abc", "eyJhbGciOiJIUzI1NiJ9"),
        ('password="hunter2 hunter2"', "hunter2"),
        ("postgresql://df_app:TopSecret@db:5432/x", "TopSecret"),
        ("cookie: __Host-df_session=abcdefgh", "abcdefgh"),
    ],
)
def test_scrub_text(text: str, secret: str) -> None:
    out = scrub_text(text)
    assert secret not in out
    assert REDACTED in out


def test_scrub_text_leaves_normal_text() -> None:
    assert scrub_text("rule 14 shadowed by rule 3") == "rule 14 shadowed by rule 3"


def test_scrub_value_by_key() -> None:
    doc = {"user": "bob", "password": "x", "nested": {"api_token": "y", "n": 3}, "list": ["ok"]}
    assert scrub_value("doc", doc) == {
        "user": "bob",
        "password": REDACTED,
        "nested": {"api_token": REDACTED, "n": 3},
        "list": ["ok"],
    }


def test_formatter_masks_extra_and_exceptions() -> None:
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "login for %s", ("bob",), None)
    record.password = "hunter2"
    record.request_id = "abc"
    try:
        raise ValueError("Authorization: Basic c2VjcmV0c2VjcmV0")
    except ValueError:
        import sys

        record.exc_info = sys.exc_info()
    out = json.loads(JsonFormatter().format(record))
    assert out["msg"] == "login for bob"
    assert out["password"] == REDACTED
    assert out["request_id"] == "abc"
    assert "c2VjcmV0c2VjcmV0" not in out["exc"]


def test_configure_logging_installs_json_handler() -> None:
    configure_logging("INFO")
    root = logging.getLogger()
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
    assert logging.getLogger("httpx").level == logging.WARNING
