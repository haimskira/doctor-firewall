from __future__ import annotations

import pytest

from app.fmc.validation import host_for_url, validate_host


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("fmc.corp.local", "fmc.corp.local"),
        ("FMC-VIP", "fmc-vip"),
        ("10.1.2.3", "10.1.2.3"),
        ("fd00::1", "fd00::1"),
        ("fmc.corp.local.", "fmc.corp.local."),
    ],
)
def test_valid_hosts(value: str, expected: str) -> None:
    assert validate_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://fmc",
        "fmc:443",
        "user@fmc",
        "fmc/path",
        "-bad.example",
        "a" * 254,
        "fmc corp",
        "fmc_underscore",
        "x" * 64 + ".example",
    ],
)
def test_invalid_hosts(value: str) -> None:
    with pytest.raises(ValueError, match="invalid host"):
        validate_host(value)


def test_host_for_url() -> None:
    assert host_for_url("fd00::1") == "[fd00::1]"
    assert host_for_url("10.0.0.1") == "10.0.0.1"
    assert host_for_url("fmc") == "fmc"
