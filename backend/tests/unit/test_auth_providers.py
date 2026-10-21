"""External sign-in providers: TACACS+ against a local fake server, LDAP against ldap3's mock."""

from __future__ import annotations

import hashlib
import socket
import struct
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from ldap3 import MOCK_SYNC, Connection, Server

from app.auth.providers import tacacs
from app.auth.providers.external import ProviderUnavailableError
from app.auth.providers.ldap import LdapProvider
from app.core.config import Settings

SECRET = "tacacs-shared-secret"


# ------------------------------------------------------------------ TACACS+


def test_obfuscation_matches_the_rfc_pad() -> None:
    body = b"x" * 40
    session, key, version, seq = 0x01020304, b"k", 0xC1, 1
    seed = struct.pack("!I", session) + key + bytes([version, seq])
    first = hashlib.md5(seed, usedforsecurity=False).digest()
    second = hashlib.md5(seed + first, usedforsecurity=False).digest()
    third = hashlib.md5(seed + second, usedforsecurity=False).digest()
    pad = first + second + third
    expected = bytes(a ^ b for a, b in zip(body, pad, strict=False))
    assert tacacs.obfuscate(body, session, key, version, seq) == expected
    assert tacacs.obfuscate(expected, session, key, version, seq) == body


def test_roles_from_attributes() -> None:
    args = ["service=shell", "df-role=optimizer, approver", "priv-lvl=1", "df-role*admin"]
    assert tacacs.roles_from(args, "df-role") == {"optimizer", "approver", "admin"}
    assert tacacs.roles_from(["df-role=superuser"], "df-role") == frozenset()
    assert tacacs.roles_from(["other=admin"], "df-role") == frozenset()


Reply = Callable[[tacacs.Packet], bytes | None]


class FakeTacacs:
    """A TACACS+ server: checks the request layout and answers like ISE."""

    def __init__(self, users: dict[str, tuple[str, list[str]]], secret: str = SECRET) -> None:
        self.users = users
        self.key = secret.encode()
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen: list[tuple[int, int]] = []  # (type, minor version)
        self.author_args: list[list[str]] = []
        self.unobfuscated = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except (
                    OSError,
                    ProviderUnavailableError,
                    ValueError,
                    KeyError,
                    IndexError,
                    AssertionError,
                    struct.error,
                ):
                    continue  # garbage (e.g. another secret): drop the connection

    def _handle(self, conn: socket.socket) -> None:
        request = tacacs.read_packet(conn, self.key)
        self.seen.append((request.type, request.version & 0x0F))
        body = request.body
        if request.type == tacacs.TYPE_AUTHEN:
            action, _priv, authen_type, _svc, ulen, plen, rlen, dlen = body[:8]
            assert (action, authen_type) == (tacacs.AUTHEN_LOGIN, tacacs.AUTHEN_TYPE_PAP)
            user = body[8 : 8 + ulen].decode()
            password = body[8 + ulen + plen + rlen : 8 + ulen + plen + rlen + dlen].decode()
            ok = user in self.users and self.users[user][0] == password
            status = tacacs.AUTHEN_STATUS_PASS if ok else tacacs.AUTHEN_STATUS_FAIL
            reply = struct.pack("!BBHH", status, 0, 0, 0)
        else:
            count = body[7]
            lengths = body[8 : 8 + count]
            ulen, plen, rlen = body[4], body[5], body[6]
            user = body[8 + count : 8 + count + ulen].decode()
            offset = 8 + count + ulen + plen + rlen
            sent = []
            for size in lengths:
                sent.append(body[offset : offset + size].decode())
                offset += size
            self.author_args.append(sent)
            args = self.users.get(user, ("", []))[1]
            encoded = [a.encode() for a in args]
            status = tacacs.AUTHOR_STATUS_PASS_ADD if user in self.users else 0x10
            assert sum(lengths) > 0  # service=... was sent
            reply = (
                struct.pack("!BBHH", status, len(encoded), 0, 0)
                + bytes(len(a) for a in encoded)
                + b"".join(encoded)
            )
        flags = tacacs.FLAG_UNENCRYPTED if self.unobfuscated else 0
        packet = tacacs.Packet(request.version, request.type, 2, flags, request.session_id, reply)
        data = (
            tacacs.HEADER.pack(packet.version, packet.type, 2, flags, packet.session_id, len(reply))
            + reply
            if self.unobfuscated
            else tacacs.encode(packet, self.key)
        )
        conn.sendall(data)

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "tacacs_secret"
    path.write_text(SECRET + "\n", encoding="utf-8")
    return path


@pytest.fixture
def server() -> Iterator[FakeTacacs]:
    fake = FakeTacacs(
        {
            "alice": ("Alice-Pass-1", ["service=shell", "df-role=optimizer,approver"]),
            "bob": ("Bob-Pass-1", ["service=shell", "priv-lvl=15"]),
        }
    )
    yield fake
    fake.close()


def _tacacs_settings(port: int, secret_file: Path, **extra: Any) -> Settings:
    return Settings(
        auth_providers="local,tacacs",
        tacacs_host="127.0.0.1",
        tacacs_port=port,
        tacacs_secret_file=secret_file,
        tacacs_timeout_seconds=3,
        **extra,
    )


def test_tacacs_pap_and_roles(server: FakeTacacs, secret_file: Path) -> None:
    provider = tacacs.TacacsProvider(_tacacs_settings(server.port, secret_file), "10.1.1.9")
    alice = provider.verify("alice", "Alice-Pass-1")
    assert alice is not None
    assert alice.roles == frozenset({"optimizer", "approver"})
    # PAP uses minor version 1; authorization the default, asking like an exec shell start.
    assert server.seen == [(tacacs.TYPE_AUTHEN, 1), (tacacs.TYPE_AUTHOR, 0)]
    assert server.author_args == [["service=shell", "cmd*"]]
    assert provider.verify("alice", "wrong") is None
    bob = provider.verify("bob", "Bob-Pass-1")
    assert bob is not None
    assert bob.roles == frozenset()  # authorised, but no Doctor Firewall role
    assert provider.verify("alice", "") is None


def test_tacacs_roles_stay_local_without_attribute(server: FakeTacacs, secret_file: Path) -> None:
    settings = _tacacs_settings(server.port, secret_file, tacacs_role_attribute="")
    alice = tacacs.TacacsProvider(settings).verify("alice", "Alice-Pass-1")
    assert alice is not None
    assert alice.roles is None
    assert server.seen == [(tacacs.TYPE_AUTHEN, 1)]  # no authorization request


def test_tacacs_rejects_bad_replies(server: FakeTacacs, secret_file: Path, tmp_path: Path) -> None:
    server.unobfuscated = True
    provider = tacacs.TacacsProvider(_tacacs_settings(server.port, secret_file))
    with pytest.raises(ProviderUnavailableError, match="not obfuscated"):
        provider.verify("alice", "Alice-Pass-1")
    server.unobfuscated = False
    # A different shared secret: the server cannot read the request.
    other = tmp_path / "other"
    other.write_text("not-the-secret", encoding="utf-8")
    with pytest.raises(ProviderUnavailableError):
        tacacs.TacacsProvider(_tacacs_settings(server.port, other)).verify("alice", "Alice-Pass-1")
    closed = socket.create_server(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(ProviderUnavailableError, match="unreachable"):
        tacacs.TacacsProvider(_tacacs_settings(port, secret_file)).verify("alice", "x")


# ------------------------------------------------------------------ LDAP

BASE = "dc=corp,dc=local"
SVC = "cn=svc-df,ou=service,dc=corp,dc=local"
GROUP_OPT = "CN=DF-Optimizers,OU=Groups,DC=corp,DC=local"
GROUP_ADMIN = "CN=DF-Admins,OU=Groups,DC=corp,DC=local"


@pytest.fixture
def directory(tmp_path: Path) -> tuple[Settings, Callable[[str, str], Connection]]:
    server = Server("fake-ad")

    def connect(user: str, password: str) -> Connection:
        return Connection(
            server, user=user, password=password, client_strategy=MOCK_SYNC, raise_exceptions=False
        )

    seed = connect(SVC, "Svc-Pass-1")
    seed.strategy.add_entry(SVC, {"objectClass": "person", "userPassword": "Svc-Pass-1"})

    def person(cn: str, sam: str, password: str, groups: list[str]) -> None:
        seed.strategy.add_entry(
            f"cn={cn},ou=people,{BASE}",
            {
                "objectClass": "user",
                "sAMAccountName": sam,
                "userPassword": password,
                "displayName": cn.title(),
                "memberOf": groups,
            },
        )

    person("dana", "dana", "Dana-Pass-1", [f" {GROUP_OPT.lower()} ", "CN=Other,DC=corp,DC=local"])
    person("eli", "eli", "Eli-Pass-1", [])
    person("twin one", "twin", "Twin-Pass-1", [GROUP_ADMIN])
    person("twin two", "twin", "Twin-Pass-2", [GROUP_ADMIN])
    password_file = tmp_path / "ldap_bind_password"
    password_file.write_text("Svc-Pass-1", encoding="utf-8")
    settings = Settings(
        auth_providers="local,ldap",
        ldap_url="ldaps://dc1.corp.local",
        ldap_bind_dn=SVC,
        ldap_bind_password_file=password_file,
        ldap_user_base=BASE,
        ldap_group_roles=f"optimizer={GROUP_OPT};admin={GROUP_ADMIN}",
    )
    return settings, connect


def test_ldap_bind_search_bind_and_group_roles(
    directory: tuple[Settings, Callable[[str, str], Connection]],
) -> None:
    settings, connect = directory
    provider = LdapProvider(settings, connect)
    dana = provider.verify("dana", "Dana-Pass-1")
    assert dana is not None
    assert (dana.roles, dana.display_name) == (frozenset({"optimizer"}), "Dana")
    assert provider.verify("dana", "wrong") is None
    assert provider.verify("dana", "") is None  # never an unauthenticated bind
    assert provider.verify("nobody", "x") is None
    eli = provider.verify("eli", "Eli-Pass-1")
    assert eli is not None
    assert eli.roles == frozenset()
    assert provider.verify("twin", "Twin-Pass-1") is None  # ambiguous: never guess
    assert provider.verify("*", "Dana-Pass-1") is None  # the filter value is escaped


def test_ldap_without_group_mapping_and_service_failure(
    directory: tuple[Settings, Callable[[str, str], Connection]], tmp_path: Path
) -> None:
    settings, connect = directory
    plain = settings.model_copy(update={"ldap_group_roles": ""})
    dana = LdapProvider(plain, connect).verify("dana", "Dana-Pass-1")
    assert dana is not None
    assert dana.roles is None
    wrong = tmp_path / "wrong"
    wrong.write_text("nope", encoding="utf-8")
    broken = settings.model_copy(update={"ldap_bind_password_file": wrong})
    with pytest.raises(ProviderUnavailableError, match="service account"):
        LdapProvider(broken, connect).verify("dana", "Dana-Pass-1")


# ------------------------------------------------------------------ configuration


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"auth_providers": "local,radius"}, "unknown auth provider"),
        ({"auth_providers": "ldap", "ldap_url": "ldap://dc1"}, "plain LDAP is refused"),
        ({"auth_providers": "ldap", "ldap_url": "https://dc1"}, "DF_LDAP_URL"),
        (
            {"auth_providers": "ldap", "ldap_url": "ldaps://dc1", "ldap_bind_dn": SVC},
            "DF_LDAP_USER_BASE",
        ),
        (
            {
                "auth_providers": "ldap",
                "ldap_url": "ldaps://dc1",
                "ldap_bind_dn": SVC,
                "ldap_user_base": BASE,
                "ldap_user_filter": "(uid=fixed)",
            },
            "DF_LDAP_USER_FILTER",
        ),
        (
            {
                "auth_providers": "ldap",
                "ldap_url": "ldaps://dc1",
                "ldap_bind_dn": SVC,
                "ldap_user_base": BASE,
                "ldap_group_roles": f"root={GROUP_ADMIN}",
            },
            "DF_LDAP_GROUP_ROLES",
        ),
        ({"auth_providers": "tacacs"}, "DF_TACACS_HOST"),
    ],
)
def test_auth_configuration_is_validated(values: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings(**values)


def test_start_tls_allows_ldap_scheme() -> None:
    settings = Settings(
        auth_providers="ldap",
        ldap_url="ldap://dc1.corp.local",
        ldap_start_tls=True,
        ldap_bind_dn=SVC,
        ldap_user_base=BASE,
        ldap_group_roles=f"admin={GROUP_ADMIN} ; optimizer = {GROUP_OPT}",
    )
    assert settings.providers == ("ldap",)
    assert settings.ldap_role_groups["optimizer"] == {GROUP_OPT.lower()}
