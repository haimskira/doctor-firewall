"""TACACS+ sign-in (RFC 8907), e.g. against Cisco ISE.

Authentication: one ``START`` (PAP: user and password) per TCP connection, answered by
``PASS`` / ``FAIL``. Authorization (when ``DF_TACACS_ROLE_ATTRIBUTE`` is set): one
``REQUEST`` for ``service=<DF_TACACS_SERVICE>``; the roles come from the attribute in the
reply (e.g. an ISE TACACS profile with the custom attribute ``df-role=optimizer,approver``).

The body is obfuscated with the shared secret (MD5 pad, RFC 8907 §4.5). This is
*obfuscation*, not encryption: run TACACS+ on the management network only. Replies that are
not obfuscated, belong to another session or are malformed are rejected.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import struct
from dataclasses import dataclass

from app.auth.providers.external import ExternalIdentity, ProviderUnavailableError
from app.core.config import ROLES, SecretFileError, Settings, read_secret_file

HEADER = struct.Struct("!BBBBII")  # version, type, seq_no, flags, session_id, length
MAJOR = 0xC
MINOR_DEFAULT, MINOR_ONE = 0x0, 0x1  # PAP needs minor version 1
TYPE_AUTHEN, TYPE_AUTHOR = 0x01, 0x02
FLAG_UNENCRYPTED = 0x01
MAX_BODY = 65_536

AUTHEN_LOGIN = 0x01
AUTHEN_TYPE_PAP = 0x02
AUTHEN_SVC_LOGIN = 0x01
PRIV_LVL_USER = 0x01
AUTHEN_STATUS_PASS, AUTHEN_STATUS_FAIL = 0x01, 0x02
AUTHEN_METH_TACACSPLUS = 0x06
AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL = 0x01, 0x02
PORT = b"doctor-firewall"


def obfuscate(body: bytes, session_id: int, key: bytes, version: int, seq_no: int) -> bytes:
    """XOR with the MD5 pseudo-pad (its own inverse)."""
    if not body:
        return body
    seed = struct.pack("!I", session_id) + key + bytes([version, seq_no])
    pad = b""
    block = b""
    while len(pad) < len(body):
        # MD5 is what the protocol specifies for the pad; it is not used as a security hash.
        block = hashlib.md5(seed + block, usedforsecurity=False).digest()
        pad += block
    return bytes(a ^ b for a, b in zip(body, pad, strict=False))


@dataclass(frozen=True)
class Packet:
    version: int
    type: int
    seq_no: int
    flags: int
    session_id: int
    body: bytes


def encode(packet: Packet, key: bytes) -> bytes:
    body = obfuscate(packet.body, packet.session_id, key, packet.version, packet.seq_no)
    header = HEADER.pack(
        packet.version, packet.type, packet.seq_no, packet.flags, packet.session_id, len(body)
    )
    return header + body


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProviderUnavailableError("TACACS+ connection closed early")
        data += chunk
    return data


def read_packet(sock: socket.socket, key: bytes) -> Packet:
    version, type_, seq_no, flags, session_id, length = HEADER.unpack(
        _read_exact(sock, HEADER.size)
    )
    if version >> 4 != MAJOR or length > MAX_BODY:
        raise ProviderUnavailableError("TACACS+ reply malformed")
    if flags & FLAG_UNENCRYPTED:
        raise ProviderUnavailableError("TACACS+ reply not obfuscated (shared secret not set?)")
    body = obfuscate(_read_exact(sock, length), session_id, key, version, seq_no)
    return Packet(version, type_, seq_no, flags, session_id, body)


def _field(text: str) -> bytes:
    value = text.encode()
    if len(value) > 255:
        raise ValueError("TACACS+ field longer than 255 bytes")
    return value


def authen_start(username: str, password: str, remote: str) -> bytes:
    user, port, rem, data = _field(username), PORT, _field(remote), _field(password)
    return (
        bytes(
            [
                AUTHEN_LOGIN,
                PRIV_LVL_USER,
                AUTHEN_TYPE_PAP,
                AUTHEN_SVC_LOGIN,
                len(user),
                len(port),
                len(rem),
                len(data),
            ]
        )
        + user
        + port
        + rem
        + data
    )


def author_request(username: str, remote: str, args: list[str]) -> bytes:
    user, port, rem = _field(username), PORT, _field(remote)
    encoded = [_field(a) for a in args]
    head = bytes(
        [
            AUTHEN_METH_TACACSPLUS,
            PRIV_LVL_USER,
            AUTHEN_TYPE_PAP,
            AUTHEN_SVC_LOGIN,
            len(user),
            len(port),
            len(rem),
            len(encoded),
        ]
    )
    return head + bytes(len(a) for a in encoded) + user + port + rem + b"".join(encoded)


def parse_authen_reply(body: bytes) -> int:
    if len(body) < 6:
        raise ProviderUnavailableError("TACACS+ authentication reply too short")
    status, _flags, msg_len, data_len = struct.unpack("!BBHH", body[:6])
    if 6 + msg_len + data_len != len(body):
        raise ProviderUnavailableError("TACACS+ authentication reply malformed")
    return int(status)


def parse_author_reply(body: bytes) -> tuple[int, list[str]]:
    if len(body) < 6:
        raise ProviderUnavailableError("TACACS+ authorization reply too short")
    status, arg_cnt, msg_len, data_len = (int(x) for x in struct.unpack("!BBHH", body[:6]))
    lengths = body[6 : 6 + arg_cnt]
    offset = 6 + arg_cnt + msg_len + data_len
    if len(lengths) != arg_cnt or offset + sum(lengths) != len(body):
        raise ProviderUnavailableError("TACACS+ authorization reply malformed")
    args = []
    for size in lengths:
        args.append(body[offset : offset + size].decode("utf-8", "replace"))
        offset += size
    return status, args


def roles_from(args: list[str], attribute: str) -> frozenset[str]:
    """``df-role=optimizer,approver`` (mandatory ``=`` or optional ``*`` pairs)."""
    found: set[str] = set()
    for arg in args:
        for sep in ("=", "*"):
            name, has, value = arg.partition(sep)
            if has and name.strip().lower() == attribute.lower():
                found |= {v.strip().lower() for v in value.split(",")}
                break
    return frozenset(found & set(ROLES))


class TacacsProvider:
    name = "tacacs"

    def __init__(self, settings: Settings, remote: str = "") -> None:
        self.settings = settings
        self.remote = remote[:64]

    def _exchange(self, type_: int, minor: int, body: bytes) -> Packet:
        try:
            key = read_secret_file(self.settings.tacacs_secret_file).encode()
        except SecretFileError as exc:
            raise ProviderUnavailableError("TACACS+ shared secret not set") from exc
        session_id = secrets.randbits(32)
        version = (MAJOR << 4) | minor
        try:
            with socket.create_connection(
                (self.settings.tacacs_host, self.settings.tacacs_port),
                timeout=self.settings.tacacs_timeout_seconds,
            ) as sock:
                sock.sendall(encode(Packet(version, type_, 1, 0, session_id, body), key))
                reply = read_packet(sock, key)
        except OSError as exc:
            raise ProviderUnavailableError("TACACS+ server unreachable") from exc
        if reply.session_id != session_id or reply.seq_no != 2 or reply.type != type_:
            raise ProviderUnavailableError("TACACS+ reply does not match the request")
        return reply

    def _author_args(self) -> list[str]:
        service = self.settings.tacacs_service
        # Like a Cisco device starting an exec shell: ISE matches its shell profiles on this.
        return [f"service={service}", "cmd*"] if service == "shell" else [f"service={service}"]

    def verify(self, username: str, password: str) -> ExternalIdentity | None:
        if not password:
            return None
        reply = self._exchange(
            TYPE_AUTHEN, MINOR_ONE, authen_start(username, password, self.remote)
        )
        status = parse_authen_reply(reply.body)
        if status != AUTHEN_STATUS_PASS:
            return None  # FAIL, or a dialogue (GETDATA, ...) PAP does not continue
        roles: frozenset[str] | None = None
        attribute = self.settings.tacacs_role_attribute
        if attribute:
            reply = self._exchange(
                TYPE_AUTHOR,
                MINOR_DEFAULT,
                author_request(username, self.remote, self._author_args()),
            )
            author_status, args = parse_author_reply(reply.body)
            ok = author_status in (AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL)
            roles = roles_from(args, attribute) if ok else frozenset()
        return ExternalIdentity(username=username, display_name="", roles=roles)
