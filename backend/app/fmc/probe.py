"""Connection test: authenticate, read the server version, revoke. Read-only."""

from __future__ import annotations

import ssl
from dataclasses import dataclass

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.fmc.client import FmcSession, PasswordProvider
from app.fmc.errors import FmcProtocolError

SERVER_VERSION_PATH = "/api/fmc_platform/v1/info/serverversion"


class _ServerVersionItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    server_version: str = Field(alias="serverVersion", min_length=1, max_length=128)


class _ServerVersionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: list[_ServerVersionItem] = Field(min_length=1, max_length=16)


@dataclass(frozen=True)
class ProbeResult:
    server_version: str
    domain_uuid: str


async def probe(
    *,
    host: str,
    port: int,
    username: str,
    password_provider: PasswordProvider,
    ssl_context: ssl.SSLContext,
    timeout: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ProbeResult:
    async with FmcSession(
        host=host,
        port=port,
        username=username,
        password_provider=password_provider,
        ssl_context=ssl_context,
        timeout=timeout,
        transport=transport,
    ) as session:
        raw = await session.get_json(SERVER_VERSION_PATH)
        try:
            parsed = _ServerVersionResponse.model_validate(raw)
        except ValidationError as exc:
            raise FmcProtocolError("serverversion response failed validation") from exc
        return ProbeResult(
            server_version=parsed.items[0].server_version,
            domain_uuid=session.domain_uuid,
        )
