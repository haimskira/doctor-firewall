"""Request/response schemas. Every request model forbids unknown fields."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.auth.rbac import Role
from app.fmc.validation import validate_host

USERNAME_PATTERN = r"^[A-Za-z0-9._@-]+$"

Username = Annotated[str, Field(min_length=1, max_length=64, pattern=USERNAME_PATTERN)]
Password = Annotated[str, Field(min_length=1, max_length=128)]
Language = Literal["he", "en"]
Host = Annotated[str, Field(min_length=1, max_length=253), AfterValidator(validate_host)]
ConnectionName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._-]+$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


# ---- auth / self-service ----


class LoginRequest(StrictModel):
    username: Username
    password: Password


class ChangePasswordRequest(StrictModel):
    current_password: Password
    new_password: Password


class PreferencesRequest(StrictModel):
    language: Language


class MeResponse(BaseModel):
    id: int
    username: str
    display_name: str
    roles: list[Role]
    permissions: list[str]
    language: Language
    must_change_password: bool
    csrf_token: str


# ---- users (admin) ----


class UserCreateRequest(StrictModel):
    username: Username
    display_name: Annotated[str, Field(max_length=128)] = ""
    roles: Annotated[list[Role], Field(min_length=1, max_length=4)]
    temporary_password: Password


class UserUpdateRequest(StrictModel):
    display_name: Annotated[str, Field(max_length=128)] | None = None
    roles: Annotated[list[Role], Field(min_length=1, max_length=4)] | None = None
    is_active: bool | None = None


class PasswordResetRequest(StrictModel):
    temporary_password: Password


class UserResponse(BaseModel):
    id: int
    username: str
    display_name: str
    roles: list[Role]
    is_active: bool
    must_change_password: bool
    language: Language
    created_at: datetime
    last_login_at: datetime | None


# ---- FMC connection (admin) ----


class FmcConnectionCreate(StrictModel):
    name: ConnectionName
    host: Host
    port: Annotated[int, Field(ge=1, le=65535)] = 443
    username: Username
    password: Password


class FmcConnectionUpdate(StrictModel):
    name: ConnectionName | None = None
    host: Host | None = None
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    username: Username | None = None
    password: Password | None = None


class FmcConnectionResponse(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    domain_uuid: str | None
    server_version: str | None
    last_test_at: datetime | None
    last_test_ok: bool | None


class FmcTestResponse(BaseModel):
    ok: bool
    server_version: str | None = None
    domain_uuid: str | None = None
    error: str | None = None


# ---- audit ----


class AuditRecordResponse(BaseModel):
    id: int
    ts: datetime
    actor: str
    action: str
    outcome: str
    cluster: str | None
    target: str | None
    source_ip: str | None
    details: dict[str, object]


class AuditVerifyResponse(BaseModel):
    ok: bool
    checked: int
    head_id: int | None
    head_hash: str | None
    broken_at_id: int | None
    reason: str | None
