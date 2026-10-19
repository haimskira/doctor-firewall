"""Tamper-evident audit log.

Each record carries ``prev_hash`` (the previous record's hash) and ``record_hash`` =
HMAC-SHA256 over a canonical serialisation of the record, keyed with a subkey derived
from the master keyring. Altering, reordering or removing a row in the middle breaks
the chain; forging a row requires the master key, which the database never sees.

Appends are serialised with a PostgreSQL transaction-scoped advisory lock so two
concurrent writers can never fork the chain. Rows are protected at the database
level as well (no UPDATE/DELETE grant for the runtime role + a rejecting trigger).
Removal of the newest rows is detected by comparing against the head hash that the
periodic verification job writes to the log stream (an external anchor).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import Keyring, derive_subkey
from app.core.logging import scrub_value
from app.models.audit import AuditRecord

GENESIS_HASH = "0" * 64
# Arbitrary constant identifying the audit append lock ("DF_AUDIT" in hex, fits int64).
AUDIT_LOCK_ID = 0x44465F4155444954
_HMAC_PURPOSE = "audit-hmac"

Outcome = Literal["success", "failure", "denied"]


class AuditDetailsError(ValueError):
    """Audit details contain a value that cannot be canonically serialised."""


def _check_json(value: Any, depth: int = 0) -> None:
    # Floats are rejected: their text form can change across a JSONB round-trip,
    # which would make an honest record look tampered.
    if depth > 8:
        raise AuditDetailsError("audit details nested too deeply")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, list):
        for item in value:
            _check_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditDetailsError("audit detail keys must be strings")
            _check_json(item, depth + 1)
        return
    raise AuditDetailsError(f"unsupported audit detail type: {type(value).__name__}")


@dataclass(frozen=True)
class AuditEvent:
    actor: str
    action: str
    outcome: Outcome
    actor_id: int | None = None
    cluster: str | None = None
    target: str | None = None
    source_ip: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


def _canonical(fields: Mapping[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _record_fields(rec: AuditRecord) -> dict[str, Any]:
    return {
        "ts": rec.ts.astimezone(UTC).isoformat(timespec="microseconds"),
        "actor": rec.actor,
        "actor_id": rec.actor_id,
        "action": rec.action,
        "outcome": rec.outcome,
        "cluster": rec.cluster,
        "target": rec.target,
        "source_ip": rec.source_ip,
        "details": rec.details,
        "key_id": rec.key_id,
        "prev_hash": rec.prev_hash,
    }


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    head_id: int | None
    head_hash: str | None
    broken_at_id: int | None = None
    reason: str | None = None


class AuditLog:
    def __init__(self, keyring: Keyring) -> None:
        self._keyring = keyring

    def _mac(self, key_id: str, fields: Mapping[str, Any]) -> str:
        key = derive_subkey(self._keyring.key(key_id), _HMAC_PURPOSE)
        return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()

    def record(self, session: Session, event: AuditEvent) -> AuditRecord:
        """Append an event inside the caller's transaction (caller commits)."""
        details = {str(k): scrub_value(str(k), v) for k, v in event.details.items()}
        _check_json(details)
        session.execute(select(func.pg_advisory_xact_lock(AUDIT_LOCK_ID)))
        prev = session.scalar(
            select(AuditRecord.record_hash).order_by(AuditRecord.id.desc()).limit(1)
        )
        rec = AuditRecord(
            ts=datetime.now(UTC),
            actor=event.actor[:64],
            actor_id=event.actor_id,
            action=event.action,
            outcome=event.outcome,
            cluster=event.cluster,
            target=event.target[:256] if event.target else None,
            source_ip=event.source_ip,
            details=details,
            key_id=self._keyring.active_id,
            prev_hash=prev or GENESIS_HASH,
        )
        rec.record_hash = self._mac(rec.key_id, _record_fields(rec))
        session.add(rec)
        session.flush()
        return rec

    def verify(self, session: Session, batch_size: int = 1000) -> VerifyResult:
        """Walk the whole chain in id order and recompute every link."""
        expected_prev = GENESIS_HASH
        checked = 0
        last_id: int | None = None
        last_hash: str | None = None
        after_id = 0
        while True:
            rows = session.scalars(
                select(AuditRecord)
                .where(AuditRecord.id > after_id)
                .order_by(AuditRecord.id)
                .limit(batch_size)
            ).all()
            if not rows:
                break
            for rec in rows:
                if rec.prev_hash != expected_prev:
                    return VerifyResult(False, checked, last_id, last_hash, rec.id, "chain_break")
                if rec.key_id not in self._keyring.keys:
                    return VerifyResult(False, checked, last_id, last_hash, rec.id, "unknown_key")
                if not hmac.compare_digest(
                    self._mac(rec.key_id, _record_fields(rec)), rec.record_hash
                ):
                    return VerifyResult(False, checked, last_id, last_hash, rec.id, "bad_hash")
                expected_prev = rec.record_hash
                checked += 1
                last_id, last_hash = rec.id, rec.record_hash
            after_id = rows[-1].id
        return VerifyResult(True, checked, last_id, last_hash)
