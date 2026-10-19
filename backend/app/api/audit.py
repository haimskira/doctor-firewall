from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import AuditRecordResponse, AuditVerifyResponse
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.audit import AuditRecord
from app.runtime import get_audit

router = APIRouter(prefix="/api/audit", tags=["audit"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.AUDIT_READ))]


@router.get("", response_model=list[AuditRecordResponse])
def list_audit(
    db: DbDep,
    _: ReaderDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> list[AuditRecordResponse]:
    query = select(AuditRecord).order_by(AuditRecord.id.desc()).limit(limit)
    if before_id is not None:
        query = query.where(AuditRecord.id < before_id)
    return [
        AuditRecordResponse(
            id=r.id,
            ts=r.ts,
            actor=r.actor,
            action=r.action,
            outcome=r.outcome,
            cluster=r.cluster,
            target=r.target,
            source_ip=r.source_ip,
            details=r.details,
        )
        for r in db.scalars(query)
    ]


@router.post("/verify", response_model=AuditVerifyResponse)
def verify_audit(
    request: Request,
    db: DbDep,
    principal: ReaderDep,
    audit: Annotated[AuditLog, Depends(get_audit)],
) -> AuditVerifyResponse:
    result = audit.verify(db)
    audit.record(
        db,
        AuditEvent(
            actor=principal.username,
            actor_id=principal.user_id,
            action="audit.verify",
            outcome="success" if result.ok else "failure",
            source_ip=client_ip(request),
            details={"checked": result.checked, "broken_at_id": result.broken_at_id},
        ),
    )
    db.commit()
    return AuditVerifyResponse(
        ok=result.ok,
        checked=result.checked,
        head_id=result.head_id,
        head_hash=result.head_hash,
        broken_at_id=result.broken_at_id,
        reason=result.reason,
    )
