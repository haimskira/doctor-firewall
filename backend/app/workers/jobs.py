"""Background jobs.

Jobs are plain functions with JSON-serialisable arguments. Only functions listed
in :data:`ALLOWED_JOBS` may be executed by a worker (see :mod:`app.workers.worker`).
"""

from __future__ import annotations

import logging

from app.db.session import get_sessionmaker
from app.runtime import get_audit

log = logging.getLogger(__name__)


def verify_audit_chain() -> dict[str, object]:
    """Recompute the audit hash chain and publish the head hash as an external anchor."""
    with get_sessionmaker()() as session:
        result = get_audit().verify(session)
    payload: dict[str, object] = {
        "ok": result.ok,
        "checked": result.checked,
        "head_id": result.head_id,
        "head_hash": result.head_hash,
        "broken_at_id": result.broken_at_id,
        "reason": result.reason,
    }
    if result.ok:
        log.info("audit chain verified", extra={"audit_anchor": payload})
    else:
        log.error("AUDIT CHAIN INTEGRITY FAILURE", extra={"audit_anchor": payload})
    return payload


ALLOWED_JOBS: frozenset[str] = frozenset({"app.workers.jobs.verify_audit_chain"})
