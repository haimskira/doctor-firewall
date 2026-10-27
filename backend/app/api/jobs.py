"""Background jobs: what is queued or running, how far it is, and how recent runs ended."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from rq.exceptions import NoSuchJobError
from rq.job import Job
from rq.serializers import JSONSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.enforce import DeployWatch
from app.models.jobs import JOB_KINDS, JobRun
from app.runtime import get_redis

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/jobs", tags=["jobs"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
# A run queued this long ago without an RQ job id never reached the queue.
UNQUEUED_AFTER = timedelta(minutes=2)
LOST_STATES = {"failed", "stopped", "canceled"}


class JobOut(BaseModel):
    id: int
    kind: str
    title: str
    requested_by: str
    status: str
    progress: int
    step: str
    step_args: dict[str, Any]
    error: str | None
    snapshot_id: int | None
    batch_id: int | None
    changeset_id: int | None
    created_at: datetime
    started_at: datetime | None
    updated_at: datetime | None
    finished_at: datetime | None


class JobsOut(BaseModel):
    active: int
    rows: list[JobOut]
    # Deployed batches whose after-deploy watch raised an alert (shown in the top bar).
    alerts: int = 0


def _reconcile(db: Session, runs: list[JobRun]) -> None:
    """A run still queued / running whose worker died is failed, not left spinning."""
    now = datetime.now(UTC)
    redis = None
    changed = False
    for run in runs:
        if run.status not in ("queued", "running"):
            continue
        lost: str | None = None
        if run.rq_job_id is None:
            if now - run.created_at > UNQUEUED_AFTER:
                lost = "not_queued"
        else:
            redis = redis or get_redis()
            try:
                state = Job.fetch(run.rq_job_id, connection=redis, serializer=JSONSerializer)
                status = str(state.get_status(refresh=True) or "")
            except NoSuchJobError:
                status = "missing"
            if status in LOST_STATES or status == "missing":
                lost = "worker_lost"
            elif status == "finished":
                lost = "finished_unrecorded"
        if lost is not None:
            log.warning("job run reconciled", extra={"run": run.id, "reason": lost})
            run.status = "failed"
            run.error = lost
            run.finished_at = now
            changed = True
    if changed:
        db.commit()


@router.get("", response_model=JobsOut)
def list_jobs(
    db: DbDep,
    who: ReaderDep,
    state: Literal["active", "finished", "all"] = "all",
    kind: Annotated[str | None, Query(pattern=r"^[a-z_]{1,16}$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 30,
) -> JobsOut:
    """Queued and running jobs first, then the most recent finished ones."""
    visible = [
        k for k in JOB_KINDS if k != "audit_verify" or Permission.AUDIT_READ in who.permissions
    ]
    base = select(JobRun).where(JobRun.kind.in_(visible))
    if kind is not None:
        base = base.where(JobRun.kind == kind)
    active = list(
        db.scalars(base.where(JobRun.status.in_(("queued", "running"))).order_by(JobRun.id.desc()))
    )
    _reconcile(db, active)
    active = [r for r in active if r.status in ("queued", "running")]
    rows: list[JobRun] = []
    if state != "finished":
        rows += active[:limit]
    if state != "active":
        rows += list(
            db.scalars(
                base.where(JobRun.status.in_(("done", "failed")))
                .order_by(JobRun.id.desc())
                .limit(max(0, limit - len(rows)))
            )
        )
    alerts = db.scalar(
        select(func.count()).select_from(DeployWatch).where(DeployWatch.status == "alert")
    )
    return JobsOut(
        active=len(active),
        rows=[JobOut.model_validate(r, from_attributes=True) for r in rows],
        alerts=alerts or 0,
    )
