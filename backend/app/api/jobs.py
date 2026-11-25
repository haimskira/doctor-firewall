"""Background jobs: what is queued or running, how far it is, and how recent runs ended."""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from redis.exceptions import RedisError
from rq.command import send_stop_job_command
from rq.exceptions import InvalidJobOperation, NoSuchJobError
from rq.job import Job
from rq.serializers import JSONSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission, Role
from app.db.session import get_db
from app.models.enforce import DeployWatch
from app.models.inventory import Snapshot
from app.models.jobs import JOB_KINDS, JobRun
from app.runtime import get_audit, get_redis
from app.workers import cancel

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/jobs", tags=["jobs"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
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
    # Whether the caller may cancel this run (queued or running, and allowed to start its kind).
    can_cancel: bool = False


class JobsOut(BaseModel):
    active: int
    rows: list[JobOut]
    # Deployed batches whose after-deploy watch raised an alert (shown in the top bar).
    alerts: int = 0


# Who may cancel a run: whoever may start that kind of job. Admin-only for the rest.
WRITE_KINDS = frozenset({"batch", "rollback", "revert"})
READ_ONLY_KINDS = frozenset({"collect", "analyze", "proof", "audit_verify"})


def may_cancel(who: Principal, kind: str) -> bool:
    if kind in WRITE_KINDS:
        return Permission.DEPLOY_APPROVE in who.permissions
    if kind in ("collect", "analyze"):
        return Permission.COLLECT_RUN in who.permissions
    return Role.ADMIN in who.roles


def _out(run: JobRun, who: Principal) -> JobOut:
    out = JobOut.model_validate(run, from_attributes=True)
    out.can_cancel = run.status in ("queued", "running") and may_cancel(who, run.kind)
    return out


class CancelOut(BaseModel):
    run_id: int
    # cancelled: ended now (queued job removed, or read-only job stopped).
    # requested: a write job was told to stop at its next safe point.
    result: Literal["cancelled", "requested"]
    # The FMC deployment (or the undo) already started: it cannot be aborted, so the request
    # takes effect only if the run had not reached it.
    deploy_started: bool = False


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
                raw = state.get_status(refresh=True)
                # JobStatus is a str Enum: str() gives "JobStatus.FAILED", its value "failed".
                status = str(getattr(raw, "value", raw) or "")
            except NoSuchJobError:
                status = "missing"
            except RedisError:
                # Redis unreachable: the queue's state is unknown, so nothing is reconciled
                # now (the list itself comes from the database and is still shown).
                log.warning("job reconcile skipped: redis unavailable")
                break
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
                base.where(JobRun.status.in_(("done", "failed", "cancelled")))
                .order_by(JobRun.id.desc())
                .limit(max(0, limit - len(rows)))
            )
        )
    alerts = db.scalar(
        select(func.count()).select_from(DeployWatch).where(DeployWatch.status == "alert")
    )
    return JobsOut(
        active=len(active),
        rows=[_out(r, who) for r in rows],
        alerts=alerts or 0,
    )


def _rq_job(redis: Any, run: JobRun) -> Job | None:
    if run.rq_job_id is None:
        return None
    try:
        return Job.fetch(run.rq_job_id, connection=redis, serializer=JSONSerializer)
    except NoSuchJobError:
        return None


@router.post("/{run_id}/cancel", response_model=CancelOut)
def cancel_run(
    run_id: int, request: Request, db: DbDep, audit: AuditDep, who: ReaderDep
) -> CancelOut:
    """Cancel a queued or running job.

    Queued: removed from the queue. Read-only jobs (collection, analysis, proof): stopped now;
    a stopped collection ends failed and resumable. Jobs that write to the FMC are never killed:
    a flag makes them stop at the next safe point (before a write, before verification, before
    the deployment starts; between batches of a revert) and roll back through the normal path.
    """
    run = db.get(JobRun, run_id, with_for_update=True)
    if run is None or (run.kind == "audit_verify" and Permission.AUDIT_READ not in who.permissions):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if not may_cancel(who, run.kind):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
    if run.status not in ("queued", "running"):
        raise HTTPException(status.HTTP_409_CONFLICT, "not_cancellable")
    redis = get_redis()
    queued = run.status == "queued"
    deploy_started = not queued and run.step in ("deploying", "rolling_back")
    if run.kind in WRITE_KINDS:
        # The job looks at the flag itself; a queued one is also taken off the queue.
        cancel.request(redis, run.id, who.username)
        if queued:
            job = _rq_job(redis, run)
            if job is not None:
                try:
                    job.cancel()
                except InvalidJobOperation:
                    pass  # a worker took it just now: the flag stops it
                else:
                    _end(run)
        result: Literal["cancelled", "requested"] = (
            "cancelled" if run.status == "cancelled" else "requested"
        )
    else:
        if not queued and run.rq_job_id is not None:
            # It may have ended meanwhile; the run is still recorded as cancelled.
            with contextlib.suppress(InvalidJobOperation, NoSuchJobError):
                send_stop_job_command(redis, run.rq_job_id)
        elif queued:
            job = _rq_job(redis, run)
            if job is not None:
                with contextlib.suppress(InvalidJobOperation):
                    job.cancel()
        _end(run)
        _fail_snapshot(db, run)
        result = "cancelled"
    audit.record(
        db,
        AuditEvent(
            actor=who.username,
            actor_id=who.user_id,
            action="job.cancel",
            outcome="success",
            target=run.title[:256],
            source_ip=client_ip(request),
            details={
                "run_id": run.id,
                "kind": run.kind,
                "was": "queued" if queued else "running",
                "result": result,
                "batch_id": run.batch_id,
                "changeset_id": run.changeset_id,
                "snapshot_id": run.snapshot_id,
            },
        ),
    )
    db.commit()
    return CancelOut(run_id=run.id, result=result, deploy_started=deploy_started)


def _end(run: JobRun) -> None:
    run.status, run.error, run.finished_at = "cancelled", "cancelled", datetime.now(UTC)
    run.step, run.step_args = "cancelled", {}


def _fail_snapshot(db: Session, run: JobRun) -> None:
    """A cancelled collection leaves its snapshot failed (resumable), never pending / running."""
    if run.kind != "collect" or run.snapshot_id is None:
        return
    snap = db.get(Snapshot, run.snapshot_id, with_for_update=True)
    if snap is not None and snap.status in ("pending", "running"):
        snap.status, snap.error, snap.error_detail = "failed", "cancelled", None
        snap.finished_at = datetime.now(UTC)
