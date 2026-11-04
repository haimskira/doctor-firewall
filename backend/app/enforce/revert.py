"""Revert a deployed batch: put back exactly what it changed, then deploy.

1. **Nothing changed since.** Every item the batch wrote must still be what it wrote (the
   after-images kept in the journal), every item it deleted must still be absent. Anything else
   — someone edited it in the FMC, another change built on it — stops the revert before any write.
2. **Undo** the journal in reverse (the same idempotent steps as a rollback).
3. **Exactly as before.** Every rule and object reads back as its pre-image, objects the batch
   created are gone, and every touched policy lists its rules in the same order as before the
   batch. Only then is the result deployed; otherwise the batch is left ``failed`` with the reason
   (its remaining steps, or the re-deploy, can be finished from the journal: "resume rollback",
   which ends ``reverted``).

A revert that fails before its first write (FMC unreachable, a read refused) leaves the batch
``deployed``, as it was. A revert marks the batch (a ``revert_started`` result) so an interrupted
one is finished as a revert, never as the rollback of a failed run.

Batches are reverted newest first: a batch can only be reverted when no batch deployed after it
to the same FMC is still in place (rollback to a point = revert every later batch, in order), and
no later batch is running or failed with writes left to undo.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.chain import AuditEvent, AuditLog
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.enforce.batch_proof import model_before
from app.enforce.executor import (
    REVERT_MARKER,
    ROLLBACK_ROUNDS,
    BatchError,
    Writer,
    _connection_and_targets,
    _journal_sink,
    _replace_ids,
    deploy,
)
from app.fmc.adapters import select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError
from app.fmc.probe import server_version
from app.models.enforce import Batch, Changeset
from app.workers import progress

log = logging.getLogger(__name__)
VOLATILE = frozenset({"metadata", "links"})


def _comparable(value: Any) -> Any:
    """An FMC item without the fields the FMC changes on its own (metadata, links)."""
    if isinstance(value, dict):
        return {k: _comparable(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [_comparable(v) for v in value]
    return value


def _undo_left(batch: Batch) -> bool:
    """A failed batch whose writes (or the re-deploy after them) are not all undone."""
    return any(step.get("state") != "undone" for step in batch.journal) or any(
        r.get("op") == "undo_failed" for r in batch.results
    )


def later_batches(db: Session, batch: Batch, cs: Changeset) -> list[dict[str, Any]]:
    """Batches on the same FMC after this one that are still in place (deployed), or that are
    running or failed with writes left to undo (``status`` says which)."""
    if batch.finished_at is None:
        return []
    after = batch.finished_at
    rows = db.execute(
        select(Changeset.id, Changeset.title, Batch)
        .join(Batch, Batch.changeset_id == Changeset.id)
        .where(
            Changeset.connection_id == cs.connection_id,
            Batch.id != batch.id,
            or_(
                and_(Batch.status == "deployed", Batch.finished_at > after),
                Batch.status == "running",
                and_(
                    Batch.status == "failed",
                    or_(Batch.finished_at > after, Batch.started_at > after),
                ),
            ),
        )
        .order_by(Batch.finished_at.desc().nulls_first())
    ).all()
    return [
        {
            "changeset_id": c,
            "title": t,
            "batch": b.seq,
            "status": b.status,
            "at": b.finished_at.isoformat() if b.finished_at else None,
        }
        for c, t, b in rows
        if b.status != "failed" or _undo_left(b)
    ]


def revert_blocker(db: Session, batch: Batch) -> str | None:
    """Why this batch cannot be reverted now (None: it can)."""
    cs = db.get(Changeset, batch.changeset_id)
    if cs is None or batch.status != "deployed":
        return "not_deployed"
    if not batch.journal or any(step.get("state") != "applied" for step in batch.journal):
        return "no_journal"
    if any("after" not in step for step in batch.journal):
        return "deployed_before_history"  # batches deployed before after-images were kept
    later = later_batches(db, batch, cs)
    if any(entry["status"] != "deployed" for entry in later):
        return "later_batch_unfinished"
    if later:
        return "later_batches_first"
    return None


async def _changed_since(writer: Writer, journal: list[dict[str, Any]]) -> list[str]:
    """Items that no longer hold what the batch wrote (or exist again after it deleted them)."""
    changed: list[str] = []
    for n, step in enumerate(journal):
        progress.advance(n, len(journal))
        label = str(step.get("label") or step.get("name") or step.get("path"))
        if step.get("undo") == "recreate":
            if await writer._find(str(step["path"]), str(step["name"])) is not None:
                changed.append(f"{label}: exists again")
            continue
        current = await writer.fmc.get_json(str(step["path"]), allow_not_found=True)
        if current is None:
            changed.append(f"{label}: no longer exists")
        elif _comparable(Writer._clean(current, keep_id=True)) != _comparable(step["after"]):
            changed.append(f"{label}: changed in the FMC since the batch")
    return changed


def _remap_path(path: str, remap: dict[str, str]) -> str:
    for old, new in remap.items():
        path = path.replace(f"/{old}", f"/{new}")
    return path


async def _not_restored(
    writer: Writer, journal: list[dict[str, Any]], before_orders: dict[str, list[str]]
) -> list[str]:
    """Differences from the state before the batch (content of every item, order of rules).

    An item the batch wrote more than once (e.g. a rule's fields, then its inspection) is
    checked against its earliest pre-image only — the later ones are states in between. Objects
    the undo re-created have new ids: expected bodies are compared with those ids mapped.
    """
    remap = {
        str(s["recreates"]): str(s["recreated_as"])
        for s in journal
        if s.get("recreated_as") and s.get("recreates")
    }
    wrong: list[str] = []
    checked: set[str] = set()
    for step in journal:
        label = str(step.get("label") or step.get("name") or step.get("path"))
        kind = step.get("undo")
        if kind == "recreate":
            new_id = step.get("recreated_as")
            key = f"{step['path']}/{new_id}"
        else:
            key = _remap_path(str(step.get("path") or ""), remap)
        if not key or key in checked:
            continue
        checked.add(key)
        if kind == "delete":  # created by the batch
            if await writer.fmc.get_json(key, allow_not_found=True) is not None:
                wrong.append(f"{label}: still exists")
            continue
        current = await writer.fmc.get_json(key, allow_not_found=True)
        if current is None:
            wrong.append(f"{label}: missing")
            continue
        expected = _comparable(_replace_ids(step["body"], remap))
        found = _comparable(Writer._clean(current, keep_id=True))
        if kind == "recreate" or key != step.get("path"):  # a new id: compare without it
            expected = {k: v for k, v in expected.items() if k != "id"}
            found = {k: v for k, v in found.items() if k != "id"}
        if found != expected:
            wrong.append(f"{label}: differs from before the batch")
    for collection, names in before_orders.items():
        now = [
            str(item.get("name"))
            async for _offset, items in writer.fmc.iter_pages(
                collection, params={"expanded": "false"}
            )
            for item in items
        ]
        if now != names:
            wrong.append(f"rule order of {collection.rsplit('/', 2)[-2]}")
    return wrong


def _rule_collections(journal: list[dict[str, Any]]) -> set[str]:
    """The rule collections (one per policy) the batch touched."""
    out: set[str] = set()
    for step in journal:
        path = str(step.get("path") or (step.get("find") or {}).get("path") or "")
        for marker in ("/accessrules", "/prefilterrules"):
            if marker in path:
                out.add(path[: path.index(marker) + len(marker)])
    return out


async def revert_batch(
    batch_id: int,
    *,
    sessions: sessionmaker[Session],
    box: SecretBox,
    audit: AuditLog,
    settings: Settings,
    lock: Callable[[str, int], Awaitable[Callable[[], Awaitable[None]] | None]],
    requested_by: str,
    transport: Any = None,
    poll_seconds: float | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, Any]:
    with sessions.begin() as db:
        b = db.get(Batch, batch_id, with_for_update=True)
        if b is None:
            raise BatchError("not_found")
        blocker = revert_blocker(db, b)
        if blocker is not None:
            return {"ok": False, "error": blocker, "status": b.status}
        cs = db.get(Changeset, b.changeset_id)
        if cs is None:
            raise BatchError("not_found")
        connection, targets = _connection_and_targets(db, cs, b)
        journal = copy.deepcopy(b.journal)
        before = model_before(db, cs.id, b.seq)
        changeset_id, seq, title = cs.id, b.seq, cs.title
        original = (list(b.results), b.started_at)
        # The marker says "being reverted" for good (a resume finishes it as a revert);
        # started_at: a live revert is not offered as a stale run to resume.
        b.status, b.started_at = "running", datetime.now(UTC)
        b.results = [
            *b.results,
            {"op": REVERT_MARKER, "by": requested_by, "at": b.started_at.isoformat()},
        ]
    # The policy before the batch, in order — what every touched rulebase must list again.
    collections = _rule_collections(journal)
    before_orders: dict[str, list[str]] = {}
    for collection in collections:
        policy_id = collection.rsplit("/", 2)[-2]
        policy = before.policies.get(policy_id)
        if policy is not None:
            before_orders[collection] = [r.name for r in policy.rules]

    def still_deployed(error: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Nothing was written: the batch is in place, as it was before the revert."""
        with sessions.begin() as db:
            batch = db.get(Batch, batch_id, with_for_update=True)
            if batch is not None:
                batch.status = "deployed"
                batch.results, batch.started_at = original
        return {"ok": False, "status": "deployed", "error": error, **(extra or {})}

    def finish(
        status: str,
        error: str | None,
        extra: dict[str, Any] | None = None,
        left: list[str] | None = None,
    ) -> dict[str, Any]:
        with sessions.begin() as db:
            batch = db.get(Batch, batch_id, with_for_update=True)
            if batch is not None:
                batch.status = status
                batch.error = error[:512] if error else None
                if status == "reverted":
                    batch.finished_at = datetime.now(UTC)
                if left:
                    # What is left to do (undo steps, or the re-deploy after them): the batch
                    # stays resumable, and the resume ends it "reverted".
                    batch.results = [
                        *(r for r in batch.results if r.get("op") != "undo_failed"),
                        *({"op": "undo_failed", "detail": x[:200]} for x in left),
                    ]
            audit.record(
                db,
                AuditEvent(
                    actor=requested_by,
                    actor_id=None,
                    action=f"changeset.batch_revert_{'ok' if status == 'reverted' else 'failed'}",
                    outcome="success" if status == "reverted" else "failure",
                    target=title[:256],
                    details={
                        "changeset_id": changeset_id,
                        "batch": seq,
                        "error": error,
                        **(extra or {}),
                    },
                ),
            )
        return {"ok": status == "reverted", "status": status, "error": error, **(extra or {})}

    host, port, username, token, context = connection
    try:
        release = await lock(f"df:fmc-write:{host}:{port}", settings.write_lock_ttl_seconds)
    except Exception:
        still_deployed("write_lock_error")
        raise
    if release is None:
        return still_deployed("write_lock_busy")

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

    # check: nothing written yet | undo: writing | undone: every step undone
    stage = "check"
    try:
        async with FmcSession(
            host=host,
            port=port,
            username=username,
            password_provider=password_provider,
            ssl_context=build_ssl_context(settings.fmc_ca_bundle),
            timeout=settings.fmc_timeout_seconds,
            transport=transport,
            throttle=ThrottlePolicy(
                requests_per_minute=settings.fmc_requests_per_minute,
                concurrency=1,
                connect_retries=settings.fmc_connect_retries,
            ),
        ) as fmc:
            adapter = select_adapter(await server_version(fmc))
            writer = Writer(
                fmc=fmc,
                adapter=adapter,
                domain=fmc.domain_uuid,
                undo=journal,
                persist=_journal_sink(sessions, batch_id),
                sleep=sleep,
            )
            progress.phase("revert_check", 2, 25)
            changed = await _changed_since(writer, journal)
            if changed:
                return still_deployed("changed_since", {"items": changed[:50]})
            progress.phase("revert_undo", 25, 65)
            stage = "undo"
            left = await writer.rollback(ROLLBACK_ROUNDS, settings.rollback_retry_seconds)
            if left:
                return finish("failed", "revert_incomplete: " + "; ".join(left)[:400], left=left)
            stage = "undone"
            progress.phase("revert_verify", 65, 75)
            wrong = await _not_restored(writer, journal, before_orders)
            if wrong:
                # Undone, but not as before: the devices still run the batch. The re-deploy is
                # left to do (resume), once the operator has seen the differences.
                return finish(
                    "failed",
                    "not_restored: " + "; ".join(wrong)[:400],
                    {"items": wrong[:50]},
                    left=["redeploy after revert: not restored as before"],
                )
            progress.phase("deploying", 75, 98)
            await deploy(
                fmc,
                adapter,
                fmc.domain_uuid,
                targets,
                poll_seconds=settings.deploy_poll_seconds if poll_seconds is None else poll_seconds,
                timeout_seconds=settings.deploy_timeout_seconds,
                sleep=sleep,
            )
    except Exception as exc:
        expected = isinstance(exc, BatchError | FmcError)
        if isinstance(exc, BatchError | FmcError):
            code = exc.code
            detail = scrub_text(exc.detail if isinstance(exc, BatchError) else str(exc))[:300]
            log.error("revert failed", extra={"batch": batch_id, "code": code, "detail": detail})
        else:
            code, detail = "internal_error", type(exc).__name__
            log.exception("revert failed unexpectedly", extra={"batch": batch_id})
        if stage == "check":
            outcome = still_deployed(code, {"detail": detail})
        elif stage == "undo":
            outcome = finish("failed", f"{code}: {detail}", left=[f"undo: {code}"])
        else:
            outcome = finish("failed", f"{code}: {detail}", left=[f"redeploy after revert: {code}"])
        if not expected:
            raise
        return outcome
    finally:
        await release()
    return finish("reverted", None, {"steps": len(journal)})
