"""Revert a deployed batch: put back exactly what it changed, then deploy.

1. **Nothing changed since.** Every item the batch wrote must still be what it wrote (the
   after-images kept in the journal), every item it deleted must still be absent. Anything else
   — someone edited it in the FMC, another change built on it — stops the revert before any write.
2. **Undo** the journal in reverse (the same idempotent steps as a rollback).
3. **Exactly as before.** Every rule and object reads back as its pre-image, objects the batch
   created are gone, and every touched policy lists its rules in the same order as before the
   batch. Only then is the result deployed; otherwise the batch is left ``failed`` with the reason
   (its remaining steps can be finished from the journal).

Batches are reverted newest first: a batch can only be reverted when no batch deployed after it
to the same FMC is still in place (rollback to a point = revert every later batch, in order).
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.chain import AuditEvent, AuditLog
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.enforce.batch_proof import model_before
from app.enforce.executor import (
    ROLLBACK_ROUNDS,
    BatchError,
    Writer,
    _connection_and_targets,
    _journal_sink,
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


def later_batches(db: Session, batch: Batch, cs: Changeset) -> list[dict[str, Any]]:
    """Batches deployed to the same FMC after this one and still in place."""
    if batch.finished_at is None:
        return []
    rows = db.execute(
        select(Changeset.id, Changeset.title, Batch.seq, Batch.finished_at)
        .join(Batch, Batch.changeset_id == Changeset.id)
        .where(
            Changeset.connection_id == cs.connection_id,
            Batch.status == "deployed",
            Batch.finished_at > batch.finished_at,
        )
        .order_by(Batch.finished_at.desc())
    ).all()
    return [
        {"changeset_id": c, "title": t, "batch": s, "at": f.isoformat() if f else None}
        for c, t, s, f in rows
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
    if later_batches(db, batch, cs):
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


async def _not_restored(
    writer: Writer, journal: list[dict[str, Any]], before_orders: dict[str, list[str]]
) -> list[str]:
    """Differences from the state before the batch (content of every item, order of rules)."""
    wrong: list[str] = []
    for step in journal:
        label = str(step.get("label") or step.get("name") or step.get("path"))
        kind = step.get("undo")
        if kind == "delete":  # created by the batch
            if await writer.fmc.get_json(str(step["path"]), allow_not_found=True) is not None:
                wrong.append(f"{label}: still exists")
            continue
        if kind == "recreate":
            new_id = step.get("recreated_as")
            path = f"{step['path']}/{new_id}"
            current = await writer.fmc.get_json(path, allow_not_found=True)
            expected = {k: v for k, v in _comparable(step["body"]).items() if k != "id"}
        else:
            current = await writer.fmc.get_json(str(step["path"]), allow_not_found=True)
            expected = _comparable(step["body"])
        if current is None:
            wrong.append(f"{label}: missing")
            continue
        found = _comparable(Writer._clean(current, keep_id=True))
        if kind == "recreate":
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
        b.status = "running"
    # The policy before the batch, in order — what every touched rulebase must list again.
    collections = _rule_collections(journal)
    before_orders: dict[str, list[str]] = {}
    for collection in collections:
        policy_id = collection.rsplit("/", 2)[-2]
        policy = before.policies.get(policy_id)
        if policy is not None:
            before_orders[collection] = [r.name for r in policy.rules]

    def finish(
        status: str, error: str | None, extra: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with sessions.begin() as db:
            batch = db.get(Batch, batch_id, with_for_update=True)
            if batch is not None:
                batch.status = status
                batch.error = error[:512] if error else None
                if status == "reverted":
                    batch.finished_at = datetime.now(UTC)
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
    release = await lock(f"df:fmc-write:{host}:{port}", settings.write_lock_ttl_seconds)
    if release is None:
        with sessions.begin() as db:
            batch = db.get(Batch, batch_id, with_for_update=True)
            if batch is not None:
                batch.status = "deployed"
        return {"ok": False, "error": "write_lock_busy", "status": "deployed"}

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

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
                # Nothing written: the batch is still in place, as it was.
                with sessions.begin() as db:
                    batch = db.get(Batch, batch_id, with_for_update=True)
                    if batch is not None:
                        batch.status = "deployed"
                return {
                    "ok": False,
                    "status": "deployed",
                    "error": "changed_since",
                    "items": changed[:50],
                }
            progress.phase("revert_undo", 25, 65)
            left = await writer.rollback(ROLLBACK_ROUNDS, settings.rollback_retry_seconds)
            if left:
                return finish("failed", "revert_incomplete: " + "; ".join(left)[:400])
            progress.phase("revert_verify", 65, 75)
            wrong = await _not_restored(writer, journal, before_orders)
            if wrong:
                return finish(
                    "failed", "not_restored: " + "; ".join(wrong)[:400], {"items": wrong[:50]}
                )
            progress.phase("deploying", 75, 98)
            await deploy(
                fmc,
                adapter,
                fmc.domain_uuid,
                targets,
                poll_seconds=settings.deploy_poll_seconds if poll_seconds is None else poll_seconds,
                timeout_seconds=settings.deploy_timeout_seconds,
            )
    except (BatchError, FmcError) as exc:
        detail = scrub_text(exc.detail if isinstance(exc, BatchError) else str(exc))[:300]
        log.error("revert failed", extra={"batch": batch_id, "code": exc.code, "detail": detail})
        return finish("failed", f"{exc.code}: {detail}")
    finally:
        await release()
    return finish("reverted", None, {"steps": len(journal)})
