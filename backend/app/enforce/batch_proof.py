"""Traffic proof per batch of a changeset (see app.enforce.proof).

Batches run in order, so batch *k* is proved against the snapshot with batches 1..k-1 already
applied. A batch *preserves* traffic when every recommendation in it does (by kind); such a batch
may only be approved and deployed with no flow changed. A batch that *changes* traffic by design
shows which flows change, and its approver acknowledges them.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.enforce.plan import item_ops
from app.enforce.proof import Model, apply_plan, compare, load_model
from app.models.enforce import Batch, Changeset, ChangesetItem
from app.models.recommendations import behavior
from app.workers import progress


def batch_plans(
    db: Session, changeset_id: int
) -> tuple[dict[int, list[dict[str, Any]]], dict[int, str]]:
    """Operations of every batch in execution order, and whether the batch preserves traffic."""
    ops: dict[int, list[dict[str, Any]]] = defaultdict(list)
    kinds: dict[int, set[str]] = defaultdict(set)
    for item in db.scalars(
        select(ChangesetItem)
        .where(ChangesetItem.changeset_id == changeset_id)
        .order_by(ChangesetItem.batch_seq, ChangesetItem.position)
    ):
        ops[item.batch_seq].extend(item_ops(item.plan, item.position))
        kinds[item.batch_seq].add(behavior(item.kind))
    return dict(ops), {
        seq: "changes" if "changes" in k else "preserves" for seq, k in kinds.items()
    }


def model_before(db: Session, changeset_id: int, seq: int) -> Model:
    """The snapshot with every earlier batch of the changeset applied."""
    cs = db.get(Changeset, changeset_id)
    if cs is None or cs.snapshot_id is None:
        raise LookupError("changeset_without_snapshot")
    model = load_model(db, cs.snapshot_id)
    ops, _ = batch_plans(db, changeset_id)
    for earlier in sorted(s for s in ops if s < seq):
        model = apply_plan(model, ops[earlier])
    return model


def prove_changeset(sessions: sessionmaker[Session], changeset_id: int) -> dict[int, bool]:
    """Compute and store the proof of every batch; returns batch seq -> proof ok."""
    with sessions() as db:
        cs = db.get(Changeset, changeset_id)
        if cs is None or cs.snapshot_id is None:
            raise LookupError("changeset_without_snapshot")
        progress.phase("proof_model", 0, 10)
        model = load_model(db, cs.snapshot_id)
        ops, behaviors = batch_plans(db, changeset_id)
    outcome: dict[int, bool] = {}
    seqs = sorted(ops)
    progress.phase("proof_batches", 10, 99)
    for n, seq in enumerate(seqs):
        progress.advance(n, len(seqs), batch=seq)
        after = apply_plan(model, ops[seq])
        report = compare(model, after)
        report["behavior"] = behaviors.get(seq, "preserves")
        report["computed_at"] = datetime.now(UTC).isoformat()
        with sessions.begin() as db:
            batch = db.scalar(
                select(Batch).where(Batch.changeset_id == changeset_id, Batch.seq == seq)
            )
            if batch is not None:
                batch.proof = report
        outcome[seq] = bool(report["ok"])
        model = after
    return outcome
