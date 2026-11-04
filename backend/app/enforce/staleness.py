"""Is a snapshot still what the FMC holds? Not after this system changed the FMC since.

A batch that deployed (or failed part-way, leaving changes) after a snapshot was taken makes the
snapshot stale for changes: its recommendations were computed on a configuration that no longer
exists, and the ones that batch carried out are already applied. Changes made outside this
system are caught later by the executor's drift check.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.models.enforce import Batch, Changeset, ChangesetItem
from app.models.inventory import Snapshot

# A reverted batch changed the FMC too: the revert itself (re-created objects get new ids).
CHANGED_FMC = ("deployed", "failed", "reverted")


def _left_changes(batch: Batch) -> bool:
    """Did this batch leave changes on the FMC?"""
    if batch.status in ("deployed", "reverted"):
        return True
    if batch.journal:  # failed: only what its rollback could not undo is left
        return any(step.get("state") != "undone" for step in batch.journal)
    return any(r.get("op") != "undo_failed" for r in batch.results)  # before the journal


def stale_since(
    db: Session, snap: Snapshot, *, exclude_changeset: int | None = None
) -> dict[str, Any] | None:
    """The latest batch that changed this snapshot's FMC after the snapshot was taken.

    ``exclude_changeset``: a changeset planned on this snapshot — its own earlier batches are
    part of its plan (each batch is planned on the snapshot with the earlier ones applied).
    """
    if snap.connection_id is None:
        return None
    query = (
        select(Changeset.id, Changeset.title, Batch)
        .join(Batch, Batch.changeset_id == Changeset.id)
        .where(
            Changeset.connection_id == snap.connection_id,
            Batch.status.in_(CHANGED_FMC),
            Batch.finished_at.is_not(None),
            Batch.finished_at > snap.created_at,
        )
        .order_by(Batch.finished_at.desc())
    )
    if exclude_changeset is not None:
        query = query.where(Changeset.id != exclude_changeset)
    for changeset_id, title, batch in db.execute(query):
        if _left_changes(batch):
            return {
                "changeset_id": changeset_id,
                "title": title,
                "batch": batch.seq,
                "at": batch.finished_at,
            }
    return None


def applied_fingerprints(db: Session, snap: Snapshot) -> set[str]:
    """Recommendations of this snapshot that a later deployed batch already carried out."""
    if snap.connection_id is None:
        return set()
    return set(
        db.scalars(
            select(ChangesetItem.fingerprint)
            .join(Changeset, Changeset.id == ChangesetItem.changeset_id)
            .join(
                Batch,
                and_(
                    Batch.changeset_id == ChangesetItem.changeset_id,
                    Batch.seq == ChangesetItem.batch_seq,
                ),
            )
            .where(
                Changeset.connection_id == snap.connection_id,
                Batch.status == "deployed",
                Batch.finished_at > snap.created_at,
            )
        )
    )
