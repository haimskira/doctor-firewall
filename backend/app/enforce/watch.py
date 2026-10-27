"""After a deployment: do the hit counters show traffic that used to pass and is now blocked?

The traffic proof shows, before writing, that a *preserves* batch changes no verdict. This is
the second net, on live traffic: for ``deploy_watch_hours`` after a batch is deployed, the hit
counters of

* the access rules the batch changed (directly, or through an object it changed), and
* every enabled BLOCK rule *behind* the first of them whose match space overlaps theirs (where
  traffic a changed rule no longer takes would land)

are read every ``deploy_watch_minutes``. The rate of each block rule since the deployment is
compared with its rate between the snapshot and the deployment. New hits of at least
``deploy_watch_min_hits`` that are ``deploy_watch_ratio`` times what that rate predicts raise an
alert: the history page and the top bar show it, next to the batch's revert. A counter that went
down was reset (a reboot, a redeploy of the rule): it counts from zero.

Limits: the default action has no hit counter, so traffic falling through to it is not seen;
only access policies have hit counters in the FMC API. Read-only toward the FMC.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.expand import Resolver, rule_spaces
from app.audit.chain import AuditEvent, AuditLog
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.enforce.batch_proof import batch_plans
from app.enforce.plan import touched
from app.fmc.adapters import select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError
from app.fmc.probe import server_version
from app.fmc.records import PolicyKind
from app.models.enforce import Batch, Changeset, DeployWatch
from app.models.fmc import FmcConnection
from app.models.inventory import (
    Cluster,
    ClusterPolicy,
    GroupMember,
    Policy,
    Rule,
    RuleRef,
    Snapshot,
)

log = logging.getLogger(__name__)

BLOCK_ACTIONS = frozenset({"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"})
MAX_WATCHED = 400  # rules per watch (changed first, then the blocks behind them)
MAX_NESTING = 16


def open_watch(db: Session, batch: Batch, settings: Settings, now: datetime) -> None:
    """Start watching a batch that was just deployed (its first check reads the baseline)."""
    if db.scalar(select(DeployWatch.id).where(DeployWatch.batch_id == batch.id)) is not None:
        return
    db.add(
        DeployWatch(
            batch_id=batch.id,
            status="watching",
            started_at=now,
            until=now + timedelta(hours=settings.deploy_watch_hours),
            next_check_at=now,
        )
    )


def key(policy: str, rule: str) -> str:
    return f"{policy}/{rule}"


# ------------------------------------------------------------------ what to watch


def _holders(db: Session, snapshot_id: int, objects: set[str]) -> set[str]:
    """The objects and every group that contains them, at any depth."""
    found, frontier = set(objects), set(objects)
    for _ in range(MAX_NESTING):
        if not frontier:
            break
        parents = set(
            db.scalars(
                select(GroupMember.group_fmc_id).where(
                    GroupMember.snapshot_id == snapshot_id,
                    GroupMember.member_fmc_id.in_(frontier),
                )
            )
        )
        frontier = parents - found
        found |= parents
    return found


def watched_rules(db: Session, cs: Changeset, batch: Batch) -> list[dict[str, Any]]:
    """The changed access rules of a batch and the overlapping BLOCK rules behind them."""
    if cs.snapshot_id is None:
        return []
    sid = cs.snapshot_id
    plans, _ = batch_plans(db, cs.id)
    changed: dict[str, set[str]] = defaultdict(set)
    objects: set[str] = set()
    t = touched({"ops": plans.get(batch.seq, [])})
    for item in t["rules"]:
        policy, _, rule = item.partition("/")
        changed[policy].add(rule)
    objects |= t["objects"]
    if objects:
        holders = _holders(db, sid, objects)
        for policy, rule in db.execute(
            select(Rule.policy_fmc_id, Rule.fmc_id)
            .join(RuleRef, RuleRef.rule_id == Rule.id)
            .where(Rule.snapshot_id == sid, RuleRef.object_fmc_id.in_(holders))
            .distinct()
        ):
            changed[policy].add(rule)
    access = set(
        db.scalars(
            select(Policy.fmc_id).where(
                Policy.snapshot_id == sid, Policy.kind == PolicyKind.ACCESS.value
            )
        )
    )
    resolver = Resolver.load(db, sid)
    mine_out: list[dict[str, Any]] = []
    behind_out: list[dict[str, Any]] = []
    for policy_id in sorted(changed):
        if policy_id not in access:
            continue
        spaces = rule_spaces(db, sid, policy_id, resolver)
        mine = [rs for rs in spaces if rs.fmc_id in changed[policy_id]]
        if not mine:
            continue
        first = min(rs.rule_index for rs in mine)
        for rs in mine:
            mine_out.append(_row(policy_id, rs, "changed"))
        for rs in spaces:
            if (
                rs.rule_index <= first
                or not rs.enabled
                or rs.action not in BLOCK_ACTIONS
                or rs.fmc_id in changed[policy_id]
            ):
                continue
            if any(rs.space.intersects(m.space) for m in mine):
                behind_out.append(_row(policy_id, rs, "block_behind"))
    return [*mine_out, *behind_out][:MAX_WATCHED]


def _row(policy: str, rs: Any, role: str) -> dict[str, Any]:
    return {
        "policy": policy,
        "id": rs.fmc_id,
        "name": rs.name,
        "index": rs.rule_index,
        "action": rs.action,
        "role": role,
        "snapshot_hits": rs.hit_count,
    }


# ------------------------------------------------------------------ judging the counters


def judge(
    rules: Iterable[dict[str, Any]],
    *,
    snapshot_at: datetime | None,
    baseline_at: datetime,
    baseline: dict[str, int],
    now: datetime,
    hits: dict[str, int],
    min_hits: int,
    ratio: float,
) -> list[dict[str, Any]]:
    """Block rules hit far more since the deployment than their earlier rate predicts."""
    alerts: list[dict[str, Any]] = []
    since = max((now - baseline_at).total_seconds(), 1.0)
    for r in rules:
        if r["role"] != "block_behind":
            continue
        k = key(r["policy"], r["id"])
        if k not in hits or k not in baseline:
            continue
        current, base = hits[k], baseline[k]
        new = current - base if current >= base else current  # a reset counts from zero
        rate = 0.0
        before = r.get("snapshot_hits")
        if snapshot_at is not None and isinstance(before, int) and base >= before:
            window = (baseline_at - snapshot_at).total_seconds()
            if window > 0:
                rate = (base - before) / window
        expected = rate * since
        if new >= min_hits and new > ratio * expected:
            alerts.append(
                {
                    "policy": r["policy"],
                    "id": r["id"],
                    "name": r["name"],
                    "index": r["index"],
                    "new_hits": new,
                    "expected": round(expected, 1),
                    "at": now.isoformat(),
                }
            )
    return alerts


# ------------------------------------------------------------------ the scheduled check


async def _read_hits(
    fmc: FmcSession,
    adapter: Any,
    devices: dict[str, list[str]],
    wanted: set[str],
) -> dict[str, int]:
    """Hit counts of the wanted rules (summed over the units of each cluster)."""
    out: dict[str, int] = {}
    resource = adapter.POLICY_RESOURCES[PolicyKind.ACCESS]
    for policy, units in devices.items():
        path = adapter.config_path(
            fmc.domain_uuid, f"/policy/{resource}/{policy}/operational/hitcounts"
        )
        for device in units:
            async for _, items in fmc.iter_pages(
                path, params={"filter": f'"deviceId:{device}"'}, optional=True
            ):
                for item in items:
                    h = adapter.map_hitcount(item)
                    k = key(policy, h.rule_id)
                    if k in wanted:
                        out[k] = out.get(k, 0) + h.hit_count
    return out


def _devices(db: Session, snapshot_id: int, policies: set[str]) -> dict[str, list[str]]:
    clusters: dict[str, list[str]] = defaultdict(list)
    for policy, cluster in db.execute(
        select(ClusterPolicy.policy_fmc_id, ClusterPolicy.cluster_fmc_id).where(
            ClusterPolicy.snapshot_id == snapshot_id, ClusterPolicy.policy_fmc_id.in_(policies)
        )
    ):
        clusters[policy].append(cluster)
    units = {
        c.fmc_id: [str(m["id"]) for m in c.members if m.get("id")]
        for c in db.scalars(select(Cluster).where(Cluster.snapshot_id == snapshot_id))
    }
    return {p: sorted({u for c in cs for u in units.get(c, [])}) for p, cs in clusters.items()}


def due(sessions: sessionmaker[Session], now: datetime) -> list[int]:
    with sessions() as db:
        return list(
            db.scalars(
                select(DeployWatch.id)
                .where(DeployWatch.status == "watching", DeployWatch.next_check_at <= now)
                .order_by(DeployWatch.next_check_at)
            )
        )


async def check(
    watch_id: int,
    *,
    sessions: sessionmaker[Session],
    box: SecretBox,
    audit: AuditLog,
    settings: Settings,
    now: datetime | None = None,
    transport: Any = None,
) -> str:
    """One check of one watch; returns its status afterwards."""
    now = now or datetime.now(UTC)
    with sessions.begin() as db:
        w = db.get(DeployWatch, watch_id, with_for_update=True)
        if w is None or w.status != "watching":
            return w.status if w is not None else "gone"
        b = db.get(Batch, w.batch_id)
        cs = db.get(Changeset, b.changeset_id) if b is not None else None
        if b is None or cs is None or b.status != "deployed" or cs.snapshot_id is None:
            w.status, w.next_check_at = "ended", None
            return w.status
        if not w.rules and w.checks == 0:
            w.rules = watched_rules(db, cs, b)
        if not w.rules:
            w.status, w.next_check_at, w.checks = "ok", None, w.checks + 1
            return w.status
        rules = list(w.rules)
        snapshot = db.get(Snapshot, cs.snapshot_id)
        snapshot_at = snapshot.finished_at if snapshot is not None else None
        devices = _devices(db, cs.snapshot_id, {r["policy"] for r in rules})
        conn = db.get(FmcConnection, cs.connection_id) if cs.connection_id else None
        if conn is None:
            w.status, w.next_check_at, w.error = "ended", None, "connection_deleted"
            return w.status
        host, port, username = conn.host, conn.port, conn.username
        token, context = conn.password_enc, FmcConnection.password_context(conn.id)
        baseline_at, baseline = w.baseline_at, dict(w.baseline)
        w.next_check_at = now + timedelta(minutes=settings.deploy_watch_minutes)

    try:
        async with FmcSession(
            host=host,
            port=port,
            username=username,
            password_provider=lambda: box.decrypt(token, context),
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
            hits = await _read_hits(
                fmc, adapter, devices, {key(r["policy"], r["id"]) for r in rules}
            )
    except FmcError as exc:
        # The FMC is unreachable for now (VPN, maintenance): try again at the next check.
        with sessions.begin() as db:
            w = db.get(DeployWatch, watch_id, with_for_update=True)
            if w is not None:
                w.error = f"{exc.code}: {scrub_text(str(exc))[:200]}"
        return "watching"

    with sessions.begin() as db:
        w = db.get(DeployWatch, watch_id, with_for_update=True)
        if w is None or w.status != "watching":
            return w.status if w is not None else "gone"
        w.checks += 1
        w.error = None
        w.last_at, w.last = now, hits
        if baseline_at is None:
            w.baseline_at, w.baseline = now, hits
        else:
            alerts = judge(
                rules,
                snapshot_at=snapshot_at,
                baseline_at=baseline_at,
                baseline=baseline,
                now=now,
                hits=hits,
                min_hits=settings.deploy_watch_min_hits,
                ratio=settings.deploy_watch_ratio,
            )
            if alerts:
                w.alerts, w.status, w.next_check_at = alerts, "alert", None
                audit.record(
                    db,
                    AuditEvent(
                        actor="system:watch",
                        actor_id=None,
                        action="changeset.watch_alert",
                        outcome="failure",
                        target=f"batch {w.batch_id}",
                        details={
                            "batch_id": w.batch_id,
                            "alerts": [
                                {"rule": a["name"], "id": a["id"], "new_hits": a["new_hits"]}
                                for a in alerts[:20]
                            ],
                        },
                    ),
                )
                log.warning("blocked traffic after a deployment", extra={"batch": w.batch_id})
                return w.status
        if now >= w.until:
            w.status, w.next_check_at = "ok", None
        return w.status
