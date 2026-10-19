"""Read-only collection of one FMC into a new snapshot.

Stages (in order): objects -> devices / HA pairs / policy assignments -> clusters ->
access policies (categories, ordered rules, hit counts) -> per cluster: interfaces,
static routes, BGP -> stub objects and connected routes.

Guarantees:

* **Read-only**: only GET requests (plus the token lifecycle) are ever sent.
* **Checkpointing**: every page is committed together with its checkpoint, so a
  failed run resumes at the next page; small per-device resources are replaced
  atomically per key (idempotent).
* **Consistency**: a policy's stored rule count must equal the FMC's total. If the
  FMC changed during collection (or returned duplicates), that policy is reset and
  the run fails with ``config_changed``; a resume re-collects it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.collector import store
from app.fmc.adapters import FmcAdapter
from app.fmc.client import FmcSession
from app.fmc.errors import FmcError
from app.fmc.records import AssignmentRecord, DeviceRecord, HaPairRecord
from app.models.inventory import Policy, Snapshot

log = logging.getLogger(__name__)

PageHandler = Callable[[Session, int, list[dict[str, Any]]], int]


class CollectionError(FmcError):
    code = "collection_failed"


class ConfigChangedError(CollectionError):
    code = "config_changed"


@dataclass
class Stats:
    objects: int = 0
    rules: int = 0
    policies: int = 0
    clusters: int = 0
    interfaces: int = 0
    routes: int = 0
    stubs: int = 0
    pages: int = 0
    by_resource: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "objects": self.objects,
            "rules": self.rules,
            "policies": self.policies,
            "clusters": self.clusters,
            "interfaces": self.interfaces,
            "routes": self.routes,
            "stub_objects": self.stubs,
            "pages": self.pages,
            "by_resource": self.by_resource,
        }


class Collector:
    def __init__(
        self,
        *,
        snapshot_id: int,
        fmc: FmcSession,
        adapter: FmcAdapter,
        sessions: sessionmaker[Session],
    ) -> None:
        self.snapshot_id = snapshot_id
        self.fmc = fmc
        self.adapter = adapter
        self.sessions = sessions
        self.domain = fmc.domain_uuid
        self.stats = Stats()

    def _path(self, suffix: str) -> str:
        return self.adapter.config_path(self.domain, suffix)

    # ------------------------------------------------------------ generic paging

    async def _paged(
        self,
        key: str,
        path: str,
        handle: PageHandler,
        *,
        params: dict[str, str | int] | None = None,
        optional: bool = False,
    ) -> None:
        """Collect a paged resource with checkpoints; ``handle`` stores one page."""
        with self.sessions() as session:
            cp = store.checkpoint(session, self.snapshot_id, key)
            session.commit()
            if cp.done:
                return
            start = cp.next_offset
        async for offset, items in self.fmc.iter_pages(
            path, start_offset=start, params=params, optional=optional
        ):
            with self.sessions.begin() as session:
                stored = handle(session, offset, items)
                store.advance(session, self.snapshot_id, key, offset + len(items))
            self.stats.pages += 1
            self.stats.by_resource[key] = self.stats.by_resource.get(key, 0) + stored
        with self.sessions.begin() as session:
            cp = store.checkpoint(session, self.snapshot_id, key)
            store.advance(session, self.snapshot_id, key, cp.next_offset, done=True)

    async def _fetch_all(self, path: str, *, optional: bool = False) -> list[dict[str, Any]]:
        """Small resources: read every page into memory (no checkpoint needed)."""
        items: list[dict[str, Any]] = []
        async for _, page in self.fmc.iter_pages(path, optional=optional):
            items.extend(page)
            self.stats.pages += 1
        return items

    async def _total(self, path: str) -> int:
        raw = await self.fmc.get_json(path, {"offset": 0, "limit": 1})
        paging = raw.get("paging") if isinstance(raw, dict) else None
        count = paging.get("count") if isinstance(paging, dict) else None
        if not isinstance(count, int) or count < 0:
            raise CollectionError(f"GET {path}: missing paging count")
        return count

    # ------------------------------------------------------------ stages

    async def run(self) -> dict[str, Any]:
        await self._objects()
        clusters = await self._topology()
        await self._policies(clusters)
        for cluster in clusters:
            await self._cluster_network(cluster)
        with self.sessions.begin() as session:
            self.stats.stubs = store.add_stub_objects(
                session, self.snapshot_id, self.adapter.kind_of
            )
            for cluster in clusters:
                store.replace_connected_routes(session, self.snapshot_id, cluster["fmc_id"])
        return self.stats.as_dict()

    async def _objects(self) -> None:
        for resource in self.adapter.OBJECT_RESOURCES:

            def handle(
                session: Session,
                _offset: int,
                items: list[dict[str, Any]],
                resource: str = resource,
            ) -> int:
                records = [self.adapter.map_object(resource, item) for item in items]
                stored = store.store_objects(session, self.snapshot_id, records)
                self.stats.objects += stored
                return stored

            await self._paged(
                f"objects:{resource}", self._path(f"/object/{resource}"), handle, optional=True
            )

    async def _topology(self) -> list[dict[str, Any]]:
        devices = [
            self.adapter.map_device(i)
            for i in await self._fetch_all(self._path("/devices/devicerecords"))
        ]
        pairs = [
            self.adapter.map_ha_pair(i)
            for i in await self._fetch_all(
                self._path("/devicehapairs/ftddevicehapairs"), optional=True
            )
        ]
        assignments = [
            a
            for i in await self._fetch_all(
                self._path("/assignment/policyassignments"), optional=True
            )
            if (a := self.adapter.map_assignment(i)) is not None
        ]
        clusters = build_clusters(devices, pairs, assignments)
        with self.sessions.begin() as session:
            store.replace_clusters(session, self.snapshot_id, clusters)
        self.stats.clusters = len(clusters)
        return clusters

    async def _policies(self, clusters: list[dict[str, Any]]) -> None:
        wanted = {c["policy_fmc_id"] for c in clusters if c["policy_fmc_id"]}
        policies = [
            self.adapter.map_policy(i)
            for i in await self._fetch_all(self._path("/policy/accesspolicies"))
        ]
        for policy in policies:
            if policy.fmc_id not in wanted:
                continue  # unassigned policies are not enforced anywhere
            base = f"/policy/accesspolicies/{policy.fmc_id}"
            categories = [
                self.adapter.map_category(i)
                for i in await self._fetch_all(self._path(f"{base}/categories"), optional=True)
            ]
            with self.sessions.begin() as session:
                store.upsert_policy(
                    session,
                    self.snapshot_id,
                    {
                        "fmc_id": policy.fmc_id,
                        "name": policy.name,
                        "default_action": policy.default_action,
                        "categories": categories,
                    },
                )
            await self._rules(policy.fmc_id, self._path(f"{base}/accessrules"))
            devices = [
                m["id"]
                for c in clusters
                if c["policy_fmc_id"] == policy.fmc_id
                for m in c["members"]
            ]
            await self._hitcounts(
                policy.fmc_id, self._path(f"{base}/operational/hitcounts"), devices
            )
            self.stats.policies += 1

    async def _rules(self, policy_id: str, path: str) -> None:
        key = f"rules:{policy_id}"
        expected = await self._total(path)

        def handle(session: Session, offset: int, items: list[dict[str, Any]]) -> int:
            records = [self.adapter.map_rule(item, offset + i + 1) for i, item in enumerate(items)]
            stored = store.store_rules(session, self.snapshot_id, policy_id, records)
            self.stats.rules += stored
            return stored

        try:
            await self._paged(key, path, handle)
        except IntegrityError as exc:
            self._reset_policy(policy_id, key)
            raise ConfigChangedError(f"policy {policy_id}: duplicate rules while paging") from exc
        with self.sessions() as session:
            stored = store.count_rules(session, self.snapshot_id, policy_id)
        if stored != expected:
            self._reset_policy(policy_id, key)
            raise ConfigChangedError(
                f"policy {policy_id}: FMC reports {expected} rules, collected {stored}"
            )
        with self.sessions.begin() as session:
            session.execute(
                update(Policy)
                .where(Policy.snapshot_id == self.snapshot_id, Policy.fmc_id == policy_id)
                .values(rule_count=stored)
            )

    def _reset_policy(self, policy_id: str, key: str) -> None:
        with self.sessions.begin() as session:
            store.delete_policy_rules(session, self.snapshot_id, policy_id)
            store.reset_checkpoint(session, self.snapshot_id, key)
            store.reset_checkpoint(session, self.snapshot_id, f"hits:{policy_id}")

    async def _hitcounts(self, policy_id: str, path: str, devices: list[str]) -> None:
        for device in devices:

            def handle(session: Session, _offset: int, items: list[dict[str, Any]]) -> int:
                hits = [self.adapter.map_hitcount(i) for i in items]
                store.apply_hitcounts(
                    session,
                    self.snapshot_id,
                    policy_id,
                    ((h.rule_id, h.hit_count, h.last_hit) for h in hits),
                )
                return len(hits)

            await self._paged(
                f"hits:{policy_id}:{device}",
                path,
                handle,
                params={"filter": f'"deviceId:{device}"'},
                optional=True,
            )

    async def _cluster_network(self, cluster: dict[str, Any]) -> None:
        cluster_id: str = cluster["fmc_id"]
        device: str = cluster["primary_device_fmc_id"]
        key = f"network:{cluster_id}"
        with self.sessions() as session:
            if store.checkpoint(session, self.snapshot_id, key).done:
                return
            session.commit()
        dev = f"/devices/devicerecords/{device}"
        interfaces = {
            kind: [
                self.adapter.map_interface(kind, i)
                for i in await self._fetch_all(self._path(f"{dev}/{kind}"), optional=True)
            ]
            for kind in self.adapter.INTERFACE_RESOURCES
        }
        routes = [
            self.adapter.map_static_route(i)
            for i in await self._fetch_all(
                self._path(f"{dev}/routing/ipv4staticroutes"), optional=True
            )
        ]
        bgp = self.adapter.map_bgp(
            await self._fetch_all(self._path(f"{dev}/routing/bgpgeneralsettings"), optional=True),
            await self._fetch_all(self._path(f"{dev}/routing/bgp"), optional=True),
        )
        with self.sessions.begin() as session:
            for kind, records in interfaces.items():
                store.replace_interfaces(
                    session, self.snapshot_id, cluster_id, device, kind, records
                )
                self.stats.interfaces += len(records)
            store.replace_static_routes(session, self.snapshot_id, cluster_id, routes)
            store.replace_bgp(session, self.snapshot_id, cluster_id, bgp)
            store.advance(session, self.snapshot_id, key, 0, done=True)
        self.stats.routes += sum(max(1, len(r.networks)) for r in routes)


def build_clusters(
    devices: list[DeviceRecord],
    pairs: list[HaPairRecord],
    assignments: list[AssignmentRecord],
) -> list[dict[str, Any]]:
    """Group devices into enforcement units: HA pairs, plus standalone devices."""
    by_id = {d.fmc_id: d for d in devices}
    policy_of_target = {t: a.policy_id for a in assignments for t in a.target_ids}
    clusters: list[dict[str, Any]] = []
    in_pair: set[str] = set()
    for pair in pairs:
        primary = by_id.get(pair.primary_id)
        secondary = by_id.get(pair.secondary_id)
        if primary is None:
            raise CollectionError(f"HA pair {pair.name}: primary device not found")
        members = [{"id": primary.fmc_id, "name": primary.name, "role": "primary"}]
        if secondary is not None:
            members.append({"id": secondary.fmc_id, "name": secondary.name, "role": "secondary"})
        in_pair.update(m["id"] for m in members)
        clusters.append(
            {
                "fmc_id": pair.fmc_id,
                "name": pair.name,
                "kind": "ha_pair",
                "policy_fmc_id": policy_of_target.get(pair.fmc_id) or primary.policy_id,
                "primary_device_fmc_id": primary.fmc_id,
                "sw_version": primary.sw_version,
                "model": primary.model,
                "members": members,
            }
        )
    for d in devices:
        if d.fmc_id in in_pair:
            continue
        clusters.append(
            {
                "fmc_id": d.fmc_id,
                "name": d.name,
                "kind": "standalone",
                "policy_fmc_id": policy_of_target.get(d.fmc_id) or d.policy_id,
                "primary_device_fmc_id": d.fmc_id,
                "sw_version": d.sw_version,
                "model": d.model,
                "members": [{"id": d.fmc_id, "name": d.name, "role": "standalone"}],
            }
        )
    return sorted(clusters, key=lambda c: str(c["name"]))


def mark(sessions: sessionmaker[Session], snapshot_id: int, **values: Any) -> None:
    with sessions.begin() as session:
        session.execute(update(Snapshot).where(Snapshot.id == snapshot_id).values(**values))
