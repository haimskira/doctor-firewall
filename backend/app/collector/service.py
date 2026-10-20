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
from app.fmc.records import (
    AssignmentRecord,
    DeviceRecord,
    HaPairRecord,
    PolicyKind,
    PolicyRecord,
)
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
    rules_by_kind: dict[str, int] = field(default_factory=dict)
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
            "rules_by_kind": self.rules_by_kind,
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
        clusters, assignments = await self._topology()
        await self._policies(clusters, assignments)
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

    async def _topology(self) -> tuple[list[dict[str, Any]], list[AssignmentRecord]]:
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
        access = [a for a in assignments if a.policy_type == "AccessPolicy"]
        clusters = build_clusters(devices, pairs, access)
        with self.sessions.begin() as session:
            store.replace_clusters(session, self.snapshot_id, clusters)
        self.stats.clusters = len(clusters)
        return clusters, assignments

    async def _policies(
        self, clusters: list[dict[str, Any]], assignments: list[AssignmentRecord]
    ) -> None:
        """Every policy kind; rules for the rule-bearing kinds; cluster associations."""
        inventory: dict[PolicyKind, list[PolicyRecord]] = {}
        for kind, resource in self.adapter.POLICY_RESOURCES.items():
            items = await self._fetch_all(
                self._path(f"/policy/{resource}"), optional=kind is not PolicyKind.ACCESS
            )
            inventory[kind] = [self.adapter.map_policy(i, kind) for i in items]

        governed = cluster_policy_links(clusters, assignments, inventory[PolicyKind.ACCESS])
        with self.sessions.begin() as session:
            store.replace_cluster_policies(session, self.snapshot_id, governed)

        enforced_access = {c["policy_fmc_id"] for c in clusters if c["policy_fmc_id"]}
        for kind, policies in inventory.items():
            for policy in policies:
                if kind is PolicyKind.ACCESS and policy.fmc_id not in enforced_access:
                    continue  # unassigned access policies are not enforced anywhere
                await self._policy(kind, policy, clusters)

    async def _policy(
        self, kind: PolicyKind, policy: PolicyRecord, clusters: list[dict[str, Any]]
    ) -> None:
        base = f"/policy/{self.adapter.POLICY_RESOURCES[kind]}/{policy.fmc_id}"
        categories: list[str] = []
        if kind is PolicyKind.ACCESS:
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
                    "kind": kind.value,
                    "name": policy.name,
                    "default_action": policy.default_action,
                    "categories": categories,
                    "links": [
                        {
                            "relation": rel,
                            "id": ref.object_id or "",
                            "name": ref.name,
                            "type": ref.fmc_type,
                        }
                        for rel, ref in policy.links
                    ],
                    "attrs": policy.attrs,
                },
            )
        self.stats.policies += 1
        subresources = self.adapter.RULE_RESOURCES.get(kind, ())
        if not subresources:
            return
        for sub, rule_type in subresources:
            await self._rules(kind, policy.fmc_id, sub, rule_type, self._path(f"{base}/{sub}"))
        with self.sessions.begin() as session:
            total = store.count_rules(session, self.snapshot_id, policy.fmc_id)
            session.execute(
                update(Policy)
                .where(Policy.snapshot_id == self.snapshot_id, Policy.fmc_id == policy.fmc_id)
                .values(rule_count=total)
            )
        if kind is PolicyKind.ACCESS:
            devices = [
                m["id"]
                for c in clusters
                if c["policy_fmc_id"] == policy.fmc_id
                for m in c["members"]
            ]
            await self._hitcounts(
                policy.fmc_id, self._path(f"{base}/operational/hitcounts"), devices
            )

    async def _rules(
        self, kind: PolicyKind, policy_id: str, sub: str, rule_type: str | None, path: str
    ) -> None:
        key = f"rules:{policy_id}:{sub}"
        expected = await self._total(path)

        def handle(session: Session, offset: int, items: list[dict[str, Any]]) -> int:
            records = [
                self.adapter.map_any_rule(kind, rule_type, item, offset + i + 1)
                for i, item in enumerate(items)
            ]
            stored = store.store_rules(session, self.snapshot_id, policy_id, records, kind)
            self.stats.rules += stored
            self.stats.rules_by_kind[kind.value] = (
                self.stats.rules_by_kind.get(kind.value, 0) + stored
            )
            return stored

        try:
            await self._paged(key, path, handle)
        except IntegrityError as exc:
            self._reset_policy(policy_id)
            raise ConfigChangedError(f"policy {policy_id}: duplicate rules while paging") from exc
        with self.sessions() as session:
            stored = store.count_rules(session, self.snapshot_id, policy_id, rule_type)
        if stored != expected:
            self._reset_policy(policy_id)
            raise ConfigChangedError(
                f"policy {policy_id} ({sub}): FMC reports {expected} rules, collected {stored}"
            )

    def _reset_policy(self, policy_id: str) -> None:
        """Discard a policy's rules and every checkpoint that depends on them."""
        with self.sessions.begin() as session:
            store.delete_policy_rules(session, self.snapshot_id, policy_id)
            store.reset_checkpoints(session, self.snapshot_id, f"rules:{policy_id}:")
            store.reset_checkpoints(session, self.snapshot_id, f"hits:{policy_id}:")

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


def cluster_policy_links(
    clusters: list[dict[str, Any]],
    assignments: list[AssignmentRecord],
    access_policies: list[PolicyRecord],
) -> list[dict[str, str]]:
    """(cluster, policy, via) rows: direct assignments (access, NAT, ...) to the cluster or
    any of its units, plus policies linked from the cluster's access policy (prefilter, ...)."""
    rows: dict[tuple[str, str], str] = {}
    links = {p.fmc_id: p.links for p in access_policies}
    for cluster in clusters:
        targets = {cluster["fmc_id"], *(m["id"] for m in cluster["members"])}
        for a in assignments:
            if targets & set(a.target_ids):
                rows.setdefault((cluster["fmc_id"], a.policy_id), "assignment")
        access = cluster["policy_fmc_id"]
        if access:
            rows.setdefault((cluster["fmc_id"], access), "assignment")
            for relation, ref in links.get(access, ()):
                if ref.object_id:
                    rows.setdefault((cluster["fmc_id"], ref.object_id), relation)
    return [
        {"cluster_fmc_id": c, "policy_fmc_id": p, "via": via}
        for (c, p), via in sorted(rows.items())
    ]


def mark(sessions: sessionmaker[Session], snapshot_id: int, **values: Any) -> None:
    with sessions.begin() as session:
        session.execute(update(Snapshot).where(Snapshot.id == snapshot_id).values(**values))
