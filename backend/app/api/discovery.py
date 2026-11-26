"""Asset discovery: run it on a snapshot, review its segments / domains / suggested assets,
and clear the table in bulk.

Suggestions are stored unconfirmed (``source = discovery``) with the evidence behind each one.
Running discovery again replaces the unconfirmed suggestions (and the per-address suggestions
of the old name-only bootstrap) and never touches what an operator confirmed or entered.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import AfterValidator, BaseModel, Field, field_validator
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session

from app.analysis import discovery
from app.api.assets import AuditDep, DbDep, ReaderDep, WriterDep, _audit, _canonical_network
from app.api.schemas import StrictModel
from app.models.assets import Asset, AssetDomain, AssetGroup, Segment
from app.models.inventory import Snapshot

router = APIRouter(prefix="/api", tags=["assets"])

Role = Literal[
    "dc_servers",
    "sda_users",
    "legacy_users",
    "vc_sda",
    "vc_legacy",
    "network_devices",
    "management",
    "dmz",
    "outside",
    "unknown",
]
Network = Annotated[str, Field(min_length=1, max_length=96), AfterValidator(_canonical_network)]
DomainName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[\w .-]+$")]


# ------------------------------------------------------------------ schemas


class DiscoverRequest(StrictModel):
    snapshot_id: Annotated[int, Field(ge=1)]


class DiscoverResult(BaseModel):
    segments: int
    assets: int
    components: int
    domains: int
    replaced: int  # earlier unconfirmed suggestions removed
    skipped: int  # addresses already in a confirmed / manual asset


class Evidence(BaseModel):
    source: str
    detail: str


class SegmentOut(BaseModel):
    id: int
    network: str
    name: str
    role: str
    domain: str | None
    cluster: str
    interface: str
    zone: str
    gateway: bool
    in_dc: bool
    source: str
    confirmed: bool
    confidence: int
    evidence: list[Evidence]
    notes: str
    updated_by: str


class SegmentIn(StrictModel):
    network: Network
    name: Annotated[str, Field(max_length=128)] = ""
    role: Role = "unknown"
    domain: DomainName | None = None
    notes: Annotated[str, Field(max_length=512)] = ""


def _not_null(value: object) -> object:
    if value is None:
        raise ValueError("may be omitted but not null")
    return value


class SegmentPatch(StrictModel):
    name: Annotated[str, Field(max_length=128)] | None = None
    role: Role | None = None
    domain: DomainName | None = None
    notes: Annotated[str, Field(max_length=512)] | None = None
    confirmed: bool | None = None
    _required = field_validator("name", "role", "notes", "confirmed", mode="after")(_not_null)


class DomainOut(BaseModel):
    id: int
    name: str
    description: str
    source: str
    confirmed: bool
    evidence: list[Evidence]
    segments: int
    assets: int


class DomainIn(StrictModel):
    name: DomainName
    description: Annotated[str, Field(max_length=512)] = ""


class DomainPatch(StrictModel):
    name: DomainName | None = None
    description: Annotated[str, Field(max_length=512)] | None = None
    confirmed: bool | None = None
    _required = field_validator("name", "description", "confirmed", mode="after")(_not_null)


class ConfirmIds(StrictModel):
    """Either explicit ids or every pending suggestion."""

    ids: Annotated[list[int], Field(default_factory=list, max_length=100_000)]
    all: bool = False


class ConfirmResult(BaseModel):
    confirmed: int


class PurgeRequest(StrictModel):
    scope: Literal["all", "unassigned", "suggested"]
    confirm: Literal["DELETE"]


class SegmentPurge(StrictModel):
    scope: Literal["all", "suggested"]
    confirm: Literal["DELETE"]


class PurgeResult(BaseModel):
    deleted: int


# ------------------------------------------------------------------ discovery


def _rows(result: Any) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def _suggestions_cleared(db: Session) -> int:
    """Drop every unconfirmed suggestion (discovery's and the old bootstrap's)."""
    removed = _rows(
        db.execute(
            delete(Asset).where(
                Asset.confirmed.is_(False), Asset.source.in_(["bootstrap", "discovery"])
            )
        )
    )
    groups = list(
        db.scalars(
            select(AssetGroup.id).where(
                AssetGroup.source == "discovery", AssetGroup.confirmed.is_(False)
            )
        )
    )
    if groups:
        db.execute(delete(Asset).where(Asset.group_id.in_(groups)))
        removed += _rows(db.execute(delete(AssetGroup).where(AssetGroup.id.in_(groups))))
    removed += _rows(
        db.execute(
            delete(Segment).where(Segment.source == "discovery", Segment.confirmed.is_(False))
        )
    )
    db.execute(
        delete(AssetDomain).where(
            AssetDomain.source == "discovery", AssetDomain.confirmed.is_(False)
        )
    )
    return removed


def store(db: Session, result: discovery.Discovery, who: str) -> DiscoverResult:
    replaced = _suggestions_cleared(db)
    taken_networks = set(db.scalars(select(Asset.network)))
    taken_segments = set(db.scalars(select(Segment.network)))
    taken_names = set(db.scalars(select(AssetGroup.name)))
    taken_domains = {n.upper() for n in db.scalars(select(AssetDomain.name))}

    domains = 0
    for name, evidence in sorted(result.domains.items()):
        if name.upper() in taken_domains:
            continue
        db.add(
            AssetDomain(
                name=name.upper()[:64],
                source="discovery",
                confirmed=False,
                evidence=evidence,
                updated_by=who,
            )
        )
        taken_domains.add(name.upper())
        domains += 1

    segments = 0
    for seg in result.segments:
        if seg.network in taken_segments:
            continue
        db.add(
            Segment(
                network=seg.network,
                name=seg.name[:128],
                role=seg.role,
                domain=seg.domain,
                cluster=seg.cluster[:128],
                interface=seg.interface[:256],
                zone=seg.zone[:128],
                gateway=seg.gateway,
                in_dc=seg.in_dc,
                source="discovery",
                confirmed=False,
                confidence=round(seg.confidence * 100),
                evidence=seg.evidence,
                updated_by=who,
            )
        )
        taken_segments.add(seg.network)
        segments += 1

    assets = components = skipped = 0
    rows: list[dict[str, Any]] = []
    for s in result.systems:
        comps = [c for c in s.components if c[0] not in taken_networks]
        skipped += len(s.components) - len(comps)
        if not comps:
            continue
        name, n = s.name[:128], 2
        while name in taken_names:
            name = f"{s.name[:120]} ({n})"
            n += 1
        taken_names.add(name)
        group = AssetGroup(
            name=name,
            kind=s.kind,
            tier=s.tier,
            user_type=_user_type(s),
            domain=s.domain,
            source="discovery",
            confirmed=False,
            confidence=round(s.confidence * 100),
            evidence=s.evidence,
            updated_by=who,
        )
        db.add(group)
        db.flush()
        assets += 1
        for network, cname, role in comps:
            taken_networks.add(network)
            rows.append(
                {
                    "group_id": group.id,
                    "network": network,
                    "system": cname[:128],
                    "tier": s.tier,
                    "system_type": role[:32],
                    "user_type": group.user_type,
                    "ports": "",
                    "notes": "",
                    "source": "discovery",
                    "confirmed": True,  # the asset's own flag decides
                    "updated_by": who,
                }
            )
            components += 1
    for i in range(0, len(rows), 5000):
        db.execute(insert(Asset), rows[i : i + 5000])
    return DiscoverResult(
        segments=segments,
        assets=assets,
        components=components,
        domains=domains,
        replaced=replaced,
        skipped=skipped,
    )


def _user_type(s: discovery.SystemSuggestion) -> str | None:
    if s.kind != "user_segment":
        return None
    for user_type in discovery.USER_TYPE.values():
        if s.name == user_type or s.name.startswith(user_type + " "):
            return user_type
    return None


@router.post("/assets/discover", response_model=DiscoverResult)
def discover_assets(
    body: DiscoverRequest, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> DiscoverResult:
    """Infer segments, domains and assets from a snapshot; stored unconfirmed for review."""
    snap = db.get(Snapshot, body.snapshot_id)
    if snap is None or snap.status != "complete":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    result = store(db, discovery.run(db, snap.id), who.username)
    _audit(
        audit, db, who, request, "asset.discover", {"snapshot_id": snap.id, **result.model_dump()}
    )
    db.commit()
    return result


# ------------------------------------------------------------------ suggested assets


@router.post("/asset-groups/confirm", response_model=ConfirmResult)
def confirm_groups(
    body: ConfirmIds, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> ConfirmResult:
    """Accept suggested assets (by id, or every pending one)."""
    query = update(AssetGroup).where(AssetGroup.confirmed.is_(False))
    if not body.all:
        if not body.ids:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "ids_or_all")
        query = query.where(AssetGroup.id.in_(body.ids))
    count = _rows(db.execute(query.values(confirmed=True, updated_by=who.username)))
    _audit(audit, db, who, request, "asset_group.confirm", {"count": count, "all": body.all})
    db.commit()
    return ConfirmResult(confirmed=count)


@router.post("/assets/purge", response_model=PurgeResult)
def purge_assets(
    body: PurgeRequest, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> PurgeResult:
    """Bulk delete: ``all`` (every asset and entry), ``unassigned`` (entries outside any asset)
    or ``suggested`` (every unconfirmed suggestion). Requires ``confirm: "DELETE"``."""
    if body.scope == "all":
        deleted = _rows(db.execute(delete(Asset)))
        deleted += _rows(db.execute(delete(AssetGroup)))
    elif body.scope == "unassigned":
        deleted = _rows(db.execute(delete(Asset).where(Asset.group_id.is_(None))))
    else:
        deleted = _suggestions_cleared(db)
    _audit(audit, db, who, request, "asset.purge", {"scope": body.scope, "deleted": deleted})
    db.commit()
    return PurgeResult(deleted=deleted)


# ------------------------------------------------------------------ segments


def _segment_out(s: Segment) -> SegmentOut:
    return SegmentOut(
        id=s.id,
        network=s.network,
        name=s.name,
        role=s.role,
        domain=s.domain,
        cluster=s.cluster,
        interface=s.interface,
        zone=s.zone,
        gateway=s.gateway,
        in_dc=s.in_dc,
        source=s.source,
        confirmed=s.confirmed,
        confidence=s.confidence,
        evidence=[Evidence(**e) for e in s.evidence],
        notes=s.notes,
        updated_by=s.updated_by,
    )


@router.get("/segments", response_model=list[SegmentOut])
def list_segments(db: DbDep, _: ReaderDep) -> list[SegmentOut]:
    rows = db.scalars(select(Segment)).all()
    return [_segment_out(s) for s in sorted(rows, key=lambda s: discovery._sort_key(s.network))]


@router.post("/segments", response_model=SegmentOut, status_code=status.HTTP_201_CREATED)
def create_segment(
    body: SegmentIn, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> SegmentOut:
    if db.scalar(select(Segment.id).where(Segment.network == body.network)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "segment_exists")
    seg = Segment(
        **body.model_dump(),
        in_dc=body.role == "dc_servers",
        source="manual",
        confirmed=True,
        updated_by=who.username,
    )
    db.add(seg)
    db.flush()
    _audit(audit, db, who, request, "segment.create", {"network": seg.network, "role": seg.role})
    db.commit()
    return _segment_out(seg)


@router.patch("/segments/{segment_id}", response_model=SegmentOut)
def update_segment(
    segment_id: int,
    body: SegmentPatch,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    who: WriterDep,
) -> SegmentOut:
    seg = db.get(Segment, segment_id)
    if seg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(seg, key, value)
    if "role" in changes:
        seg.in_dc = seg.role == "dc_servers"
        seg.confirmed = changes.get("confirmed", True)  # an operator's choice is a decision
    seg.updated_by = who.username
    _audit(audit, db, who, request, "segment.update", {"network": seg.network, **changes})
    db.commit()
    return _segment_out(seg)


@router.delete("/segments/{segment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_segment(
    segment_id: int, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> None:
    seg = db.get(Segment, segment_id)
    if seg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    db.delete(seg)
    _audit(audit, db, who, request, "segment.delete", {"network": seg.network})
    db.commit()


@router.post("/segments/confirm", response_model=ConfirmResult)
def confirm_segments(
    body: ConfirmIds, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> ConfirmResult:
    query = update(Segment).where(Segment.confirmed.is_(False))
    if not body.all:
        if not body.ids:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "ids_or_all")
        query = query.where(Segment.id.in_(body.ids))
    count = _rows(db.execute(query.values(confirmed=True, updated_by=who.username)))
    _audit(audit, db, who, request, "segment.confirm", {"count": count, "all": body.all})
    db.commit()
    return ConfirmResult(confirmed=count)


@router.post("/segments/purge", response_model=PurgeResult)
def purge_segments(
    body: SegmentPurge, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> PurgeResult:
    query = delete(Segment)
    if body.scope == "suggested":
        query = query.where(Segment.confirmed.is_(False))
    deleted = _rows(db.execute(query))
    _audit(audit, db, who, request, "segment.purge", {"scope": body.scope, "deleted": deleted})
    db.commit()
    return PurgeResult(deleted=deleted)


# ------------------------------------------------------------------ domains


@router.get("/asset-domains", response_model=list[DomainOut])
def list_domains(db: DbDep, _: ReaderDep) -> list[DomainOut]:
    seg_count = dict(
        db.execute(
            select(Segment.domain, func.count())
            .where(Segment.domain.is_not(None))
            .group_by(Segment.domain)
        ).all()
    )
    asset_count = dict(
        db.execute(
            select(AssetGroup.domain, func.count())
            .where(AssetGroup.domain.is_not(None))
            .group_by(AssetGroup.domain)
        ).all()
    )
    return [
        DomainOut(
            id=d.id,
            name=d.name,
            description=d.description,
            source=d.source,
            confirmed=d.confirmed,
            evidence=[Evidence(**e) for e in d.evidence],
            segments=seg_count.get(d.name, 0),
            assets=asset_count.get(d.name, 0),
        )
        for d in db.scalars(select(AssetDomain).order_by(AssetDomain.name))
    ]


@router.post("/asset-domains", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
def create_domain(
    body: DomainIn, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> DomainOut:
    name = body.name.upper()
    if db.scalar(select(AssetDomain.id).where(AssetDomain.name == name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "domain_exists")
    d = AssetDomain(name=name, description=body.description, updated_by=who.username)
    db.add(d)
    db.flush()
    _audit(audit, db, who, request, "domain.create", {"name": name})
    db.commit()
    return next(x for x in list_domains(db, who) if x.id == d.id)


@router.patch("/asset-domains/{domain_id}", response_model=DomainOut)
def update_domain(
    domain_id: int, body: DomainPatch, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> DomainOut:
    d = db.get(AssetDomain, domain_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    changes = body.model_dump(exclude_unset=True)
    old = d.name
    if "name" in changes:
        changes["name"] = changes["name"].upper()
        if changes["name"] != old and db.scalar(
            select(AssetDomain.id).where(AssetDomain.name == changes["name"])
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "domain_exists")
    for key, value in changes.items():
        setattr(d, key, value)
    d.updated_by = who.username
    if d.name != old:  # a rename follows into the segments and assets that carry it
        db.execute(update(Segment).where(Segment.domain == old).values(domain=d.name))
        db.execute(update(AssetGroup).where(AssetGroup.domain == old).values(domain=d.name))
    _audit(audit, db, who, request, "domain.update", {"name": d.name, **changes})
    db.commit()
    return next(x for x in list_domains(db, who) if x.id == d.id)


@router.delete("/asset-domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    domain_id: int, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> None:
    d = db.get(AssetDomain, domain_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    db.execute(update(Segment).where(Segment.domain == d.name).values(domain=None))
    db.execute(update(AssetGroup).where(AssetGroup.domain == d.name).values(domain=None))
    db.delete(d)
    _audit(audit, db, who, request, "domain.delete", {"name": d.name})
    db.commit()
