"""Asset table (doctrine classification) and per-cluster platform limits."""

from __future__ import annotations

import csv
import io
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import AfterValidator, BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.bootstrap import suggest
from app.api.schemas import StrictModel
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.core.config import get_settings
from app.db.session import get_db
from app.fmc import normalize
from app.models.assets import ASSET_KINDS, Asset, AssetGroup, ClusterSetting
from app.models.inventory import Snapshot
from app.runtime import get_audit

router = APIRouter(prefix="/api", tags=["assets"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
WriterDep = Annotated[Principal, Depends(require(Permission.ASSETS_WRITE))]
FmcAdminDep = Annotated[Principal, Depends(require(Permission.FMC_MANAGE))]

ClusterIdPath = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
CSV_COLUMNS = ("network", "system", "tier", "system_type", "user_type", "ports", "notes")
# Optional: the asset a row belongs to (created on import if it does not exist).
CSV_ASSET_COLUMNS = ("asset", "asset_kind")
MAX_CSV_BYTES = 1_000_000
MAX_CSV_ROWS = 20_000
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _canonical_network(value: str) -> str:
    text = value.strip()
    try:
        return normalize.ip_range(text) if "-" in text else normalize.address(text)
    except ValueError as exc:
        raise ValueError("network must be an IP, CIDR or start-end range") from exc


Network = Annotated[str, Field(min_length=1, max_length=96), AfterValidator(_canonical_network)]
Tier = Literal["CORE", "GOLD", "SILVER", "BRONZE", "USERS"]
Label = Annotated[str, Field(max_length=32, pattern=r"^[\w .+-]*$")]


class AssetIn(StrictModel):
    network: Network
    system: Annotated[str, Field(min_length=1, max_length=128)]
    tier: Tier
    system_type: Label = ""
    user_type: Annotated[str, Field(max_length=16, pattern=r"^[\w-]+$")] | None = None
    ports: Annotated[str, Field(max_length=256)] = ""
    notes: Annotated[str, Field(max_length=512)] = ""


class AssetPatch(StrictModel):
    group_id: int | None = None  # move to another asset (null: stand-alone)
    system: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    tier: Tier | None = None
    system_type: Label | None = None
    user_type: Annotated[str, Field(max_length=16, pattern=r"^[\w-]+$")] | None = None
    ports: Annotated[str, Field(max_length=256)] | None = None
    notes: Annotated[str, Field(max_length=512)] | None = None
    confirmed: bool | None = None


class AssetOut(BaseModel):
    id: int
    group_id: int | None
    network: str
    system: str
    tier: str
    system_type: str
    user_type: str | None
    ports: str
    notes: str
    source: str
    confirmed: bool
    updated_by: str


AssetKind = Literal["system", "server", "user", "user_segment"]
UserType = Annotated[str, Field(max_length=16, pattern=r"^[\w-]+$")]


class GroupIn(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    kind: AssetKind = "system"
    tier: Tier
    user_type: UserType | None = None
    owner: Annotated[str, Field(max_length=128)] = ""
    description: Annotated[str, Field(max_length=512)] = ""


class GroupPatch(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    kind: AssetKind | None = None
    tier: Tier | None = None
    user_type: UserType | None = None
    owner: Annotated[str, Field(max_length=128)] | None = None
    description: Annotated[str, Field(max_length=512)] | None = None


class ComponentIn(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    network: Network
    role: Label = ""
    ports: Annotated[str, Field(max_length=256)] = ""
    notes: Annotated[str, Field(max_length=512)] = ""


class GroupOut(BaseModel):
    id: int
    name: str
    kind: str
    tier: str
    user_type: str | None
    owner: str
    description: str
    updated_by: str
    components: list[AssetOut]


class CsvImport(StrictModel):
    csv: Annotated[str, Field(max_length=MAX_CSV_BYTES)]


class ImportResult(BaseModel):
    created: int
    updated: int


class BootstrapRequest(StrictModel):
    snapshot_id: Annotated[int, Field(ge=1)]


class ConfirmRequest(StrictModel):
    ids: Annotated[list[int], Field(min_length=1, max_length=10_000)]


class ClusterLimitIn(StrictModel):
    ace_limit: Annotated[int, Field(ge=1000, le=100_000_000)]
    ace_limit_verified: bool
    deploy_change_limit: Annotated[int, Field(ge=1, le=100_000)]
    deploy_limit_verified: bool


class ClusterLimitOut(BaseModel):
    cluster_fmc_id: str
    ace_limit: int
    ace_limit_verified: bool
    deploy_change_limit: int
    deploy_limit_verified: bool
    is_default: bool


def _out(a: Asset) -> AssetOut:
    return AssetOut(
        id=a.id,
        group_id=a.group_id,
        network=a.network,
        system=a.system,
        tier=a.tier,
        system_type=a.system_type,
        user_type=a.user_type,
        ports=a.ports,
        notes=a.notes,
        source=a.source,
        confirmed=a.confirmed,
        updated_by=a.updated_by,
    )


def _audit(
    audit: AuditLog,
    db: Session,
    who: Principal,
    request: Request,
    action: str,
    details: dict[str, Any],
) -> None:
    audit.record(
        db,
        AuditEvent(
            actor=who.username,
            actor_id=who.user_id,
            action=action,
            outcome="success",
            source_ip=client_ip(request),
            details=details,
        ),
    )


# ------------------------------------------------------------------ assets


@router.get("/assets", response_model=list[AssetOut])
def list_assets(db: DbDep, _: ReaderDep, confirmed: bool | None = None) -> list[AssetOut]:
    query = select(Asset).order_by(Asset.tier, Asset.system, Asset.network)
    if confirmed is not None:
        query = query.where(Asset.confirmed.is_(confirmed))
    return [_out(a) for a in db.scalars(query)]


@router.post("/assets", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetIn, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> AssetOut:
    if db.scalar(select(Asset.id).where(Asset.network == body.network)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "network_exists")
    asset = Asset(**body.model_dump(), source="manual", confirmed=True, updated_by=who.username)
    db.add(asset)
    db.flush()
    _audit(audit, db, who, request, "asset.create", {"network": asset.network, "tier": asset.tier})
    db.commit()
    return _out(asset)


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int, body: AssetPatch, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    changes = body.model_dump(exclude_unset=True)
    if changes.get("group_id") is not None:
        group = db.get(AssetGroup, changes["group_id"])
        if group is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
        changes["tier"], changes["user_type"] = group.tier, group.user_type
        changes["confirmed"] = True
    for key, value in changes.items():
        setattr(asset, key, value)
    asset.updated_by = who.username
    _audit(
        audit,
        db,
        who,
        request,
        "asset.update",
        {"network": asset.network, "fields": sorted(changes)},
    )
    db.commit()
    return _out(asset)


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> None:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    _audit(audit, db, who, request, "asset.delete", {"network": asset.network})
    db.delete(asset)
    db.commit()


@router.post("/assets/confirm", response_model=ImportResult)
def confirm_assets(
    body: ConfirmRequest, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> ImportResult:
    assets = db.scalars(select(Asset).where(Asset.id.in_(body.ids))).all()
    for a in assets:
        a.confirmed = True
        a.updated_by = who.username
    _audit(audit, db, who, request, "asset.confirm", {"count": len(assets)})
    db.commit()
    return ImportResult(created=0, updated=len(assets))


@router.post("/assets/import", response_model=None)
def import_assets(
    body: CsvImport, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> ImportResult | JSONResponse:
    """Upsert assets from CSV (header row required). All-or-nothing: any invalid row
    rejects the whole file with per-line errors."""
    reader = csv.DictReader(io.StringIO(body.csv))
    if reader.fieldnames is None or "network" not in reader.fieldnames:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "csv_header_missing")
    unknown = set(reader.fieldnames) - set(CSV_COLUMNS) - set(CSV_ASSET_COLUMNS)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "csv_unknown_columns")
    rows: dict[str, AssetIn] = {}
    # The asset (name, kind) each network belongs to, when the CSV says so.
    owners: dict[str, tuple[str, str]] = {}
    errors: list[dict[str, object]] = []
    for line, raw in enumerate(reader, start=2):
        if line > MAX_CSV_ROWS + 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "csv_too_many_rows")
        cleaned = {k: (v or "").strip() for k, v in raw.items() if k}
        asset_name = cleaned.pop("asset", "")
        asset_kind = cleaned.pop("asset_kind", "") or "system"
        if len(asset_name) > 128 or asset_kind not in ASSET_KINDS:
            errors.append(
                {"line": line, "fields": ["asset" if len(asset_name) > 128 else "asset_kind"]}
            )
            continue
        if not cleaned.get("user_type"):
            cleaned.pop("user_type", None)
        cleaned["tier"] = cleaned.get("tier", "").upper()
        try:
            item = AssetIn.model_validate(cleaned)
        except ValidationError as exc:
            errors.append(
                {
                    "line": line,
                    "fields": sorted({str(e["loc"][0]) for e in exc.errors() if e["loc"]}),
                }
            )
            continue
        if item.network in rows:
            errors.append({"line": line, "fields": ["network"], "duplicate": True})
            continue
        rows[item.network] = item
        if asset_name:
            owners[item.network] = (asset_name, asset_kind)
    if errors:
        # Line numbers and field names only — cell values are never echoed back.
        return JSONResponse(
            {"detail": "csv_invalid_rows", "errors": errors[:200]},
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    existing = {a.network: a for a in db.scalars(select(Asset).where(Asset.network.in_(rows)))}
    groups = {g.name: g for g in db.scalars(select(AssetGroup))}
    created = updated = 0
    for network, item in rows.items():
        values = item.model_dump()
        owner = owners.get(network)
        if owner is not None:
            group = groups.get(owner[0])
            if group is None:
                group = AssetGroup(
                    name=owner[0],
                    kind=owner[1],
                    tier=item.tier,
                    user_type=item.user_type,
                    updated_by=who.username,
                )
                db.add(group)
                db.flush()
                groups[group.name] = group
            values.update(group_id=group.id, tier=group.tier, user_type=group.user_type)
        asset = existing.get(network)
        if asset is None:
            db.add(Asset(**values, source="csv", confirmed=True, updated_by=who.username))
            created += 1
        else:
            for key, value in values.items():
                setattr(asset, key, value)
            asset.confirmed, asset.updated_by = True, who.username
            updated += 1
    _audit(audit, db, who, request, "asset.import", {"created": created, "updated": updated})
    db.commit()
    return ImportResult(created=created, updated=updated)


def _safe_cell(value: str) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


@router.get("/assets/export")
def export_assets(db: DbDep, _: ReaderDep) -> Response:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow((*CSV_COLUMNS, *CSV_ASSET_COLUMNS))
    for a, joined in db.execute(
        select(Asset, AssetGroup)
        .outerjoin(AssetGroup, AssetGroup.id == Asset.group_id)
        .where(Asset.confirmed.is_(True))
        .order_by(Asset.network)
    ).all():
        g: AssetGroup | None = joined  # outer join: None for a stand-alone entry
        writer.writerow(
            [
                _safe_cell(str(v or ""))
                for v in (
                    a.network,
                    a.system,
                    a.tier,
                    a.system_type,
                    a.user_type,
                    a.ports,
                    a.notes,
                    g.name if g else "",
                    g.kind if g else "",
                )
            ]
        )
    return Response(
        out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="assets.csv"'},
    )


@router.post("/assets/bootstrap", response_model=ImportResult)
def bootstrap_assets(
    body: BootstrapRequest, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> ImportResult:
    """Suggest classifications from object names; stored unconfirmed for review."""
    snap = db.get(Snapshot, body.snapshot_id)
    if snap is None or snap.status != "complete":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    existing = set(db.scalars(select(Asset.network)))
    suggestions = suggest(db, body.snapshot_id, existing)
    for s in suggestions:
        db.add(
            Asset(
                network=s.network,
                system=s.system,
                tier=s.tier,
                user_type=s.user_type,
                source="bootstrap",
                confirmed=False,
                updated_by=who.username,
            )
        )
    _audit(
        audit,
        db,
        who,
        request,
        "asset.bootstrap",
        {"snapshot_id": body.snapshot_id, "suggested": len(suggestions)},
    )
    db.commit()
    return ImportResult(created=len(suggestions), updated=0)


# ------------------------------------------------------------------ asset groups


def _group_out(g: AssetGroup, components: list[Asset]) -> GroupOut:
    return GroupOut(
        id=g.id,
        name=g.name,
        kind=g.kind,
        tier=g.tier,
        user_type=g.user_type,
        owner=g.owner,
        description=g.description,
        updated_by=g.updated_by,
        components=[_out(a) for a in components],
    )


def _components(db: Session, group_id: int) -> list[Asset]:
    return list(db.scalars(select(Asset).where(Asset.group_id == group_id).order_by(Asset.network)))


@router.get("/asset-groups", response_model=list[GroupOut])
def list_groups(db: DbDep, _: ReaderDep) -> list[GroupOut]:
    """Assets with their components (address, ports, role)."""
    members: dict[int, list[Asset]] = {}
    for a in db.scalars(select(Asset).where(Asset.group_id.is_not(None)).order_by(Asset.network)):
        if a.group_id is not None:
            members.setdefault(a.group_id, []).append(a)
    return [
        _group_out(g, members.get(g.id, []))
        for g in db.scalars(select(AssetGroup).order_by(AssetGroup.tier, AssetGroup.name))
    ]


@router.post("/asset-groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
def create_group(
    body: GroupIn, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> GroupOut:
    if db.scalar(select(AssetGroup.id).where(AssetGroup.name == body.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "asset_exists")
    group = AssetGroup(**body.model_dump(), updated_by=who.username)
    db.add(group)
    db.flush()
    _audit(audit, db, who, request, "asset_group.create", {"name": group.name, "tier": group.tier})
    db.commit()
    return _group_out(group, [])


@router.patch("/asset-groups/{group_id}", response_model=GroupOut)
def update_group(
    group_id: int, body: GroupPatch, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> GroupOut:
    group = db.get(AssetGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    changes = body.model_dump(exclude_unset=True)
    renamed = "name" in changes and changes["name"] != group.name
    if renamed and db.scalar(select(AssetGroup.id).where(AssetGroup.name == changes["name"])):
        raise HTTPException(status.HTTP_409_CONFLICT, "asset_exists")
    for key, value in changes.items():
        setattr(group, key, value)
    group.updated_by = who.username
    components = _components(db, group.id)
    for a in components:  # components carry the asset's classification
        a.tier, a.user_type = group.tier, group.user_type
    _audit(audit, db, who, request, "asset_group.update", {"name": group.name, **changes})
    db.commit()
    return _group_out(group, components)


@router.delete("/asset-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    group_id: int, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> None:
    group = db.get(AssetGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    count = len(_components(db, group.id))
    db.delete(group)
    _audit(audit, db, who, request, "asset_group.delete", {"name": group.name, "components": count})
    db.commit()


@router.post(
    "/asset-groups/{group_id}/components",
    response_model=AssetOut,
    status_code=status.HTTP_201_CREATED,
)
def add_component(
    group_id: int, body: ComponentIn, request: Request, db: DbDep, audit: AuditDep, who: WriterDep
) -> AssetOut:
    group = db.get(AssetGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if db.scalar(select(Asset.id).where(Asset.network == body.network)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "network_exists")
    component = Asset(
        group_id=group.id,
        network=body.network,
        system=body.name,
        tier=group.tier,
        user_type=group.user_type,
        system_type=body.role,
        ports=body.ports,
        notes=body.notes,
        source="manual",
        confirmed=True,
        updated_by=who.username,
    )
    db.add(component)
    db.flush()
    _audit(
        audit,
        db,
        who,
        request,
        "asset.create",
        {"network": component.network, "asset": group.name},
    )
    db.commit()
    return _out(component)


# ------------------------------------------------------------------ cluster limits


@router.get("/clusters/{cluster_id}/limits", response_model=ClusterLimitOut)
def get_limits(cluster_id: ClusterIdPath, db: DbDep, _: ReaderDep) -> ClusterLimitOut:
    setting = db.get(ClusterSetting, cluster_id)
    settings = get_settings()
    if setting is None:
        return ClusterLimitOut(
            cluster_fmc_id=cluster_id,
            ace_limit=settings.default_ace_limit,
            ace_limit_verified=False,
            deploy_change_limit=settings.default_deploy_change_limit,
            deploy_limit_verified=False,
            is_default=True,
        )
    return ClusterLimitOut(
        cluster_fmc_id=cluster_id,
        ace_limit=setting.ace_limit,
        ace_limit_verified=setting.ace_limit_verified,
        deploy_change_limit=setting.deploy_change_limit,
        deploy_limit_verified=setting.deploy_limit_verified,
        is_default=False,
    )


@router.put("/clusters/{cluster_id}/limits", response_model=ClusterLimitOut)
def set_limits(
    cluster_id: ClusterIdPath,
    body: ClusterLimitIn,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    who: FmcAdminDep,
) -> ClusterLimitOut:
    setting = db.get(ClusterSetting, cluster_id)
    if setting is None:
        setting = ClusterSetting(
            cluster_fmc_id=cluster_id, updated_by=who.username, **body.model_dump()
        )
        db.add(setting)
    else:
        for key, value in body.model_dump().items():
            setattr(setting, key, value)
        setting.updated_by = who.username
    _audit(audit, db, who, request, "cluster.limits", {"cluster": cluster_id, **body.model_dump()})
    db.commit()
    return ClusterLimitOut(cluster_fmc_id=cluster_id, **body.model_dump(), is_default=False)
