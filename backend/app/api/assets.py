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
from app.models.assets import Asset, ClusterSetting
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
    system: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    tier: Tier | None = None
    system_type: Label | None = None
    user_type: Annotated[str, Field(max_length=16, pattern=r"^[\w-]+$")] | None = None
    ports: Annotated[str, Field(max_length=256)] | None = None
    notes: Annotated[str, Field(max_length=512)] | None = None
    confirmed: bool | None = None


class AssetOut(BaseModel):
    id: int
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
    unknown = set(reader.fieldnames) - set(CSV_COLUMNS)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "csv_unknown_columns")
    rows: dict[str, AssetIn] = {}
    errors: list[dict[str, object]] = []
    for line, raw in enumerate(reader, start=2):
        if line > MAX_CSV_ROWS + 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "csv_too_many_rows")
        cleaned = {k: (v or "").strip() for k, v in raw.items() if k}
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
    if errors:
        # Line numbers and field names only — cell values are never echoed back.
        return JSONResponse(
            {"detail": "csv_invalid_rows", "errors": errors[:200]},
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    existing = {a.network: a for a in db.scalars(select(Asset).where(Asset.network.in_(rows)))}
    created = updated = 0
    for network, item in rows.items():
        asset = existing.get(network)
        if asset is None:
            db.add(
                Asset(**item.model_dump(), source="csv", confirmed=True, updated_by=who.username)
            )
            created += 1
        else:
            for key, value in item.model_dump().items():
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
    writer.writerow(CSV_COLUMNS)
    for a in db.scalars(select(Asset).where(Asset.confirmed.is_(True)).order_by(Asset.network)):
        writer.writerow(
            [
                _safe_cell(str(v or ""))
                for v in (a.network, a.system, a.tier, a.system_type, a.user_type, a.ports, a.notes)
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
