"""The effective asset classification used by every analysis.

A component inside an asset is analysed as the asset: the map node, the naming tokens and
the tier come from the asset; the address, ports and role stay the component's own.
Only confirmed entries count (discovery suggestions wait for an operator).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assets import Asset, AssetGroup


@dataclass(frozen=True)
class AssetRow:
    network: str
    system: str  # the asset's name (or the stand-alone entry's system)
    tier: str
    system_type: str  # the component's role (DB, App, ...)
    user_type: str | None
    ports: str
    component: str  # the component's own name


def effective_assets(session: Session) -> list[AssetRow]:
    rows: list[AssetRow] = []
    for a, joined in session.execute(
        select(Asset, AssetGroup)
        .outerjoin(AssetGroup, AssetGroup.id == Asset.group_id)
        .where(Asset.confirmed.is_(True))
        .where((AssetGroup.id.is_(None)) | AssetGroup.confirmed.is_(True))
        .order_by(Asset.network)
    ).all():
        g: AssetGroup | None = joined  # outer join: None for a stand-alone entry
        rows.append(
            AssetRow(
                network=a.network,
                system=g.name if g is not None else a.system,
                tier=g.tier if g is not None else a.tier,
                system_type=a.system_type,
                user_type=(g.user_type if g is not None else a.user_type),
                ports=a.ports,
                component=a.system,
            )
        )
    return rows


def fingerprint(rows: Iterable[AssetRow]) -> str:
    """What the map and the scores depend on: changes when an asset is added, moved, renamed,
    re-tiered or removed (recorded at analysis time; the map compares it with the table now)."""
    digest = hashlib.sha256()
    for line in sorted(f"{r.network}|{r.system}|{r.tier}|{r.user_type or ''}" for r in rows):
        digest.update(line.encode())
        digest.update(bytes([10]))
    return digest.hexdigest()
