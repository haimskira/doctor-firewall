"""``python -m app.cli reset-data``: a fresh start against the same FMCs."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import cli
from app.db.session import get_sessionmaker
from app.models.assets import Asset
from app.models.audit import AuditRecord
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot
from app.models.user import User
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import DOCTRINE_CSV, _snapshot


def _count(model: type[object]) -> int:
    with get_sessionmaker()() as s:
        return s.scalar(select(func.count()).select_from(model)) or 0


def test_reset_keeps_users_connections_and_audit(client: TestClient) -> None:
    make_user("reset-admin", ["admin"])
    h = {"X-CSRF-Token": login(client, "reset-admin")}
    client.post("/api/assets/import", headers=h, json={"csv": DOCTRINE_CSV})
    _snapshot(client, h)
    assert _count(Snapshot) == 1
    assert cli.main(["reset-data"]) == 2  # refuses without --yes
    assert _count(Snapshot) == 1
    assert cli.main(["reset-data", "--yes", "--keep-assets"]) == 0
    assert (_count(Snapshot), _count(Asset) > 0) == (0, True)
    assert cli.main(["reset-data", "--yes"]) == 0
    assert _count(Asset) == 0
    assert _count(User) >= 1
    assert _count(FmcConnection) == 1
    with get_sessionmaker()() as s:
        actions = list(
            s.scalars(select(AuditRecord.action).where(AuditRecord.action == "data.reset"))
        )
    assert len(actions) == 2
    assert cli.main(["verify-audit"]) == 0
