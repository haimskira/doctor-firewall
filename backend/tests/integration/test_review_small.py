"""Small review fixes: objects narrowed to a policy; bulk decisions on a stale snapshot."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.db.session import get_sessionmaker
from app.models.enforce import Batch, Changeset
from app.models.inventory import Snapshot
from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _all, _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("small-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "small-admin")}


def test_objects_of_one_policy_match_the_dashboard_count(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    everything = client.get(f"/api/snapshots/{sid}/objects?limit=1").json()["total"]
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, sid)
        assert snap is not None
        counts = dict(snap.stats["objects_by_policy"])
    assert counts
    for policy, expected in counts.items():
        page = client.get(f"/api/snapshots/{sid}/objects?limit=500&policy={policy}")
        assert page.status_code == 200, page.text
        assert page.json()["total"] == expected
    assert min(counts.values()) < everything
    bad = client.get(f"/api/snapshots/{sid}/objects?policy=a%20b")
    assert bad.status_code == 422


def test_bulk_decision_is_accepted_on_a_stale_snapshot(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, sid)
        assert snap is not None
        changeset = Changeset(
            connection_id=snap.connection_id,
            snapshot_id=sid,
            title="earlier deploy",
            ticket_id="CHG-1",
            deploy_limit=100,
            created_by="small-admin",
        )
        s.add(changeset)
        s.flush()
        s.add(
            Batch(
                changeset_id=changeset.id,
                seq=1,
                status="deployed",
                op_count=1,
                deploy_limit=100,
                finished_at=datetime.now(UTC) + timedelta(hours=1),
                results=[{"op": "update_rule"}],
            )
        )
        s.commit()
    make_user("small-opt", ["optimizer"])
    kind = "merge_duplicate_objects"
    url = f"/api/snapshots/{sid}/recommendations/decisions"
    with TestClient(client.app, base_url="https://testserver") as opt:
        h = {"X-CSRF-Token": login(opt, "small-opt")}
        wanted = [r for r in _all(opt, sid, kind=kind) if r["executable"]]
        assert wanted
        one = opt.put(
            f"/api/snapshots/{sid}/recommendations/{wanted[0]['id']}/decision",
            headers=h,
            json={"status": "dismissed"},
        )
        assert one.status_code == 200
        done = opt.post(url, headers=h, json={"status": "accepted", "kind": kind})
        assert done.status_code == 200, done.text
        assert done.json()["count"] == len(wanted) - 1
