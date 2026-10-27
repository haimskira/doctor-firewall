"""One decision for a whole filtered list of recommendations (e.g. every duplicate-object merge)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _all, _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("bulk-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "bulk-admin")}


def test_accept_and_reopen_a_whole_kind(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    kind = "merge_duplicate_objects"
    wanted = [r for r in _all(client, sid, kind=kind) if r["executable"]]
    assert len(wanted) > 1
    url = f"/api/snapshots/{sid}/recommendations/decisions"

    # Separation of duties: deciding is the optimizer's job, not the admin's or a viewer's.
    assert (
        client.post(url, headers=admin, json={"status": "accepted", "kind": kind}).status_code
        == 403
    )
    make_user("bulk-opt", ["optimizer"])
    make_user("bulk-viewer", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "bulk-viewer")}
        assert viewer.post(url, headers=h, json={"status": "accepted"}).status_code == 403

    with TestClient(client.app, base_url="https://testserver") as opt:
        h = {"X-CSRF-Token": login(opt, "bulk-opt")}
        assert (
            opt.post(url, headers=h, json={"status": "accepted", "kind": "bogus"}).status_code
            == 422
        )
        assert opt.post(url, headers=h, json={"status": "maybe"}).status_code == 422

        preview = opt.post(
            url, headers=h, json={"status": "accepted", "kind": kind, "dry_run": True}
        )
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["count"] == len(wanted)
        assert body["deploy_cost"] == sum(r["deploy_cost"] for r in wanted)
        assert body["batches"] == -(-body["deploy_cost"] // body["deploy_limit"])
        assert _all(opt, sid, state="accepted") == []  # a preview changes nothing

        done = opt.post(url, headers=h, json={"status": "accepted", "kind": kind, "note": "CHG-77"})
        assert done.json()["count"] == len(wanted)
        accepted = _all(opt, sid, state="accepted")
        assert {r["id"] for r in accepted} == {r["id"] for r in wanted}
        assert all(r["decision"]["note"] == "CHG-77" for r in accepted)
        # Accepting again finds nothing open of that kind.
        assert (
            opt.post(url, headers=h, json={"status": "accepted", "kind": kind}).json()["count"] == 0
        )

        # Dismissed ones are not swept up by a later bulk accept.
        other = _all(opt, sid, kind="remove_unused_object")[0]
        opt.put(
            f"/api/snapshots/{sid}/recommendations/{other['id']}/decision",
            headers=h,
            json={"status": "dismissed"},
        )
        everything = opt.post(url, headers=h, json={"status": "accepted", "dry_run": True}).json()
        assert other["id"] not in {r["id"] for r in _all(opt, sid, state="accepted")}
        assert everything["count"] >= 1

        reopened = opt.post(url, headers=h, json={"status": "open", "kind": kind})
        assert reopened.json()["count"] == len(wanted)
        assert _all(opt, sid, state="accepted") == []
        assert _all(opt, sid, state="dismissed")[0]["id"] == other["id"]

    with get_sessionmaker()() as s:
        actions = list(
            s.scalars(
                select(AuditRecord.action).where(AuditRecord.action.like("recommendation.bulk_%"))
            )
        )
    assert actions.count("recommendation.bulk_accepted") == 1  # nothing matched: no record
    assert "recommendation.bulk_open" in actions
