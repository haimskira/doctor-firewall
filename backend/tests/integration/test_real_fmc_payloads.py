"""Behaviour learned from a real FMC 10.1 lab: built-in objects, disabled features, FTDv."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import _snapshot
from tests.integration.test_phase3 import _all
from tests.integration.test_phase5_writes import _fresh_mock, mock

__all__ = ["_fresh_mock"]  # autouse: every test starts from a fresh mock


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("real-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "real-admin")}


def test_builtin_objects_are_never_changed(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    page = client.get(f"/api/snapshots/{sid}/objects", params={"q": "any-ipv6"}).json()
    any6 = next(o for o in page["rows"] if o["name"] == "any-ipv6")
    assert any6["value"] == "::/0"  # a built-in Host whose value is a prefix
    unused = {
        t["name"] for r in _all(client, sid, kind="remove_unused_object") for t in r["targets"]
    }
    assert "any-ipv6" not in unused
    # Duplicates of a built-in port: the built-in survives, the custom copy goes.
    merges = _all(client, sid, kind="merge_duplicate_objects")
    https = next(r for r in merges if "value TCP/443" in r["title"])
    assert "into HTTPS" in https["title"]
    assert all("HTTPS" not in r["title"].split(" into ", 1)[-1].split(":", 1)[-1] for r in merges)


def test_feature_disabled_resources_do_not_fail_the_pull(
    client: TestClient, admin: dict[str, str]
) -> None:
    mock("POST", "/mock/faults", {"ise_disabled": True})
    sid = _snapshot(client, admin)
    snap = client.get(f"/api/snapshots/{sid}").json()
    assert snap["status"] == "complete"
    assert snap["stats"]["unavailable"]["isesecuritygrouptags"] == "feature_disabled"
