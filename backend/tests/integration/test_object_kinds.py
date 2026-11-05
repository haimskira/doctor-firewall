"""Objects page: per-kind tab counts, several kinds at once and the unused filter."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("kinds-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "kinds-admin")}


def _total(client: TestClient, url: str) -> int:
    resp = client.get(url)
    assert resp.status_code == 200, resp.text
    return int(resp.json()["total"])


def test_kind_counts_match_the_object_list(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    base = f"/api/snapshots/{sid}/objects?limit=1"
    resp = client.get(f"/api/snapshots/{sid}/object-kinds")
    assert resp.status_code == 200, resp.text
    kinds = {k["kind"]: k for k in resp.json()["kinds"]}
    assert kinds
    assert sum(k["total"] for k in kinds.values()) == _total(client, base)
    for name, row in kinds.items():
        assert _total(client, f"{base}&kind={name}") == row["total"]
        assert _total(client, f"{base}&kind={name}&usage=unused") == row["unused"]
        assert _total(client, f"{base}&kind={name}&usage=used") == row["total"] - row["unused"]
    two = sorted(kinds)[:2]
    assert _total(client, f"{base}&kind={two[0]}&kind={two[-1]}") == sum(
        kinds[k]["total"] for k in set(two)
    )


def test_kind_counts_follow_the_policy_and_search(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    policies = client.get(f"/api/snapshots/{sid}/policies").json()
    policy = next(p["id"] for p in policies if p["kind"] == "access")
    scoped = client.get(f"/api/snapshots/{sid}/object-kinds?policy={policy}").json()["kinds"]
    assert sum(k["total"] for k in scoped) == _total(
        client, f"/api/snapshots/{sid}/objects?limit=1&policy={policy}"
    )
    found = client.get(f"/api/snapshots/{sid}/object-kinds?q=zzz-no-such-object").json()
    assert found["kinds"] == []


def test_bad_kind_and_usage_are_rejected(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    assert client.get(f"/api/snapshots/{sid}/objects?kind=Bad-Kind").status_code == 422
    assert client.get(f"/api/snapshots/{sid}/objects?usage=maybe").status_code == 422
    assert client.get(f"/api/snapshots/{sid}/object-kinds?policy=a%20b").status_code == 422
