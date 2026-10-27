"""Server-side sorting of the paged tables: whitelisted columns, both directions, stable."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("sort-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "sort-admin")}


def _rows(client: TestClient, url: str) -> list[dict[str, Any]]:
    response = client.get(url)
    assert response.status_code == 200, response.text
    body = response.json()
    return list(body["rows"] if isinstance(body, dict) else body)


def test_tables_sort_on_the_server(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    base = f"/api/snapshots/{sid}"

    refs = [o["rule_refs"] for o in _rows(client, f"{base}/objects?sort=rule_refs&order=desc")]
    assert refs == sorted(refs, reverse=True)
    assert refs[0] > 0
    groups = [o["member_of"] for o in _rows(client, f"{base}/objects?sort=member_of&order=asc")]
    assert groups == sorted(groups)
    # Paging stays stable under a sort with many ties.
    first = _rows(client, f"{base}/objects?sort=kind&order=asc&limit=20")
    again = _rows(client, f"{base}/objects?sort=kind&order=asc&limit=10&offset=10")
    assert [o["id"] for o in first[10:]] == [o["id"] for o in again]

    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    sev = [rank[f["severity"]] for f in _rows(client, f"{base}/findings?sort=severity&order=asc")]
    assert sev == sorted(sev)

    deltas = [
        r["ace_delta"]
        for r in _rows(client, f"{base}/recommendations?sort=ace_delta&order=asc&limit=200")
    ]
    assert deltas == sorted(deltas)

    aces = [r["ace_count"] for r in _rows(client, f"{base}/scores?sort=ace&order=desc")]
    assert aces == sorted(aces, reverse=True)

    for url in (
        f"{base}/objects?sort=id",
        f"{base}/objects?sort=name;drop",
        f"{base}/findings?sort=severity&order=up",
        f"{base}/recommendations?sort=plan",
        f"{base}/scores?sort=reasons",
    ):
        assert client.get(url).status_code == 422, url
