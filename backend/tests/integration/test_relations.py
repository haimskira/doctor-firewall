"""Object relations map and the redundancy fixes (redundant references / members)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase5_writes import CONFIG, Flow, _fresh_mock, _run, mock

__all__ = ["_fresh_mock"]


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("rel-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "rel-admin")}


def _object_id(client: TestClient, sid: int, name: str) -> str:
    page = client.get(f"/api/snapshots/{sid}/objects", params={"q": name, "limit": 50}).json()
    return str(next(o["id"] for o in page["rows"] if o["name"] == name))


def test_relations_map_and_fixes(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)  # pull + analysis
    sid = flow.sid
    host = _object_id(client, sid, "H_CHAIN_X")
    rel: dict[str, Any] = client.get(f"/api/snapshots/{sid}/objects/{host}/relations").json()
    by_label = {n["label"]: n for n in rel["nodes"]}
    # The whole chain above the host, with its depth (level 3 holds it directly: depth 1).
    assert by_label["GRP_CHAIN_1"]["depth"] == 1
    assert by_label["GRP_CHAIN_3"]["depth"] == 1
    assert by_label["GRP_CHAIN_8"]["depth"] == 6  # shortest path: host -> 3 -> ... -> 8
    assert by_label["GRP_CHAIN_8"]["role"] == "ancestor"
    rule = next(
        n for n in rel["nodes"] if n["role"] == "rule" and n["label"].endswith("CHAIN_RULE")
    )
    uses = {e["source"] for e in rel["edges"] if e["target"] == rule["id"] and e["kind"] == "uses"}
    assert uses == {host, by_label["GRP_CHAIN_4"]["id"], by_label["GRP_CHAIN_8"]["id"]}
    # Overlaps: SQL-FIN's network contains the host.
    overlaps = {e["label"] for e in rel["edges"] if e["kind"] == "overlap"}
    assert "within" in overlaps
    kinds = {(i["kind"], i["removed"], i["kept"]) for i in rel["issues"]}
    assert ("redundant_member", "H_CHAIN_X", "GRP_CHAIN_2") in kinds
    assert any(k == "redundant_reference" and removed == "H_CHAIN_X" for k, removed, _ in kinds)
    assert any(k == "redundant_reference" and removed == "GRP_CHAIN_4" for k, removed, _ in kinds)
    assert all(i["recommendation_id"] is not None for i in rel["issues"])

    # A group: its members tree is below it.
    top = by_label["GRP_CHAIN_8"]["id"]
    tree = client.get(f"/api/snapshots/{sid}/objects/{top}/relations").json()
    depth = {n["label"]: n["depth"] for n in tree["nodes"]}
    assert depth["GRP_CHAIN_7"] == -1
    assert depth["H_CHAIN_X"] == -6
    assert client.get(f"/api/snapshots/{sid}/objects/nope/relations").status_code == 404

    # The explorer's lazy tree: one level at a time, paged, with counts to expand further.
    level3 = by_label["GRP_CHAIN_3"]["id"]
    down = client.get(f"/api/snapshots/{sid}/objects/{level3}/tree?direction=down").json()
    assert {n["name"] for n in down["nodes"]} == {"GRP_CHAIN_2", "H_CHAIN_X"}
    chain2 = next(n for n in down["nodes"] if n["name"] == "GRP_CHAIN_2")
    assert (chain2["members"], chain2["member_of"]) == (1, 1)
    up = client.get(f"/api/snapshots/{sid}/objects/{host}/tree?direction=up&limit=1").json()
    assert (up["total"], len(up["nodes"])) == (2, 1)  # GRP_CHAIN_1 and GRP_CHAIN_3
    assert up["nodes"][0]["rule_refs"] == 0
    more = client.get(f"/api/snapshots/{sid}/objects/{host}/tree?direction=up&offset=1").json()
    assert {up["nodes"][0]["name"], more["nodes"][0]["name"]} == {"GRP_CHAIN_1", "GRP_CHAIN_3"}
    assert (
        client.get(f"/api/snapshots/{sid}/objects/{host}/tree?direction=sideways").status_code
        == 422
    )

    # The fixes: executable, behaviour-preserving, applied through the normal approval flow.
    ref = flow.find("remove_redundant_reference", "CHAIN_RULE")
    member = flow.find("remove_redundant_member", "GRP_CHAIN_3")
    assert ref["executable"] is True
    assert member["executable"] is True
    detail = client.get(f"/api/snapshots/{sid}/recommendations/{ref['id']}").json()
    removed = {r["removed"] for r in detail["preview"]["redundant"]}
    assert removed == {"H_CHAIN_X", "GRP_CHAIN_4"}
    assert all(r["kept"] == "GRP_CHAIN_8" for r in detail["preview"]["redundant"])
    _cs, batch_id = flow.approved_batch([ref, member])
    result = _run(batch_id)
    assert result["ok"] is True, result
    written = flow.rules(ref["policy_fmc_id"])["CHAIN_RULE"]
    assert [o["name"] for o in written["destinationNetworks"]["objects"]] == ["GRP_CHAIN_8"]
    groups = {g["name"]: g for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert [o["name"] for o in groups["GRP_CHAIN_3"]["objects"]] == ["GRP_CHAIN_2"]
    flow.close()
