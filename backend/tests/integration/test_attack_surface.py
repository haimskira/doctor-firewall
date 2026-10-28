"""Attack surface API over a collected and analysed snapshot of the FMC mock."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.analysis.attack import load_hops
from app.db.session import get_sessionmaker
from app.models.inventory import FwObject
from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("atk-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "atk-admin")}


def test_paths_to_a_target_and_blast_radius(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    base = f"/api/snapshots/{sid}/attack-surface"
    targets = client.get(f"{base}/targets").json()
    gold = [t for t in targets if t["tier"] == "GOLD"]
    users = [t for t in targets if t["tier"] == "USERS"]
    assert gold
    assert users

    results = [client.get(base, params={"system": t["id"], "depth": 3}) for t in gold]
    assert all(r.status_code == 200 for r in results)
    reached = [r.json() for r in results if r.json()["paths"]]
    assert reached, "some GOLD system must be reachable in the mock rulebase"
    surface = reached[0]
    assert surface["mode"] == "to"
    origin = set(surface["origin"]["nodes"])
    assert origin
    for path in surface["paths"]:
        assert set(path["steps"][-1]["nodes"]) & origin  # every path ends at the target
        assert len(path["hops"]) == len(path["steps"]) - 1
        assert all(h["rules"] for h in path["hops"])
    scores = [p["score"] for p in surface["paths"]]
    assert scores == sorted(scores, reverse=True)
    assert {n["id"] for n in surface["nodes"]} >= origin
    assert surface["summary"]["paths"] >= len(surface["paths"])

    blast = client.get(base, params={"system": users[0]["id"], "mode": "from", "depth": 2})
    assert blast.status_code == 200
    for path in blast.json()["paths"]:
        assert set(path["steps"][0]["nodes"]) & set(blast.json()["origin"]["nodes"])

    by_ip = client.get(base, params={"address": "10.20.0.10", "depth": 1})
    assert by_ip.status_code == 200
    assert by_ip.json()["origin"]["networks"] == ["10.20.0.10/32"]

    for params, code in (
        ({}, 422),
        ({"system": gold[0]["id"], "address": "10.0.0.1"}, 422),
        ({"address": "10.0.0.1/40"}, 422),
        ({"address": "0.0.0.0/0"}, 422),
        ({"system": "GOLD|no such system"}, 404),
        ({"object": "nope"}, 404),
        ({"system": gold[0]["id"], "depth": 9}, 422),
        ({"system": gold[0]["id"], "mode": "sideways"}, 422),
    ):
        assert client.get(base, params=params).status_code == code, params
    assert client.get("/api/snapshots/999999/attack-surface/targets").status_code == 404


def test_identity_conditions_and_dynamic_mappings(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    with get_sessionmaker()() as s:
        hops = {h.name: h for h in load_hops(s, sid)}
        dyn = s.scalar(
            select(FwObject).where(FwObject.snapshot_id == sid, FwObject.name == "DYN_K8S_PODS")
        )
    # A permit that also needs an SGT says so: the addresses alone overstate who gets through.
    assert ("src_sgt", "SGT_FIN_USERS") in hops["FIN-APP_TO_GOLD-DB_SQL"].conditions
    assert hops["FIN-APP_TO_GOLD-DB_SQL"].describe()["conditions"] == [
        {"field": "src_sgt", "name": "SGT_FIN_USERS"}
    ]
    assert any(("dst_dyn", "DYN_K8S_PODS") in h.conditions for h in hops.values())
    # The addresses a dynamic object maps to are collected (junk dropped), shown on the object.
    assert dyn is not None
    assert dyn.attrs["mappings"] == ["10.60.1.10/32", "10.60.2.0/24", "pods.k8s.local"]
    assert dyn.attrs["mappings_total"] == 3
    detail = client.get(f"/api/snapshots/{sid}/objects/{dyn.fmc_id}").json()
    assert detail["attrs"]["mappings_total"] == 3


def test_prefilter_blocks_cut_hops_and_zones_narrow_them(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    with get_sessionmaker()() as s:
        hops = {h.name: h for h in load_hops(s, sid)}
    # BLOCK_BOGONS (prefilter, 0.0.0.0/8) drops all of it before the access policy: no hop.
    assert "BOGON_ALLOW" not in hops
    # 0.0.0.0/7 is half bogons: still a hop, marked as partly decided earlier.
    assert hops["HALF_BOGON_ALLOW"].partial is True
    # "any" source from the users zone is only what is routed behind that zone.
    users = hops["USERS_ZONE_ANY"]
    assert not users.src.any
    assert not users.src.empty


def test_an_unassigned_policy_is_cleaned_up_but_opens_nothing(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    policies = {p["name"]: p for p in client.get(f"/api/snapshots/{sid}/policies").json()}
    staging = policies["ACP-STAGING"]
    # Collected and analysed like any policy: its shadowed and disabled rules get fixes.
    recs = client.get(
        f"/api/snapshots/{sid}/recommendations", params={"policy": staging["id"], "limit": 50}
    ).json()["rows"]
    assert {"remove_shadowed_rule", "remove_disabled_rule"} <= {r["kind"] for r in recs}
    # ... but no device enforces it: not on the map, not in the attack surface by default —
    # and when it is chosen, they show what it would allow.
    with get_sessionmaker()() as s:
        hops = load_hops(s, sid)
        staged_hops = load_hops(s, sid, only=staging["id"])
    assert not [h for h in hops if h.policy_fmc_id == staging["id"]]
    assert {h.name for h in staged_hops} == {"STAGE_WEB"}  # its shadowed copy never matches
    by_default = client.get(f"/api/snapshots/{sid}/map").json()
    chosen = client.get(f"/api/snapshots/{sid}/map", params={"policy": staging["id"]}).json()
    rules = {r["name"] for e in chosen["edges"] for r in e["rules"]}
    assert rules == {"STAGE_WEB"}
    assert not any(r["name"] == "STAGE_WEB" for e in by_default["edges"] for r in e["rules"])
    # Dashboard and roadmap narrowed to the policy's world: its rules and the two objects they
    # use. Unused objects belong to no policy, other policies' objects are not its work.
    dash = client.get(f"/api/snapshots/{sid}/dashboard", params={"policy": staging["id"]}).json()
    assert dash["totals"]["rules"] == 3
    assert dash["totals"]["clusters"] == 0
    assert dash["totals"]["objects"] == 2  # NET_STAGE_SRC, H_STAGE_DST
    kinds = {k["key"] for k in dash["recommendations_by_kind"]}
    assert {"remove_shadowed_rule", "remove_disabled_rule"} <= kinds
    assert "remove_unused_object" not in kinds
    everything = client.get(f"/api/snapshots/{sid}/dashboard").json()
    assert "remove_unused_object" in {k["key"] for k in everything["recommendations_by_kind"]}
    page = client.get(
        f"/api/snapshots/{sid}/recommendations", params={"policy": staging["id"], "limit": 1}
    ).json()
    assert sum(k["count"] for k in page["summary"].values()) == page["total"]
    found = client.get(
        f"/api/snapshots/{sid}/findings", params={"policy_id": staging["id"], "limit": 500}
    ).json()
    assert found["total"] == sum(sum(v.values()) for v in found["summary"].values())
    assert {f["kind"] for f in found["rows"]} <= {
        "shadowed_rule",
        "disabled_rule",
        "identical_rules",
    }
    # ... and the enforced policy's world holds none of the staging policy's items.
    enforced = next(p for p in policies.values() if p["kind"] == "access" and p["clusters"])
    other = client.get(
        f"/api/snapshots/{sid}/findings", params={"policy_id": enforced["id"], "limit": 500}
    ).json()
    assert not [f for f in other["rows"] if "STAGE_" in f["title"]]
    assert {f["kind"] for f in other["rows"]} - {f["kind"] for f in found["rows"]}
    road = client.get(f"/api/snapshots/{sid}/roadmap", params={"policy": staging["id"]}).json()
    first = road["phases"][0]
    assert {k["kind"]: k["total"] for k in first["kinds"]} == {
        "remove_disabled_rule": 1,
        "remove_shadowed_rule": 1,
    }
