"""End-to-end collection: FMC mock (TLS) -> collector -> PostgreSQL -> analysis -> API.

The mock's data is deterministic, so the expected inventory is regenerated here from
the same seed and every count is compared exactly.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from fmc_mock.seed import generate
from sqlalchemy import func, select

from app.collector import runner, store
from app.core.config import get_settings, read_secret_file
from app.db.session import get_sessionmaker
from app.fmc.adapters import v10_1
from app.fmc.adapters.v10_1 import AdapterError
from app.fmc.client import ThrottlePolicy
from app.models.inventory import Rule, Snapshot, SnapshotCheckpoint
from app.workers import jobs
from tests.integration.conftest import login, make_user

DATA = generate(
    clusters=int(os.environ.get("MOCK_CLUSTERS", "2")),
    rules_per_policy=int(os.environ.get("MOCK_RULES_PER_POLICY", "150")),
    seed=int(os.environ.get("MOCK_SEED", "1")),
)


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real client throttle (240/min) would make this suite take minutes."""
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("collector-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "collector-admin")}


def _connection(client: TestClient, h: dict[str, str], **extra: Any) -> int:
    password = read_secret_file(Path(os.environ["DF_TEST_FMC_PASSWORD_FILE"]))
    resp = client.post(
        "/api/fmc/connections",
        headers=h,
        json={
            "name": "FMC-HA",
            "host": "fmc-mock",
            "port": 443,
            "username": "api_user",
            "password": password,
            **extra,
        },
    )
    assert resp.status_code == 201, resp.text
    conn_id: int = resp.json()["id"]
    return conn_id


def _collect(client: TestClient, h: dict[str, str], conn_id: int) -> int:
    resp = client.post(f"/api/fmc/connections/{conn_id}/collect", headers=h)
    assert resp.status_code == 202, resp.text
    snapshot_id: int = resp.json()["id"]
    return snapshot_id


def _snapshot(snapshot_id: int) -> Snapshot:
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, snapshot_id)
        assert snap is not None
        return snap


def _expected_by_kind() -> dict[str, int]:
    kinds = {
        "prefilterpolicies": "prefilter",
        "decryptionpolicies": "decryption",
        "identitypolicies": "identity",
        "ftdnatpolicies": "nat",
    }
    counts = {"access": sum(len(r) for r in DATA.rules.values())}
    for (resource, _pid, _sub), rules in DATA.policy_rules.items():
        counts[kinds[resource]] = counts.get(kinds[resource], 0) + len(rules)
    return counts


def _expected_rules() -> int:
    return sum(_expected_by_kind().values())


def test_full_collection_and_analysis(client: TestClient, admin: dict[str, str]) -> None:
    conn_id = _connection(client, admin)
    sid = _collect(client, admin, conn_id)
    assert _snapshot(sid).status == "pending"

    result = jobs.collect_snapshot(sid)
    assert result["ok"] is True, result
    snap = _snapshot(sid)
    assert snap.status == "complete"
    assert snap.fmc_version == "10.1.0 (build 117)"
    assert snap.stats["rules"] == _expected_rules()
    assert snap.stats["rules_by_kind"] == _expected_by_kind()
    assert snap.stats["clusters"] == len(DATA.ha_pairs)
    assert snap.stats["objects"] == sum(len(v) for v in DATA.objects.values())
    assert snap.stats["stub_objects"] > 0  # applications etc. known only by reference

    summary = jobs.analyze_snapshot(sid)
    assert _snapshot(sid).analyzed_at is not None
    for kind in (
        "duplicate_object",
        "group_cycle",
        "deep_nesting",
        "duplicate_membership",
        "inline_literal",
        "unused_object",
    ):
        assert summary.get(kind, 0) > 0, kind

    # ---- clusters & rulebase, exactly as in the FMC ----
    clusters = client.get(f"/api/snapshots/{sid}/clusters").json()
    assert [c["name"] for c in clusters] == sorted(p["name"] for p in DATA.ha_pairs)
    first = clusters[0]
    policy = first["policy_fmc_id"]
    expected = DATA.rules[policy]
    assert first["rule_count"] == len(expected)
    page = client.get(f"/api/snapshots/{sid}/policies/{policy}/rules?limit=500").json()
    assert page["total"] == len(expected)
    assert [r["name"] for r in page["rows"]] == [r["name"] for r in expected][:500]
    assert [r["index"] for r in page["rows"]] == list(range(1, len(page["rows"]) + 1))
    assert page["categories"] == ["DC-Inbound", "Users", "Infra"]
    # Section bands: contiguous runs covering every rule exactly once, in order.
    assert page["default_action"]
    bands = page["groups"]
    assert sum(g["count"] for g in bands) == len(expected)
    assert [g["start"] for g in bands] == [
        sum(g["count"] for g in bands[:i]) for i in range(len(bands))
    ]
    runs = [(r["metadata"]["section"], r["metadata"]["category"]) for r in expected]
    assert [(g["section"], g["category"]) for g in bands] == [
        run for i, run in enumerate(runs) if i == 0 or runs[i - 1] != run
    ]
    assert bands[0]["first_index"] == 1
    assert bands[-1]["last_index"] == len(expected)
    later = client.get(f"/api/snapshots/{sid}/policies/{policy}/rules?offset=200").json()
    assert later["groups"] == []
    sql_rule = next(r for r in page["rows"] if r["name"] == "FIN-APP_TO_GOLD-DB_SQL")
    assert sql_rule["section"] == "Mandatory"
    assert sql_rule["ips_policy"] == "Maximum Detection"
    assert [x["name"] for x in sql_rule["refs"]["dst_net"]] == ["GRP_SRV_GOLD"]
    assert sql_rule["refs"]["dst_port"][0]["kind"] == "port"
    hits_expected = sum(
        h["hitCount"] for (pid, _), items in DATA.hitcounts.items() if pid == policy for h in items
    )
    with get_sessionmaker()() as s:
        hits = s.scalar(
            select(func.sum(Rule.hit_count)).where(
                Rule.snapshot_id == sid, Rule.policy_fmc_id == policy
            )
        )
    assert hits == hits_expected

    search = client.get(f"/api/snapshots/{sid}/policies/{policy}/rules?q=gold-db").json()
    assert {r["name"] for r in search["rows"]} >= {
        "FIN-APP_TO_GOLD-DB_SQL",
        "DBA-PAW_TO_GOLD-DB_ADMIN",
    }
    by_object = client.get(f"/api/snapshots/{sid}/policies/{policy}/rules?q=GRP_LOOP_B").json()
    assert [r["name"] for r in by_object["rows"]] == ["NESTED_LOOP"]

    # ---- objects: where-used through groups and the membership tree ----
    hosts = client.get(f"/api/snapshots/{sid}/objects?kind=host&q=H_GOLD_DB1").json()
    assert hosts["total"] == 1
    db1 = hosts["rows"][0]["id"]
    detail = client.get(f"/api/snapshots/{sid}/objects/{db1}").json()
    groups = {e["group_name"] for e in detail["member_of"]}
    assert {"GRP_SRV_GOLD", "GRP_DC_ALL"} <= groups
    via = {u["via_name"] for u in detail["used_by"]}
    assert "GRP_SRV_GOLD" in via  # used by rules only through its group
    assert detail["used_by_total"] >= 1
    loop = client.get(f"/api/snapshots/{sid}/objects?q=GRP_LOOP_A").json()["rows"][0]
    loop_detail = client.get(f"/api/snapshots/{sid}/objects/{loop['id']}").json()
    assert {e["group_name"] for e in loop_detail["member_of"]} == {"GRP_LOOP_A", "GRP_LOOP_B"}
    assert client.get(f"/api/snapshots/{sid}/objects/does-not-exist").status_code == 404

    # ---- findings ----
    findings = client.get(f"/api/snapshots/{sid}/findings?limit=500").json()
    assert findings["summary"]["group_cycle"] == {"high": 1}
    assert findings["rows"][0]["severity"] == "high"  # most severe first

    def titles(kind: str) -> list[str]:
        page = client.get(f"/api/snapshots/{sid}/findings?kind={kind}&limit=500").json()
        return [f["title"] for f in page["rows"]]

    assert any("10.0.0.53/32" in t for t in titles("duplicate_object"))  # H_DNS1 / dns-primary
    assert any("GRP_NEST_1" in t for t in titles("deep_nesting"))
    assert any("203.0.113.254" in t for t in titles("inline_literal"))  # literal gateway
    assert any("GRP_UNUSED" in t for t in titles("unused_object"))
    dup = client.get(f"/api/snapshots/{sid}/findings?kind=duplicate_membership").json()
    assert any(f["details"].get("group", {}).get("name") == "GRP_DC_ALL" for f in dup["rows"])

    # ---- policy dependencies ----
    governing = {(p["kind"], p["via"]) for p in first["policies"]}
    assert governing == {
        ("access", "assignment"),
        ("nat", "assignment"),
        ("prefilter", "prefilterPolicySetting"),
    }
    inventory = client.get(f"/api/snapshots/{sid}/policies").json()
    kinds = {p["kind"] for p in inventory}
    assert kinds == {
        "access",
        "prefilter",
        "decryption",
        "identity",
        "nat",
        "intrusion",
        "file",
        "dns",
    }
    decrypt = next(p for p in inventory if p["kind"] == "decryption")
    assert decrypt["rule_count"] == 3
    assert decrypt["clusters"] == []  # association to an ACP is not documented; shown unlinked
    ips = [p for p in inventory if p["kind"] == "intrusion"]
    assert {p["attrs"].get("inspection_mode") for p in ips} == {"PREVENTION"}
    prefilter = next(p for p in first["policies"] if p["kind"] == "prefilter")
    pf_rules = client.get(f"/api/snapshots/{sid}/policies/{prefilter['id']}/rules").json()
    assert pf_rules["policy_kind"] == "prefilter"
    assert [(r["action"], r["rule_type"]) for r in pf_rules["rows"]] == [
        ("BLOCK", "PREFILTER"),
        ("FASTPATH", "PREFILTER"),
        ("ANALYZE", "TUNNEL"),
    ]
    nat = next(p for p in first["policies"] if p["kind"] == "nat")
    nat_rules = client.get(f"/api/snapshots/{sid}/policies/{nat['id']}/rules").json()
    assert [r["section"] for r in nat_rules["rows"]] == ["BEFORE_AUTO", "AUTO", "AFTER_AUTO"]
    assert [(g["section"], g["count"]) for g in nat_rules["groups"]] == [
        ("BEFORE_AUTO", 1),
        ("AUTO", 1),
        ("AFTER_AUTO", 1),
    ]
    auto = nat_rules["rows"][1]
    assert {x["name"] for x in auto["refs"]["nat_orig_src"]} == {"H_DMZ_WEB"}
    assert [x["literal"] for x in auto["refs"]["nat_trans_sport"]] == ["TCP/443"]
    dmz = client.get(f"/api/snapshots/{sid}/objects?q=H_DMZ_WEB_PUBLIC").json()["rows"][0]
    dmz_detail = client.get(f"/api/snapshots/{sid}/objects/{dmz['id']}").json()
    assert {(u["policy_kind"], u["field"]) for u in dmz_detail["used_by"]} == {
        ("nat", "nat_trans_src")
    }
    unused_titles = [
        f["title"]
        for f in client.get(f"/api/snapshots/{sid}/findings?kind=unused_object&limit=500").json()[
            "rows"
        ]
    ]
    assert not any("H_DMZ_WEB" in t for t in unused_titles)  # used by NAT only, still "used"

    # ---- network ----
    net = client.get(f"/api/snapshots/{sid}/clusters/{first['fmc_id']}/network").json()
    assert {i["ifname"] for i in net["interfaces"]} == {"outside", "inside", "dc", "users", "dmz"}
    kinds = {r["kind"] for r in net["routes"]}
    assert kinds == {"static", "connected"}
    default = next(r for r in net["routes"] if r["network_name"] == "any-ipv4")
    assert default["network"] == "0.0.0.0/0"
    assert default["gateway"] == "203.0.113.254"
    assert net["bgp"][0]["neighbors"]


def test_busy_and_rbac(client: TestClient, admin: dict[str, str]) -> None:
    conn_id = _connection(client, admin)
    _collect(client, admin, conn_id)
    again = client.post(f"/api/fmc/connections/{conn_id}/collect", headers=admin)
    assert again.status_code == 409
    assert again.json()["detail"] == "collection_in_progress"
    assert client.post("/api/fmc/connections/999/collect", headers=admin).status_code == 404

    make_user("watcher", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "watcher")}
        assert viewer.post(f"/api/fmc/connections/{conn_id}/collect", headers=h).status_code == 403
        assert viewer.get("/api/snapshots").status_code == 200
        names = viewer.get("/api/connections").json()
        assert names == [{"id": conn_id, "name": "FMC-HA", "sync_interval_minutes": None}]


def test_failure_then_resume_from_checkpoint(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    conn_id = _connection(client, admin)
    sid = _collect(client, admin, conn_id)
    calls = {"n": 0}
    real = v10_1.map_rule

    def flaky(item: Any, position: int) -> Any:
        calls["n"] += 1
        if calls["n"] > 160:  # fail inside the second policy, after a committed page
            raise AdapterError("accessrule x: injected failure")
        return real(item, position)

    monkeypatch.setattr(v10_1, "map_rule", flaky)
    result = jobs.collect_snapshot(sid)
    assert result == {"ok": False, "error": "unexpected_response"}
    failed = _snapshot(sid)
    assert failed.status == "failed"
    assert "injected failure" in (failed.error_detail or "")
    with get_sessionmaker()() as s:
        done = s.scalars(
            select(SnapshotCheckpoint.resource).where(
                SnapshotCheckpoint.snapshot_id == sid, SnapshotCheckpoint.done.is_(True)
            )
        ).all()
    assert any(r.startswith("objects:") for r in done)

    monkeypatch.setattr(v10_1, "map_rule", real)
    resumed = client.post(f"/api/snapshots/{sid}/resume", headers=admin)
    assert resumed.status_code == 202
    assert jobs.collect_snapshot(sid)["ok"] is True
    snap = _snapshot(sid)
    assert snap.status == "complete"
    with get_sessionmaker()() as s:
        total = s.scalar(select(func.count(Rule.id)).where(Rule.snapshot_id == sid))
    assert total == _expected_rules()  # nothing duplicated or lost across the resume
    assert client.post(f"/api/snapshots/{sid}/resume", headers=admin).status_code == 409


def test_config_change_during_collection_is_detected(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    conn_id = _connection(client, admin)
    sid = _collect(client, admin, conn_id)
    monkeypatch.setattr(store, "count_rules", lambda *_: -1)
    result = jobs.collect_snapshot(sid)
    assert result == {"ok": False, "error": "config_changed"}
    with get_sessionmaker()() as s:
        leftovers = s.scalar(select(func.count(Rule.id)).where(Rule.snapshot_id == sid))
    assert leftovers == 0  # the inconsistent policy was reset, not kept half-collected


def test_wrong_credentials_fail_cleanly(client: TestClient, admin: dict[str, str]) -> None:
    conn_id = _connection(client, admin, password="Definitely-Wrong-9")
    sid = _collect(client, admin, conn_id)
    assert jobs.collect_snapshot(sid) == {"ok": False, "error": "auth_failed"}
    assert _snapshot(sid).error == "auth_failed"
    assert jobs.analyze_snapshot(sid) == {}  # failed snapshots are never analysed


def test_retention(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    keep_two = get_settings().model_copy(update={"snapshot_retention": 2})
    monkeypatch.setattr(jobs, "get_settings", lambda: keep_two)
    conn_id = _connection(client, admin)
    ids = []
    for _ in range(3):
        sid = _collect(client, admin, conn_id)
        assert jobs.collect_snapshot(sid)["ok"] is True
        ids.append(sid)
    remaining = [s["id"] for s in client.get(f"/api/snapshots?connection_id={conn_id}").json()]
    assert remaining == [ids[2], ids[1]]


def test_scheduler_starts_due_collections(client: TestClient, admin: dict[str, str]) -> None:
    conn_id = _connection(client, admin, sync_interval_minutes=60)
    manual_only = client.post(
        "/api/fmc/connections",
        headers=admin,
        json={
            "name": "NO-SYNC",
            "host": "fmc-mock",
            "port": 443,
            "username": "api_user",
            "password": "Whatever-Pass-1",
        },
    )
    assert manual_only.status_code == 201
    started = jobs.schedule_due_collections()
    assert len(started) == 1
    assert _snapshot(started[0]).connection_id == conn_id
    assert _snapshot(started[0]).requested_by == "system:scheduler"
    assert jobs.schedule_due_collections() == []  # pending / interval not elapsed
    upd = client.patch(
        f"/api/fmc/connections/{conn_id}", headers=admin, json={"disable_sync": True}
    )
    assert upd.json()["sync_interval_minutes"] is None


def test_snapshot_reads_validate_input(client: TestClient, admin: dict[str, str]) -> None:
    assert client.get("/api/snapshots/999999").status_code == 404
    assert client.get("/api/snapshots/1/policies/bad id!/rules").status_code in (404, 422)
    assert client.get("/api/snapshots/1/findings?severity=extreme").status_code == 422
    assert client.get("/api/snapshots/1/objects?kind=DROP%20TABLE").status_code == 422
    assert client.get("/api/snapshots/999999/findings").status_code == 404
