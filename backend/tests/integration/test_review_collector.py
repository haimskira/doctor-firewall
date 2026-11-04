"""Collector review: resume safety, group members, stats after a resume, overrides, hit times."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collector import runner, store
from app.collector.service import CollectionError, Collector
from app.db.session import get_sessionmaker
from app.fmc.adapters import v10_1
from app.fmc.adapters.v10_1 import AdapterError
from app.fmc.client import FmcSession, ThrottlePolicy
from app.fmc.errors import FmcWriteRejectedError
from app.fmc.records import HitCountRecord, ObjectKind, ObjectRecord, Ref
from app.models.inventory import FwObject, GroupMember, Rule, SnapshotCheckpoint
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import DATA, _collect, _connection, _snapshot
from tests.integration.test_phase5_writes import _fresh_mock, mock

__all__ = ["_fresh_mock"]

BASE = "/api/fmc_config/v1/domain/{domain}"


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("rc-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "rc-admin")}


def _full(client: TestClient, admin: dict[str, str]) -> int:
    sid = _collect(client, admin, _connection(client, admin))
    assert jobs.collect_snapshot(sid)["ok"] is True
    return sid


def _object(sid: int, fmc_id: str) -> FwObject | None:
    with get_sessionmaker()() as s:
        return s.scalar(
            select(FwObject).where(FwObject.snapshot_id == sid, FwObject.fmc_id == fmc_id)
        )


def test_resume_after_objects_changed_between_attempts_loses_nothing(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = DATA.objects["hosts"]
    size = len(hosts) - 1
    last_id = hosts[-1]["id"]
    sid = _collect(client, admin, _connection(client, admin))

    real_pages: Any = FmcSession.iter_pages
    real_map: Any = v10_1.map_object
    seen = {"hosts": 0}

    def small_pages(self: Any, path: str, **kwargs: Any) -> Any:
        if path.endswith("/object/hosts"):
            kwargs["page_size"] = size  # first page: every host but the last
        return real_pages(self, path, **kwargs)

    def flaky(resource: str, item: Any) -> Any:
        if resource == "hosts":
            seen["hosts"] += 1
            if seen["hosts"] == len(hosts):  # the last host, on the second page
                raise AdapterError("host x: injected failure")
        return real_map(resource, item)

    monkeypatch.setattr(FmcSession, "iter_pages", small_pages)
    monkeypatch.setattr(v10_1, "map_object", flaky)
    assert jobs.collect_snapshot(sid) == {"ok": False, "error": "unexpected_response"}
    with get_sessionmaker()() as s:
        cp = s.get(SnapshotCheckpoint, (sid, "objects:hosts"))
        assert cp is not None
        assert cp.done is False
        assert cp.next_offset == size

    # An unused host disappears from the FMC: every later host moves one position up.
    for host in hosts[:size]:
        try:
            mock("DELETE", f"{BASE}/object/hosts/{host['id']}")
        except FmcWriteRejectedError:
            continue
        break
    else:
        pytest.fail("no deletable host in the mock data")

    monkeypatch.setattr(FmcSession, "iter_pages", real_pages)
    monkeypatch.setattr(v10_1, "map_object", real_map)
    assert client.post(f"/api/snapshots/{sid}/resume", headers=admin).status_code == 202
    assert jobs.collect_snapshot(sid)["ok"] is True
    last = _object(sid, last_id)
    assert last is not None
    assert last.stub is False
    assert last.value is not None


def test_object_met_again_does_not_duplicate_group_members(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _full(client, admin)
    group = next(g for g in DATA.objects["networkgroups"] if g.get("objects"))
    record = v10_1.map_object("networkgroups", group)

    def members(group_id: str) -> int:
        with get_sessionmaker()() as s:
            return (
                s.scalar(
                    select(func.count(GroupMember.id)).where(
                        GroupMember.snapshot_id == sid, GroupMember.group_fmc_id == group_id
                    )
                )
                or 0
            )

    before = members(record.fmc_id)
    assert before > 0
    with get_sessionmaker().begin() as s:
        assert store.store_objects(s, sid, [record, record]) == 0  # a re-read page
    assert members(record.fmc_id) == before

    fresh = ObjectRecord(
        fmc_id="dup-grp",
        kind=ObjectKind.NETWORK_GROUP,
        fmc_type="NetworkGroup",
        name="dup",
        value=None,
        members=(
            Ref(object_id="m1", name="x", fmc_type="Host"),
            Ref(literal="10.0.0.0/8", literal_kind="address"),
        ),
    )
    with get_sessionmaker().begin() as s:
        assert store.store_objects(s, sid, [fresh, fresh]) == 1  # twice on one page
    assert members("dup-grp") == 2


def test_stats_after_a_resume_equal_a_fresh_collection(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    conn_id = _connection(client, admin)
    fresh_sid = _collect(client, admin, conn_id)
    assert jobs.collect_snapshot(fresh_sid)["ok"] is True
    fresh = dict(_snapshot(fresh_sid).stats)
    assert fresh["runtime_routes"]

    sid = _collect(client, admin, conn_id)
    real: Any = Collector._show_route
    calls = {"n": 0}

    async def flaky(self: Any, device_id: str) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:  # the second cluster; the first one is already checkpointed
            raise CollectionError("injected failure")
        return await real(self, device_id)

    monkeypatch.setattr(Collector, "_show_route", flaky)
    assert jobs.collect_snapshot(sid) == {"ok": False, "error": "collection_failed"}
    monkeypatch.setattr(Collector, "_show_route", real)
    assert client.post(f"/api/snapshots/{sid}/resume", headers=admin).status_code == 202
    assert jobs.collect_snapshot(sid)["ok"] is True

    def comparable(stats: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in stats.items() if k not in ("pages", "by_resource")}

    resumed = dict(_snapshot(sid).stats)
    assert comparable(resumed) == comparable(fresh)
    assert resumed["rules"] > 0


def test_overrides_are_collected_into_attrs(client: TestClient, admin: dict[str, str]) -> None:
    def host(name: str, value: str, overridable: bool) -> dict[str, Any]:
        body = {"type": "Host", "name": name, "value": value, "overridable": overridable}
        created: dict[str, Any] = mock("POST", f"{BASE}/object/hosts", body)
        return created

    site = host("T_OVR_SITE", "10.99.0.1", True)
    empty = host("T_OVR_NONE", "10.99.0.2", True)
    plain = host("T_PLAIN", "10.99.0.3", False)
    mock(
        "POST",
        "/mock/overrides",
        {
            "object": site["id"],
            "targets": [
                {"id": "dev-2", "name": "FTD-B", "value": "10.99.2.1"},
                {"id": "dev-1", "name": "FTD-A", "value": "10.99.1.1"},
            ],
        },
    )
    sid = _full(client, admin)

    with_overrides = _object(sid, site["id"])
    assert with_overrides is not None
    assert with_overrides.attrs["overridable"] is True
    assert with_overrides.attrs["overrides"] == [
        {"target_id": "dev-1", "target_name": "FTD-A", "value": "10.99.1.1/32"},
        {"target_id": "dev-2", "target_name": "FTD-B", "value": "10.99.2.1/32"},
    ]
    without = _object(sid, empty["id"])
    assert without is not None
    assert without.attrs["overrides"] == []
    ordinary = _object(sid, plain["id"])
    assert ordinary is not None
    assert "overrides" not in ordinary.attrs
    assert "overridable" not in ordinary.attrs


def test_hit_count_fetch_time_is_kept_per_policy(client: TestClient, admin: dict[str, str]) -> None:
    sid = _full(client, admin)
    fetched = _snapshot(sid).stats["hits_fetched_at"]
    assert fetched
    assert set(fetched) <= set(DATA.rules)
    # The mock's cache was refreshed when it started: a recent, valid time per policy.
    for value in fetched.values():
        assert datetime.now(UTC) - datetime.fromisoformat(value) < timedelta(days=1)

    def total() -> int:
        with get_sessionmaker()() as s:
            return s.scalar(select(func.sum(Rule.hit_count)).where(Rule.snapshot_id == sid)) or 0

    before = total()
    policy = next(iter(fetched))
    unknown = HitCountRecord(rule_id="not-a-rule", hit_count=99, last_hit=None)
    with get_sessionmaker().begin() as s:
        store.apply_hitcounts(s, sid, policy, [unknown])  # not a rule of the snapshot: ignored
    assert total() == before
