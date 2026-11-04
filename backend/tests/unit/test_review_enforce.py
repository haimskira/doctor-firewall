"""Review fixes of the enforcement engine (no database, no FMC): deploy polling, revert checks,
the batch state helpers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.enforce import executor
from app.enforce.executor import (
    BatchError,
    Writer,
    abandoned_unwritten,
    deploy,
    reverting,
    rollback_resumable,
)
from app.enforce.revert import _not_restored
from app.fmc.errors import FmcProtocolError, FmcUnavailableError
from app.models.enforce import Batch


class _Adapter:
    def config_path(self, domain: str, suffix: str) -> str:
        return suffix


class _DeployFmc:
    """Deployable devices, a deployment request, then the task's answers in turn."""

    def __init__(self, answers: list[Any], versions: tuple[str, ...] = ("999", "1000")) -> None:
        self.answers = answers
        self.versions = versions
        self.posted: list[dict[str, Any]] = []
        self.polls = 0

    async def get_json(self, path: str, params: Any = None, **_: Any) -> Any:
        if path.endswith("/deployabledevices"):
            return {
                "items": [
                    {"version": v, "device": {"id": f"dev{n}"}} for n, v in enumerate(self.versions)
                ]
            }
        self.polls += 1
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return {"status": answer, "message": answer}

    async def write_json(self, method: str, path: str, body: Any = None, params: Any = None) -> Any:
        self.posted.append(body)
        return {"metadata": {"task": {"id": "task-1"}}}


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _deploy(fmc: _DeployFmc, clock: _Clock, timeout: float = 100) -> str | None:
    async def tick(seconds: float) -> None:
        clock.now += seconds

    return asyncio.run(
        deploy(
            fmc,  # type: ignore[arg-type]
            _Adapter(),  # type: ignore[arg-type]
            "d",
            {"dev0", "dev1"},
            poll_seconds=10,
            timeout_seconds=timeout,
            sleep=tick,
            clock=clock,
        )
    )


def test_deploy_polling_tolerates_a_failed_read_and_picks_the_newest_version() -> None:
    fmc = _DeployFmc(
        [
            "Deploying",
            FmcUnavailableError("vpn hiccup"),
            FmcProtocolError("GET returned HTTP 502", 502),
            "Deploying",
            "Deployed",
        ]
    )
    assert _deploy(fmc, _Clock()) == "task-1"
    assert fmc.polls == 5
    # Versions are numbers: "1000" is newer than "999" (a string max picked "999").
    assert fmc.posted[0]["version"] == "1000"


def test_deploy_polling_does_not_swallow_a_client_error() -> None:
    fmc = _DeployFmc([FmcProtocolError("GET returned HTTP 400", 400)])
    with pytest.raises(FmcProtocolError):
        _deploy(fmc, _Clock())


def test_a_deployment_still_running_at_the_timeout_gets_a_grace_period() -> None:
    clock = _Clock()
    fmc = _DeployFmc(["Deploying"] * 13 + ["Deployed"])
    # 100 s timeout, polled every 10 s: still running at 130 s, done before 100 + 50.
    assert _deploy(fmc, clock) == "task-1"
    assert clock.now > 100

    clock = _Clock()
    with pytest.raises(BatchError, match="deploy_timeout"):
        _deploy(_DeployFmc(["Deploying"]), clock)
    assert 150 <= clock.now <= 170

    # Past the deadline and the task cannot even be read: give up (no grace on silence).
    clock = _Clock()
    with pytest.raises(BatchError, match="deploy_timeout"):
        _deploy(_DeployFmc([FmcUnavailableError("down")]), clock)
    assert clock.now <= 120


class _ReadFmc:
    def __init__(self, items: dict[str, dict[str, Any]]) -> None:
        self.items = items

    async def get_json(self, path: str, params: Any = None, **_: Any) -> Any:
        return self.items.get(path)

    async def iter_pages(self, path: str, **_: Any) -> AsyncIterator[tuple[int, list[Any]]]:
        pages: list[tuple[int, list[Any]]] = []  # an async generator without pages
        for page in pages:
            yield page


def _writer(fmc: _ReadFmc) -> Writer:
    return Writer(fmc=fmc, adapter=_Adapter(), domain="d")  # type: ignore[arg-type]


def test_not_restored_checks_an_item_written_twice_against_its_first_pre_image() -> None:
    """update_rule then set_inspection on one rule: the second pre-image is a state in between,
    the rule is back to the first one — restored, not "differs"."""
    original = {"id": "r1", "name": "R", "action": "ALLOW", "enabled": True}
    between = {**original, "enabled": False}
    fmc = _ReadFmc({"/rules/r1": {**original, "metadata": {"ruleIndex": 3}}})
    journal = [
        {"undo": "restore", "path": "/rules/r1", "body": original, "state": "undone"},
        {"undo": "restore", "path": "/rules/r1", "body": between, "state": "undone"},
    ]
    assert asyncio.run(_not_restored(_writer(fmc), journal, {})) == []
    fmc.items["/rules/r1"]["enabled"] = False
    assert len(asyncio.run(_not_restored(_writer(fmc), journal, {}))) == 1


def test_not_restored_maps_the_ids_of_recreated_objects() -> None:
    """The batch emptied a group, then deleted the member; the undo re-created the member (new
    id) and restored the group with that id."""
    group_before = {"id": "g1", "name": "G", "objects": [{"id": "h-old", "name": "H"}]}
    fmc = _ReadFmc(
        {
            "/object/networkgroups/g1": {
                "id": "g1",
                "name": "G",
                "objects": [{"id": "h-new", "name": "H"}],
            },
            "/object/hosts/h-new": {"id": "h-new", "name": "H", "value": "10.0.0.1"},
        }
    )
    journal = [
        {
            "undo": "restore",
            "path": "/object/networkgroups/g1",
            "body": group_before,
            "state": "undone",
        },
        {
            "undo": "recreate",
            "path": "/object/hosts",
            "body": {"name": "H", "value": "10.0.0.1"},
            "name": "H",
            "recreates": "h-old",
            "recreated_as": "h-new",
            "state": "undone",
        },
    ]
    assert asyncio.run(_not_restored(_writer(fmc), journal, {})) == []


def _batch(**fields: Any) -> Batch:
    values: dict[str, Any] = {"status": "running", "journal": [], "results": []}
    values.update(fields)
    return Batch(**values)


def test_a_running_batch_without_journal_is_closable_once_stale() -> None:
    now = datetime.now(UTC)
    stale = timedelta(hours=3)
    old = _batch(started_at=now - timedelta(days=1))
    assert abandoned_unwritten(old, now, stale)
    assert not rollback_resumable(old, now, stale)  # nothing to undo
    assert not abandoned_unwritten(_batch(started_at=now), now, stale)  # may still be running
    written = _batch(started_at=now - timedelta(days=1), journal=[{"state": "intent"}])
    assert not abandoned_unwritten(written, now, stale)
    assert rollback_resumable(written, now, stale)


def test_a_revert_is_recognised_by_its_marker_whatever_the_status() -> None:
    marker = [{"op": "create_rule"}, {"op": executor.REVERT_MARKER}]
    assert reverting(_batch(status="failed", results=marker))
    assert not reverting(_batch(status="failed", results=[{"op": "create_rule"}]))


def test_job_timeout_covers_two_deployments_with_their_grace() -> None:
    class _S:
        deploy_timeout_seconds = 1800

    seconds = executor.job_timeout_seconds(_S())  # type: ignore[arg-type]
    assert seconds >= 2 * 1800 * (1 + executor.DEPLOY_GRACE)
    assert executor.stale_after_run(_S()) == timedelta(seconds=seconds)  # type: ignore[arg-type]


def test_redis_lock_releases_atomically_and_only_its_own() -> None:
    class _Redis:
        def __init__(self) -> None:
            self.data: dict[str, str] = {}
            self.evals: list[tuple[Any, ...]] = []

        def set(self, key: str, value: str, nx: bool, ex: int) -> bool:
            if nx and key in self.data:
                return False
            self.data[key] = value
            return True

        def eval(self, script: str, numkeys: int, key: str, owner: str) -> int:
            self.evals.append((numkeys, key))
            if self.data.get(key) == owner:
                del self.data[key]
                return 1
            return 0

    redis = _Redis()
    acquire = executor.redis_lock(redis)

    async def run() -> None:
        release = await acquire("k", 60)
        assert release is not None
        assert await acquire("k", 60) is None
        redis.data["k"] = "someone-else"  # expired and taken by another writer
        await release()
        assert redis.data["k"] == "someone-else"

    asyncio.run(run())
    assert redis.evals == [(1, "k")]
