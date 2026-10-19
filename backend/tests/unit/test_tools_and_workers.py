from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import fakeredis
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.audit.chain import AuditDetailsError, _check_json
from app.tools.certs import main as certs_main
from app.workers import scheduler
from app.workers.jobs import ALLOWED_JOBS
from app.workers.queues import QueueName, get_queue
from app.workers.scheduler import Schedule, run_due


def test_cert_tool_issues_ca_signed_leaves(tmp_path: Path) -> None:
    assert (
        certs_main(
            [
                "--out",
                str(tmp_path),
                "--leaf",
                "ui:localhost,127.0.0.1",
                "--leaf",
                "fmc-mock:fmc-mock",
            ]
        )
        == 0
    )
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
    leaf = x509.load_pem_x509_certificate((tmp_path / "ui.pem").read_bytes())
    leaf.verify_directly_issued_by(ca)
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in sans.get_values_for_type(x509.DNSName)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert isinstance(leaf.public_key(), ec.EllipticCurvePublicKey)
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(tmp_path / "ui.key").st_mode) == 0o600


def test_cert_tool_never_overwrites(tmp_path: Path) -> None:
    certs_main(["--out", str(tmp_path), "--leaf", "ui:localhost"])
    with pytest.raises(FileExistsError):
        certs_main(["--out", str(tmp_path), "--leaf", "ui:localhost"])


def test_cert_tool_rejects_bad_leaf(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        certs_main(["--out", str(tmp_path), "--leaf", "nolabel"])


@pytest.mark.parametrize("bad", [1.5, {"a": {1: "x"}}, object(), [[[[[[[[[["deep"]]]]]]]]]]])
def test_audit_details_reject_unstable_values(bad: object) -> None:
    with pytest.raises(AuditDetailsError):
        _check_json(bad)


def test_audit_details_accept_plain_json() -> None:
    _check_json({"a": [1, "x", None, True], "b": {"c": "d"}})


def _noop() -> None:
    return None


def test_scheduler_enqueues_once_per_slot() -> None:
    redis = fakeredis.FakeRedis()
    schedules = (Schedule("noop", _noop, QueueName.MAINTENANCE, 60),)
    assert run_due(redis, 1000.0, schedules) == ["noop"]
    assert run_due(redis, 1010.0, schedules) == []  # same 60s slot
    assert run_due(redis, 1081.0, schedules) == ["noop"]  # next slot
    queue = get_queue(QueueName.MAINTENANCE, redis)
    assert queue.count == 2
    job = queue.jobs[0]
    assert job.func_name == "tests.unit.test_tools_and_workers._noop"


def test_scheduled_jobs_are_allow_listed() -> None:
    for sched in scheduler.SCHEDULES:
        assert f"{sched.func.__module__}.{sched.func.__name__}" in ALLOWED_JOBS


def test_queues_never_use_pickle() -> None:
    queue = get_queue(QueueName.MAINTENANCE, fakeredis.FakeRedis())
    assert "pickle" not in repr(queue.serializer).lower()
    assert queue.serializer.dumps({"a": 1}) == b'{"a": 1}'


def test_singleton_builds_once_under_concurrency() -> None:
    import threading
    import time

    from app.core.singleton import singleton

    calls: list[int] = []

    @singleton
    def make() -> object:
        calls.append(1)
        time.sleep(0.05)
        return object()

    results: list[object] = []
    threads = [threading.Thread(target=lambda: results.append(make())) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(calls) == 1
    assert all(r is results[0] for r in results)
    assert make.is_initialized
    make.cache_clear()
    assert not make.is_initialized
