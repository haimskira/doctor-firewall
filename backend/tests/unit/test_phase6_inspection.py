"""Phase 6 units: intrusion policy strength, the set_inspection plan operation."""

from __future__ import annotations

from app.analysis.inspection import DOCTRINE, ips_level
from app.enforce.batching import KIND_ORDER
from app.enforce.plan import PlanBuilder, touched

RULE = {"policy": "p1", "policy_kind": "access", "id": "r1", "name": "APP_TO_GOLD"}


def test_ips_level_by_name_then_base_policy() -> None:
    assert ips_level("Maximum Detection") == 4
    assert ips_level("Security Over Connectivity") == 3
    assert ips_level("Balanced Security and Connectivity") == 2
    assert ips_level("Connectivity Over Security") == 1
    assert ips_level("No Rules Active") == 0
    assert ips_level("IPS-GOLD", "Maximum Detection") == 4
    assert ips_level("IPS-DC", "Balanced") == 2
    assert ips_level("Custom") is None
    assert ips_level(None) is None


def test_doctrine_table() -> None:
    assert DOCTRINE["GOLD"].min_level == 4
    assert DOCTRINE["GOLD"].file_policy
    assert DOCTRINE["SILVER"].file_policy
    assert not DOCTRINE["BRONZE"].file_policy
    assert DOCTRINE["BRONZE"].default_ips == "Balanced Security and Connectivity"


def test_set_inspection_plan() -> None:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE,
        {"action": "TRUST", "ips": None, "file": None},
        ips={"id": "i4", "name": "Maximum Detection"},
        file={"id": "f1", "name": "Block Malware"},
        action="ALLOW",
    )
    plan = pb.build()
    assert plan["executable"] is True
    (op,) = plan["ops"]
    assert op["expect"] == {"name": "APP_TO_GOLD", "action": "TRUST", "ips": None, "file": None}
    assert op["ips"] == {"id": "i4", "name": "Maximum Detection", "type": "IntrusionPolicy"}
    assert op["file"]["type"] == "FilePolicy"
    assert op["action"] == "ALLOW"
    assert touched(plan)["rules"] == {"p1/r1"}

    nothing = PlanBuilder()
    nothing.set_inspection(RULE, {"action": "ALLOW"})
    assert nothing.build()["executable"] is False  # no operation, nothing to run

    prefilter = PlanBuilder()
    prefilter.set_inspection(
        {**RULE, "policy_kind": "prefilter"}, {"action": "FASTPATH"}, ips={"id": "i", "name": "x"}
    )
    assert prefilter.build()["blocked"] == ["unsupported_rule_kind:prefilter"]


def test_inspection_runs_after_tightening() -> None:
    assert KIND_ORDER.index("tighten_ports") < KIND_ORDER.index("add_inspection")
    assert KIND_ORDER.index("add_inspection") < KIND_ORDER.index("remove_dead_rule")
