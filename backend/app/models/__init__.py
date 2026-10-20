"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.assets import Asset, ClusterSetting, RuleScore
from app.models.audit import AuditRecord
from app.models.fmc import FmcConnection
from app.models.inventory import (
    Bgp,
    Cluster,
    ClusterPolicy,
    Finding,
    FwObject,
    GroupMember,
    Interface,
    Policy,
    Route,
    Rule,
    RuleRef,
    Snapshot,
    SnapshotCheckpoint,
)
from app.models.user import User

__all__ = [
    "Asset",
    "AuditRecord",
    "Bgp",
    "Cluster",
    "ClusterPolicy",
    "ClusterSetting",
    "Finding",
    "FmcConnection",
    "FwObject",
    "GroupMember",
    "Interface",
    "Policy",
    "Route",
    "Rule",
    "RuleRef",
    "RuleScore",
    "Snapshot",
    "SnapshotCheckpoint",
    "User",
]
