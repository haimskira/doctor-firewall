"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.audit import AuditRecord
from app.models.fmc import FmcConnection
from app.models.inventory import (
    Bgp,
    Cluster,
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
    "AuditRecord",
    "Bgp",
    "Cluster",
    "Finding",
    "FmcConnection",
    "FwObject",
    "GroupMember",
    "Interface",
    "Policy",
    "Route",
    "Rule",
    "RuleRef",
    "Snapshot",
    "SnapshotCheckpoint",
    "User",
]
