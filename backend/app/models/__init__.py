"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.assets import Asset, AssetGroup, ClusterSetting, RuleScore
from app.models.audit import AuditRecord
from app.models.enforce import Batch, Changeset, ChangesetItem, DeployWatch
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
from app.models.jobs import JobRun
from app.models.map import MapEdge
from app.models.recommendations import (
    InspectionProfile,
    NamingConvention,
    Recommendation,
    RecommendationDecision,
)
from app.models.user import User

__all__ = [
    "Asset",
    "AssetGroup",
    "AuditRecord",
    "Batch",
    "Bgp",
    "Changeset",
    "ChangesetItem",
    "Cluster",
    "ClusterPolicy",
    "ClusterSetting",
    "DeployWatch",
    "Finding",
    "FmcConnection",
    "FwObject",
    "GroupMember",
    "InspectionProfile",
    "Interface",
    "JobRun",
    "MapEdge",
    "NamingConvention",
    "Policy",
    "Recommendation",
    "RecommendationDecision",
    "Route",
    "Rule",
    "RuleRef",
    "RuleScore",
    "Snapshot",
    "SnapshotCheckpoint",
    "User",
]
