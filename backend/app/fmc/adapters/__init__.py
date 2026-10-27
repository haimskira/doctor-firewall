"""FMC API adapters, selected by FMC server version.

An adapter isolates everything version-specific (paths, JSON shapes). Adding a new
FMC version = adding a module that satisfies :class:`FmcAdapter` and registering it;
the collector, storage and analysis engine are untouched. Unknown versions are
refused (fail closed) rather than parsed with a best-effort guess.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from app.fmc.adapters import v10_1
from app.fmc.errors import FmcError
from app.fmc.records import (
    AssignmentRecord,
    BgpRecord,
    DeviceRecord,
    HaPairRecord,
    HitCountRecord,
    InterfaceRecord,
    ObjectKind,
    ObjectRecord,
    PolicyKind,
    PolicyRecord,
    RuleRecord,
    StaticRouteRecord,
)


class FmcAdapter(Protocol):
    VERSION: str
    OBJECT_RESOURCES: tuple[str, ...]
    INTERFACE_RESOURCES: tuple[str, ...]
    POLICY_RESOURCES: dict[PolicyKind, str]
    RULE_RESOURCES: dict[PolicyKind, tuple[tuple[str, str | None], ...]]

    def config_path(self, domain: str, suffix: str) -> str: ...
    def kind_of(self, fmc_type: str) -> ObjectKind: ...
    def map_object(self, resource: str, item: Any) -> ObjectRecord: ...
    def map_rule(self, item: Any, position: int) -> RuleRecord: ...
    def map_device(self, item: Any) -> DeviceRecord: ...
    def map_ha_pair(self, item: Any) -> HaPairRecord: ...
    def map_assignment(self, item: Any) -> AssignmentRecord | None: ...
    def map_policy(self, item: Any, kind: PolicyKind = ...) -> PolicyRecord: ...
    def map_any_rule(
        self, kind: PolicyKind, rule_type: str | None, item: Any, position: int
    ) -> RuleRecord: ...
    def map_category(self, item: Any) -> str: ...
    def map_hitcount(self, item: Any) -> HitCountRecord: ...
    def map_dynamic_mapping(self, item: Any) -> str | None: ...
    def map_interface(self, kind: str, item: Any) -> InterfaceRecord: ...
    def map_static_route(self, item: Any) -> StaticRouteRecord: ...
    def map_bgp(self, general: list[Any], bgp: list[Any]) -> BgpRecord | None: ...


SUPPORTED: dict[str, FmcAdapter] = {v10_1.VERSION: v10_1}
_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)")


class UnsupportedFmcVersionError(FmcError):
    code = "unsupported_fmc_version"


def select_adapter(server_version: str) -> FmcAdapter:
    match = _VERSION_RE.match(server_version)
    if match is None:
        raise UnsupportedFmcVersionError(f"unparseable FMC version {server_version[:64]!r}")
    key = f"{match.group(1)}.{match.group(2)}"
    adapter = SUPPORTED.get(key)
    if adapter is None:
        raise UnsupportedFmcVersionError(
            f"FMC {key} is not supported (supported: {', '.join(sorted(SUPPORTED))})"
        )
    return adapter
