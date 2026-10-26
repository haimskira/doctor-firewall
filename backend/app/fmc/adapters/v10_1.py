"""FMC 10.1 REST API adapter: FMC JSON (``expanded=true``) -> version-neutral records.

Every item is validated with a strict schema (identifier format, length bounds,
known enumerations). Unknown extra fields are ignored; a missing or malformed field
that the system relies on fails the collection with the resource and item id — a
partial local copy would silently corrupt every analysis built on it.

Payload shapes follow the Secure Firewall Management Center REST API (10.1). They
must be re-validated against sanitised production payloads before go-live
(see docs/architecture.md, "payload validation").
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.fmc import normalize
from app.fmc.errors import FmcProtocolError
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
    Ref,
    RuleField,
    RuleRecord,
    StaticRouteRecord,
)

VERSION = "10.1"
CONFIG_PREFIX = "/api/fmc_config/v1/domain/{domain}"

FmcId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Name = Annotated[str, Field(max_length=256)]
TypeName = Annotated[str, Field(max_length=64)]
ShortText = Annotated[str, Field(max_length=1024)]


class AdapterError(FmcProtocolError):
    """An FMC item did not match the expected 10.1 schema."""


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class RefModel(_M):
    id: FmcId
    name: Name = ""
    type: TypeName = ""


class LiteralModel(_M):
    type: TypeName = ""
    value: ShortText | None = None
    port: Annotated[str, Field(max_length=32)] | None = None
    protocol: Annotated[str, Field(max_length=16)] | None = None
    url: ShortText | None = None
    icmpType: str | int | None = None  # noqa: N815 - FMC field name


class ObjList(_M):
    objects: list[RefModel] = Field(default_factory=list, max_length=10_000)
    literals: list[LiteralModel] = Field(default_factory=list, max_length=10_000)


class AppList(_M):
    applications: list[RefModel] = Field(default_factory=list, max_length=10_000)
    applicationFilters: list[RefModel] = Field(default_factory=list, max_length=10_000)  # noqa: N815


class UrlList(ObjList):
    urlCategoriesWithReputation: list[dict[str, Any]] = Field(  # noqa: N815
        default_factory=list, max_length=10_000
    )


class RuleMetadata(_M):
    ruleIndex: int | None = Field(default=None, ge=1)  # noqa: N815
    section: Annotated[str, Field(max_length=32)] = "Default"
    category: Name = "--Undefined--"
    timestamp: int | None = Field(default=None, ge=0)  # last change, epoch milliseconds


RuleAction = Literal[
    "ALLOW",
    "TRUST",
    "BLOCK",
    "MONITOR",
    "BLOCK_RESET",
    "BLOCK_INTERACTIVE",
    "BLOCK_RESET_INTERACTIVE",
]


class RuleModel(_M):
    id: FmcId
    name: Name
    enabled: bool = True
    action: RuleAction
    metadata: RuleMetadata = Field(default_factory=RuleMetadata)
    sourceZones: ObjList | None = None  # noqa: N815
    destinationZones: ObjList | None = None  # noqa: N815
    sourceNetworks: ObjList | None = None  # noqa: N815
    destinationNetworks: ObjList | None = None  # noqa: N815
    sourcePorts: ObjList | None = None  # noqa: N815
    destinationPorts: ObjList | None = None  # noqa: N815
    applications: AppList | None = None
    urls: UrlList | None = None
    sourceSecurityGroupTags: ObjList | None = None  # noqa: N815
    destinationSecurityGroupTags: ObjList | None = None  # noqa: N815
    sourceDynamicObjects: ObjList | None = None  # noqa: N815
    destinationDynamicObjects: ObjList | None = None  # noqa: N815
    users: ObjList | None = None
    vlanTags: ObjList | None = None  # noqa: N815
    ipsPolicy: RefModel | None = None  # noqa: N815
    filePolicy: RefModel | None = None  # noqa: N815
    variableSet: RefModel | None = None  # noqa: N815
    logBegin: bool = False  # noqa: N815
    logEnd: bool = False  # noqa: N815
    sendEventsToFMC: bool = False  # noqa: N815
    description: ShortText | None = None


class ObjectModel(_M):
    id: FmcId
    name: Name
    type: TypeName
    value: ShortText | None = None
    description: ShortText | None = None
    overridable: bool = False
    protocol: Annotated[str, Field(max_length=16)] | None = None
    port: Annotated[str, Field(max_length=32)] | None = None
    icmpType: str | int | None = None  # noqa: N815
    code: str | int | None = None
    tag: str | int | None = None
    objectType: Annotated[str, Field(max_length=32)] | None = None  # noqa: N815
    url: ShortText | None = None
    interfaceMode: Annotated[str, Field(max_length=32)] | None = None  # noqa: N815
    metadata: dict[str, Any] | None = None
    objects: list[RefModel] = Field(default_factory=list, max_length=100_000)
    literals: list[LiteralModel] = Field(default_factory=list, max_length=100_000)


class DeviceModel(_M):
    id: FmcId
    name: Name
    model: Name = ""
    sw_version: Annotated[str, Field(max_length=64)] = ""
    accessPolicy: RefModel | None = None  # noqa: N815


class HaPairModel(_M):
    id: FmcId
    name: Name
    primary: RefModel
    secondary: RefModel


class AssignmentModel(_M):
    policy: RefModel
    targets: list[RefModel] = Field(default_factory=list, max_length=10_000)


class DefaultActionModel(_M):
    action: Annotated[str, Field(max_length=64)] = ""


class PolicyModel(_M):
    id: FmcId
    name: Name
    defaultAction: DefaultActionModel | None = None  # noqa: N815
    description: ShortText | None = None
    inspectionMode: Annotated[str, Field(max_length=32)] | None = None  # noqa: N815
    basePolicy: RefModel | None = None  # noqa: N815


class CategoryModel(_M):
    id: FmcId
    name: Name


class HitCountModel(_M):
    rule: RefModel
    hitCount: int = Field(ge=0)  # noqa: N815
    lastHitTimeStamp: Annotated[str, Field(max_length=64)] | None = None  # noqa: N815
    # When the rule reached the device; blank: never deployed. Absent on older FMCs.
    lastDeployedTimeStamp: Annotated[str, Field(max_length=64)] | None = None  # noqa: N815


class StaticIpv4(_M):
    address: Annotated[str, Field(max_length=64)]
    netmask: Annotated[str, Field(max_length=64)]


class Ipv4Config(_M):
    static: StaticIpv4 | None = None


class InterfaceModel(_M):
    id: FmcId
    name: Name
    ifname: Name = ""
    enabled: bool = False
    securityZone: RefModel | None = None  # noqa: N815
    ipv4: Ipv4Config | None = None
    vlanId: int | None = Field(default=None, ge=0, le=4095)  # noqa: N815


class GatewayModel(_M):
    object: RefModel | None = None
    literal: LiteralModel | None = None


class StaticRouteModel(_M):
    id: FmcId
    interfaceName: Name = ""  # noqa: N815
    selectedNetworks: list[RefModel] = Field(default_factory=list, max_length=10_000)  # noqa: N815
    gateway: GatewayModel | None = None
    metricValue: int = Field(default=1, ge=0, le=65535)  # noqa: N815


class BgpGeneralModel(_M):
    asNumber: str | int | None = None  # noqa: N815
    routerId: Annotated[str, Field(max_length=64)] | None = None  # noqa: N815


class BgpNeighborModel(_M):
    ipv4Address: Annotated[str, Field(max_length=64)] | None = None  # noqa: N815
    remoteAs: str | int | None = None  # noqa: N815


class BgpFamilyModel(_M):
    neighbors: list[BgpNeighborModel] = Field(default_factory=list, max_length=10_000)


class BgpModel(_M):
    addressFamilyIPv4: BgpFamilyModel | None = None  # noqa: N815


# --------------------------------------------------------------------------- helpers

# FMC object resources collected in full (applications/geolocations are recorded
# from the references inside rules instead of downloading the whole catalogue).
OBJECT_RESOURCES: tuple[str, ...] = (
    "hosts",
    "networks",
    "ranges",
    "fqdns",
    "networkgroups",
    "protocolportobjects",
    "portobjectgroups",
    "icmpv4objects",
    "icmpv6objects",
    "securityzones",
    "securitygrouptags",
    "isesecuritygrouptags",
    "dynamicobjects",
    "urls",
    "urlgroups",
)
INTERFACE_RESOURCES: tuple[str, ...] = (
    "physicalinterfaces",
    "subinterfaces",
    "etherchannelinterfaces",
    "vlaninterfaces",
)

_TYPE_KIND: dict[str, ObjectKind] = {
    "host": ObjectKind.HOST,
    "network": ObjectKind.NETWORK,
    "range": ObjectKind.RANGE,
    "fqdn": ObjectKind.FQDN,
    "networkgroup": ObjectKind.NETWORK_GROUP,
    "protocolportobject": ObjectKind.PORT,
    "portobjectgroup": ObjectKind.PORT_GROUP,
    "icmpv4object": ObjectKind.ICMP,
    "icmpv6object": ObjectKind.ICMP,
    "securityzone": ObjectKind.ZONE,
    "interfacegroup": ObjectKind.ZONE,
    "securitygrouptag": ObjectKind.SGT,
    "isesecuritygrouptag": ObjectKind.SGT,
    "dynamicobject": ObjectKind.DYNAMIC,
    "application": ObjectKind.APPLICATION,
    "applicationfilter": ObjectKind.APPLICATION,
    "url": ObjectKind.URL,
    "urlgroup": ObjectKind.URL_GROUP,
    "geolocation": ObjectKind.GEO,
    "country": ObjectKind.GEO,
    "continent": ObjectKind.GEO,
}


def kind_of(fmc_type: str) -> ObjectKind:
    return _TYPE_KIND.get(fmc_type.lower(), ObjectKind.OTHER)


def config_path(domain: str, suffix: str) -> str:
    return CONFIG_PREFIX.format(domain=domain) + suffix


def _validate[T: BaseModel](model: type[T], item: Any, what: str) -> T:
    try:
        return model.model_validate(item)
    except ValidationError as exc:
        item_id = item.get("id", "?") if isinstance(item, dict) else "?"
        fields = ",".join(sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()}))
        raise AdapterError(f"{what} {str(item_id)[:64]}: invalid fields [{fields[:200]}]") from exc


def _ref(model: RefModel) -> Ref:
    return Ref(object_id=model.id, name=model.name, fmc_type=model.type)


def _network_literal(lit: LiteralModel) -> Ref:
    if lit.value is None:
        raise ValueError("network literal without value")
    t = lit.type.lower()
    if t == "range":
        value = normalize.ip_range(lit.value)
    elif t == "host":
        value = normalize.host(lit.value)
    else:
        value = normalize.address(lit.value)
    return Ref(literal=value, literal_kind="range" if t == "range" else "address")


def _port_literal(lit: LiteralModel) -> Ref:
    if lit.icmpType is not None:
        return Ref(
            literal=f"{normalize.protocol(lit.protocol or 'ICMP')}/{lit.icmpType}",
            literal_kind="icmp",
        )
    return Ref(literal=normalize.port_spec(lit.protocol, lit.port), literal_kind="port")


def _url_literal(lit: LiteralModel) -> Ref:
    return Ref(literal=normalize.text(lit.url or lit.value), literal_kind="url")


def _refs(
    group: ObjList | None,
    literal: Callable[[LiteralModel], Ref] | None,
) -> list[Ref]:
    if group is None:
        return []
    refs = [_ref(o) for o in group.objects]
    if literal is not None:
        refs.extend(literal(lit) for lit in group.literals)
    return refs


# Policy collections per kind: (list resource, rule sub-resources with their rule type).
POLICY_RESOURCES: dict[PolicyKind, str] = {
    PolicyKind.ACCESS: "accesspolicies",
    PolicyKind.PREFILTER: "prefilterpolicies",
    PolicyKind.DECRYPTION: "decryptionpolicies",
    PolicyKind.IDENTITY: "identitypolicies",
    PolicyKind.NAT: "ftdnatpolicies",
    PolicyKind.INTRUSION: "intrusionpolicies",
    PolicyKind.FILE: "filepolicies",
    PolicyKind.DNS: "dnspolicies",
}
RULE_RESOURCES: dict[PolicyKind, tuple[tuple[str, str | None], ...]] = {
    PolicyKind.ACCESS: (("accessrules", None),),
    PolicyKind.PREFILTER: (("prefilterrules", None),),
    PolicyKind.DECRYPTION: (("decryptionpolicyrules", None),),
    PolicyKind.IDENTITY: (("identityrules", None),),
    PolicyKind.NAT: (("manualnatrules", "MANUAL"), ("autonatrules", "AUTO")),
}
# NAT evaluation order: manual (before auto) -> auto NAT -> manual (after auto).
NAT_SECTION_RANK = {"BEFORE_AUTO": 0, "AUTO": 1, "AFTER_AUTO": 2}


# --------------------------------------------------------------------------- mappers


def map_object(resource: str, item: Any) -> ObjectRecord:
    m = _validate(ObjectModel, item, resource)
    kind = kind_of(m.type)
    attrs: dict[str, Any] = {}
    if m.description and m.description.strip():
        attrs["description"] = normalize.text(m.description)
    if m.overridable:
        attrs["overridable"] = True
    read_only = (m.metadata or {}).get("readOnly")
    if isinstance(read_only, dict) and read_only.get("state") is True:
        # Built-in objects (any-ipv6, IPv4-Private-..., SSH...): the FMC refuses to change them.
        attrs["read_only"] = str(read_only.get("reason") or "SYSTEM")[:32]
    members: list[Ref] = []
    try:
        match kind:
            case ObjectKind.HOST:
                value: str | None = normalize.host(m.value or "")
            case ObjectKind.NETWORK:
                value = normalize.network(m.value or "")
            case ObjectKind.RANGE:
                value = normalize.ip_range(m.value or "")
            case ObjectKind.FQDN:
                value = normalize.text(m.value).lower()
            case ObjectKind.PORT:
                value = normalize.port_spec(m.protocol, m.port)
            case ObjectKind.ICMP:
                value = f"{'ICMPV6' if 'v6' in m.type.lower() else 'ICMP'}/{m.icmpType or 'any'}"
                if m.code is not None:
                    value += f"/{m.code}"
            case ObjectKind.SGT:
                value = str(m.tag) if m.tag is not None else None
            case ObjectKind.DYNAMIC:
                value = m.objectType
            case ObjectKind.URL:
                value = normalize.text(m.url or m.value)
            case ObjectKind.ZONE:
                value = None
                if m.interfaceMode:
                    attrs["interface_mode"] = m.interfaceMode
            case ObjectKind.NETWORK_GROUP:
                value = None
                members = [_ref(o) for o in m.objects]
                members += [_network_literal(lit) for lit in m.literals]
            case ObjectKind.PORT_GROUP:
                value = None
                members = [_ref(o) for o in m.objects]
                members += [_port_literal(lit) for lit in m.literals]
            case ObjectKind.URL_GROUP:
                value = None
                members = [_ref(o) for o in m.objects]
                members += [_url_literal(lit) for lit in m.literals]
            case _:
                value = normalize.text(m.value) or None
    except ValueError as exc:
        raise AdapterError(f"{resource} {m.id}: invalid value") from exc
    return ObjectRecord(
        fmc_id=m.id,
        kind=kind,
        fmc_type=m.type,
        name=m.name,
        value=value,
        attrs=attrs,
        members=tuple(members),
    )


def map_rule(item: Any, position: int) -> RuleRecord:
    """``position`` (1-based order in the API listing) is used if ruleIndex is absent."""
    m = _validate(RuleModel, item, "accessrule")
    refs: list[tuple[RuleField, Ref]] = []

    def add(field: RuleField, items: list[Ref]) -> None:
        refs.extend((field, r) for r in items)

    try:
        add(RuleField.SRC_ZONE, _refs(m.sourceZones, None))
        add(RuleField.DST_ZONE, _refs(m.destinationZones, None))
        add(RuleField.SRC_NET, _refs(m.sourceNetworks, _network_literal))
        add(RuleField.DST_NET, _refs(m.destinationNetworks, _network_literal))
        add(RuleField.SRC_PORT, _refs(m.sourcePorts, _port_literal))
        add(RuleField.DST_PORT, _refs(m.destinationPorts, _port_literal))
        add(RuleField.URL, _refs(m.urls, _url_literal))
        add(RuleField.SRC_SGT, _refs(m.sourceSecurityGroupTags, None))
        add(RuleField.DST_SGT, _refs(m.destinationSecurityGroupTags, None))
        add(RuleField.SRC_DYN, _refs(m.sourceDynamicObjects, None))
        add(RuleField.DST_DYN, _refs(m.destinationDynamicObjects, None))
        add(RuleField.USER, _refs(m.users, None))
        add(RuleField.VLAN, _refs(m.vlanTags, None))
    except ValueError as exc:
        raise AdapterError(f"accessrule {m.id}: invalid literal") from exc
    if m.applications is not None:
        add(RuleField.APP, [_ref(a) for a in m.applications.applications])
        add(RuleField.APP, [_ref(a) for a in m.applications.applicationFilters])
    attrs: dict[str, Any] = {}
    if m.description and m.description.strip():
        attrs["description"] = normalize.text(m.description)
    if m.urls is not None and m.urls.urlCategoriesWithReputation:
        attrs["url_categories"] = len(m.urls.urlCategoriesWithReputation)
    if m.metadata.timestamp:
        changed = datetime.fromtimestamp(m.metadata.timestamp / 1000, UTC)
        attrs["modified_at"] = changed.isoformat()
    return RuleRecord(
        fmc_id=m.id,
        rule_index=m.metadata.ruleIndex or position,
        section=m.metadata.section,
        category=m.metadata.category,
        name=m.name,
        enabled=m.enabled,
        action=m.action,
        ips_policy=m.ipsPolicy.name if m.ipsPolicy else None,
        file_policy=m.filePolicy.name if m.filePolicy else None,
        variable_set=m.variableSet.name if m.variableSet else None,
        log_begin=m.logBegin,
        log_end=m.logEnd,
        send_events=m.sendEventsToFMC,
        attrs=attrs,
        refs=tuple(refs),
        ips_policy_id=m.ipsPolicy.id if m.ipsPolicy else None,
        file_policy_id=m.filePolicy.id if m.filePolicy else None,
    )


def map_device(item: Any) -> DeviceRecord:
    m = _validate(DeviceModel, item, "device")
    return DeviceRecord(
        fmc_id=m.id,
        name=m.name,
        model=m.model,
        sw_version=m.sw_version,
        policy_id=m.accessPolicy.id if m.accessPolicy else None,
    )


def map_ha_pair(item: Any) -> HaPairRecord:
    m = _validate(HaPairModel, item, "ftddevicehapair")
    return HaPairRecord(
        fmc_id=m.id, name=m.name, primary_id=m.primary.id, secondary_id=m.secondary.id
    )


def map_assignment(item: Any) -> AssignmentRecord | None:
    m = _validate(AssignmentModel, item, "policyassignment")
    return AssignmentRecord(
        policy_id=m.policy.id,
        target_ids=tuple(t.id for t in m.targets),
        policy_type=m.policy.type or "AccessPolicy",
    )


_POLICY_LINK_KEY = re.compile(r"^[a-z][A-Za-z]{0,48}PolicySetting$")


def map_policy(item: Any, kind: PolicyKind = PolicyKind.ACCESS) -> PolicyRecord:
    """Any policy (access, prefilter, decryption, identity, NAT, intrusion, file, DNS).

    Links to dependent policies are discovered from every ``*PolicySetting`` reference
    the FMC returns (e.g. ``prefilterPolicySetting`` on an access policy), instead of
    hard-coding names that are not documented for every policy type.
    """
    m = _validate(PolicyModel, item, f"{kind.value}policy")
    links: list[tuple[str, Ref]] = []
    if isinstance(item, dict):
        for key in sorted(item):
            value = item[key]
            if _POLICY_LINK_KEY.fullmatch(key) and isinstance(value, dict) and "id" in value:
                links.append((key, _ref(_validate(RefModel, value, f"{m.id}.{key}"))))
    attrs: dict[str, Any] = {}
    if m.description and m.description.strip():
        attrs["description"] = normalize.text(m.description)
    if m.inspectionMode:
        attrs["inspection_mode"] = m.inspectionMode
    if m.basePolicy is not None:
        attrs["base_policy"] = m.basePolicy.name
    return PolicyRecord(
        fmc_id=m.id,
        name=m.name,
        default_action=m.defaultAction.action if m.defaultAction else "",
        kind=kind,
        links=tuple(links),
        attrs=attrs,
    )


def map_category(item: Any) -> str:
    return _validate(CategoryModel, item, "category").name


def _timestamp(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def map_hitcount(item: Any) -> HitCountRecord:
    m = _validate(HitCountModel, item, "hitcount")
    return HitCountRecord(
        rule_id=m.rule.id,
        hit_count=m.hitCount,
        last_hit=_timestamp(m.lastHitTimeStamp),
        deploy_known=m.lastDeployedTimeStamp is not None,
        deployed_at=_timestamp(m.lastDeployedTimeStamp),
    )


def map_interface(kind: str, item: Any) -> InterfaceRecord:
    m = _validate(InterfaceModel, item, kind)
    ipv4 = None
    if m.ipv4 is not None and m.ipv4.static is not None:
        try:
            ipv4 = normalize.interface_cidr(m.ipv4.static.address, m.ipv4.static.netmask)
        except ValueError as exc:
            raise AdapterError(f"{kind} {m.id}: invalid IPv4 address") from exc
    return InterfaceRecord(
        fmc_id=m.id,
        kind=kind,
        name=m.name,
        ifname=m.ifname,
        enabled=m.enabled,
        zone_id=m.securityZone.id if m.securityZone else None,
        ipv4=ipv4,
        vlan=m.vlanId,
    )


def map_static_route(item: Any) -> StaticRouteRecord:
    m = _validate(StaticRouteModel, item, "ipv4staticroute")
    gateway: Ref | None = None
    if m.gateway is not None:
        if m.gateway.object is not None:
            gateway = _ref(m.gateway.object)
        elif m.gateway.literal is not None:
            try:
                gateway = _network_literal(m.gateway.literal)
            except ValueError as exc:
                raise AdapterError(f"ipv4staticroute {m.id}: invalid gateway") from exc
    return StaticRouteRecord(
        fmc_id=m.id,
        interface=m.interfaceName,
        networks=tuple(_ref(n) for n in m.selectedNetworks),
        gateway=gateway,
        metric=m.metricValue,
    )


def map_bgp(general: list[Any], bgp: list[Any]) -> BgpRecord | None:
    if not general and not bgp:
        return None
    g = _validate(BgpGeneralModel, general[0], "bgpgeneralsettings") if general else None
    neighbors: list[dict[str, str]] = []
    for item in bgp:
        b = _validate(BgpModel, item, "bgp")
        if b.addressFamilyIPv4 is not None:
            neighbors.extend(
                {"address": n.ipv4Address or "", "remote_as": str(n.remoteAs or "")}
                for n in b.addressFamilyIPv4.neighbors
            )
    return BgpRecord(
        as_number=str(g.asNumber) if g and g.asNumber is not None else None,
        router_id=g.routerId if g else None,
        neighbors=tuple(neighbors),
    )


# --------------------------------------------------------------------------- other rule types

UpperToken = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,39}$")]


class GenericRuleModel(_M):
    """Decryption / identity rules. Field names follow the access-rule conventions; the
    action is validated as an FMC enum token (the full value list is version-specific)."""

    id: FmcId
    name: Name = ""
    enabled: bool = True
    action: UpperToken
    metadata: RuleMetadata = Field(default_factory=RuleMetadata)
    sourceZones: ObjList | None = None  # noqa: N815
    destinationZones: ObjList | None = None  # noqa: N815
    sourceInterfaces: ObjList | None = None  # noqa: N815
    destinationInterfaces: ObjList | None = None  # noqa: N815
    sourceNetworks: ObjList | None = None  # noqa: N815
    destinationNetworks: ObjList | None = None  # noqa: N815
    sourcePorts: ObjList | None = None  # noqa: N815
    destinationPorts: ObjList | None = None  # noqa: N815
    applications: AppList | None = None
    urls: UrlList | None = None
    users: ObjList | None = None
    vlanTags: ObjList | None = None  # noqa: N815
    sourceSecurityGroupTags: ObjList | None = None  # noqa: N815
    destinationSecurityGroupTags: ObjList | None = None  # noqa: N815
    logBegin: bool = False  # noqa: N815
    logEnd: bool = False  # noqa: N815
    sendEventsToFMC: bool = False  # noqa: N815
    description: ShortText | None = None


class PrefilterRuleModel(GenericRuleModel):
    action: Literal["ANALYZE", "BLOCK", "FASTPATH"]
    ruleType: Literal["PREFILTER", "TUNNEL"] = "PREFILTER"  # noqa: N815


def _generic_refs(m: GenericRuleModel) -> list[tuple[RuleField, Ref]]:
    refs: list[tuple[RuleField, Ref]] = []

    def add(field: RuleField, items: list[Ref]) -> None:
        refs.extend((field, r) for r in items)

    add(RuleField.SRC_ZONE, _refs(m.sourceZones, None) + _refs(m.sourceInterfaces, None))
    add(RuleField.DST_ZONE, _refs(m.destinationZones, None) + _refs(m.destinationInterfaces, None))
    add(RuleField.SRC_NET, _refs(m.sourceNetworks, _network_literal))
    add(RuleField.DST_NET, _refs(m.destinationNetworks, _network_literal))
    add(RuleField.SRC_PORT, _refs(m.sourcePorts, _port_literal))
    add(RuleField.DST_PORT, _refs(m.destinationPorts, _port_literal))
    add(RuleField.URL, _refs(m.urls, _url_literal))
    add(RuleField.USER, _refs(m.users, None))
    add(RuleField.VLAN, _refs(m.vlanTags, None))
    add(RuleField.SRC_SGT, _refs(m.sourceSecurityGroupTags, None))
    add(RuleField.DST_SGT, _refs(m.destinationSecurityGroupTags, None))
    if m.applications is not None:
        add(RuleField.APP, [_ref(a) for a in m.applications.applications])
        add(RuleField.APP, [_ref(a) for a in m.applications.applicationFilters])
    return refs


def _generic_rule(model: type[GenericRuleModel], what: str, item: Any, position: int) -> RuleRecord:
    m = _validate(model, item, what)
    try:
        refs = _generic_refs(m)
    except ValueError as exc:
        raise AdapterError(f"{what} {m.id}: invalid literal") from exc
    attrs: dict[str, Any] = {}
    if m.description and m.description.strip():
        attrs["description"] = normalize.text(m.description)
    return RuleRecord(
        fmc_id=m.id,
        rule_index=m.metadata.ruleIndex or position,
        section=m.metadata.section,
        category=m.metadata.category,
        name=m.name or f"rule-{position}",
        enabled=m.enabled,
        action=m.action,
        ips_policy=None,
        file_policy=None,
        variable_set=None,
        log_begin=m.logBegin,
        log_end=m.logEnd,
        send_events=m.sendEventsToFMC,
        attrs=attrs,
        refs=tuple(refs),
        rule_type=m.ruleType if isinstance(m, PrefilterRuleModel) else None,
    )


def map_prefilter_rule(item: Any, position: int) -> RuleRecord:
    return _generic_rule(PrefilterRuleModel, "prefilterrule", item, position)


def map_decryption_rule(item: Any, position: int) -> RuleRecord:
    return _generic_rule(GenericRuleModel, "decryptionpolicyrule", item, position)


def map_identity_rule(item: Any, position: int) -> RuleRecord:
    return _generic_rule(GenericRuleModel, "identityrule", item, position)


NatType = Annotated[str, Field(pattern=r"^(STATIC|DYNAMIC)$")]


class AutoNatModel(_M):
    id: FmcId
    natType: NatType  # noqa: N815
    originalNetwork: RefModel | None = None  # noqa: N815
    translatedNetwork: RefModel | None = None  # noqa: N815
    interfaceInTranslatedNetwork: bool = False  # noqa: N815
    sourceInterface: RefModel | None = None  # noqa: N815
    destinationInterface: RefModel | None = None  # noqa: N815
    originalPort: int | str | None = None  # noqa: N815
    translatedPort: int | str | None = None  # noqa: N815
    serviceProtocol: Annotated[str, Field(max_length=16)] | None = None  # noqa: N815
    description: ShortText | None = None


class ManualNatModel(_M):
    id: FmcId
    natType: NatType  # noqa: N815
    section: Annotated[str, Field(pattern=r"^(BEFORE_AUTO|AFTER_AUTO)$")] = "BEFORE_AUTO"
    enabled: bool = True
    originalSource: RefModel | None = None  # noqa: N815
    translatedSource: RefModel | None = None  # noqa: N815
    originalDestination: RefModel | None = None  # noqa: N815
    translatedDestination: RefModel | None = None  # noqa: N815
    originalSourcePort: RefModel | None = None  # noqa: N815
    translatedSourcePort: RefModel | None = None  # noqa: N815
    originalDestinationPort: RefModel | None = None  # noqa: N815
    translatedDestinationPort: RefModel | None = None  # noqa: N815
    sourceInterface: RefModel | None = None  # noqa: N815
    destinationInterface: RefModel | None = None  # noqa: N815
    interfaceInTranslatedSource: bool = False  # noqa: N815
    description: ShortText | None = None


def _opt(field: RuleField, ref: RefModel | None) -> list[tuple[RuleField, Ref]]:
    return [(field, _ref(ref))] if ref is not None else []


def map_nat_rule(item: Any, position: int, rule_type: str) -> RuleRecord:
    """Manual (``MANUAL``) or auto (``AUTO``) NAT rule; NAT has no names, so the
    description (or a positional label) is used."""
    refs: list[tuple[RuleField, Ref]] = []
    attrs: dict[str, Any] = {}
    if rule_type == "AUTO":
        a = _validate(AutoNatModel, item, "autonatrule")
        refs += _opt(RuleField.SRC_ZONE, a.sourceInterface)
        refs += _opt(RuleField.DST_ZONE, a.destinationInterface)
        refs += _opt(RuleField.NAT_ORIG_SRC, a.originalNetwork)
        refs += _opt(RuleField.NAT_TRANS_SRC, a.translatedNetwork)
        try:
            if a.originalPort not in (None, ""):
                refs.append(
                    (
                        RuleField.NAT_ORIG_SPORT,
                        Ref(
                            literal=normalize.port_spec(a.serviceProtocol, str(a.originalPort)),
                            literal_kind="port",
                        ),
                    )
                )
            if a.translatedPort not in (None, ""):
                refs.append(
                    (
                        RuleField.NAT_TRANS_SPORT,
                        Ref(
                            literal=normalize.port_spec(a.serviceProtocol, str(a.translatedPort)),
                            literal_kind="port",
                        ),
                    )
                )
        except ValueError as exc:
            raise AdapterError(f"autonatrule {a.id}: invalid port") from exc
        if a.interfaceInTranslatedNetwork:
            attrs["translate_to_interface"] = True
        fmc_id, nat_type, section, enabled, desc = a.id, a.natType, "AUTO", True, a.description
    else:
        m = _validate(ManualNatModel, item, "manualnatrule")
        refs += _opt(RuleField.SRC_ZONE, m.sourceInterface)
        refs += _opt(RuleField.DST_ZONE, m.destinationInterface)
        refs += _opt(RuleField.NAT_ORIG_SRC, m.originalSource)
        refs += _opt(RuleField.NAT_TRANS_SRC, m.translatedSource)
        refs += _opt(RuleField.NAT_ORIG_DST, m.originalDestination)
        refs += _opt(RuleField.NAT_TRANS_DST, m.translatedDestination)
        refs += _opt(RuleField.NAT_ORIG_SPORT, m.originalSourcePort)
        refs += _opt(RuleField.NAT_TRANS_SPORT, m.translatedSourcePort)
        refs += _opt(RuleField.NAT_ORIG_DPORT, m.originalDestinationPort)
        refs += _opt(RuleField.NAT_TRANS_DPORT, m.translatedDestinationPort)
        if m.interfaceInTranslatedSource:
            attrs["translate_to_interface"] = True
        fmc_id, nat_type, section, enabled, desc = (
            m.id,
            m.natType,
            m.section,
            m.enabled,
            m.description,
        )
    label = normalize.text(desc, 256) if desc and desc.strip() else f"{rule_type} NAT {position}"
    return RuleRecord(
        fmc_id=fmc_id,
        rule_index=position,
        section=section,
        category="",
        name=label,
        enabled=enabled,
        action=nat_type,
        ips_policy=None,
        file_policy=None,
        variable_set=None,
        log_begin=False,
        log_end=False,
        send_events=False,
        attrs=attrs,
        refs=tuple(refs),
        rule_type=rule_type,
    )


def map_any_rule(kind: PolicyKind, rule_type: str | None, item: Any, position: int) -> RuleRecord:
    if kind is PolicyKind.ACCESS:
        return map_rule(item, position)
    if kind is PolicyKind.PREFILTER:
        return map_prefilter_rule(item, position)
    if kind is PolicyKind.DECRYPTION:
        return map_decryption_rule(item, position)
    if kind is PolicyKind.IDENTITY:
        return map_identity_rule(item, position)
    if kind is PolicyKind.NAT:
        return map_nat_rule(item, position, rule_type or "MANUAL")
    raise AdapterError(f"{kind.value} policies have no rules")
