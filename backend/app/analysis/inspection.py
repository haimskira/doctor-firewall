"""Phase 6: inspection where the doctrine wants it — IPS / file policy and SSL decryption.

Access and inspection are two separate layers (doctrine): the rule decides whether a flow is
allowed, the inspection profile what is done to an allowed flow, and the two are crossed by
the tier of the **destination** — east-west included (a SILVER app calling a GOLD database
gets GOLD inspection):

========  ======================  ==========================  ==============
tier      decryption              IPS                         file / malware
========  ======================  ==========================  ==============
CORE      no (do-not-decrypt)     identity: GOLD's full IPS   no
                                  DNS / patching: balanced
                                  NTP: fastpath
GOLD      yes, inbound known-key  full, aggressive            yes
SILVER    selective               full / balanced             yes
BRONZE    by exposure             balanced                    optional
========  ======================  ==========================  ==============

IPS is the rule, everywhere it can run. The only exemptions are traffic Snort would break or
drown in **and** that stays between known systems (``IPS_EXEMPT``): storage, replication,
routing protocols, BFD, FMC-FTD management inside the data centre, and NTP to CORE. Those rules
are proposed for fastpath (``fastpath_candidate``) instead of getting an intrusion policy.
Traffic from the WAN is never exempt — an exemption needs both ends inside.

Decryption is the opposite: never on CORE systems, nor on identity / management services by
port (``NEVER_DECRYPT``) wherever they are.

The system proposes *where*. Attaching an intrusion / file policy to an access rule is an
ordinary executable plan (approved and deployed like any other change); decryption and fastpath
rules are proposals only — they depend on certificates, keys and a prefilter design the system
does not own.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.expand import build_space
from app.analysis.recommend import (
    Draft,
    Estate,
    Evaluator,
    RuleInfo,
    _old_score,
    _plan,
    _policy_ref,
    _rule_dict,
    _rule_priority,
    _rule_target,
    rule_view,
    with_status,
)
from app.analysis.space import AddressSet, PortSet
from app.enforce.plan import PlanBuilder
from app.models.inventory import Policy
from app.models.recommendations import INSPECTION_TIERS, InspectionProfile

# Cisco's built-in intrusion policies, weakest to strongest. Custom policies are ranked by
# their base policy; a policy that matches none of these is not judged.
IPS_LEVELS = (
    ("no rules active", 0),
    ("connectivity over security", 1),
    ("balanced", 2),
    ("security over connectivity", 3),
    ("maximum detection", 4),
)
DECRYPT_ACTIONS = frozenset({"DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY"})
# TLS a known-key rule could open for the IPS. LDAPS is TLS but never decrypted (NEVER_DECRYPT).
TLS_PORTS = PortSet.build(["TCP/443", "TCP/8443", "TCP/9443", "TCP/993", "TCP/995", "TCP/465"])
TLS_APPS = frozenset({"HTTPS", "SSL", "TLS", "IMAPS", "POP3S", "SMTPS"})
SAMPLE = 20

# Services never decrypted, wherever they run: identity (LDAPS, global catalog over TLS,
# RADIUS over TLS) and security-infrastructure management (FMC-FTD sftunnel, ISE pxGrid).
# A failed decryption here takes down authentication or device control for everyone.
NEVER_DECRYPT_SERVICES = (
    ("LDAPS TCP-636", "TCP/636"),
    ("Global Catalog TLS TCP-3269", "TCP/3269"),
    ("RADIUS over TLS TCP-2083", "TCP/2083"),
    ("FMC-FTD sftunnel TCP-8305", "TCP/8305"),
    ("ISE pxGrid TCP-8910", "TCP/8910"),
)
NEVER_DECRYPT = PortSet.build([spec for _, spec in NEVER_DECRYPT_SERVICES])
SERVER_TIERS = frozenset({"CORE", "GOLD", "SILVER", "BRONZE"})
SMALL_END = 256  # "between known devices": each end at most a /24 worth of addresses


@dataclass(frozen=True)
class Exempt:
    """A traffic class the doctrine keeps out of Snort (see the module docstring)."""

    key: str
    label: str
    ports: PortSet
    # "dc": both ends are data-centre systems of the asset table (CORE..BRONZE).
    # "devices": infrastructure devices, often not in the asset table: both ends small and
    # explicit (no any, at most SMALL_END addresses each).
    # "core": a simple CORE service — the destination is CORE only, the source any classified
    # address (users included, nothing from outside).
    scope: str


IPS_EXEMPT = (
    Exempt(
        "storage", "storage (iSCSI, NFS)", PortSet.build(["TCP/3260", "TCP/2049", "UDP/2049"]), "dc"
    ),
    Exempt(
        "replication",
        "virtualisation and replication (vMotion, VMware NFC, NetApp SnapMirror, SQL AlwaysOn)",
        PortSet.build(["TCP/8000", "TCP/902", "TCP/11104-11105", "TCP/5022"]),
        "dc",
    ),
    Exempt(
        "routing",
        "routing protocols (BGP, OSPF, EIGRP)",
        PortSet.build(["TCP/179", "OSPF/any", "OSPFIGP/any", "89/any", "EIGRP/any", "88/any"]),
        "devices",
    ),
    Exempt("bfd", "BFD", PortSet.build(["UDP/3784-3785", "UDP/4784"]), "devices"),
    Exempt("management", "FMC-FTD management (sftunnel)", PortSet.build(["TCP/8305"]), "devices"),
    # Doctrine: a simple protocol of low value to an attacker; saves CPU for GOLD and the DCs.
    Exempt("ntp", "NTP", PortSet.build(["UDP/123"]), "core"),
)
_EXEMPT_ALL = PortSet.build(
    [
        f"{proto}/{lo}-{hi}"
        for e in IPS_EXEMPT
        for proto, intervals in e.ports.by_protocol
        for lo, hi in intervals
    ]
)


@dataclass(frozen=True)
class Need:
    min_level: int  # weakest acceptable intrusion policy (IPS_LEVELS)
    file_policy: bool
    default_ips: str
    priority: int


DOCTRINE = {
    # CORE is a tier for access, not for inspection. Its profile is the one for DNS and
    # patching (balanced); identity services (AD / DC, PKI) get GOLD's full IPS (CORE_IDENTITY)
    # and NTP is proposed for fastpath. No file policy, and never decrypted.
    "CORE": Need(2, False, "Balanced Security and Connectivity", 60),
    "GOLD": Need(4, True, "Maximum Detection", 70),
    "SILVER": Need(2, True, "Security Over Connectivity", 55),
    "BRONZE": Need(2, False, "Balanced Security and Connectivity", 40),
}
# A rule reaching several tiers gets the most demanding one (SILVER before CORE: the same
# default IPS strength plus a file policy).
DEMAND_ORDER = ("GOLD", "SILVER", "CORE", "BRONZE")

# "AD is CORE for access and GOLD for inspection": a rule to CORE gets GOLD's intrusion policy
# (no file policy) unless every service it allows is DNS or patching. Any port, an unknown
# port, or an identity port (Kerberos, LDAP, Global Catalog, SMB, RPC) means identity.
CORE_IDENTITY = Need(4, False, "Maximum Detection", 70)
CORE_BALANCED = PortSet.build(["TCP/53", "UDP/53", "TCP/8530-8531"])  # DNS, WSUS


def core_service(info: RuleInfo) -> str:
    """``identity`` or ``dns_patching`` for a rule whose destination is CORE."""
    ports = build_space(info.leaves).dst_port
    if ports.any or ports.tokens or not ports.by_protocol or not CORE_BALANCED.covers(ports):
        return "identity"
    return "dns_patching"


@dataclass(frozen=True)
class Profile:
    tier: str
    ips_policy: str | None
    file_policy: str | None
    configured: bool


def load_profiles(session: Session) -> dict[str, Profile]:
    """The tier -> intrusion / file policy mapping (doctrine defaults where not configured)."""
    rows = {p.tier: p for p in session.scalars(select(InspectionProfile))}
    out: dict[str, Profile] = {}
    for tier in INSPECTION_TIERS:
        row = rows.get(tier)
        if row is None:
            out[tier] = Profile(tier, DOCTRINE[tier].default_ips, None, configured=False)
        else:
            out[tier] = Profile(tier, row.ips_policy, row.file_policy, configured=True)
    return out


def ips_level(name: str | None, base: str | None = None) -> int | None:
    """Strength of an intrusion policy by its name, else by its base policy."""
    for text in (name, base):
        if not text:
            continue
        lowered = text.lower()
        for keyword, level in reversed(IPS_LEVELS):
            if keyword in lowered:
                return level
    return None


def _policy_level(policy: Policy | None, name: str | None) -> int | None:
    if policy is not None:
        return ips_level(policy.name, str(policy.attrs.get("base_policy") or "") or None)
    return ips_level(name)


def _by_name(estate: Estate, kind: str) -> dict[str, Policy]:
    return {p.name: p for p in estate.policies.values() if p.kind == kind}


def _destination_tier(info: RuleInfo) -> str | None:
    tiers = set(info.score.dst_tiers) if info.score else set()
    return next((t for t in DEMAND_ORDER if t in tiers), None)


def _dc_end(estate: Estate, addresses: AddressSet) -> bool:
    """Every address is a data-centre system of the asset table (no users, no outside)."""
    if addresses.any or addresses.tokens or addresses.empty or not len(estate.assets):
        return False
    if estate.assets.unclassified(addresses):
        return False
    return {e.tier for e in estate.assets.touching(addresses)} <= SERVER_TIERS


def _core_end(estate: Estate, addresses: AddressSet) -> bool:
    if addresses.any or addresses.tokens or addresses.empty or not len(estate.assets):
        return False
    if estate.assets.unclassified(addresses):
        return False
    return {e.tier for e in estate.assets.touching(addresses)} == {"CORE"}


def _known_end(estate: Estate, addresses: AddressSet) -> bool:
    """Explicit and fully in the asset table (users included): nothing from outside."""
    if addresses.any or addresses.tokens or addresses.empty or not len(estate.assets):
        return False
    return not estate.assets.unclassified(addresses)


def _small_end(addresses: AddressSet) -> bool:
    size = addresses.size()
    return not addresses.any and not addresses.tokens and size is not None and 0 < size <= SMALL_END


def ips_exemption(estate: Estate, info: RuleInfo) -> list[Exempt]:
    """The exempt classes a rule's traffic belongs to — empty unless *all* of it is exempt.

    Every service the rule allows must be in ``IPS_EXEMPT``, and both ends must be inside: DC
    systems for storage / replication, small explicit device sets for routing / BFD /
    management, CORE destinations from known addresses for NTP. Anything from the outside or
    "any" keeps the IPS."""
    if info.unmodelled:
        return []
    space = build_space(info.leaves)
    ports = space.dst_port
    if ports.any or ports.tokens or not ports.by_protocol or not _EXEMPT_ALL.covers(ports):
        return []
    used = [e for e in IPS_EXEMPT if e.ports.intersects(ports)]
    if not used:
        return []
    scopes = {e.scope for e in used}
    if scopes == {"core"}:
        inside = _known_end(estate, space.src_net) and _core_end(estate, space.dst_net)
    elif "dc" in scopes or "core" in scopes:
        inside = _dc_end(estate, space.src_net) and _dc_end(estate, space.dst_net)
    else:
        inside = _small_end(space.src_net) and _small_end(space.dst_net)
    return used if inside else []


def _view(
    info: RuleInfo, ips: str | None, file: str | None, action: str | None = None
) -> dict[str, Any]:
    view = rule_view(info)
    fields = dict(view["fields"])
    if ips:
        fields["ips_policy"] = [ips]
    if file:
        fields["file_policy"] = [file]
    view["fields"] = fields
    if action is not None:
        view["action"] = action
    return view


def recommend_inspection(
    estate: Estate, policy: Policy, rules: list[RuleInfo], profiles: dict[str, Profile]
) -> list[Draft]:
    """Access rules whose destination tier needs more inspection than they have."""
    intrusion = _by_name(estate, "intrusion")
    files = _by_name(estate, "file")
    by_id = {p.fmc_id: p for p in estate.policies.values() if p.kind == "intrusion"}
    evaluator = Evaluator(estate)
    drafts: list[Draft] = []
    for info in rules:
        r = info.rule
        if not (r.enabled and info.permit) or info.score is None:
            continue
        if info.score.shadowed_by is not None or info.score.dead:
            continue  # removal is proposed for these
        exempt = ips_exemption(estate, info)
        if exempt:
            # Heavy / fragile traffic between known DC systems: fastpath, not more IPS.
            if r.action != "TRUST":
                drafts.append(_fastpath_draft(policy, info, exempt))
            continue
        tier = _destination_tier(info)
        if tier is None:
            continue
        need, profile = DOCTRINE[tier], profiles[tier]
        service = core_service(info) if tier == "CORE" else None
        if service == "identity":
            # CORE for access, GOLD for inspection: GOLD's intrusion policy, no file policy.
            gold = profiles["GOLD"]
            need, profile = CORE_IDENTITY, Profile("CORE", gold.ips_policy, None, gold.configured)
        target = intrusion.get(profile.ips_policy) if profile.ips_policy else None
        target_level = _policy_level(target, profile.ips_policy)
        required = target_level if target_level is not None else need.min_level
        current_level = _policy_level(
            by_id.get(r.ips_policy_id or "") or intrusion.get(r.ips_policy or ""), r.ips_policy
        )
        trust = r.action == "TRUST"
        ips_ok = (
            not trust
            and r.ips_policy is not None
            and (
                r.ips_policy == profile.ips_policy
                or current_level is None
                or current_level >= required
            )
        )
        file_needed = need.file_policy and not r.file_policy
        if ips_ok and not file_needed:
            continue
        file_target = files.get(profile.file_policy) if profile.file_policy else None
        drafts.append(
            _inspection_draft(
                estate,
                evaluator,
                policy,
                info,
                tier=tier,
                service=service,
                need=need,
                profile=profile,
                ips_target=None if ips_ok else target,
                ips_needed=not ips_ok,
                file_target=file_target if file_needed else None,
                file_needed=file_needed,
                trust=trust,
            )
        )
    return drafts


def _inspection_draft(
    estate: Estate,
    evaluator: Evaluator,
    policy: Policy,
    info: RuleInfo,
    *,
    tier: str,
    service: str | None,
    need: Need,
    profile: Profile,
    ips_target: Policy | None,
    ips_needed: bool,
    file_target: Policy | None,
    file_needed: bool,
    trust: bool,
) -> Draft:
    r = info.rule
    warnings: list[str] = []
    blocked: list[str] = []
    if ips_needed and ips_target is None:
        blocked.append("ips_profile_missing")
    if file_needed and file_target is None:
        reason = "file_profile_missing" if profile.file_policy else "file_profile_not_configured"
        # The intrusion part can still go ahead; the file policy stays a to-do.
        (warnings if ips_needed and ips_target is not None else blocked).append(reason)
    if trust:
        warnings.append("trust_to_allow")
    if ips_target is not None and ips_level(ips_target.name) == 4:
        warnings.append("ips_performance")

    new_ips = ips_target.name if ips_target is not None else r.ips_policy
    new_file = file_target.name if file_target is not None else r.file_policy
    before = _view(info, r.ips_policy, r.file_policy)
    after = with_status(
        _view(info, new_ips, new_file, "ALLOW" if trust else None), "modified", before
    )
    if trust:
        after["changes"]["action"] = {"added": ["ALLOW"], "removed": ["TRUST"]}

    _ace, score = evaluator.evaluate(
        info, info.refs, overrides={"ips_policy": new_ips, "file_policy": new_file}
    )
    old = _old_score(info)

    def build(pb: PlanBuilder) -> None:
        for reason in blocked:
            pb.block(reason)
        pb.set_inspection(
            _rule_dict(info),
            {"action": r.action, "ips": r.ips_policy_id, "file": r.file_policy_id},
            ips={"id": ips_target.fmc_id, "name": ips_target.name}
            if ips_target is not None
            else None,
            file={"id": file_target.fmc_id, "name": file_target.name}
            if file_target is not None
            else None,
            action="ALLOW" if trust and ips_target is not None else None,
        )

    parts = []
    if ips_needed:
        wanted = ips_target.name if ips_target else profile.ips_policy or "(not configured)"
        parts.append(f"IPS {wanted}")
    if file_needed:
        if file_target is not None:
            parts.append(f"file policy {file_target.name}")
        elif profile.file_policy:
            parts.append("file policy (not in this snapshot)")
        else:
            parts.append("file policy (not configured)")
    return Draft(
        kind="add_inspection",
        principle="inspection_by_destination_tier",
        title=(
            f"Inspect #{r.rule_index} {r.name} "
            f"({tier}{' ' + service.replace('_', ' / ') if service else ''} destination): "
            + " + ".join(parts)
        ),
        priority=_rule_priority(need.priority, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [after],
            "tier": tier,
            **({"core_service": service} if service else {}),
        },
        policy_fmc_id=policy.fmc_id,
        score_delta=(score - old) if score is not None and old is not None else None,
        warnings=warnings,
        plan=_plan(build),
    )


def _fastpath_draft(policy: Policy, info: RuleInfo, exempt: list[Exempt]) -> Draft:
    r = info.rule
    before = rule_view(info)
    after_view = rule_view(info)
    fields = {
        k: v for k, v in after_view["fields"].items() if k not in ("ips_policy", "file_policy")
    }
    after_view["fields"] = fields
    after_view["action"] = "TRUST"
    after = with_status(after_view, "modified", before)
    after["changes"]["action"] = {"added": ["TRUST"], "removed": [r.action]}
    classes = [e.key for e in exempt]
    return Draft(
        kind="fastpath_candidate",
        principle="heavy_trusted_traffic_skips_snort",
        title=(
            f"Consider fastpath for #{r.rule_index} {r.name}: "
            + ", ".join(e.label for e in exempt)
            + " between known systems"
        ),
        priority=_rule_priority(35 if r.ips_policy else 25, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [after],
            "classes": classes,
        },
        policy_fmc_id=policy.fmc_id,
        warnings=["fastpath_no_inspection"],
        plan=_plan(lambda pb: pb.block("fastpath_manual")),
    )


# ------------------------------------------------------------------ SSL decryption


def _dnd_rule(name: str, fields: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "id": None,
        "index": None,
        "name": name,
        "action": "DO_NOT_DECRYPT",
        "enabled": True,
        "section": "",
        "category": "",
        "fields": fields,
        "status": "added",
    }


@dataclass
class _Node:
    tier: str
    system: str
    addresses: AddressSet
    rules: list[dict[str, Any]] = field(default_factory=list)


class SslAdvisor:
    """Collects TLS exposure of GOLD / SILVER systems and checks the decryption policies."""

    def __init__(self, estate: Estate) -> None:
        self.estate = estate
        networks: dict[tuple[str, str], list[str]] = defaultdict(list)
        for row in estate.asset_rows:
            networks[(row.tier, row.system)].append(row.network)
        self.nodes = {
            key: _Node(key[0], key[1], AddressSet.build(values))
            for key, values in sorted(networks.items())
        }
        # Access policy -> its exposed (tier, system) nodes: each access policy is decrypted by
        # the decryption policy it links, never by another one.
        self.exposed: dict[str, dict[tuple[str, str], _Node]] = {}
        self.access_policies: dict[str, Policy] = {}
        self.decryption: list[tuple[Policy, list[RuleInfo]]] = []

    def access(self, policy: Policy, rules: list[RuleInfo]) -> None:
        self.access_policies[policy.fmc_id] = policy
        exposed_here = self.exposed.setdefault(policy.fmc_id, {})
        for info in rules:
            r = info.rule
            if not (r.enabled and info.permit) or info.score is None:
                continue
            if info.score.shadowed_by is not None:
                continue
            if not {"GOLD", "SILVER"} & set(info.score.dst_tiers):
                continue
            space = build_space(info.leaves)
            apps = {x.label.upper() for x in info.refs.get("app", [])}
            tls = (
                (space.dst_port.any and space.token("app").any)
                or (not space.dst_port.any and space.dst_port.intersects(TLS_PORTS))
                or bool(apps & TLS_APPS)
            )
            if not tls:
                continue
            for key, node in self.nodes.items():
                if node.tier in ("GOLD", "SILVER") and space.dst_net.intersects(node.addresses):
                    exposed = exposed_here.setdefault(
                        key, _Node(node.tier, node.system, node.addresses)
                    )
                    if len(exposed.rules) < SAMPLE:
                        exposed.rules.append(
                            {
                                "policy": policy.name,
                                "index": r.rule_index,
                                "name": r.name,
                                "id": r.fmc_id,
                            }
                        )

    def decryption_policy(self, policy: Policy, rules: list[RuleInfo]) -> None:
        self.decryption.append((policy, rules))

    def drafts(self) -> list[Draft]:
        out: list[Draft] = []
        for policy, rules in self.decryption:
            draft = self._exempt_core(policy, rules)
            if draft is not None:
                out.append(draft)
        out += self._decrypt_inbound()
        return out

    # ---- CORE must never be decrypted

    def _exempt_core(self, policy: Policy, rules: list[RuleInfo]) -> Draft | None:
        """Decrypt rules reaching CORE systems, or identity / management services by port,
        before a do-not-decrypt rule exempts them."""
        core = [n for n in self.nodes.values() if n.tier == "CORE"]
        services = [(label, PortSet.build([spec])) for label, spec in NEVER_DECRYPT_SERVICES]
        exempt: set[str] = set()
        exempt_services: set[str] = set()
        caught: dict[str, _Node] = {}
        caught_services: set[str] = set()
        offenders: list[RuleInfo] = []
        for info in rules:
            r = info.rule
            if not r.enabled:
                continue
            space = build_space(info.leaves)
            dst, ports = space.dst_net, space.dst_port
            if r.action == "DO_NOT_DECRYPT":
                if info.unmodelled:
                    continue  # its other conditions may leave part of the traffic decrypted
                if ports.any:
                    exempt |= {n.system for n in core if dst.covers(n.addresses)}
                if dst.any:
                    exempt_services |= {label for label, p in services if ports.covers(p)}
            elif r.action in DECRYPT_ACTIONS:
                hit = [n for n in core if n.system not in exempt and dst.intersects(n.addresses)]
                svc = {
                    label
                    for label, p in services
                    if label not in exempt_services and ports.intersects(p)
                }
                if hit or svc:
                    offenders.append(info)
                    caught.update({n.system: n for n in hit})
                    caught_services |= svc
        if not caught and not caught_services:
            return None
        systems = sorted(caught)
        named = [label for label, _ in NEVER_DECRYPT_SERVICES if label in caught_services]
        new_rules: list[dict[str, Any]] = []
        if systems:
            new_rules.append(_dnd_rule("DND_CORE_SERVICES", {"dst_net": systems}))
        if named:
            new_rules.append(_dnd_rule("DND_IDENTITY_MGMT_SERVICES", {"dst_port": named}))
        parts = []
        if systems:
            parts.append(f"{len(systems)} CORE system(s)")
        if named:
            parts.append(f"{len(named)} identity / management service(s)")
        return Draft(
            kind="ssl_exempt_core",
            principle="core_not_decrypted",
            title=(
                f"{policy.name}: exempt {' and '.join(parts)} from decryption — "
                f"add do-not-decrypt at the top"
            ),
            priority=80,
            display="inline",
            deploy_cost=len(new_rules),
            targets=[{"type": "policy", "id": policy.fmc_id, "name": policy.name}]
            + [_rule_target(i) for i in offenders[:SAMPLE]],
            preview={
                "policy": _policy_ref(policy),
                "before": [rule_view(i) for i in offenders[:SAMPLE]],
                "after": [*new_rules, *(rule_view(i) for i in offenders[:SAMPLE])],
                "systems": systems,
                "services": named,
            },
            policy_fmc_id=policy.fmc_id,
            warnings=["core_breaks_under_decryption"],
            plan=_plan(lambda pb: pb.block("decryption_rule_manual")),
        )

    # ---- GOLD / SILVER served over TLS need inbound known-key decryption

    def _covered(self, rules: list[RuleInfo], node: _Node) -> bool:
        for info in rules:
            r = info.rule
            if not r.enabled:
                continue
            if info.unmodelled:
                continue  # conditions the analysis does not model: proves nothing either way
            dst = build_space(info.leaves).dst_net
            if r.action == "DO_NOT_DECRYPT" and dst.covers(node.addresses):
                return False
            if r.action == "DECRYPT_KNOWN_KEY" and dst.intersects(node.addresses):
                return True
        return False

    @staticmethod
    def _merge(into: dict[tuple[str, str], _Node], nodes: dict[tuple[str, str], _Node]) -> None:
        for key, node in nodes.items():
            mine = into.setdefault(key, _Node(node.tier, node.system, node.addresses))
            mine.rules.extend(node.rules[: max(0, SAMPLE - len(mine.rules))])

    def _targets(self) -> list[tuple[Policy | None, list[RuleInfo], list[_Node]]]:
        """(decryption policy or None, its rules, the exposure it is responsible for).

        An access policy's exposure belongs to the decryption policies it links; the exposure
        of access policies linking none is reported once, without a policy. When no access
        policy links any decryption policy (the FMC did not report the setting), every
        decryption policy is checked against all the exposure, as nothing better is known."""
        decryption = {p.fmc_id: (p, rules) for p, rules in self.decryption}
        per_target: dict[str | None, dict[tuple[str, str], _Node]] = {}
        targets: list[str | None]
        any_link = False
        for pid, nodes in self.exposed.items():
            policy = self.access_policies[pid]
            linked = sorted(
                {str(link["id"]) for link in policy.links or [] if link.get("id")} & set(decryption)
            )
            any_link = any_link or bool(linked)
            targets = list(linked) if linked else [None]
            for target in targets:
                self._merge(per_target.setdefault(target, {}), nodes)
        if not any_link:
            everything: dict[tuple[str, str], _Node] = {}
            for nodes in self.exposed.values():
                self._merge(everything, nodes)
            if not decryption:
                return [(None, [], list(everything.values()))]
            return [(p, rules, list(everything.values())) for p, rules in self.decryption]
        out: list[tuple[Policy | None, list[RuleInfo], list[_Node]]] = []
        for target, nodes in per_target.items():
            if target is None:
                out.append((None, [], list(nodes.values())))
            else:
                policy, rules = decryption[target]
                out.append((policy, rules, list(nodes.values())))
        return sorted(out, key=lambda t: t[0].name if t[0] is not None else "")

    def _decrypt_inbound(self) -> list[Draft]:
        out: list[Draft] = []
        for policy, rules, exposed in self._targets():
            for tier in ("GOLD", "SILVER"):
                missing = [n for n in exposed if n.tier == tier and not self._covered(rules, n)]
                if missing:
                    out.append(self._inbound_draft(policy, tier, missing))
        return out

    def _inbound_draft(self, policy: Policy | None, tier: str, nodes: list[_Node]) -> Draft:
        systems = sorted(n.system for n in nodes)
        where = policy.name if policy is not None else "No decryption policy"
        new_rule = {
            "id": None,
            "index": None,
            "name": f"KNOWN_KEY_{tier}",
            "action": "DECRYPT_KNOWN_KEY",
            "enabled": True,
            "section": "",
            "category": "",
            "fields": {"dst_net": systems},
            "status": "added",
        }
        sample = [r for n in nodes for r in n.rules][:SAMPLE]
        return Draft(
            kind="ssl_decrypt_inbound",
            principle="inspection_by_destination_tier",
            title=(
                f"{where}: decrypt inbound TLS to {len(systems)} {tier} system(s) with their "
                f"own certificate (known-key) — the IPS is blind to it today"
            ),
            priority=65 if tier == "GOLD" else 45,
            display="inline",
            deploy_cost=1,
            targets=(
                [{"type": "policy", "id": policy.fmc_id, "name": policy.name}]
                if policy is not None
                else []
            )
            + [{"type": "system", "id": f"{tier}|{s}", "name": s} for s in systems],
            preview={
                **({"policy": _policy_ref(policy)} if policy is not None else {}),
                "before": [],
                "after": [new_rule],
                "systems": systems,
                "rules": sample,
            },
            policy_fmc_id=policy.fmc_id if policy is not None else None,
            warnings=["server_cert_import_required", "cert_lifecycle"],
            plan=_plan(lambda pb: pb.block("decryption_rule_manual")),
        )
