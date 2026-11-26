"""Phase 6: inspection where the doctrine wants it — IPS, file policy and SSL decryption.

Access and inspection are two separate layers (doctrine): the rule decides whether a flow is
allowed, the inspection what is done to an allowed flow. The organisation has **one** intrusion
policy, **one** file policy and **one** decryption policy — no per-tier profiles. The tier of the
destination only decides *whether* a rule needs inspection and how urgent it is:

========  ==================================  ==================  =======================
tier      IPS (the organisation's policy)     file policy         decryption
========  ==================================  ==================  =======================
CORE      yes (NTP and storage: fastpath)     no                  never (do-not-decrypt)
GOLD      yes                                 yes                 Decrypt-Resign, HTTPS
SILVER    yes                                 yes                 Decrypt-Resign, HTTPS
BRONZE    yes                                 no                  no
========  ==================================  ==================  =======================

IPS is the rule, everywhere it can run. The only exemptions are traffic Snort would break or
drown in **and** that stays between known systems (``IPS_EXEMPT``): storage, replication,
routing protocols, BFD, FMC-FTD management inside the data centre, and NTP to CORE. Those rules
are proposed for fastpath (``fastpath_candidate``) instead of getting an intrusion policy.
Traffic from the WAN is never exempt — an exemption needs both ends inside.

The intrusion policy and the file policy are two separate recommendations on a rule
(``add_inspection`` and ``add_file_policy``): each is an ordinary executable plan, they write
different fields and can be deployed together or one after the other.

Decryption is Decrypt-Resign on HTTPS only (TCP/443), for the systems whose traffic the IPS and
the file policy cannot read otherwise (GOLD, SILVER). Never on CORE systems, nor on identity /
management services by port (``NEVER_DECRYPT``) wherever they are. Decryption and fastpath rules
are proposals only — they depend on the internal CA and a prefilter design the system does not
own.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
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
from app.models.inventory import Policy, Rule
from app.models.recommendations import ORG_PROFILE, InspectionProfile

# Cisco's built-in intrusion policies, weakest to strongest. Custom policies are ranked by
# their base policy; a policy that matches none of these is not judged.
IPS_LEVELS = (
    ("no rules active", 0),
    ("connectivity over security", 1),
    ("balanced", 2),
    ("security over connectivity", 3),
    ("maximum detection", 4),
)
# Any decrypt action counts as "already decrypted" (an existing known-key rule decrypts too).
DECRYPT_ACTIONS = frozenset({"DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY"})
# Only HTTPS is decrypted: other TLS (mail, LDAPS, 8443 ...) is left alone.
HTTPS_PORT = PortSet.build(["TCP/443"])
HTTPS_APPS = frozenset({"HTTPS", "SSL"})
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
    file_policy: bool
    priority: int


# The tier decides whether a rule also needs a file policy and how urgent the work is. The IPS
# itself is wanted on every tier.
DOCTRINE = {
    "CORE": Need(False, 60),
    "GOLD": Need(True, 70),
    "SILVER": Need(True, 55),
    "BRONZE": Need(False, 40),
}
# A rule reaching several tiers gets the most demanding one.
DEMAND_ORDER = ("GOLD", "SILVER", "CORE", "BRONZE")


@dataclass(frozen=True)
class Profile:
    """The organisation's intrusion / file policy (names as in the FMC)."""

    ips_policy: str | None
    file_policy: str | None
    configured: bool  # a row was saved (a value may still come from the snapshot)
    ips_default: bool  # the intrusion policy is the one most allow rules already carry
    file_default: bool


def most_used(session: Session, snapshot_id: int, column: Any) -> str | None:
    """The policy name carried by most enabled allow rules of the snapshot (ties: by name)."""
    count = func.count()
    row = session.execute(
        select(column, count)
        .where(
            Rule.snapshot_id == snapshot_id,
            Rule.policy_kind == "access",
            Rule.enabled.is_(True),
            Rule.action == "ALLOW",
            column.is_not(None),
        )
        .group_by(column)
        .order_by(count.desc(), column)
        .limit(1)
    ).first()
    return str(row[0]) if row is not None else None


def load_profile(session: Session, snapshot_id: int | None) -> Profile:
    """The saved profile; what it leaves open is the policy most allow rules already carry."""
    row = session.get(InspectionProfile, ORG_PROFILE)
    ips = row.ips_policy if row is not None else None
    file = row.file_policy if row is not None else None
    ips_default = ips is None and snapshot_id is not None
    file_default = file is None and snapshot_id is not None
    if snapshot_id is not None:
        if ips is None:
            ips = most_used(session, snapshot_id, Rule.ips_policy)
        if file is None:
            file = most_used(session, snapshot_id, Rule.file_policy)
    return Profile(
        ips,
        file,
        configured=row is not None,
        ips_default=ips_default and ips is not None,
        file_default=file_default and file is not None,
    )


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
    estate: Estate, policy: Policy, rules: list[RuleInfo], profile: Profile
) -> list[Draft]:
    """Allow rules that miss the organisation's intrusion policy (``add_inspection``) or, for
    GOLD / SILVER destinations, a file policy (``add_file_policy``) — two separate proposals."""
    intrusion = _by_name(estate, "intrusion")
    files = _by_name(estate, "file")
    ips_target = intrusion.get(profile.ips_policy) if profile.ips_policy else None
    file_target = files.get(profile.file_policy) if profile.file_policy else None
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
        trust = r.action == "TRUST"
        ips_ok = (
            not trust
            and r.ips_policy is not None
            and (
                r.ips_policy == profile.ips_policy
                or (ips_target is not None and r.ips_policy_id == ips_target.fmc_id)
            )
        )
        if not ips_ok:
            drafts.append(
                _ips_draft(estate, evaluator, policy, info, tier, profile, ips_target, trust)
            )
        # A Trust rule cannot carry a file policy: it becomes Allow first (the IPS proposal),
        # the file policy follows at the next analysis.
        if DOCTRINE[tier].file_policy and not r.file_policy and not trust:
            drafts.append(_file_draft(estate, evaluator, policy, info, tier, profile, file_target))
    return drafts


def _ips_draft(
    estate: Estate,
    evaluator: Evaluator,
    policy: Policy,
    info: RuleInfo,
    tier: str,
    profile: Profile,
    target: Policy | None,
    trust: bool,
) -> Draft:
    r = info.rule
    warnings: list[str] = []
    blocked: list[str] = []
    if target is None:
        blocked.append(
            "ips_profile_missing" if profile.ips_policy else "ips_profile_not_configured"
        )
    if trust:
        warnings.append("trust_to_allow")
    if (
        target is not None
        and ips_level(target.name, str(target.attrs.get("base_policy") or "")) == 4
    ):
        warnings.append("ips_performance")

    wanted = target.name if target is not None else profile.ips_policy
    new_ips = target.name if target is not None else r.ips_policy
    before = _view(info, r.ips_policy, r.file_policy)
    after = with_status(
        _view(info, new_ips, r.file_policy, "ALLOW" if trust else None), "modified", before
    )
    if trust:
        after["changes"]["action"] = {"added": ["ALLOW"], "removed": ["TRUST"]}
    _ace, score = evaluator.evaluate(info, info.refs, overrides={"ips_policy": new_ips})
    old = _old_score(info)

    def build(pb: PlanBuilder) -> None:
        for reason in blocked:
            pb.block(reason)
        pb.set_inspection(
            _rule_dict(info),
            {"action": r.action, "ips": r.ips_policy_id, "file": r.file_policy_id},
            ips={"id": target.fmc_id, "name": target.name} if target is not None else None,
            action="ALLOW" if trust and target is not None else None,
        )

    name = f"#{r.rule_index} {r.name}"
    goal = wanted or "(none chosen)"
    if trust:
        title = f"Change {name} from Trust to Allow and attach intrusion policy {goal}"
    elif r.ips_policy:
        title = f"Switch {name} to the organisation's intrusion policy {goal} (now {r.ips_policy})"
    else:
        title = f"Attach the organisation's intrusion policy {goal} to {name}"
    return Draft(
        kind="add_inspection",
        principle="ips_wherever_possible",
        title=f"{title} ({tier} destination)",
        priority=_rule_priority(DOCTRINE[tier].priority, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [after],
            "tier": tier,
        },
        policy_fmc_id=policy.fmc_id,
        score_delta=(score - old) if score is not None and old is not None else None,
        warnings=warnings,
        plan=_plan(build),
    )


def _file_draft(
    estate: Estate,
    evaluator: Evaluator,
    policy: Policy,
    info: RuleInfo,
    tier: str,
    profile: Profile,
    target: Policy | None,
) -> Draft:
    r = info.rule
    blocked: list[str] = []
    if target is None:
        blocked.append(
            "file_profile_missing" if profile.file_policy else "file_profile_not_configured"
        )
    new_file = target.name if target is not None else r.file_policy
    before = _view(info, r.ips_policy, r.file_policy)
    after = with_status(_view(info, r.ips_policy, new_file), "modified", before)
    _ace, score = evaluator.evaluate(info, info.refs, overrides={"file_policy": new_file})
    old = _old_score(info)

    def build(pb: PlanBuilder) -> None:
        for reason in blocked:
            pb.block(reason)
        pb.set_inspection(
            _rule_dict(info),
            {"action": r.action, "ips": r.ips_policy_id, "file": r.file_policy_id},
            file={"id": target.fmc_id, "name": target.name} if target is not None else None,
        )

    goal = target.name if target is not None else profile.file_policy or "(none chosen)"
    return Draft(
        kind="add_file_policy",
        principle="file_policy_gold_silver",
        title=f"Attach file policy {goal} to #{r.rule_index} {r.name} ({tier} destination)",
        priority=_rule_priority(DOCTRINE[tier].priority - 5, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [after],
            "tier": tier,
        },
        policy_fmc_id=policy.fmc_id,
        score_delta=(score - old) if score is not None and old is not None else None,
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
            + " between known systems (no IPS on this traffic)"
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
    """Collects the HTTPS exposure of GOLD / SILVER systems and checks the decryption policies."""

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
            ports = space.dst_port
            https = (
                (ports.any and space.token("app").any)
                or (not ports.any and ports.intersects(HTTPS_PORT))
                or bool(apps & HTTPS_APPS)
            )
            if not https:
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
                f"add a Do not decrypt rule above the decrypt rules"
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

    # ---- GOLD / SILVER served over HTTPS need Decrypt-Resign

    def _covered(self, rules: list[RuleInfo], node: _Node) -> bool:
        """True when the decryption policy settles HTTPS to the system, either way: the first
        rule that reaches it on TCP/443 decrypts it (any decrypt action) or deliberately leaves
        it alone (do-not-decrypt covering it)."""
        for info in rules:
            r = info.rule
            if not r.enabled:
                continue
            if info.unmodelled:
                continue  # conditions the analysis does not model: proves nothing either way
            space = build_space(info.leaves)
            dst, ports = space.dst_net, space.dst_port
            on_https = ports.any or ports.intersects(HTTPS_PORT)
            if r.action == "DO_NOT_DECRYPT" and on_https and dst.covers(node.addresses):
                return True
            if r.action in DECRYPT_ACTIONS and on_https and dst.intersects(node.addresses):
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
            missing = [n for n in exposed if not self._covered(rules, n)]
            if missing:
                out.append(self._resign_draft(policy, missing))
        return out

    def _resign_draft(self, policy: Policy | None, nodes: list[_Node]) -> Draft:
        by_system = {n.system: n for n in nodes}
        systems = sorted(by_system)
        gold = sum(1 for n in by_system.values() if n.tier == "GOLD")
        silver = len(systems) - gold
        where = policy.name if policy is not None else "No decryption policy"
        mix = ", ".join(
            f"{count} {tier}" for tier, count in (("GOLD", gold), ("SILVER", silver)) if count
        )
        new_rule = {
            "id": None,
            "index": None,
            "name": "DECRYPT_RESIGN_HTTPS",
            "action": "DECRYPT_RESIGN",
            "enabled": True,
            "section": "",
            "category": "",
            "fields": {"dst_net": systems, "dst_port": ["TCP/443"]},
            "status": "added",
        }
        sample = [r for n in nodes for r in n.rules][:SAMPLE]
        return Draft(
            kind="ssl_decrypt_inbound",
            principle="decrypt_https_for_inspection",
            title=(
                f"{where}: add a Decrypt-Resign rule for HTTPS (TCP/443) to {len(systems)} "
                f"system(s) ({mix}) — IPS and file policy cannot read their HTTPS today"
            ),
            priority=65 if gold else 45,
            display="inline",
            deploy_cost=1,
            targets=(
                [{"type": "policy", "id": policy.fmc_id, "name": policy.name}]
                if policy is not None
                else []
            )
            + [{"type": "system", "id": f"{n.tier}|{n.system}", "name": n.system} for n in nodes],
            preview={
                **({"policy": _policy_ref(policy)} if policy is not None else {}),
                "before": [],
                "after": [new_rule],
                "systems": systems,
                "rules": sample,
            },
            policy_fmc_id=policy.fmc_id if policy is not None else None,
            warnings=["resign_ca_trust", "resign_pinning_mtls", "resign_invalid_cert"],
            plan=_plan(lambda pb: pb.block("decryption_rule_manual")),
        )
