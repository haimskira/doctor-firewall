"""Phase 6: inspection where the doctrine wants it — IPS / file policy and SSL decryption.

Access and inspection are two separate layers (doctrine): the rule decides whether a flow is
allowed, the inspection profile what is done to an allowed flow, and the two are crossed by
the tier of the **destination** — east-west included (a SILVER app calling a GOLD database
gets GOLD inspection):

========  ======================  ==================  ==============
tier      decryption              IPS                 file / malware
========  ======================  ==================  ==============
CORE      no (do-not-decrypt)     light / none        no
GOLD      yes, inbound known-key  full, aggressive    yes
SILVER    selective               full / balanced     yes
BRONZE    by exposure             balanced            optional
========  ======================  ==================  ==============

The system proposes *where*. Attaching an intrusion / file policy to an access rule is an
ordinary executable plan (approved and deployed like any other change); decryption rules are
proposals only — they depend on certificates and keys the system does not hold.
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
TLS_PORTS = PortSet.build(
    ["TCP/443", "TCP/8443", "TCP/9443", "TCP/636", "TCP/993", "TCP/995", "TCP/465"]
)
TLS_APPS = frozenset({"HTTPS", "SSL", "TLS", "LDAPS", "IMAPS", "POP3S", "SMTPS"})
SAMPLE = 20


@dataclass(frozen=True)
class Need:
    min_level: int  # weakest acceptable intrusion policy (IPS_LEVELS)
    file_policy: bool
    default_ips: str
    priority: int


DOCTRINE = {
    "GOLD": Need(4, True, "Maximum Detection", 70),
    "SILVER": Need(2, True, "Security Over Connectivity", 55),
    "BRONZE": Need(2, False, "Balanced Security and Connectivity", 40),
}


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
    return next((t for t in INSPECTION_TIERS if t in tiers), None)


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
        tier = _destination_tier(info)
        if tier is None:
            continue
        need, profile = DOCTRINE[tier], profiles[tier]
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
        title=f"Inspect #{r.rule_index} {r.name} ({tier} destination): " + " + ".join(parts),
        priority=_rule_priority(DOCTRINE[tier].priority, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={"policy": _policy_ref(policy), "before": [before], "after": [after], "tier": tier},
        policy_fmc_id=policy.fmc_id,
        score_delta=(score - old) if score is not None and old is not None else None,
        warnings=warnings,
        plan=_plan(build),
    )


# ------------------------------------------------------------------ SSL decryption


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
        self.exposed: dict[tuple[str, str], _Node] = {}
        self.decryption: list[tuple[Policy, list[RuleInfo]]] = []

    def access(self, policy: Policy, rules: list[RuleInfo]) -> None:
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
                    exposed = self.exposed.setdefault(key, node)
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
        core = [n for n in self.nodes.values() if n.tier == "CORE"]
        if not core:
            return None
        exempt: set[str] = set()
        caught: dict[str, _Node] = {}
        offenders: list[RuleInfo] = []
        for info in rules:
            r = info.rule
            if not r.enabled:
                continue
            dst = build_space(info.leaves).dst_net
            if r.action == "DO_NOT_DECRYPT":
                exempt |= {n.system for n in core if dst.covers(n.addresses)}
            elif r.action in DECRYPT_ACTIONS:
                hit = [n for n in core if n.system not in exempt and dst.intersects(n.addresses)]
                if hit:
                    offenders.append(info)
                    caught.update({n.system: n for n in hit})
        if not caught:
            return None
        systems = sorted(caught)
        new_rule = {
            "id": None,
            "index": None,
            "name": "DND_CORE_SERVICES",
            "action": "DO_NOT_DECRYPT",
            "enabled": True,
            "section": "",
            "category": "",
            "fields": {"dst_net": systems},
            "status": "added",
        }
        return Draft(
            kind="ssl_exempt_core",
            principle="core_not_decrypted",
            title=(
                f"{policy.name}: exempt {len(systems)} CORE system(s) from decryption — "
                f"add a do-not-decrypt rule at the top"
            ),
            priority=80,
            display="inline",
            deploy_cost=1,
            targets=[{"type": "policy", "id": policy.fmc_id, "name": policy.name}]
            + [_rule_target(i) for i in offenders[:SAMPLE]],
            preview={
                "policy": _policy_ref(policy),
                "before": [rule_view(i) for i in offenders[:SAMPLE]],
                "after": [new_rule, *(rule_view(i) for i in offenders[:SAMPLE])],
                "systems": systems,
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
            dst = build_space(info.leaves).dst_net
            if r.action == "DO_NOT_DECRYPT" and dst.covers(node.addresses):
                return False
            if r.action == "DECRYPT_KNOWN_KEY" and dst.intersects(node.addresses):
                return True
        return False

    def _decrypt_inbound(self) -> list[Draft]:
        out: list[Draft] = []
        targets: list[tuple[Policy | None, list[RuleInfo]]] = (
            [(p, rules) for p, rules in self.decryption] if self.decryption else [(None, [])]
        )
        for policy, rules in targets:
            for tier in ("GOLD", "SILVER"):
                missing = [
                    n
                    for n in self.exposed.values()
                    if n.tier == tier and not self._covered(rules, n)
                ]
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
